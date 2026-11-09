package web

// AI advisory surface: one model call per explicit operator request.
//
// Two things this file deliberately does NOT do:
//
//   - It never changes a scan's behaviour, ordering, or any finding's verdict.
//     The scanner's deterministic pipeline decides what is tested and what is
//     confirmed; a model's answer is prose attached to a task, exactly like the
//     report summary.
//   - It never calls a provider implicitly. A scan running in the background
//     makes no AI request unless the operator asks for one (report creation
//     with ai_summary, or POST .../ai/assist).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/ai"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/llm"
)

// aiAssistTimeout bounds one advisory call. It is longer than the settings
// probe but short enough that an operator does not wait on a stuck provider.
const aiAssistTimeout = 60 * time.Second

// handleListLLMProviders reports every supported provider and whether a
// credential is available for it, without revealing any secret.
func (s *Server) handleListLLMProviders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.llmRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "LLM settings are not available on this server")
		return
	}
	out := struct {
		Providers []llm.Availability `json:"providers"`
		Default   string             `json:"default"`
	}{Providers: s.llmRegistry.List()}
	if cfg, err := s.llm.Load(); err == nil {
		out.Default = cfg.Provider
	}
	writeJSON(w, http.StatusOK, out)
}

// aiGatewayFor builds a gateway for one provider/model pair. With no explicit
// provider it uses the stored settings (falling back to the -ai-provider
// gateway when no settings store exists).
func (s *Server) aiGatewayFor(provider, model string) (ai.Gateway, error) {
	if strings.TrimSpace(provider) == "" && s.llmRegistry == nil {
		if s.ai != nil {
			return s.ai, nil
		}
		return ai.Disabled{}, nil
	}
	if s.llmRegistry == nil {
		return ai.Disabled{}, nil
	}
	cred, err := s.llmRegistry.Resolve(provider, model)
	if err != nil {
		return nil, err
	}
	return ai.New(ai.Settings{
		Enabled: true, Provider: cred.Provider, Model: cred.Model,
		BaseURL: cred.BaseURL, APIKey: cred.APIKey(),
		CredentialsDir: s.chatgptDir,
	})
}

// assistantKind maps a request to the advisory task kind and the instructions
// for that kind. Only kinds that are useful with the data indago actually has
// are accepted.
func assistantPrompt(kind string) (domain.AITaskKind, string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "prioritize", "":
		return domain.AIPrioritize,
			"You are assisting an authorized web security assessment. Given the discovered endpoints below, " +
				"list the order in which to test them for XSS, broken access control, IDOR and information disclosure, " +
				"with one short reason per line. Plain text, at most 10 lines, no markdown headings. " +
				"Advisory only: the scanner decides what to test and what is confirmed.", nil
	case "triage":
		return domain.AITriage,
			"Summarise the findings below for an operator: which ones matter most and what each would mean if " +
				"real, in at most 8 plain-text lines. Do not upgrade, downgrade or confirm any verdict; " +
				"the verdicts are the scanner's. Advisory only.", nil
	case "next_steps":
		return domain.AIInterpretContext,
			"Given the scan state below, propose at most 6 concrete next manual checks (plain text, one per line) " +
				"that a tester should perform. Do not claim any vulnerability is confirmed. Advisory only.", nil
	default:
		return "", "", fmt.Errorf("unknown assist kind %q (prioritize|triage|next_steps)", kind)
	}
}

type aiAssistReq struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
}

type aiAssistResp struct {
	TaskID   domain.ID `json:"task_id"`
	Kind     string    `json:"kind"`
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
	Advisory bool      `json:"advisory"`
	Text     string    `json:"text"`
}

// handleScanAIAssist asks the selected model for advisory guidance about a
// scan that already exists. It is safe to call while the scan is running: it
// only reads stored state and never touches the controller.
func (s *Server) handleScanAIAssist(w http.ResponseWriter, r *http.Request) {
	scanID := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), scanID)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req aiAssistReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	taskKind, prompt, err := assistantPrompt(req.Kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if allowed, why := s.aiAdvisoryAllowed(); !allowed {
		writeError(w, http.StatusServiceUnavailable, why)
		return
	}

	gw, err := s.aiGatewayFor(req.Provider, req.Model)
	if err != nil {
		if errors.Is(err, llm.ErrNoCredential) || errors.Is(err, llm.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeInternalError(w, "ai gateway", err)
		return
	}
	if !gw.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "AI is not configured: save a provider in Settings or set INDAGO_LLM_KEY_<PROVIDER>")
		return
	}

	ctxData, err := s.scanAssistContext(r.Context(), scanID, sc)
	if err != nil {
		s.writeInternalError(w, "load scan context", err)
		return
	}

	task := &domain.AITask{
		ID: domain.NewID(), ScanID: scanID, Kind: taskKind, State: domain.AIRunning,
		Advisory: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if b, err := json.Marshal(ctxData); err == nil {
		task.Request = b
	}
	if err := s.store.AITasks().Create(r.Context(), task); err != nil {
		s.log.Warn("ai: record task", "err", err)
	}

	callCtx, cancel := context.WithTimeout(r.Context(), aiAssistTimeout)
	defer cancel()
	resp, err := gw.Advise(callCtx, ai.Request{Kind: taskKind, Prompt: prompt, Context: ctxData})
	task.UpdatedAt = time.Now()
	if err != nil {
		task.State = domain.AIFailed
		task.Error = err.Error()
		_ = s.store.AITasks().Update(r.Context(), task)
		writeError(w, http.StatusBadGateway, "advisory call failed: "+err.Error())
		return
	}
	task.State = domain.AISucceeded
	task.Provider = resp.Provider
	task.Model = resp.Model
	task.Response = []byte(resp.Text)
	if err := s.store.AITasks().Update(r.Context(), task); err != nil {
		s.log.Warn("ai: record task result", "err", err)
	}
	s.log.Info("ai advisory served", "scan", scanID, "kind", taskKind,
		"provider", resp.Provider, "model", resp.Model)
	writeJSON(w, http.StatusOK, aiAssistResp{
		TaskID: task.ID, Kind: string(taskKind), Provider: resp.Provider,
		Model: resp.Model, Advisory: true, Text: resp.Text,
	})
}

// scanAssistContext is the bounded, non-secret picture of a scan given to the
// model: endpoint list (capped), finding counts, and coverage state. It never
// includes evidence bytes, headers, cookies or request bodies.
func (s *Server) scanAssistContext(ctx context.Context, scanID domain.ID, sc *domain.Scan) (map[string]any, error) {
	endpoints, err := s.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	const maxEndpoints = 40
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
	shown := endpoints
	if len(shown) > maxEndpoints {
		shown = shown[:maxEndpoints]
	}
	params, err := s.store.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	names := map[domain.ID][]string{}
	for _, p := range params {
		names[p.EndpointID] = append(names[p.EndpointID], p.Name+" ("+string(p.Location)+")")
	}
	eps := make([]map[string]any, 0, len(shown))
	for _, e := range shown {
		row := map[string]any{"method": string(e.Method), "url": e.URL}
		if list := names[e.ID]; len(list) > 0 {
			if len(list) > 6 {
				list = list[:6]
			}
			row["parameters"] = list
		}
		eps = append(eps, row)
	}
	findings, err := s.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	byVerdict := map[string]int{}
	confirmed := []string{}
	for _, f := range findings {
		byVerdict[string(f.Verdict)]++
		if f.Verdict == domain.VerdictConfirmed {
			confirmed = append(confirmed, f.Title)
		}
	}
	return map[string]any{
		"project":           sc.ProjectID,
		"scan_state":        string(sc.State),
		"profile":           string(sc.Profile),
		"seed_urls":         sc.SeedURLs,
		"endpoint_count":    len(endpoints),
		"endpoints":         eps,
		"findings_by_state": byVerdict,
		"confirmed_titles":  confirmed,
	}, nil
}
