package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// stubModel returns a fixed completion and records the prompt it received.
func stubModel(t *testing.T, content string) (*httptest.Server, *string) {
	t.Helper()
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		prompt = string(b)
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(map[string]any{
			"model":   "test-model",
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": content}}},
		})
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("INDAGO_LLM_KEY_OPENAI", "test-key")
	t.Setenv("INDAGO_LLM_BASE_URL_OPENAI", srv.URL)
	t.Setenv("INDAGO_LLM_MODEL_OPENAI", "test-model")
	return srv, &prompt
}

func configureLLM(t *testing.T, a api, body map[string]any) {
	t.Helper()
	if _, ok := body["provider"]; !ok {
		body["provider"] = "openai"
	}
	if _, ok := body["model"]; !ok {
		body["model"] = "test-model"
	}
	if _, ok := body["api_key"]; !ok {
		body["api_key"] = "test-key"
	}
	rec := a.do("PUT", "/api/llm/config", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("configure llm: %d %s", rec.Code, rec.Body.String())
	}
}

const diagnoseJSON = `{
  "diagnosis": "The response reflects the value inside an attribute, so raw markup is inert.",
  "why_failed": "wrong_context",
  "waf": {"suspected": false, "signature": "", "confidence": "high", "notes": "no 403 or challenge"},
  "payloads": [
    {"payload": "<mark>", "encoded": "%3Cmark%3E", "context": "html_text", "rationale": "repeat", "proof": "marker", "confidence": "low", "bypasses": "", "class": "reflected_xss"},
    {"payload": "\"><svg onload=indTEST42>", "encoded": "%22%3E%3Csvg%20onload%3DindTEST42%3E", "context": "attr_dq", "rationale": "closes the attribute", "proof": "ReferenceError indTEST42", "confidence": "medium", "bypasses": "attribute quoting", "class": "reflected_xss"},
    {"payload": "' UNION SELECT password FROM users--", "encoded": "", "context": "sql", "rationale": "dump the table", "proof": "row", "confidence": "low", "bypasses": "", "class": "sqli"}
  ],
  "next_steps": ["Confirm the sink quotes the value"]
}`

func TestDiagnoseDropsRepeatsAndOutOfScope(t *testing.T) {
	_, prompt := stubModel(t, diagnoseJSON)
	a := newAIAPI(t)
	configureLLM(t, a, map[string]any{})
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	var resp struct {
		Diagnosis         string `json:"diagnosis"`
		DuplicatesDropped int    `json:"duplicates_dropped"`
		OutOfScope        int    `json:"out_of_scope_dropped"`
		Payloads          []struct {
			Payload string `json:"payload"`
			Class   string `json:"class"`
		} `json:"payloads"`
		Advisory bool `json:"advisory"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/ai/diagnose",
		map[string]any{"finding_id": f.ID, "provider": "openai"}), http.StatusOK, &resp)

	if len(resp.Payloads) != 1 {
		t.Fatalf("payloads = %+v (want only the in-scope, untried one)", resp.Payloads)
	}
	if resp.Payloads[0].Payload != `"><svg onload=indTEST42>` || resp.Payloads[0].Class != "reflected_xss" {
		t.Fatalf("kept payload = %+v", resp.Payloads[0])
	}
	if resp.DuplicatesDropped != 1 {
		t.Fatalf("duplicates_dropped = %d", resp.DuplicatesDropped)
	}
	if resp.OutOfScope != 1 {
		t.Fatalf("out_of_scope_dropped = %d", resp.OutOfScope)
	}
	if !resp.Advisory || resp.Diagnosis == "" {
		t.Fatalf("resp = %+v", resp)
	}
	// The provider receives JSON, so inspect the decoded message text rather
	// than the wire bytes (Go escapes < and > as \u003c/\u003e).
	var wire struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(*prompt), &wire); err != nil {
		t.Fatalf("decode prompt: %v", err)
	}
	var text strings.Builder
	for _, m := range wire.Messages {
		text.WriteString(m.Content)
	}
	sent := text.String()
	if !strings.Contains(sent, "<mark>") || !strings.Contains(strings.ToLower(sent), "do not propose them again") {
		t.Fatalf("prompt does not carry the already-tried list: %.400s", sent)
	}
	// The scope fence must be in the prompt, not only in the post-filter.
	if !strings.Contains(sent, "reflected_xss") || !strings.Contains(sent, "SQL injection") {
		t.Fatalf("prompt lost the scope fence: %.400s", sent)
	}
}

func TestDiagnoseSkipsConfirmedFindingWithoutCallingModel(t *testing.T) {
	srv, _ := stubModel(t, diagnoseJSON)
	a := newAIAPI(t)
	configureLLM(t, a, map[string]any{})
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	f.Verdict = domain.VerdictConfirmed
	if err := a.st.Findings().Update(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Skipped    bool   `json:"skipped"`
		SkipReason string `json:"skip_reason"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/ai/diagnose",
		map[string]any{"finding_id": f.ID, "provider": "openai"}), http.StatusOK, &resp)
	if !resp.Skipped || !strings.Contains(resp.SkipReason, "already confirmed") {
		t.Fatalf("resp = %+v", resp)
	}
	_ = srv
	// A skipped diagnosis must not have created an AI task either.
	tasks, err := a.st.AITasks().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 0 {
		t.Fatalf("tasks = %d (want 0: no model call, no spend)", len(tasks))
	}
}

func TestDiagnoseBudgetExhaustedSkips(t *testing.T) {
	stubModel(t, diagnoseJSON)
	a := newAIAPI(t)
	configureLLM(t, a, map[string]any{"max_attempts": 2})
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	ctx := context.Background()
	req, _ := json.Marshal(map[string]any{"finding_id": string(f.ID), "mode": "why_failed"})
	for i := 0; i < 2; i++ {
		task := &domain.AITask{
			ID: domain.NewID(), ScanID: scanID, Kind: domain.AISuggestPayloads,
			State: domain.AIFailed, Request: req, Advisory: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := a.st.AITasks().Create(ctx, task); err != nil {
			t.Fatal(err)
		}
	}

	var resp struct {
		Skipped  bool   `json:"skipped"`
		Reason   string `json:"skip_reason"`
		Attempts int    `json:"attempts_used"`
		Budget   int    `json:"attempt_budget"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/ai/diagnose",
		map[string]any{"finding_id": f.ID, "provider": "openai"}), http.StatusOK, &resp)
	if !resp.Skipped || resp.Attempts != 2 || resp.Budget != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	if !strings.Contains(resp.Reason, "exhausted") {
		t.Fatalf("reason = %q", resp.Reason)
	}
}

func TestDiagnoseRespectsMasterSwitch(t *testing.T) {
	stubModel(t, diagnoseJSON)
	a := newAIAPI(t)
	configureLLM(t, a, map[string]any{"enabled": false})
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)

	rec := a.do("POST", "/api/scans/"+string(scanID)+"/ai/diagnose",
		map[string]any{"finding_id": f.ID, "provider": "openai"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
