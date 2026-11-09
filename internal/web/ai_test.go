package web_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/llm"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// newAIAPI builds a server with an LLM settings store (empty: credentials come
// from env, as a second provider would in production).
func newAIAPI(t *testing.T) api {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	srv.SetLLMStore(llm.NewStore(t.TempDir()))
	return api{t: t, h: srv.Handler(), st: st, ev: evStore}
}

func TestScanAIAssistUsesSelectedProvider(t *testing.T) {
	var gotPrompt string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPrompt = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"1. Test GET /login first"}}],"model":"test-model","usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`))
	}))
	defer model.Close()
	t.Setenv("INDAGO_LLM_KEY_OPENAI", "test-key")
	t.Setenv("INDAGO_LLM_BASE_URL_OPENAI", model.URL)
	t.Setenv("INDAGO_LLM_MODEL_OPENAI", "test-model")

	a := newAIAPI(t)
	scanID := createTestScan(t, a)

	var resp struct {
		Text     string `json:"text"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Advisory bool   `json:"advisory"`
	}
	rec := a.do("POST", "/api/scans/"+string(scanID)+"/ai/assist",
		map[string]any{"kind": "prioritize", "provider": "openai"})
	a.mustJSON(rec, http.StatusOK, &resp)
	if !strings.Contains(resp.Text, "GET /login") {
		t.Fatalf("text = %q", resp.Text)
	}
	if resp.Provider != "openai" || resp.Model != "test-model" || !resp.Advisory {
		t.Fatalf("meta = %+v", resp)
	}
	if !strings.Contains(gotPrompt, "advisory only") && !strings.Contains(gotPrompt, "Advisory only") {
		t.Fatalf("prompt lost the advisory framing: %.200s", gotPrompt)
	}

	var usage struct {
		Calls        int `json:"calls"`
		TotalTokens  int `json:"total_tokens"`
		PromptTokens int `json:"prompt_tokens"`
	}
	a.mustJSON(a.do("GET", "/api/scans/"+string(scanID)+"/ai/usage", nil), http.StatusOK, &usage)
	if usage.Calls != 1 || usage.TotalTokens != 150 || usage.PromptTokens != 120 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestScanAIAssistUnknownKind(t *testing.T) {
	a := newAIAPI(t)
	scanID := createTestScan(t, a)
	rec := a.do("POST", "/api/scans/"+string(scanID)+"/ai/assist", map[string]any{"kind": "hack"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScanAIAssistNoCredential(t *testing.T) {
	a := newAIAPI(t)
	scanID := createTestScan(t, a)
	rec := a.do("POST", "/api/scans/"+string(scanID)+"/ai/assist",
		map[string]any{"kind": "triage", "provider": "deepseek"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INDAGO_LLM_KEY_DEEPSEEK") {
		t.Fatalf("error should name the env var: %s", rec.Body.String())
	}
}

func TestListLLMProvidersShowsEnvironmentCredentials(t *testing.T) {
	t.Setenv("INDAGO_LLM_KEY_OPENAI", "test-key")
	t.Setenv("INDAGO_LLM_MODEL_OPENAI", "gpt-test")
	a := newAIAPI(t)

	var resp struct {
		Providers []struct {
			Provider   string `json:"provider"`
			Configured bool   `json:"configured"`
			Source     string `json:"source"`
			Model      string `json:"model"`
		} `json:"providers"`
	}
	a.mustJSON(a.do("GET", "/api/llm/providers", nil), http.StatusOK, &resp)
	var seen bool
	for _, p := range resp.Providers {
		if p.Provider == "openai" {
			seen = true
			if !p.Configured || p.Source != "environment" || p.Model != "gpt-test" {
				t.Fatalf("openai availability = %+v", p)
			}
		}
	}
	if !seen {
		t.Fatalf("openai missing from %+v", resp.Providers)
	}
}
