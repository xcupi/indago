package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestReportReviewReturnsTriagerVerdict(t *testing.T) {
	var gotPrompt string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPrompt = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"model": "test-model",
			"choices": []map[string]any{{"message": map[string]any{
				"role":    "assistant",
				"content": `{"verdict":"NEEDS FIXES","summary":"Reproducible but CVSS missing.","issues":[{"severity":"major","issue":"No CVSS vector","fix":"Assign a 3.1 vector in the form"}],"missing_evidence":[]}`,
			}}},
		})
	}))
	defer model.Close()
	t.Setenv("INDAGO_LLM_KEY_OPENAI", "k")
	t.Setenv("INDAGO_LLM_BASE_URL_OPENAI", model.URL)
	t.Setenv("INDAGO_LLM_MODEL_OPENAI", "test-model")

	a := newAIAPI(t)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID)
	f.Verdict = domain.VerdictConfirmed
	if err := a.st.Findings().Update(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	var resp struct {
		Verdict  string `json:"verdict"`
		Advisory bool   `json:"advisory"`
		Issues   []struct {
			Severity string `json:"severity"`
			Issue    string `json:"issue"`
		} `json:"issues"`
		Provider string `json:"provider"`
	}
	a.mustJSON(a.do("POST", "/api/scans/"+string(scanID)+"/ai/report-review",
		map[string]any{"mode": "confirmed", "provider": "openai"}), http.StatusOK, &resp)
	if resp.Verdict != "NEEDS FIXES" || !resp.Advisory || len(resp.Issues) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Provider != "openai" {
		t.Fatalf("provider = %q", resp.Provider)
	}
	// The reviewer must receive the platform's five sections, not a raw dump.
	for _, want := range []string{"## Description", "## Exploitation", "## PoC", "## Risk", "## Remediation", "strict bug-bounty triager"} {
		if !strings.Contains(gotPrompt, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
}
