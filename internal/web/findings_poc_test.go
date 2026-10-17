package web_test

// Handler-level tests for GET /api/scans/{id}/findings/{fid}/poc — confirms
// the API surface reachable from the CLI/web UI, not just the underlying
// scan.GeneratePoC function in isolation.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// seedConfirmedFinding seeds a Query-location finding whose Detail carries
// one candidate and one confirming attempt — mirrors seedFinding but with a
// real Confirmed verdict + verified-attempt shape, the minimum
// scan.GeneratePoC needs.
func seedConfirmedFinding(t *testing.T, a api, scanID domain.ID) *domain.Finding {
	t.Helper()
	f, _, _ := seedFinding(t, a, scanID)
	detail := `{"method":"GET","parameter_name":"q","dedup_key":"k1","occurrences":1,` +
		`"candidates":[{"source":"builtin","category":"html_text","context":"html_text","parameter":"q","location":"query",` +
		`"value":"<svg onload=POCMARK>","dedup_key":"ck","rationale":"survives raw"}],` +
		`"attempts":[{"candidate_value":"<svg onload=POCMARK>","candidate_dedup_key":"ck",` +
		`"verdict":"confirmed","confidence":"high","notes":"execution verified","at":"2024-01-01T00:00:00Z"}]}`
	f.Verdict = domain.VerdictConfirmed
	f.Detail = []byte(detail)
	f.UpdatedAt = time.Now()
	if err := a.st.Findings().Update(a.t.Context(), f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestGetFindingPoCConfirmedServesStandaloneHTML(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f := seedConfirmedFinding(t, a, scanID)

	rec := a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID)+"/poc", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("content-disposition = %q, want attachment (forced download)", rec.Header().Get("Content-Disposition"))
	}
	body := rec.Body.String()
	for _, want := range []string{"<!doctype html>", "POCMARK", "curl", `http-equiv="refresh"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("poc body missing %q:\n%s", want, body)
		}
	}
}

// A Pending finding is refused with 409 — the server never generates a PoC
// for anything short of Confirmed (AGENTS.md evidence integrity).
func TestGetFindingPoCPendingRefused(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	f, _, _ := seedFinding(t, a, scanID) // Pending by default

	rec := a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(f.ID)+"/poc", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func TestGetFindingPoCUnknownFinding404(t *testing.T) {
	a := newAPI(t, nil)
	scanID := createTestScan(t, a)
	rec := a.do("GET", "/api/scans/"+string(scanID)+"/findings/"+string(domain.NewID())+"/poc", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
