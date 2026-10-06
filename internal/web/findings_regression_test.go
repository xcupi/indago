package web_test

// Regression guard for the "Findings = 0" investigation.
//
// Conclusion of that investigation: the detection/correlation backend does NOT
// drop findings. A completed scan over a target that reflects produces a
// finding per reflecting injection point. Without a browser those findings are
// correctly left *pending* (browser verification is the only thing that can
// confirm them — never weakened here); with a verifier they are promoted. The
// operator-visible "zero" was a UI refresh artifact, fixed separately.
//
// This test runs the real pipeline (reflection → context → candidate planning →
// candidate execution → correlation) with NO browser against a reflecting
// target and asserts the completed scan exposes pending findings through the
// very endpoint the UI reads — so a future regression that stops creating
// pending findings would fail here.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

// reflectingTarget reflects the `q` query parameter unescaped into HTML text —
// the simplest shape that must yield a reflected-XSS candidate.
func reflectingTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="/echo?q=hi">echo</a>`)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<div>"+r.URL.Query().Get("q")+"</div>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCompletedScanWithReflectionHasFindings(t *testing.T) {
	a := newAPI(t, nil) // real executor, no browser configured
	site := reflectingTarget(t)
	projectID, targetID := setupScan(a, site.URL)

	var sc domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID, "name": "reflect",
	}), 201, &sc)
	a.mustJSON(a.do("POST", "/api/scans/"+string(sc.ID)+"/start", nil), 200, nil)

	st := pollStatus(a, string(sc.ID), 20*time.Second, func(st scan.Status) bool {
		return st.Scan.State == domain.ScanCompleted
	})

	// A completed scan that reflected is NEVER zero findings.
	if st.Findings.Pending+st.Findings.Confirmed+st.Findings.Rejected+st.Findings.Inconclusive == 0 {
		t.Fatalf("completed scan over a reflecting target produced zero findings: %+v", st.Findings)
	}
	// With no browser, every finding is correctly pending (not confirmed:
	// verification was never possible, and we never fabricate a verdict).
	if st.Findings.Pending == 0 {
		t.Fatalf("expected pending findings without a browser, got %+v", st.Findings)
	}
	if st.Findings.Confirmed != 0 {
		t.Fatalf("no browser configured, yet a finding was confirmed: %+v", st.Findings)
	}

	// The endpoint the UI reads returns those findings.
	rec := a.do("GET", "/api/scans/"+string(sc.ID)+"/findings", nil)
	var findings []map[string]any
	a.mustJSON(rec, 200, &findings)
	if len(findings) == 0 {
		t.Fatal("/findings returned no findings for a completed scan that reflected")
	}
	for _, f := range findings {
		if f["verdict"] != "pending" {
			t.Fatalf("finding verdict = %v, want pending (no browser)", f["verdict"])
		}
	}
}
