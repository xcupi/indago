//go:build browser_integration

package scan_test

// Real-Chromium coverage for the dangling-form confirmation channel (lab 16's
// class: a strict CSP that forbids inline script, injection into a quoted
// attribute value).
//
// /lab reflects `q` into value="…" unencoded and renders a hidden CSRF input
// right after it under `script-src 'self'`, so the only proof available is
// markup: the injected value closes the attribute, the element and the page's
// own form, and opens one whose action carries the scan's marker — the CSRF
// input is then parsed INSIDE that form. /safe encodes the quote, so the payload
// stays inert text and nothing is captured.
//
// The verifier reads that structure from the DOM: it never submits the form and
// the form's action uses the reserved .invalid TLD, so no request leaves the
// browser.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func newDanglingLab(t *testing.T) *site {
	t.Helper()
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/lab?q=hello">lab</a> <a href="/safe?q=hello">safe</a>`)
		})
		render := func(w http.ResponseWriter, r *http.Request, encode bool) {
			q := r.URL.Query().Get("q")
			if encode {
				q = strings.NewReplacer(`"`, "&quot;", "<", "&lt;", ">", "&gt;").Replace(q)
			}
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; img-src 'self'")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			writeHTML(w, `<!doctype html><html><body>
<form name="change-email-form" action="/my-account/change-email" method="POST">
  <input required type="email" name="email" value="`+q+`">
  <input required type="hidden" name="csrf" value="tk_9f3c1b7a2e5d4c8f">
  <button type="submit">Update email</button>
</form>
</body></html>`)
		}
		mux.HandleFunc("/lab", func(w http.ResponseWriter, r *http.Request) { render(w, r, false) })
		mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) { render(w, r, true) })
	})
}

type danglingAttempt struct {
	CandidateValue string         `json:"candidate_value"`
	Verdict        domain.Verdict `json:"verdict"`
	Notes          string         `json:"notes"`
}

type danglingDetail struct {
	Candidates []detection.Candidate `json:"candidates"`
	Attempts   []danglingAttempt     `json:"attempts"`
}

func danglingFindingDetail(t *testing.T, f *domain.Finding) danglingDetail {
	t.Helper()
	var d danglingDetail
	if len(f.Detail) > 0 {
		if err := json.Unmarshal(f.Detail, &d); err != nil {
			t.Fatalf("decode finding detail: %v", err)
		}
	}
	return d
}

func TestDanglingFormCaptureConfirmsOnlyWhenTheParseIsBroken(t *testing.T) {
	ctx := context.Background()
	lab := newDanglingLab(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, lab.URL, domain.Scope{IncludeHosts: []string{"127.0.0.1"}})
	cfg := domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 4}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc := createScan(t, ctrl, proj, tgt, &cfg, domain.StopPolicy{})

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 300*time.Second, isCompleted)

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]*domain.Finding{}
	for _, f := range findings {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil {
			byPath[urlPath(ep.URL)] = append(byPath[urlPath(ep.URL)], f)
		}
	}

	var planned string
	for _, f := range byPath["/lab"] {
		for _, c := range danglingFindingDetail(t, f).Candidates {
			if c.Technique == detection.DanglingFormTechnique {
				planned = c.Value
			}
		}
	}
	if planned == "" {
		t.Fatalf("/lab must plan the %s candidate; findings=%d", detection.DanglingFormTechnique, len(byPath["/lab"]))
	}
	if !strings.Contains(planned, "</form><form action=") {
		t.Fatalf("payload must close the page's form before opening ours, got %q", planned)
	}
	if !strings.Contains(planned, ".invalid/log") {
		t.Fatalf("the injected action must stay on the reserved .invalid TLD, got %q", planned)
	}

	var confirmed *danglingAttempt
	for _, f := range byPath["/lab"] {
		for _, a := range danglingFindingDetail(t, f).Attempts {
			if a.CandidateValue == planned {
				aa := a
				confirmed = &aa
			}
		}
	}
	if confirmed == nil {
		t.Fatalf("the %s candidate was never replayed", detection.DanglingFormTechnique)
	}
	if confirmed.Verdict != domain.VerdictConfirmed {
		t.Fatalf("the broken parse must Confirm via the captured hidden input, got verdict=%s notes=%q", confirmed.Verdict, confirmed.Notes)
	}
	if !strings.Contains(confirmed.Notes, "csrf") {
		t.Fatalf("the confirmation must name the captured input, got %q", confirmed.Notes)
	}
	t.Logf("/lab %s confirmed: %q", detection.DanglingFormTechnique, confirmed.Notes)

	// RED control: /safe encodes the quote, so the payload stays text and the
	// CSRF input never lands inside our form.
	for _, f := range byPath["/safe"] {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("/safe must not Confirm: its reflection encodes the attribute quote (%q)", f.Summary)
		}
	}
}
