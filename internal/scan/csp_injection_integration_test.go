//go:build browser_integration

package scan_test

// Real-Chromium coverage for the CSP report-uri directive-injection candidate.
//
// One loopback lab serves two routes with the SAME reflected `search` and a CSP
// whose report-uri names a query parameter:
//
//   - /lab    copies the request's `token` value into the report-uri verbatim,
//             so `token=;script-src-elem 'unsafe-inline'` appends a directive
//             that permits inline script elements;
//   - /safe   URL-encodes the same value before writing the header, so the
//             injected `;`/quotes never become policy bytes.
//
// The test drives a full scan and pins the chain: the candidate
// `csp_directive_injection` is planned only where the policy names an injectable
// parameter, it carries the directive in ExtraQuery AND a <script> marker in the
// body parameter, and the browser confirms it only at /lab — because only there
// does the relaxed policy let the reflected script run and raise the marker
// ReferenceError the verifier already trusts. /safe is the RED control.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
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

// newCSPInjectionLab serves /lab (injectable report-uri) and /safe (encoded).
func newCSPInjectionLab(t *testing.T) *site {
	t.Helper()
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/lab?search=hello">lab</a> <a href="/safe?search=hello">safe</a>`)
		})
		render := func(w http.ResponseWriter, r *http.Request, encode bool) {
			token := r.URL.Query().Get("token")
			if encode {
				token = url.QueryEscape(token)
			}
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self'; report-uri /csp-report?token="+token)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			writeHTML(w, "<!doctype html><html><body><h1>0 search results for '"+r.URL.Query().Get("search")+"'</h1></body></html>")
		}
		mux.HandleFunc("/lab", func(w http.ResponseWriter, r *http.Request) { render(w, r, false) })
		mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) { render(w, r, true) })
	})
}

type cspInjectionDetail struct {
	Candidates []detection.Candidate `json:"candidates"`
	Attempts   []cspInjectionAttempt `json:"attempts"`
}

type cspInjectionAttempt struct {
	CandidateValue string         `json:"candidate_value"`
	URL            string         `json:"url"`
	Verdict        domain.Verdict `json:"verdict"`
	Notes          string         `json:"notes"`
}

var cspInjectionMarkerRe = regexp.MustCompile(`ind[0-9a-f]{16}`)

func cspInjectionFindingDetail(t *testing.T, f *domain.Finding) cspInjectionDetail {
	t.Helper()
	var d cspInjectionDetail
	if len(f.Detail) > 0 {
		if err := json.Unmarshal(f.Detail, &d); err != nil {
			t.Fatalf("decode finding detail: %v", err)
		}
	}
	return d
}

func TestCSPReportURIParamInjectionConfirmsOnlyWhenThePolicyIsInjectable(t *testing.T) {
	ctx := context.Background()
	lab := newCSPInjectionLab(t)
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

	// The injectable route must plan the technique, carry the directive in the
	// request that is replayed, and confirm through the marker ReferenceError.
	var planned *detection.Candidate
	var labFinding *domain.Finding
	for _, f := range byPath["/lab"] {
		for _, c := range cspInjectionFindingDetail(t, f).Candidates {
			if c.Technique == detection.CSPDirectiveInjectionTechnique {
				cc := c
				planned, labFinding = &cc, f
			}
		}
	}
	if planned == nil {
		t.Fatalf("/lab must plan the %s candidate; findings=%d", detection.CSPDirectiveInjectionTechnique, len(byPath["/lab"]))
	}
	if !strings.HasPrefix(planned.Value, "<script>") || !strings.HasSuffix(planned.Value, "</script>") {
		t.Fatalf("candidate value must be a reflected <script> marker payload, got %q", planned.Value)
	}
	if !strings.Contains(planned.ExtraQuery, "token=") {
		t.Fatalf("candidate must carry the report-uri parameter in ExtraQuery, got %q", planned.ExtraQuery)
	}
	if decoded, _ := url.QueryUnescape(planned.ExtraQuery); !strings.Contains(decoded, ";script-src-elem 'unsafe-inline'") {
		t.Fatalf("candidate must carry the directive injection, got %q (decoded %q)", planned.ExtraQuery, decoded)
	}

	var confirmed *cspInjectionAttempt
	for _, a := range cspInjectionFindingDetail(t, labFinding).Attempts {
		if a.CandidateValue != planned.Value {
			continue
		}
		if a.URL != "" && !strings.Contains(a.URL, "token=") {
			t.Fatalf("the replayed URL must carry the injected policy parameter, got %q", a.URL)
		}
		aa := a
		confirmed = &aa
	}
	if confirmed == nil {
		t.Fatalf("the %s candidate was never replayed", detection.CSPDirectiveInjectionTechnique)
	}
	if confirmed.Verdict != domain.VerdictConfirmed {
		t.Fatalf("the injectable route must Confirm (the relaxed policy runs the reflected script), got verdict=%s notes=%q",
			confirmed.Verdict, confirmed.Notes)
	}
	t.Logf("/lab %s confirmed: %q", detection.CSPDirectiveInjectionTechnique, confirmed.Notes)

	// RED control: /safe encodes the value before writing the header, so the
	// policy is unchanged and the reflected script cannot run.
	for _, f := range byPath["/safe"] {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("/safe must not Confirm: its report-uri value is encoded, so the policy stays strict (%q)", f.Summary)
		}
	}
}
