//go:build browser_integration

package scan_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// PortSwigger labs 8-11 are the filter-allow-list family: every canonical
// breakout is rejected and exactly one benign shape is admitted. They were
// confirmed with -enable-evasion and the operator's explicit Technique pack.
//
// This test is the contract for "it works automatically now": a plain scan
// (EnableEvasion false) must reach the same four confirmations through the
// automatic, evidence-gated escalation — no operator flag.
//
// Filters reproduce the measured behaviour in the lab notes:
//
//	lab8   only <body onresize>           -> allowlisted_tag_event
//	lab9   only custom tags with onfocus  -> custom_element_focus
//	lab10  only <svg><animatetransform>   -> svg_smil_begin
//	lab11  only SMIL attributeName=href   -> smil_href_animation
type allowListLab struct {
	path  string
	allow *regexp.Regexp
	want  string // substring that identifies the confirming candidate
	label string
}

var allowListLabs = []allowListLab{
	{path: "lab8", label: "allowlisted body/onresize", want: "onresize",
		allow: regexp.MustCompile(`(?i)<body[^>]*onresize=`)},
	{path: "lab9", label: "custom element autofocus", want: "onfocus",
		allow: regexp.MustCompile(`(?i)<x-[a-z0-9-]+[^>]*onfocus=`)},
	{path: "lab10", label: "SVG SMIL animatetransform", want: "animatetransform",
		allow: regexp.MustCompile(`(?i)<svg>\s*<animatetransform[^>]*onbegin=`)},
	{path: "lab11", label: "SMIL-written href", want: "attributeName=href",
		allow: regexp.MustCompile(`(?i)<animate[^>]*attributeName=href`)},
}

// tagStart matches the beginning of an HTML tag with a name. The labs' filters
// block TAGS, not the '<' character: the scanner's own reflection probe carries
// `<>"'` and is echoed back by the real labs, which is how the scan learns the
// parameter reflects at all. A fixture that rejected any '<' would stop the scan
// before planning, and would prove nothing about the escalation.
var tagStart = regexp.MustCompile(`(?i)<\s*/?\s*[a-z]`)

// newAllowListSite serves one page per lab. A value carrying an HTML tag is
// admitted only when it matches that lab's allow-list, exactly like the labs;
// any other tag is a 400 — never reflected, so no canonical shape can pass.
func newAllowListSite(t *testing.T) *site {
	t.Helper()
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			var b strings.Builder
			b.WriteString("<!doctype html><html><body><h1>labs</h1>")
			for _, lab := range allowListLabs {
				b.WriteString(`<a href="/` + lab.path + `?q=hello">` + lab.path + `</a>`)
			}
			b.WriteString("</body></html>")
			writeHTML(w, b.String())
		})
		for _, lab := range allowListLabs {
			lab := lab
			mux.HandleFunc("/"+lab.path, func(w http.ResponseWriter, r *http.Request) {
				v := r.URL.Query().Get("q")
				// Only tags are filtered, like the labs: the baseline probe (and
				// any payload the allow-list admits) is echoed.
				if tagStart.MatchString(v) && !lab.allow.MatchString(v) {
					http.Error(w, "not allowed", http.StatusBadRequest)
					return
				}
				writeHTML(w, `<!doctype html><html><body><div id="results">`+v+`</div></body></html>`)
			})
		}
	})
}

func TestAutomaticEvasionConfirmsFilterAllowListLabs(t *testing.T) {
	ctx := context.Background()
	lab := newAllowListSite(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, lab.URL, domain.Scope{IncludeHosts: []string{"127.0.0.1"}})
	// EnableEvasion is deliberately FALSE: this is the automatic path.
	cfg := domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 4}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: proj, TargetID: tgt, Name: "allowlist-labs",
		Profile: domain.ProfileFast, Config: &cfg, Stop: domain.StopPolicy{},
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 600*time.Second, isCompleted)

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Diagnostics: a silent zero-finding scan is the failure mode this test
	// exists for, so print what the pipeline actually recorded.
	if eps, err := st.Endpoints().ListByScan(ctx, sc.ID); err == nil {
		for _, ep := range eps {
			t.Logf("endpoint %s %s", ep.Method, ep.URL)
		}
	}
	if cases, err := st.TestCases().ListByScan(ctx, sc.ID); err == nil {
		for _, tc := range cases {
			if strings.Contains(tc.Note, "parameter q") {
				t.Logf("testcase %s outcome=%s note=%.140s", tc.URL, tc.Outcome, tc.Note)
			}
		}
	}
	t.Logf("findings=%d", len(findings))
	confirmedBy := map[string]string{}
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		ep, err := st.Endpoints().Get(ctx, f.EndpointID)
		if err != nil {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		name := strings.TrimPrefix(u.Path, "/")
		if v := confirmedValue(f); v != "" {
			confirmedBy[name] = v
		}
	}
	for _, lab := range allowListLabs {
		got, ok := confirmedBy[lab.path]
		if !ok {
			// Report what did happen for this path, not just the absence.
			var seen []string
			for _, f := range findings {
				if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil && strings.Contains(ep.URL, "/"+lab.path) {
					seen = append(seen, string(f.Verdict))
				}
			}
			t.Errorf("%s (%s): no confirmed finding through the automatic path; findings at this path: %v",
				lab.path, lab.label, seen)
			continue
		}
		if !strings.Contains(got, lab.want) {
			t.Errorf("%s confirmed by %q, expected the allow-list shape containing %q", lab.path, got, lab.want)
		}
	}
}
