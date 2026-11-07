//go:build browser_integration

package scan_test

// Real-Chromium proof for the variation packs: one loopback lab serves, for
// each of the six reflection contexts, a RAW route and a FILTERED route. The
// filtered route rewrites the value with a realistic filter that blocks the
// pack's FIRST variant, while leaving a later variant byte-identical. The same
// one scan (with the operator evasion opt-in, which is the gate that also
// enables the packs) must still produce a Confirmed finding at every filtered
// route, and the confirmed candidate must be the later, surviving variant —
// not the first one the filter blocked.
//
// The URL-attribute filter blocks the literal "javascript:" but leaves the
// &colon; entity alone. That finding confirms ONLY through the one bounded
// click the verifier dispatches for a recognized javascript:-URL interaction
// shape: the browser decodes the entity before parsing the URL, so it is a
// live javascript: URL in the DOM. The test asserts the confirmation names
// that activation, and that no confirmed attempt anywhere in the finding
// reached confirmed without one.

import (
	"context"
	"encoding/json"
	"net/http"
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

// --- the same filters as the pure fixture (internal/detection) ---

var labEventAttrRe = regexp.MustCompile(`(?i)\son[a-z0-9_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)`)

func labStripEvents(v string) string { return labEventAttrRe.ReplaceAllString(v, " data-x=1") }

func labDisableTag(v, tag string) string {
	return regexp.MustCompile(`(?i)<`+regexp.QuoteMeta(tag)).ReplaceAllString(v, "&lt;"+tag)
}

func labBlockLiteral(v, literal string) string {
	return regexp.MustCompile(`(?i)`+regexp.QuoteMeta(literal)).ReplaceAllString(v, "")
}

func labEscapeJSQuotes(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

func labEscapeTemplate(v string) string {
	var b strings.Builder
	const hex = "0123456789abcdef"
	for _, r := range v {
		switch r {
		case '$', '{', '}', '`', '\'', '"', '\\':
			b.WriteString(`\u`)
			b.WriteRune(rune(hex[(r>>12)&0xf]))
			b.WriteRune(rune(hex[(r>>8)&0xf]))
			b.WriteRune(rune(hex[(r>>4)&0xf]))
			b.WriteRune(rune(hex[r&0xf]))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// variationLab is one route family: how the value is filtered and where the
// page reflects it.
type variationLab struct {
	path   string
	filter func(string) string
	render func(string) string
}

func newVariationLab(t *testing.T) *site {
	t.Helper()
	labs := []variationLab{
		{
			path:   "html",
			filter: func(v string) string { return labDisableTag(labStripEvents(v), "svg") },
			render: func(v string) string { return "<!doctype html><html><body><p>" + v + "</p></body></html>" },
		},
		{
			path:   "attribute",
			filter: func(v string) string { return labDisableTag(labStripEvents(v), "svg") },
			render: func(v string) string { return `<!doctype html><html><body><input value="` + v + `"></body></html>` },
		},
		{
			path:   "js_string",
			filter: func(v string) string { return labDisableTag(labEscapeJSQuotes(v), "script") },
			render: func(v string) string {
				return "<!doctype html><html><body><script>var a = '" + v + "';</script></body></html>"
			},
		},
		{
			path:   "js_template",
			filter: func(v string) string { return labDisableTag(labEscapeTemplate(v), "script") },
			render: func(v string) string {
				return "<!doctype html><html><body><script>var a = `" + v + "`;</script></body></html>"
			},
		},
		{
			path:   "script_block",
			filter: func(v string) string { return labDisableTag(v, "svg") },
			render: func(v string) string {
				return `<!doctype html><html><body><script type="text/plain">` + v + `</script></body></html>`
			},
		},
		{
			path:   "url",
			filter: func(v string) string { return labBlockLiteral(v, "javascript:") },
			render: func(v string) string { return `<!doctype html><html><body><a href="` + v + `">go</a></body></html>` },
		},
	}

	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			var b strings.Builder
			b.WriteString("<!doctype html><html><body>")
			for _, lab := range labs {
				b.WriteString(`<a href="/raw/` + lab.path + `?q=hello">r-` + lab.path + `</a>`)
				b.WriteString(`<a href="/flt/` + lab.path + `?q=hello">f-` + lab.path + `</a>`)
			}
			b.WriteString("</body></html>")
			writeHTML(w, b.String())
		})
		for _, lab := range labs {
			lab := lab
			serve := func(filtered bool) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					v := r.URL.Query().Get("q")
					if filtered {
						v = lab.filter(v)
					}
					writeHTML(w, lab.render(v))
				}
			}
			mux.HandleFunc("/raw/"+lab.path, serve(false))
			mux.HandleFunc("/flt/"+lab.path, serve(true))
		}
	})
}

// variationAttempt mirrors the verification-attempt record on Finding.Detail.
type variationAttempt struct {
	CandidateValue string         `json:"candidate_value"`
	Verdict        domain.Verdict `json:"verdict"`
	Notes          string         `json:"notes"`
}

func variationAttempts(f *domain.Finding) []variationAttempt {
	var d struct {
		Attempts []variationAttempt `json:"attempts"`
	}
	_ = json.Unmarshal(f.Detail, &d)
	return d.Attempts
}

func confirmedValue(f *domain.Finding) string {
	for _, a := range variationAttempts(f) {
		if a.Verdict == domain.VerdictConfirmed {
			return a.CandidateValue
		}
	}
	return ""
}

func TestReflectedVariationPacksConfirmAfterFirstVariantIsBlocked(t *testing.T) {
	ctx := context.Background()
	lab := newVariationLab(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, lab.URL, domain.Scope{IncludeHosts: []string{"127.0.0.1"}})
	cfg := domain.ScanConfig{
		DiscoveryConcurrency: 4,
		HTTPConcurrency:      8,
		BrowserConcurrency:   4,
		// The operator opt-in that already exists end to end. It gates BOTH the
		// evasion shapes and the variation packs (see variation.go).
		EnableEvasion: true,
	}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	// CreateScan's EnableEvasion parameter (not just cfg) is what reaches
	// PlanOptions.EnableEvasion — see controller.CreateScan.
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: proj, TargetID: tgt, Name: "variation", Profile: domain.ProfileCustom,
		Config: &cfg, Stop: domain.StopPolicy{}, EnableEvasion: true,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 300*time.Second, isCompleted)
	t.Logf("findings: breakdown=%+v", done.Findings)

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]*domain.Finding{}
	for _, f := range findings {
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil {
			byPath[urlPath(ep.URL)] = append(byPath[urlPath(ep.URL)], f)
		}
	}
	for p, fs := range byPath {
		for _, f := range fs {
			for _, a := range variationAttempts(f) {
				t.Logf("%s finding=%s attempt=%s %q", p, f.Verdict, a.Verdict, a.CandidateValue)
			}
		}
	}
	if tcs, err := st.TestCases().ListByScan(ctx, sc.ID); err == nil {
		t.Logf("test cases: %d", len(tcs))
	}

	cases := []struct {
		context  string
		survivor func(m string) string
	}{
		{"html", func(m string) string { return "<script>" + m + "</script>" }},
		{"attribute", func(m string) string { return `"><script>` + m + `</script>` }},
		{"js_string", func(m string) string { return "</script><svg onload=" + m + ">" }},
		{"js_template", func(m string) string { return "</script><svg onload=" + m + ">" }},
		{"script_block", func(m string) string { return "</script><script>" + m + "</script>" }},
	}
	for _, tc := range cases {
		t.Run(tc.context, func(t *testing.T) {
			// Raw control: the fixture reflects and is confirmed. The template
			// literal's canonical ${M} is evaluated during the page's own parse,
			// so it now confirms on its own (the provenance lexer tracks ${...}
			// substitutions — docs/verdict-provenance.md).
			if raw := verdictAt(byPath, "/raw/"+tc.context); raw != domain.VerdictConfirmed {
				t.Fatalf("raw %s verdict = %s, want confirmed", tc.context, raw)
			}
			if tc.context == "js_template" {
				m := pathMarker(byPath, "/raw/js_template")
				if v := attemptVerdict(byPath, "/raw/js_template", "${"+m+"}"); v != domain.VerdictConfirmed {
					t.Fatalf("canonical ${M} at raw js_template = %s, want confirmed", v)
				}
			}

			// Filtered: still confirms, and with the surviving later variant.
			m := pathMarker(byPath, "/flt/"+tc.context)
			if m == "" {
				t.Fatalf("no marker recorded for /flt/%s", tc.context)
			}
			want := tc.survivor(m)
			got := assertConfirmed(t, byPath, "/flt/"+tc.context, want)
			if got != want {
				t.Fatalf("filtered %s confirmed with %q, want the surviving variant %q", tc.context, got, want)
			}
		})
	}

	// URL attribute: this filter removes the literal "javascript:" (case
	// insensitively), so every shape that keeps those bytes is reflected as a
	// harmless relative URL. The entity-encoded colon survives the filter and
	// the HTML parser decodes it to a live javascript: URL, so it confirms —
	// but ONLY through the one bounded click the verifier dispatches for a
	// recognised interaction shape, never on page load.
	t.Run("url_attribute", func(t *testing.T) {
		m := pathMarker(byPath, "/flt/url")
		if m == "" {
			t.Fatalf("no marker recorded for /flt/url")
		}
		want := "javascript&colon;" + m
		got := assertConfirmed(t, byPath, "/flt/url", want)
		if got != want {
			t.Fatalf("filtered url confirmed with %q, want the surviving variant %q", got, want)
		}
		var confirmed *domain.Finding
		for _, f := range byPath["/flt/url"] {
			if f.Verdict == domain.VerdictConfirmed {
				confirmed = f
			}
		}
		if confirmed == nil {
			t.Fatal("no confirmed finding at /flt/url")
		}
		// Every CONFIRMED attempt must name the activation that produced it: a
		// javascript: URL can never fire during load, so a confirmed attempt
		// without a recorded activation would be a fabricated positive. Check
		// each attempt, not just the finding summary: a later load-only
		// confirmation would otherwise hide behind the first one's summary.
		sawConfirmedAttempt := false
		for _, a := range variationAttempts(confirmed) {
			if a.Verdict != domain.VerdictConfirmed {
				continue
			}
			sawConfirmedAttempt = true
			if !strings.Contains(a.Notes, "after one click activation") {
				t.Fatalf("confirmed attempt %q does not record the click activation it needed: %q", a.CandidateValue, a.Notes)
			}
		}
		if !sawConfirmedAttempt {
			t.Fatalf("confirmed finding at /flt/url records no confirmed attempt: %+v", confirmed.Summary)
		}
	})
}

var markerRe = regexp.MustCompile(`ind[0-9a-f]{16}`)

// pathMarker returns the probe token embedded in any attempt recorded at path.
func pathMarker(byPath map[string][]*domain.Finding, path string) string {
	for _, f := range byPath[path] {
		for _, a := range variationAttempts(f) {
			if m := markerRe.FindString(a.CandidateValue); m != "" {
				return m
			}
		}
	}
	return ""
}

// verdictAt returns the strongest verdict among the findings at path.
func verdictAt(byPath map[string][]*domain.Finding, path string) domain.Verdict {
	rank := map[domain.Verdict]int{
		domain.VerdictPending: 0, domain.VerdictRejected: 1,
		domain.VerdictInconclusive: 2, domain.VerdictConfirmed: 3,
	}
	best := domain.VerdictPending
	for _, f := range byPath[path] {
		if rank[f.Verdict] > rank[best] {
			best = f.Verdict
		}
	}
	return best
}

// attemptVerdict returns the verdict recorded for one exact candidate value.
func attemptVerdict(byPath map[string][]*domain.Finding, path, value string) domain.Verdict {
	for _, f := range byPath[path] {
		for _, a := range variationAttempts(f) {
			if a.CandidateValue == value {
				return a.Verdict
			}
		}
	}
	return domain.VerdictPending
}

// assertConfirmed fails unless path has a Confirmed finding. When want is
// non-empty the confirmed candidate value must equal it.
func assertConfirmed(t *testing.T, byPath map[string][]*domain.Finding, path, want string) string {
	t.Helper()
	for _, f := range byPath[path] {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		got := confirmedValue(f)
		if want != "" && got != want {
			continue
		}
		return got
	}
	var seen []string
	for _, f := range byPath[path] {
		seen = append(seen, string(f.Verdict)+":"+confirmedValue(f))
	}
	if want == "" {
		t.Fatalf("%s: no Confirmed finding; findings=%v", path, seen)
	}
	t.Fatalf("%s: no Confirmed finding with %q; findings=%v", path, want, seen)
	return ""
}
