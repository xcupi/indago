//go:build browser_integration

package scan

// Real-Chromium fixture for the measured same-origin external script shape:
// the page HTML contains ONLY <script src="...labHeader.js"> and the sink
// (document.write fed by location.search through a local variable and one
// function argument) lives in that file.
//
// What is asserted end to end, through the real executor:
//
//  1. the DOM pass confirms the finding (the browser's marker execution is
//     still the only verdict authority);
//  2. the recorded evidence names the SCRIPT — the reachability note carries
//     the external URL, which the inline-only static pass could never produce;
//  3. a page whose referenced script is missing stays negative AND records the
//     unreadable script instead of claiming there is no sink;
//  4. an oversized bundle is skipped whole and also stays negative (no
//     mid-expression nonsense).
//
// The lab is loopback httptest; no real host is contacted.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

const extLabScriptPath = "/resources/labheader/js/labHeader.js"

const extLabScriptBody = `// lab header: search tracking
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var searchTerms = (new URLSearchParams(location.search)).get('search');
if (searchTerms) {
    trackSearch(searchTerms);
}
`

const extLabHomeHTML = `<!doctype html>
<html>
<head>
    <title>Lab home</title>
    <script src="` + extLabScriptPath + `"></script>
</head>
<body><h1>Lab home</h1></body>
</html>
`

const extLabNoScriptHTML = `<!doctype html>
<html>
<head>
    <title>Lab home (script missing)</title>
    <script src="/missing.js"></script>
</head>
<body><h1>Lab home (script missing)</h1></body>
</html>
`

const extLabBigHTML = `<!doctype html>
<html>
<head>
    <title>Lab home (oversized bundle)</title>
    <script src="/vendor.min.js"></script>
</head>
<body><h1>Lab home (oversized bundle)</h1></body>
</html>
`

func newExternalScriptLab(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, extLabHomeHTML)
	})
	mux.HandleFunc("/search-results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"query":%q,"results":[]}`, r.URL.Query().Get("search"))
	})
	mux.HandleFunc(extLabScriptPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, extLabScriptBody)
	})
	mux.HandleFunc("/noapp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, extLabNoScriptHTML)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, extLabBigHTML)
	})
	mux.HandleFunc("/vendor.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, strings.Repeat(`(function(){var x=1;})();`, 14*1024))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// extLabPath is the URL path of a recorded TestCase, used to attribute cases
// to the endpoint of the subtest that ran them.
func extLabPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// TestDOMXSSExternalScriptSinkConfirms is the headline pipeline fixture.
func TestDOMXSSExternalScriptSinkConfirms(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := newExternalScriptLab(t)
	env := newScanEnv(t)
	ctx := context.Background()

	t.Run("sink only in the external script", func(t *testing.T) {
		ep := env.endpoint(lab.URL+"/", domain.MethodGET)
		env.param(ep, "search", domain.LocationQuery, "unused")
		ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
		if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
			t.Fatalf("dom-xss job: %v", err)
		}

		findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
		if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
			t.Fatalf("external-script sink must be confirmed, findings=%+v", findings)
		}
		if findings[0].VulnClass != domain.VulnDOMXSS {
			t.Fatalf("finding class = %v, want %v", findings[0].VulnClass, domain.VulnDOMXSS)
		}

		cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		var provenance, reachable bool
		for _, tc := range cases {
			if extLabPath(tc.URL) != "/" {
				continue
			}
			if strings.Contains(tc.Note, extLabScriptPath) {
				provenance = true
			}
			if strings.Contains(tc.Note, "reachable sink: document.write") {
				reachable = true
			}
		}
		if !reachable {
			t.Fatalf("no reachability note for document.write, cases=%+v", cases)
		}
		if !provenance {
			t.Fatalf("evidence must name the external script %s, cases=%+v", extLabScriptPath, cases)
		}
	})

	t.Run("referenced script missing stays negative", func(t *testing.T) {
		ep := env.endpoint(lab.URL+"/noapp", domain.MethodGET)
		env.param(ep, "search", domain.LocationQuery, "unused")
		ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
		if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
			t.Fatalf("dom-xss job: %v", err)
		}
		if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
			t.Fatalf("a missing script must not produce a finding: %+v", findings)
		}
		cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		var negative, recorded bool
		for _, tc := range cases {
			if extLabPath(tc.URL) != "/noapp" {
				continue
			}
			if strings.Contains(tc.Note, "no implemented DOM-XSS sink reachable") {
				negative = true
			}
			if strings.Contains(tc.Note, "/missing.js") && strings.Contains(tc.Note, "could not be analysed") {
				recorded = true
			}
		}
		if !negative {
			t.Fatalf("missing-script page must stay negative, cases=%+v", cases)
		}
		if !recorded {
			t.Fatalf("the unreadable script must be recorded, not silently absent, cases=%+v", cases)
		}
	})

	t.Run("oversized bundle skipped whole", func(t *testing.T) {
		ep := env.endpoint(lab.URL+"/big", domain.MethodGET)
		env.param(ep, "search", domain.LocationQuery, "unused")
		ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
		if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
			t.Fatalf("dom-xss job: %v", err)
		}
		if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
			t.Fatalf("an oversized bundle must not produce a finding: %+v", findings)
		}
		cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		var recorded bool
		for _, tc := range cases {
			if extLabPath(tc.URL) == "/big" && strings.Contains(tc.Note, "/vendor.min.js") && strings.Contains(tc.Note, "size cap") {
				recorded = true
			}
		}
		if !recorded {
			t.Fatalf("the skipped bundle must be recorded with the cap reason, cases=%+v", cases)
		}
	})
}
