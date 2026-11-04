//go:build browser_integration

package scan

// Real-Chromium fixture for the measured async-sink shape (QA lab
// `ps-async-settle`): the page reads `location.search`, performs an XHR, evals
// the JSON response, and only THEN writes `searchTerm` into `innerHTML`.
//
// Before the observation-timing fix the DOM pass read the page back at `load`
// and concluded "no implemented DOM-XSS sink reachable" while the response was
// still in flight. These tests assert on behaviour through the real executor
// only (no new identifiers), so the same file compiles against the pre-fix
// tree and fails there as an assertion — the RED run.
//
// Honesty controls in the same fixture:
//   - an XHR whose response does NOT contain the marker stays negative;
//   - an XHR that fails (500, and a connection aborted mid-response) stays
//     negative — a failed fetch must never be reported as reachable;
//   - a purely synchronous page stays negative.
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
	"time"

	"github.com/indago/indago/internal/domain"
)

const asyncLabScriptPath = "/resources/js/searchResults.js"

// asyncLabSlowResponse is long enough to be observably in flight after the
// page's load event, and well inside the settle budget.
const asyncLabSlowResponse = 400 * time.Millisecond

// asyncLabReplyDelay holds the measured XHR response long enough that the
// pre-fix fixed observation window (250ms) loses the race deterministically,
// while staying well inside the new settle budget. The live lab's real
// round-trip was enough to lose that race in practice; a local httptest
// responds too fast to reproduce it without this delay.
const asyncLabReplyDelay = 600 * time.Millisecond

// asyncLabScript replicates the measured application script: the source value
// travels through an XHR round-trip and an eval before it reaches innerHTML.
const asyncLabScript = `function labSearch(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            labDisplay(searchResultsObj);
        }
    };
    xhr.open('GET', path);
    xhr.send();
}
function labDisplay(o) {
    var searchTerm = o.searchTerm;
    document.getElementById('results').innerHTML =
        '<h2>Showing ' + searchTerm + ' search results</h2>';
}
(function () {
    var params = new URLSearchParams(location.search);
    var term = params.get('search');
    if (!term) { return; }
    var api = (document.currentScript && document.currentScript.getAttribute('data-api')) || '/api/results';
    labSearch(api + '?' + params.toString());
})();
`

func asyncLabPage(api string) string {
	return `<!doctype html>
<html><body>
<form action="/" method="get"><input name="search" value=""></form>
<div id="results"></div>
<script src="` + asyncLabScriptPath + `" data-api="` + api + `"></script>
</body></html>
`
}

const asyncLabSyncPage = `<!doctype html>
<html><body>
<div id="results">static content</div>
<script>
document.getElementById('results').textContent = 'still static, no source read';
</script>
</body></html>
`

func newAsyncSinkLab(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	servePage := func(api string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, asyncLabPage(api))
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		servePage("/api/results")(w, r)
	})
	mux.HandleFunc("/unrelated", servePage("/api/fixed"))
	mux.HandleFunc("/error500", servePage("/api/error"))
	mux.HandleFunc("/abort", servePage("/api/abort"))
	mux.HandleFunc("/slow", servePage("/api/slow"))
	mux.HandleFunc("/hang", servePage("/api/hang"))
	mux.HandleFunc("/sync", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, asyncLabSyncPage)
	})
	mux.HandleFunc(asyncLabScriptPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, asyncLabScript)
	})
	mux.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(asyncLabReplyDelay)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"searchTerm":%q,"results":[]}`, r.URL.Query().Get("search"))
	})
	mux.HandleFunc("/api/fixed", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(asyncLabReplyDelay)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"searchTerm":"fixed text unrelated to the query","results":[]}`)
	})
	mux.HandleFunc("/api/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(asyncLabSlowResponse)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"searchTerm":%q,"results":[]}`, r.URL.Query().Get("search"))
	})
	mux.HandleFunc("/api/hang", func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answers; the client closes it at test end
	})
	mux.HandleFunc("/api/error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failure", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/abort", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close() // status 0 / network error in the browser
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func asyncLabPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// TestDOMXSSAsyncXHRResponseReachingSinkConfirms is the headline assertion:
// the measured XHR -> eval -> innerHTML pattern is confirmed end to end. On
// the pre-fix tree this fails with zero findings, because the observation was
// read before the response landed.
func TestDOMXSSAsyncXHRResponseReachingSinkConfirms(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := newAsyncSinkLab(t)
	env := newScanEnv(t)

	ep := env.endpoint(lab.URL+"/", domain.MethodGET)
	env.param(ep, "search", domain.LocationQuery, "unused")
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
		t.Fatalf("dom-xss job: %v", err)
	}

	findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("the measured async XHR shape must be confirmed, findings=%+v", findings)
	}
	if findings[0].VulnClass != domain.VulnDOMXSS {
		t.Fatalf("finding class = %v, want %v", findings[0].VulnClass, domain.VulnDOMXSS)
	}

	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	var reachable bool
	for _, tc := range cases {
		if asyncLabPath(tc.URL) == "/" && strings.Contains(tc.Note, "reachable sink: innerHTML") {
			reachable = true
		}
	}
	if !reachable {
		t.Fatalf("no innerHTML reachability note for the async XHR page, cases=%+v", cases)
	}
}

// TestDOMXSSAsyncXHRWithoutMarkerStaysNegative covers a page that performs the
// same XHR/eval/innerHTML sequence but receives data that does not contain the
// marker: waiting longer must never turn that into a hit.
func TestDOMXSSAsyncXHRWithoutMarkerStaysNegative(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := newAsyncSinkLab(t)
	env := newScanEnv(t)

	ep := env.endpoint(lab.URL+"/unrelated", domain.MethodGET)
	env.param(ep, "search", domain.LocationQuery, "unused")
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
		t.Fatalf("dom-xss job: %v", err)
	}
	if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
		t.Fatalf("an XHR response without the marker must not produce a finding: %+v", findings)
	}
	assertAsyncLabNegative(t, env, "/unrelated")
}

// TestDOMXSSFailedXHRStaysNegative covers both a 500 response and a connection
// aborted mid-response. Neither can reach the sink, so neither may be reported
// as reachable.
func TestDOMXSSFailedXHRStaysNegative(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := newAsyncSinkLab(t)

	for _, path := range []string{"/error500", "/abort"} {
		t.Run(path, func(t *testing.T) {
			env := newScanEnv(t)
			ep := env.endpoint(lab.URL+path, domain.MethodGET)
			env.param(ep, "search", domain.LocationQuery, "unused")
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
				t.Fatalf("dom-xss job: %v", err)
			}
			if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
				t.Fatalf("a failed XHR must not produce a finding: %+v", findings)
			}
			assertAsyncLabNegative(t, env, path)
		})
	}
}

// assertAsyncLabNegative requires the explicit negative diagnostic, so a page
// that was merely skipped or errored cannot masquerade as a clean negative.
func assertAsyncLabNegative(t *testing.T, env *scanEnv, path string) {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if asyncLabPath(tc.URL) == path && strings.Contains(tc.Note, "no implemented DOM-XSS sink reachable") {
			return
		}
	}
	t.Fatalf("no negative reachability diagnostic for %s, cases=%+v", path, cases)
}
