//go:build browser_integration

package scan

// Lab 23 — "Reflected DOM XSS". The page reads its search term from the URL,
// asks the server for JSON results, and writes the returned text into
// innerHTML. The value therefore makes a round trip through the server before it
// reaches the sink: the DOM source is still location.search, but the initial
// HTML contains no reflection at all, so a scanner that only inspected the
// response body would see nothing to test.
//
// This is the local worker for that shape. It pins the whole path — query
// source → async fetch → JSON → innerHTML → marker execution — so the class can
// be validated without a live lab instance (the registry still lists lab 23 as
// unvalidated because the target was paused mid-scan).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestDOMXSSReflectedJSONPipelineConfirms(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	var searchHits atomic.Int64
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search-results" {
			searchHits.Add(1)
			term := r.URL.Query().Get("search")
			w.Header().Set("Content-Type", "application/json")
			// The lab's flaw: the term is escaped only for the JSON string
			// delimiter, so markup survives the round trip intact.
			_, _ = fmt.Fprintf(w, `{"results":[{"text":%s}]}`, jsonString(term))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><div id="results">no results</div>
<script>
const term = new URLSearchParams(location.search).get('search') || '';
fetch('/search-results?search=' + encodeURIComponent(term))
  .then((r) => r.json())
  .then((data) => {
    document.getElementById('results').innerHTML = data.results.map((x) => x.text).join('');
  })
  .catch(() => {});
</script></body></html>`)
	}))
	defer lab.Close()

	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/?search=hi", domain.MethodGET)
	env.param(ep, "search", domain.LocationQuery, "hi")

	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceQuery))); err != nil {
		t.Fatalf("handle: %v", err)
	}

	findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	confirmed := 0
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			confirmed++
		}
	}
	if confirmed == 0 {
		var verdicts []string
		for _, f := range findings {
			verdicts = append(verdicts, string(f.Verdict)+": "+f.Summary)
		}
		t.Fatalf("the reflected-JSON shape (query -> fetch -> innerHTML) was not confirmed; "+
			"%d search request(s), findings=%v", searchHits.Load(), verdicts)
	}
	if searchHits.Load() == 0 {
		t.Fatal("the page never fetched /search-results, so the round trip under test did not happen")
	}
	if got := strings.TrimSpace(summaryOfConfirmed(findings)); !strings.Contains(got, "innerHTML") && !strings.Contains(got, "is not defined") {
		t.Fatalf("confirmed finding does not name the execution signal: %q", got)
	}
}

// jsonString escapes a value the way the lab's server does: quotes and
// backslashes only. Markup is deliberately left intact — that is the bug.
func jsonString(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + r.Replace(v) + `"`
}

func summaryOfConfirmed(findings []*domain.Finding) string {
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			return f.Summary
		}
	}
	return ""
}
