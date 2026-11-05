package detection_test

// Real-browser fixture for the measured lab page: a client-side query read that
// reaches document.write through a local variable and one function argument.
//
// The measured page is served verbatim (same inline script, four-space
// indentation, same tracker.gif sink) from a loopback httptest server, once per
// accepted source spelling. For each spelling the fixture asserts two things:
//
//  1. the bounded static pass over the SERVED bytes reports document.write
//     reachable from the tested query parameter (this is the assertion the
//     `self.` spelling failed at the base revision);
//  2. the planner's document.write candidates for that reachable pair actually
//     confirm in real Chromium — the browser's own marker-specific page error
//     is the only verdict authority, exactly as in the pipeline.
//
// It skips quickly when no Chromium is available, matching the other
// real-browser fixtures in this package. The page is local; no real host is
// contacted.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// labSearchResultsScript is the measured lab script. %s is the source
// expression the page reads its query value through.
const labSearchResultsScript = `<!doctype html><html><head><title>Search results</title></head><body>
<h1>Search results</h1>
<script>
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var query = (new URLSearchParams(%s)).get('search');
if (query) { trackSearch(query); }
</script>
</body></html>`

// labSearchResultsSpellings are the equivalent ways a page reaches the same
// Location object. Each must be recognised, not just the bare global.
var labSearchResultsSpellings = []string{
	"location.search",
	"window.location.search",
	"document.location.search",
	"self.location.search",
}

// labSearchResultsServer serves the measured page once per spelling at a
// spelling-specific path, so the probe URL itself never has to carry a
// selector for which page variant to serve.
func labSearchResultsServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for _, spelling := range labSearchResultsSpellings {
		spelling := spelling
		mux.HandleFunc("/"+labSearchResultsSlug(spelling), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, labSearchResultsScript, spelling)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func labSearchResultsSlug(spelling string) string {
	return strings.ReplaceAll(spelling, ".", "-")
}

func labSearchResultsFetch(t *testing.T, pageURL string) string {
	t.Helper()
	resp, err := http.Get(pageURL)
	if err != nil {
		t.Fatalf("fetch fixture: %v", err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(buf)
}

// labSearchResultsReplayURL puts the candidate value in the parameter the page
// reads, percent-encoded the way the pipeline does (never concatenated).
func labSearchResultsReplayURL(base, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	q.Set("search", value)
	u.RawQuery = q.Encode()
	return u.String()
}

// TestLabSearchResultsDocumentWriteConfirms is the measured-page fixture.
func TestLabSearchResultsDocumentWriteConfirms(t *testing.T) {
	srv := labSearchResultsServer(t)
	// The same real-browser helper the URL/href attribute fixtures use: real
	// Chromium, process sandbox on unless the operator opted out for tests.
	v := urlAttrVerifier(t)
	const marker = "indxsswinloc"

	for _, spelling := range labSearchResultsSpellings {
		t.Run(spelling, func(t *testing.T) {
			pageURL := srv.URL + "/" + labSearchResultsSlug(spelling)

			// 1. Static reachability over exactly what the server sent.
			served := labSearchResultsFetch(t, pageURL)
			res := detection.DOMXSSStaticReachability(served, detection.DOMSourceQuery, "search")
			if res.Outcome != detection.DOMXSSFlowTainted {
				t.Fatalf("static pass must report a tainted path for %s, got %s unresolved=%+v", spelling, res.Outcome, res.Unresolved)
			}
			var reachable bool
			for _, site := range res.Sites {
				if site.Sink == detection.DOMSinkDocumentWrite {
					reachable = true
				}
			}
			if !reachable {
				t.Fatalf("static pass must report document.write reachable for %s, got %+v", spelling, res.Sites)
			}

			// 2. The planned candidates must actually execute in Chromium.
			cands := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkDocumentWrite, marker)
			if len(cands) == 0 {
				t.Fatal("planner produced no document.write candidate")
			}
			var confirmed bool
			for _, cand := range cands {
				out, err := v.Verify(context.Background(), verification.Input{
					Candidate: cand,
					Marker:    marker,
					Method:    "GET",
					URL:       labSearchResultsReplayURL(pageURL, cand.Value),
					Scope:     domain.Scope{IncludeHosts: []string{"127.0.0.1"}},
				})
				if err != nil {
					t.Fatalf("verify %q: %v", cand.Value, err)
				}
				if out.Verdict != domain.VerdictConfirmed {
					continue
				}
				if out.Report == nil || out.Report.Signal != verification.SignalPageError {
					t.Fatalf("confirmed without the browser's marker page error: %+v", out.Report)
				}
				confirmed = true
				break
			}
			if !confirmed {
				t.Fatalf("%s: no planned document.write candidate confirmed in the browser (%d tried)", spelling, len(cands))
			}
		})
	}
}
