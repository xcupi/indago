package scan

// Unit tests for the DOM-XSS content-type PREFLIGHT. An endpoint whose discovered
// ContentType is unknown used to be treated as a possible HTML document — which
// is correct as a default — but for resources that are actually JSON, plain text,
// a script or an image it meant opening headless Chrome and running 5-7
// navigations per endpoint, which is what pushed large scans into their timeout.
// One bounded HEAD (with a single GET fallback) now settles the type BEFORE any
// browser work, so the sources take the existing not-applicable skip path.
//
// Everything here runs with a nil browser manager on purpose: the whole point is
// that no browser is required or invoked. Note that store.EndpointRepo deep-copies
// on Create/Get and has no Update, so the resolved type is only observable (a)
// directly on the Endpoint a resolve call was handed and (b) through the skip
// note each source records — never by reading it back from the store.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// domXSSProbeEngine is a scripted HTTP engine: it records every request it was
// asked to send and answers through answer, so a test can assert exactly which
// preflight requests were made and what the executor did with each answer.
type domXSSProbeEngine struct {
	mu       sync.Mutex
	requests []*httpengine.Request
	// answer returns the response for a request. Returning nil simulates a
	// transport failure.
	answer func(req *httpengine.Request) *httpengine.Response
}

func (e *domXSSProbeEngine) Do(_ context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	e.mu.Lock()
	e.requests = append(e.requests, req)
	e.mu.Unlock()
	if e.answer == nil {
		return nil, nil
	}
	return e.answer(req), nil
}

// sent returns the recorded requests in send order.
func (e *domXSSProbeEngine) sent() []*httpengine.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*httpengine.Request(nil), e.requests...)
}

// contentTypeResponse builds a response carrying ct (empty means "no header").
func contentTypeResponse(status int, ct string) *httpengine.Response {
	resp := &httpengine.Response{Status: status, Headers: http.Header{}}
	if ct != "" {
		resp.Headers.Set("Content-Type", ct)
	}
	return resp
}

// staticResponse answers every request with the same status/media type.
func staticResponse(status int, ct string) func(*httpengine.Request) *httpengine.Response {
	return func(*httpengine.Request) *httpengine.Response {
		return contentTypeResponse(status, ct)
	}
}

// newPreflightExecutor is the preflight in isolation: no store, no browser, no
// evidence store — enough to prove the probe's own contract.
func newPreflightExecutor(eng httpengine.Engine) *domXSSExecutor {
	return newDOMXSSExecutor(nil, nil, nil,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), nil).withHTTP(eng)
}

// newContentTypeExec is the executing side: a real scan store plus a nil browser
// manager, exactly as a scan without a configured browser runs it.
func newContentTypeExec(env *scanEnv, eng httpengine.Engine) *domXSSExecutor {
	return newDOMXSSExecutor(env.st, nil, env.ev,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), nil).withHTTP(eng)
}

// contentTypeEndpoint persists an endpoint with an explicit (possibly empty)
// recorded content type. env.endpoint always creates it unknown, and the store
// copies on write, so mutating the fixture afterwards would never reach it.
func contentTypeEndpoint(t *testing.T, env *scanEnv, rawURL string, ct string) *domain.Endpoint {
	t.Helper()
	ep := &domain.Endpoint{
		ID: domain.NewID(), ScanID: env.scanID, URL: rawURL, Method: domain.MethodGET,
		Source: domain.SourceBrowserNetwork, ContentType: ct, CreatedAt: time.Now(),
	}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

func domXSSContentTypeJob(t *testing.T, scanID domain.ID, ep *domain.Endpoint, sources []detection.DOMXSSSource) *domain.TestJob {
	t.Helper()
	payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: scanID, Type: domain.JobDOMXSS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload,
		Attempts: 1, MaxAttempts: 1,
	}
}

// domXSSJobTestCases returns every persisted TestCase belonging to job.
func domXSSJobTestCases(t *testing.T, env *scanEnv, job *domain.TestJob) []*domain.TestCase {
	t.Helper()
	all, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	var out []*domain.TestCase
	for _, tc := range all {
		if tc.JobID == job.ID {
			out = append(out, tc)
		}
	}
	return out
}

func requestMethods(reqs []*httpengine.Request) []string {
	out := make([]string, 0, len(reqs))
	for _, req := range reqs {
		out = append(out, req.Method+" "+req.URL)
	}
	return out
}

// The requirement's core case: an empty recorded content type, a JSON answer to
// the preflight, and NO browser at all. Every source must record a skipped
// TestCase naming the resolved content type, and the executor must never touch a
// browser (its manager is nil — a dereference would panic here).
func TestDOMXSSContentTypePreflightSkipsSourcesWithoutBrowser(t *testing.T) {
	env := newScanEnv(t)
	ep := contentTypeEndpoint(t, env, "https://target.example/api/items", "")
	eng := &domXSSProbeEngine{answer: staticResponse(http.StatusOK, "application/json; charset=utf-8")}
	ex := newContentTypeExec(env, eng)

	job := domXSSContentTypeJob(t, env.scanID, ep, detection.DOMXSSSources)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle with an unknown-type non-HTML endpoint and no browser: %v", err)
	}

	// ONE HEAD request, to the endpoint itself. No GET: the type was trustworthy.
	reqs := eng.sent()
	if len(reqs) != 1 {
		t.Fatalf("preflight sent %d requests, want exactly 1 (HEAD)", len(reqs))
	}
	if reqs[0].Method != http.MethodHead || reqs[0].URL != ep.URL {
		t.Fatalf("preflight request = %s %s, want HEAD %s", reqs[0].Method, reqs[0].URL, ep.URL)
	}

	cases := domXSSJobTestCases(t, env, job)
	if len(cases) != len(detection.DOMXSSSources) {
		t.Fatalf("recorded %d test cases, want one per source (%d): %+v", len(cases), len(detection.DOMXSSSources), cases)
	}
	for _, tc := range cases {
		if tc.Status != domain.TestCaseSkipped {
			t.Fatalf("%s: status = %s, want skipped", tc.ID, tc.Status)
		}
		if tc.Outcome == domain.OutcomeError || tc.Outcome == domain.OutcomeTimeout {
			t.Fatalf("%s: outcome = %s, want a non-error skip", tc.ID, tc.Outcome)
		}
		if !strings.Contains(tc.Note, "not an HTML document") {
			t.Fatalf("%s: note %q must explain the content-type skip", tc.ID, tc.Note)
		}
		// The resolved type reached every source: the note is built from the
		// endpoint copy the preflight updated.
		if !strings.Contains(tc.Note, "application/json") {
			t.Fatalf("%s: note %q must name the resolved media type", tc.ID, tc.Note)
		}
	}
}

// The probe's own contract: an unknown type is resolved from the response header
// and written onto the endpoint the caller handed over.
func TestDOMXSSContentTypePreflightResolvesJSONForUnknownEndpoint(t *testing.T) {
	eng := &domXSSProbeEngine{answer: staticResponse(http.StatusOK, "application/json")}
	ex := newPreflightExecutor(eng)
	ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://target.example/api/items", Method: domain.MethodGET}

	ex.resolveDOMXSSContentType(context.Background(), ep)

	if ep.ContentType != "application/json" {
		t.Fatalf("content type = %q, want the probed value", ep.ContentType)
	}
	if reqs := eng.sent(); len(reqs) != 1 || reqs[0].Method != http.MethodHead {
		t.Fatalf("preflight requests = %v, want exactly one HEAD", requestMethods(reqs))
	}
}

// A server that refuses HEAD must still be classified: 405 falls back to exactly
// one GET, and that GET's answer decides the skip — never the 405 page's own
// media type, which describes the error rather than the representation.
func TestDOMXSSContentTypePreflightRetriesWithGETWhenHEADRefused(t *testing.T) {
	eng := &domXSSProbeEngine{answer: func(req *httpengine.Request) *httpengine.Response {
		if req.Method == http.MethodHead {
			return contentTypeResponse(http.StatusMethodNotAllowed, "text/html")
		}
		return contentTypeResponse(http.StatusOK, "application/rss+xml")
	}}
	ex := newPreflightExecutor(eng)
	ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://target.example/feed.xml", Method: domain.MethodGET}

	ex.resolveDOMXSSContentType(context.Background(), ep)

	reqs := eng.sent()
	if len(reqs) != 2 || reqs[0].Method != http.MethodHead || reqs[1].Method != http.MethodGet {
		t.Fatalf("preflight requests = %v, want HEAD then GET", requestMethods(reqs))
	}
	if ep.ContentType != "application/rss+xml" {
		t.Fatalf("content type = %q, want the GET's answer (the 405 page's type must not win)", ep.ContentType)
	}
}

// A 200 HEAD that omits Content-Type is not an answer at all: one GET settles it.
func TestDOMXSSContentTypePreflightRetriesWithGETWhenHEADOmitsType(t *testing.T) {
	eng := &domXSSProbeEngine{answer: func(req *httpengine.Request) *httpengine.Response {
		if req.Method == http.MethodHead {
			return contentTypeResponse(http.StatusOK, "")
		}
		return contentTypeResponse(http.StatusOK, "application/pdf")
	}}
	ex := newPreflightExecutor(eng)
	ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://target.example/download", Method: domain.MethodGET}

	ex.resolveDOMXSSContentType(context.Background(), ep)

	if ep.ContentType != "application/pdf" {
		t.Fatalf("content type = %q, want application/pdf from the GET fallback", ep.ContentType)
	}
	if reqs := eng.sent(); len(reqs) != 2 || reqs[1].Method != http.MethodGet {
		t.Fatalf("preflight requests = %v, want HEAD then GET", requestMethods(reqs))
	}
}

// A real document must NOT be skipped for a content-type reason: the preflight
// resolves text/html, so the run continues past the gate — here into the
// no-browser skip, which is the honest reason for THIS executor.
func TestDOMXSSContentTypePreflightKeepsDocumentEndpoint(t *testing.T) {
	env := newScanEnv(t)
	ep := contentTypeEndpoint(t, env, "https://target.example/search", "")
	eng := &domXSSProbeEngine{answer: staticResponse(http.StatusOK, "text/html; charset=utf-8")}
	ex := newContentTypeExec(env, eng)

	job := domXSSContentTypeJob(t, env.scanID, ep, detection.DOMXSSSources)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reqs := eng.sent(); len(reqs) != 1 || reqs[0].Method != http.MethodHead {
		t.Fatalf("preflight requests = %v, want exactly one HEAD (no GET retry)", requestMethods(reqs))
	}
	cases := domXSSJobTestCases(t, env, job)
	if len(cases) == 0 {
		t.Fatal("no test cases recorded")
	}
	for _, tc := range cases {
		if tc.Status != domain.TestCaseSkipped {
			t.Fatalf("%s: status = %s, want skipped (no browser configured)", tc.ID, tc.Status)
		}
		if strings.Contains(tc.Note, "not an HTML document") {
			t.Fatalf("%s: an HTML document must not be skipped for its content type: %q", tc.ID, tc.Note)
		}
		if !strings.Contains(tc.Note, "no browser configured") {
			t.Fatalf("%s: note %q must name the real reason", tc.ID, tc.Note)
		}
	}
}

// The preflight is scope-gated BEFORE a single request: an out-of-scope URL is
// never contacted, and its unknown type stays unknown (old behavior).
func TestDOMXSSContentTypePreflightRespectsScope(t *testing.T) {
	eng := &domXSSProbeEngine{answer: staticResponse(http.StatusOK, "application/json")}
	ex := newPreflightExecutor(eng)
	ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://outsider.example/api/items", Method: domain.MethodGET}

	ex.resolveDOMXSSContentType(context.Background(), ep)

	if reqs := eng.sent(); len(reqs) != 0 {
		t.Fatalf("out-of-scope endpoint was contacted: %v", requestMethods(reqs))
	}
	if ep.ContentType != "" {
		t.Fatalf("content type = %q, an out-of-scope probe must not set it", ep.ContentType)
	}
}

// Only a successful response may decide the skip: an error page's media type
// describes the error, so a 4xx/5xx answer leaves the endpoint unknown.
func TestDOMXSSContentTypePreflightTrustsOnlySuccessfulResponses(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		eng := &domXSSProbeEngine{answer: staticResponse(status, "application/json")}
		ex := newPreflightExecutor(eng)
		ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://target.example/api/items", Method: domain.MethodGET}

		ex.resolveDOMXSSContentType(context.Background(), ep)

		if ep.ContentType != "" {
			t.Fatalf("status %d: content type = %q, an error response must not decide the skip", status, ep.ContentType)
		}
		if reqs := eng.sent(); len(reqs) != 2 {
			t.Fatalf("status %d: requests = %v, want HEAD then GET", status, requestMethods(reqs))
		}
	}
}

// A recorded type is never second-guessed: no request is sent for it, and the
// existing gate skips the endpoint without a browser.
func TestDOMXSSContentTypePreflightLeavesRecordedTypeAlone(t *testing.T) {
	env := newScanEnv(t)
	ep := contentTypeEndpoint(t, env, "https://target.example/logo.png", "image/png")
	eng := &domXSSProbeEngine{answer: staticResponse(http.StatusOK, "text/html")}
	ex := newContentTypeExec(env, eng)

	job := domXSSContentTypeJob(t, env.scanID, ep, detection.DOMXSSSources)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reqs := eng.sent(); len(reqs) != 0 {
		t.Fatalf("a recorded content type must not be probed: %v", requestMethods(reqs))
	}
	for _, tc := range domXSSJobTestCases(t, env, job) {
		if tc.Status != domain.TestCaseSkipped || !strings.Contains(tc.Note, "not an HTML document") {
			t.Fatalf("an image endpoint must be skipped without a browser: %+v", tc)
		}
	}
}

// A nil engine (every existing caller, and any test constructing the executor
// directly) must keep the old behavior: no probe, the type stays unknown.
func TestDOMXSSContentTypePreflightDisabledWithoutEngine(t *testing.T) {
	ex := newDOMXSSExecutor(nil, nil, nil,
		domain.Scope{IncludeHosts: []string{"target.example"}}, execLog(), nil)
	ep := &domain.Endpoint{ID: domain.NewID(), URL: "https://target.example/api/items", Method: domain.MethodGET}

	ex.resolveDOMXSSContentType(context.Background(), ep)

	if ep.ContentType != "" {
		t.Fatalf("content type = %q, want it untouched with no engine attached", ep.ContentType)
	}
}
