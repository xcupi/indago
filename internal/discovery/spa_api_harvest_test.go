package discovery

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// recordingBundleEngine answers probe requests from a fixed table and records
// every request actually sent, so a test can prove discovery never sent a
// state-changing method.
type recordingBundleEngine struct {
	mu        sync.Mutex
	requests  []string
	responses map[string]*httpengine.Response
}

func (e *recordingBundleEngine) Do(_ context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	e.mu.Lock()
	e.requests = append(e.requests, req.Method+" "+req.URL)
	e.mu.Unlock()
	if resp, ok := e.responses[req.Method+" "+req.URL]; ok {
		return resp, nil
	}
	return &httpengine.Response{Status: http.StatusNotFound, Headers: http.Header{}}, nil
}

func (e *recordingBundleEngine) methods() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.requests))
	for _, r := range e.requests {
		method, _, _ := strings.Cut(r, " ")
		out = append(out, method)
	}
	return out
}

func jsonBundleResponse(body string) *httpengine.Response {
	return &httpengine.Response{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(body),
	}
}

func TestExtractBundleAPIPaths(t *testing.T) {
	// A bundle in the shape a minified SPA ships: absolute service paths,
	// root-mounted API paths, a versioned path, a GraphQL path, and a relative
	// "api/..." literal. Template and placeholder shapes must be skipped.
	js := `var a="/workshop/api/shop/products",b="/api/v2/users",c="/v2/orders",` +
		`d="/graphql",e="api/v2/user/profile",f="/api/v2/vehicle/<id>",` +
		`g="/api/v2/item?x=null",h="/static/app.js",i="https://evil.test/api/x";`

	got := extractBundleAPIPaths(js)
	want := []bundleAPILiteral{
		{path: "/workshop/api/shop/products"},
		{path: "/api/v2/users"},
		{path: "/v2/orders"},
		{path: "/graphql"},
		{path: "api/v2/user/profile", relative: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractBundleAPIPaths = %+v, want %+v", got, want)
	}
}

func TestHasUnresolvedBundlePlaceholder(t *testing.T) {
	for _, p := range []string{
		"/api/v2/user/<id>",
		"/api/v2/user/{userId}",
		"/api/v2/user/${userId}",
		"/api/v2/item?x=null",
		"/api/v2/item?x=undefined",
	} {
		if !hasUnresolvedBundlePlaceholder(p) {
			t.Errorf("hasUnresolvedBundlePlaceholder(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/api/v2/user", "api/v2/user/profile", "/graphql"} {
		if hasUnresolvedBundlePlaceholder(p) {
			t.Errorf("hasUnresolvedBundlePlaceholder(%q) = true, want false", p)
		}
	}
}

func TestBundleAPICandidatesCombineObservedServicePrefixes(t *testing.T) {
	network := []browser.NetworkEvent{
		{URL: "http://app.test/workshop/api/mechanic", Method: "GET"},
		{URL: "http://app.test/identity/api/v2/user/login", Method: "POST"},
		{URL: "http://app.test/", Method: "GET"},
		{URL: "http://evil.test/community/api/v2/community/posts", Method: "GET"},
	}
	prefixes := observedServicePrefixes(network, "http://app.test/")
	if want := []string{"/workshop/", "/identity/"}; !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("observedServicePrefixes = %v, want %v", prefixes, want)
	}

	literals := []bundleAPILiteral{
		{path: "/graphql"},
		{path: "api/v2/user", relative: true},
	}
	got := bundleAPIProbeCandidates(literals, prefixes)
	want := []string{
		"/graphql",
		"/workshop/api/v2/user",
		"/identity/api/v2/user",
		"/api/v2/user",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bundleAPIProbeCandidates = %v, want %v", got, want)
	}
}

func TestHarvestScriptAPIsRegisters405AsPassiveMethod(t *testing.T) {
	js := `var a="api/v2/user",b="api/v2/password",` +
		`c="/workshop/api/shop/products",d="/community/api/v2/community/posts/recent",` +
		`e="/api/v2/soft404";`
	eng := &recordingBundleEngine{responses: map[string]*httpengine.Response{
		// A real JSON API path answered by GET.
		"GET http://app.test/workshop/api/shop/products": jsonBundleResponse(`[]`),
		// GET refused; the 405 itself names POST.
		"GET http://app.test/identity/api/v2/user": {
			Status:  http.StatusMethodNotAllowed,
			Headers: http.Header{"Allow": []string{"POST, OPTIONS"}},
		},
		// GET refused with no Allow; a read-only OPTIONS names PUT.
		"GET http://app.test/identity/api/v2/password": {Status: http.StatusMethodNotAllowed},
		"OPTIONS http://app.test/identity/api/v2/password": {
			Status:  http.StatusNoContent,
			Headers: http.Header{"Allow": []string{"PUT"}},
		},
		// The SPA fallback: 200 HTML for an unknown path, as a soft-404 does.
		"GET http://app.test/api/v2/soft404": {
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:    []byte("<!doctype html><html><body><div id=root></div></body></html>"),
		},
	}}
	network := []browser.NetworkEvent{
		{URL: "http://app.test/workshop/api/mechanic", Method: "GET"},
		{URL: "http://app.test/identity/api/v2/user", Method: "GET"},
	}
	sink := &formTestSink{}
	n := &networkSource{engine: eng, cfg: DefaultConfig()}
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"app.test"}}}

	if err := n.harvestScriptAPIs(context.Background(), in, sink, "http://app.test/", network, []string{js}); err != nil {
		t.Fatalf("harvestScriptAPIs: %v", err)
	}

	// Discovery may only ever send read-only methods. A 405 answer registers
	// the inferred method; it must never be the request discovery sends.
	for _, method := range eng.methods() {
		if method != http.MethodGet && method != http.MethodOptions {
			t.Fatalf("discovery sent %s; only GET/OPTIONS are allowed", method)
		}
	}

	want := map[string]domain.HTTPMethod{
		"http://app.test/workshop/api/shop/products": domain.MethodGET,
		"http://app.test/identity/api/v2/user":       domain.MethodPOST,
		"http://app.test/identity/api/v2/password":   domain.MethodPUT,
	}
	got := make(map[string]domain.HTTPMethod, len(sink.endpoints))
	for _, ep := range sink.endpoints {
		got[ep.URL] = ep.Method
		if ep.Source != domain.SourceScriptLiteral {
			t.Errorf("endpoint %s source = %s, want script_literal", ep.URL, ep.Source)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registered endpoints = %v, want %v", got, want)
	}
	// PUT was inferred from OPTIONS; assert the OPTIONS probe happened rather
	// than the PUT request itself.
	var sentOPTIONS bool
	for _, r := range eng.requests {
		if r == "OPTIONS http://app.test/identity/api/v2/password" {
			sentOPTIONS = true
		}
	}
	if !sentOPTIONS {
		t.Fatalf("no OPTIONS probe sent for the 405 without an Allow header: %v", eng.requests)
	}
}

func TestHarvestScriptAPIsSkipsSoft404AndPlaceholders(t *testing.T) {
	js := `var a="/api/v2/user/<id>",b="/api/v2/invoices";`
	eng := &recordingBundleEngine{responses: map[string]*httpengine.Response{
		// Every unknown path answers with the SPA shell.
		"GET http://app.test/api/v2/invoices": {
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"text/html"}},
			Body:    []byte("<html><body><div id=\"root\"></div></body></html>"),
		},
	}}
	sink := &formTestSink{}
	n := &networkSource{engine: eng, cfg: DefaultConfig()}
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"app.test"}}}

	if err := n.harvestScriptAPIs(context.Background(), in, sink, "http://app.test/", nil, []string{js}); err != nil {
		t.Fatalf("harvestScriptAPIs: %v", err)
	}
	if len(sink.endpoints) != 0 {
		t.Fatalf("soft-404/placeholder paths registered: %+v", sink.endpoints)
	}
	for _, r := range eng.requests {
		if strings.Contains(r, "<id>") {
			t.Fatalf("placeholder path was probed: %s", r)
		}
	}
}

// TestInspectScriptBundlesRegistersDeclaredRequests proves the external bundle
// is fetched once and its declared fetch/XHR shapes are registered passively:
// no request is sent to the declarations themselves.
func TestInspectScriptBundlesRegistersDeclaredRequests(t *testing.T) {
	const bundle = `var x=new XMLHttpRequest();x.open("POST","/workshop/api/report");` +
		`x.setRequestHeader("Content-Type","application/json");x.send("{\"a\":1}");` +
		`fetch("/identity/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});`
	eng := &recordingBundleEngine{responses: map[string]*httpengine.Response{
		"GET http://app.test/static/app.js": {
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/javascript"}},
			Body:    []byte(bundle),
		},
	}}
	network := []browser.NetworkEvent{{URL: "http://app.test/static/app.js", Method: "GET", ResourceType: "script"}}
	sink := &formTestSink{}
	n := &networkSource{engine: eng, cfg: DefaultConfig()}
	in := Input{Scope: domain.Scope{IncludeHosts: []string{"app.test"}}}

	bodies := n.inspectScriptBundles(context.Background(), in, sink, "http://app.test/", network)
	if len(bodies) != 1 {
		t.Fatalf("bodies = %d, want the one bundle", len(bodies))
	}
	if len(eng.requests) != 1 {
		t.Fatalf("bundle requests = %v, want exactly one download", eng.requests)
	}

	want := map[string]domain.HTTPMethod{
		"http://app.test/workshop/api/report":     domain.MethodPOST,
		"http://app.test/identity/api/auth/login": domain.MethodPOST,
	}
	got := make(map[string]domain.HTTPMethod, len(sink.endpoints))
	for _, ep := range sink.endpoints {
		got[ep.URL] = ep.Method
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("declared endpoints = %v, want %v", got, want)
	}
}
