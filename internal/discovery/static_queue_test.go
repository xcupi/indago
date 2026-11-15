package discovery_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// Static resources must never reach the test queue, whether or not the
// (legacy) SkipStaticAssets switch is on: an endpoint row, an injection point
// or a job for a stylesheet is pure wasted request budget.
func TestCollectorNeverQueuesStaticAssets(t *testing.T) {
	cfg := discovery.DefaultConfig() // SkipStaticAssets deliberately left false
	c, st, q, scanID := newCollector(t, cfg)
	ctx := context.Background()

	static := []string{
		"http://example.com/assets/app.css",
		"http://example.com/assets/app.js?v=3",
		"http://example.com/js/bundle.min.js",
		"http://example.com/img/logo.png",
		"http://example.com/img/photo.jpeg",
		"http://example.com/img/anim.gif",
		"http://example.com/img/icon.svg",
		"http://example.com/fonts/x.woff",
		"http://example.com/fonts/x.woff2",
		"http://example.com/fonts/x.ttf",
		"http://example.com/fonts/x.eot",
		"http://example.com/favicon.ico",
		"http://example.com/js/app.js.map",
		"http://example.com/img/hero.webp",
		"http://example.com/media/clip.mp4",
		"http://example.com/docs/manual.pdf",
	}
	for _, u := range static {
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: u, Method: domain.MethodGET, Source: domain.SourceBrowserNetwork,
		})
		if err != nil {
			t.Fatalf("AddEndpoint(%s): %v", u, err)
		}
		if id != "" {
			t.Fatalf("%s was registered as a test target (id %s)", u, id)
		}
	}

	endpoints, err := st.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 {
		t.Fatalf("static assets persisted as endpoints: %+v", endpoints)
	}
	params, err := st.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Fatalf("static assets produced parameters: %+v", params)
	}
	stats, err := q.Stats(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Queued != 0 {
		t.Fatalf("static assets enqueued test jobs: %+v", stats)
	}

	// An operator-supplied seed is explicit intent: it stays testable even
	// when its path looks static.
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/assets/app.js", Method: domain.MethodGET, Source: domain.SourceUserProvided,
	})
	if err != nil || id == "" {
		t.Fatalf("operator seed was dropped: id=%q err=%v", id, err)
	}
}

// A parameter proposed against a static URL must not create an endpoint, a
// parameter, or a job either — AddParameter resolves the endpoint first.
func TestCollectorDropsParametersOnStaticAssets(t *testing.T) {
	c, st, q, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()
	if err := c.AddParameter(ctx, discovery.ParamCandidate{
		EndpointURL: "http://example.com/assets/theme.css", EndpointMethod: domain.MethodGET,
		Name: "v", Location: domain.LocationQuery, Example: "2", Source: domain.SourceForm,
	}); err != nil {
		t.Fatalf("AddParameter: %v", err)
	}
	if params, _ := st.Parameters().ListByScan(ctx, scanID); len(params) != 0 {
		t.Fatalf("parameter registered on a static asset: %+v", params)
	}
	if stats, _ := q.Stats(ctx, scanID); stats.Queued != 0 {
		t.Fatalf("jobs queued for a static asset: %+v", stats)
	}
}

// The crawler must keep mining JavaScript for the endpoints it names — that is
// the whole point of not treating "static" as "invisible" — while never
// registering the script (or any other asset) as a test target.
func TestCrawlHarvestsScriptLiteralsWithoutTestingTheAsset(t *testing.T) {
	var scriptHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/assets/app.css"></head><body>`+
			`<img src="/img/logo.png">`+
			`<script src="/static/app.js"></script>`+
			`<a href="/app/reports">reports</a></body></html>`)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		scriptHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `const urls=["/api/invoices","/api/v1/users?page=1","/static/vendor.js","/api/invoices"];`+
			`fetch("/api/export");`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	sink := runSource(t, discovery.NewCrawlSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	got := map[string]bool{}
	for _, u := range sink.endpointURLs() {
		got[u] = true
	}
	joined := strings.Join(sink.endpointURLs(), "\n")
	for _, want := range []string{"/api/invoices", "/api/v1/users?page=1", "/api/export", "/app/reports"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("script literal %q was not harvested; endpoints=%v", want, sink.endpointURLs())
		}
	}
	for _, unwanted := range []string{"/static/app.js", "/static/vendor.js", "/assets/app.css", "/img/logo.png"} {
		for u := range got {
			if strings.Contains(u, unwanted) {
				t.Fatalf("static resource %q reached the endpoint queue: %s", unwanted, u)
			}
		}
	}
	if hits := scriptHits.Load(); hits != 1 {
		t.Fatalf("script fetched %d times, want exactly 1", hits)
	}
}

// Script literals are discovery input: only root-relative, non-static,
// non-templated paths qualify, and the result is sorted and unique.
func TestExtractScriptEndpointLiterals(t *testing.T) {
	body := `var a="/api/users";fetch('/graphql');x="//cdn.example/asset";
y="/static/app.js";z="/a/{id}";n="/";q="http://evil.example/x";r="relative/path";
s="/api/users";t="/api/v1/orders?state=open";u="${base}/x";`
	got := discovery.ExtractScriptEndpointLiterals(body)
	want := []string{"/api/users", "/api/v1/orders?state=open", "/graphql"}
	if len(got) != len(want) {
		t.Fatalf("literals = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("literals = %v, want %v", got, want)
		}
	}
}

// A bundle naming hundreds of paths cannot flood the queue: the extractor caps
// one asset's contribution (32 literals, see ExtractScriptEndpointLiterals).
func TestScriptHarvestIsCappedPerAsset(t *testing.T) {
	const perAssetCap = 32
	var body strings.Builder
	body.WriteString("const u=[")
	for i := 0; i < perAssetCap+10; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, "%q", fmt.Sprintf("/api/item-%02d", i))
	}
	body.WriteString("];")

	literals := discovery.ExtractScriptEndpointLiterals(body.String())
	if len(literals) != perAssetCap {
		t.Fatalf("extracted %d literals, want the %d cap", len(literals), perAssetCap)
	}
	for i := 1; i < len(literals); i++ {
		if literals[i-1] >= literals[i] {
			t.Fatalf("literals not sorted/unique: %q then %q", literals[i-1], literals[i])
		}
	}
}
