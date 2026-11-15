package discovery_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// Regression: a React/SPA document carries its inline SVG/JSX as TEXT, and the
// link extractor hands markup back as if it were a route ("/></g></svg>",
// "/><path d=", "/><circle r="). Normalizing one used to register a GET
// endpoint for http://host/></svg> — a URL no server can route — and every
// later stage then spent request budget testing it.
//
// The sink is the last gate before persistence, so it must drop these exactly
// like any other malformed URL: silently, with no endpoint row and no job.
func TestCollectorSkipsMarkupPaths(t *testing.T) {
	c, st, q, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	for _, u := range []string{
		"http://example.com/></svg>",
		"http://example.com/></g></svg>",
		"http://example.com/><path d=",
		"http://example.com/><circle r=",
		"http://example.com/<script>",
	} {
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: u, Method: domain.MethodGET, Source: domain.SourceCrawler})
		if err != nil {
			t.Fatalf("AddEndpoint(%q) returned an error, want a silent skip: %v", u, err)
		}
		if id != "" {
			t.Fatalf("AddEndpoint(%q) = %q, want skipped (empty id)", u, id)
		}
	}

	if eps, _ := st.Endpoints().ListByScan(ctx, scanID); len(eps) != 0 {
		t.Fatalf("markup reached the endpoint table: %+v", eps)
	}
	if stats, _ := q.Stats(ctx, scanID); stats.Queued != 0 {
		t.Fatalf("jobs queued for markup paths: %+v", stats)
	}

	// The gate is not a blanket refusal: an ordinary route still registers.
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/app/reports", Method: domain.MethodGET, Source: domain.SourceCrawler,
	})
	if err != nil || id == "" {
		t.Fatalf("an ordinary route should register: id=%q err=%v", id, err)
	}
}

// The same regression end to end: a crawled page whose inline SVG wraps an
// icon in a link with markup-close quoting must not put the tag close in the
// endpoint queue, while the page's real links are unaffected.
func TestCrawlSkipsMarkupPathsFromInlineSVG(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			fmt.Fprint(w, "<html><body>ok</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body>`+
			`<svg><a href="/></g></svg>"><circle r="5"/></a></svg>`+
			`<svg><path d="M0 0L10 10"/></svg>`+
			`<a href="/app/reports">reports</a></body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	sink := runSource(t, discovery.NewCrawlSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	var joined strings.Builder
	for _, u := range sink.endpointURLs() {
		joined.WriteString(u)
		joined.WriteString("\n")
		if strings.ContainsAny(u, "<>") {
			t.Fatalf("markup reached the endpoint queue: %q (all: %v)", u, sink.endpointURLs())
		}
	}
	if !strings.Contains(joined.String(), "/app/reports") {
		t.Fatalf("the page's real link was not registered: %v", sink.endpointURLs())
	}
}
