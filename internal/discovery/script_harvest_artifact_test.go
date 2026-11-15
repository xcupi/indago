package discovery_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/httpengine"
)

// Regression (QA against a real SPA): a bundle's HTML-escaping helper
// `.replace(/"/g,"&quot;")` makes a quote-scanning extractor read "/g," as a
// path, and discovery registered GET /g, with source=script_literal. A path
// ending in list/statement punctuation is not a route: reject it, and keep the
// real endpoints the same bundle names.
func TestExtractScriptEndpointLiteralsDropsRegexFlagArtifacts(t *testing.T) {
	body := `a.replace(/"/g,"&quot;");b.replace(/"/gi,"");c.replace(/"/i,"");d.replace(/"/m,"");` +
		`x="/g,";y="/gi,";z="/i,";w="/m,";` +
		`p="/api/v1/users,";q="/api/v1/users;";r="/api/v1/y)";` +
		`var u=["/api/v1/users","/rest/products/search?q=","/api/users?ids=1,2,",` +
		`"/wiki/Foo_(bar)","/api/v1/x(my)","/id"];`

	got := discovery.ExtractScriptEndpointLiterals(body)
	want := []string{
		"/api/users?ids=1,2,",
		"/api/v1/users",
		"/api/v1/x(my)",
		"/id",
		"/rest/products/search?q=",
		"/wiki/Foo_(bar)",
	}
	if len(got) != len(want) {
		t.Fatalf("literals = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("literals = %q, want %q", got, want)
		}
	}
}

// The end-to-end shape of the same bug: a crawled page pulls a bundle whose
// sanitizer helper yields "/g,". It must never become an endpoint (or a job),
// while the bundle's real API path still does.
func TestCrawlScriptHarvestDropsRegexFlagArtifacts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><script src="/static/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `var esc=function(s){return s.replace(/"/g,"&quot;")};`+
			`var esc2=function(s){return s.replace(/"/gi,"")};`+
			`fetch("/api/orders");`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	sink := runSource(t, discovery.NewCrawlSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	joined := strings.Join(sink.endpointURLs(), "\n")
	for _, artifact := range []string{"/g,", "/gi,"} {
		for _, raw := range sink.endpointURLs() {
			info, err := discovery.Normalize(raw)
			if err != nil {
				continue
			}
			if info.Path == artifact {
				t.Fatalf("regex-flag artifact %q reached the endpoint queue: %v", artifact, sink.endpointURLs())
			}
		}
	}
	if !strings.Contains(joined, "/api/orders") {
		t.Fatalf("the bundle's real endpoint was not harvested: %v", sink.endpointURLs())
	}
}
