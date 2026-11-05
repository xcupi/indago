package browser_test

// Redirect Location values that Go's net/url and Chromium's WHATWG URL parser
// read differently. The gate resolves a 3xx Location with net/url before it asks
// the scope; if Go decides "same host, odd path" while Chromium follows the
// header to another host, the request leaves scope although the gate allowed it.
// Assertions are server-side hit counters on a SECOND host name (localhost vs
// the in-scope 127.0.0.1), never browser logs.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

func TestIntegrationScopeGateBlocksParserDifferentialRedirects(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		fmt.Fprint(w, "outside")
	}))
	defer outside.Close()
	hostPort := strings.TrimPrefix(outside.URL, "http://127.0.0.1:") // port only
	outsideHost := "localhost:" + hostPort

	// Each Location below addresses localhost (out of scope) in Chromium's eyes.
	shapes := []struct{ name, location string }{
		{"three-slashes", "///" + outsideHost + "/hit"},
		{"four-slashes", "////" + outsideHost + "/hit"},
		{"slash-tab-slash", "/\t/" + outsideHost + "/hit"},
		{"scheme-three-slashes", "http:///" + outsideHost + "/hit"},
		{"scheme-no-slashes", "http:" + outsideHost + "/hit"},
		{"leading-space", " //" + outsideHost + "/hit"},
		{"backslash", `\\` + outsideHost + "/hit"},
		{"network-path", "//" + outsideHost + "/hit"},
		{"absolute", "http://" + outsideHost + "/hit"},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			outsideHits.Store(0)
			var insideHits atomic.Int64
			inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					insideHits.Add(1)
					w.Header()["Location"] = []string{shape.location} // bypass any client-side cleaning
					w.WriteHeader(http.StatusFound)
					return
				}
				fmt.Fprint(w, "inside")
			}))
			defer inside.Close()
			scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
			m := newManagerOrSkip(t, browser.DefaultConfig())
			defer m.Close()
			_, _ = m.Render(context.Background(), inside.URL+"/start", browser.RenderOptions{
				AllowRequest: func(raw string) bool { return scope.Permits(raw).Allowed },
			})
			if insideHits.Load() == 0 {
				t.Fatal("the in-scope redirect response was never reached; the test proves nothing")
			}
			if outsideHits.Load() != 0 {
				t.Fatalf("Location %q sent the browser to the out-of-scope host %d time(s)", shape.location, outsideHits.Load())
			}
		})
	}
}

// Control: with NO gate the same browser must follow the header to the second
// host, otherwise a zero in the tests above could mean the server was unreachable.
func TestIntegrationParserDifferentialControlReachesTheSecondHost(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	port := strings.TrimPrefix(outside.URL, "http://127.0.0.1:")
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header()["Location"] = []string{"http://localhost:" + port + "/hit"}
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer inside.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	_, _ = m.Render(context.Background(), inside.URL+"/start", browser.RenderOptions{})
	if outsideHits.Load() == 0 {
		t.Fatal("control: an ungated browser never reached the second host name; the differential tests cannot discriminate")
	}
}
