package browser_test

// Real-Chromium integration tests for the scope path boundary. Each redirect
// Location encodes traversal to a path outside the scoped prefix; the in-scope
// listener must be reached, but the out-of-prefix listener must not. A normal
// in-scope path is the control and must succeed.

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

func scopePathBrowserGate() (domain.Scope, func(string) bool) {
	scope := domain.Scope{
		IncludeHosts:        []string{"127.0.0.1"},
		IncludePathPrefixes: []string{"/api"},
	}
	return scope, func(raw string) bool { return scope.Permits(raw).Allowed }
}

func TestIntegrationScopeGateBlocksEncodedTraversalRedirect(t *testing.T) {
	_, allow := scopePathBrowserGate()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()

	shapes := []struct{ name, location string }{
		{"encoded dot", "/api/%2e%2e/outside"},
		{"encoded slash", "/api%2f..%2foutside"},
		{"encoded backslash", "/api/%5c..%5coutside"},
		{"double encoded dot", "/api/%252e%252e/outside"},
		{"dot path parameter", "/api/..;/outside"},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			var startHits, outsideHits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.RequestURI {
				case "/api/start":
					startHits.Add(1)
					w.Header().Set("Location", shape.location)
					w.WriteHeader(http.StatusFound)
				default:
					if strings.Contains(r.RequestURI, "outside") {
						outsideHits.Add(1)
					}
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			_, _ = m.Render(context.Background(), srv.URL+"/api/start", browser.RenderOptions{
				AllowRequest: allow,
				WaitUntil:    browser.WaitLoad,
			})
			if startHits.Load() == 0 {
				t.Fatal("the in-scope redirect response was never reached; the test proves nothing")
			}
			if outsideHits.Load() != 0 {
				t.Fatalf("encoded traversal Location %q reached the out-of-prefix listener %d time(s)", shape.location, outsideHits.Load())
			}
		})
	}
}

func TestIntegrationScopeGateAllowsNormalPath(t *testing.T) {
	_, allow := scopePathBrowserGate()
	var okHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/api/ok" {
			http.NotFound(w, r)
			return
		}
		okHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><title>ok</title><p>ok</p>")
	}))
	defer srv.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()

	res, err := m.Render(context.Background(), srv.URL+"/api/ok", browser.RenderOptions{
		AllowRequest: allow,
		WaitUntil:    browser.WaitLoad,
	})
	if err != nil {
		t.Fatalf("normal in-scope render: %v", err)
	}
	if res == nil || res.FinalURL != srv.URL+"/api/ok" {
		t.Fatalf("normal in-scope render result = %+v", res)
	}
	if okHits.Load() == 0 {
		t.Fatal("the normal in-scope path never reached its listener")
	}
}
