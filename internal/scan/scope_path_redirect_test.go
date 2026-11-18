package scan

// Integration tests for the scope path boundary at the raw HTTP engine:
// an encoded traversal in a redirect Location must be denied before the next
// hop reaches the loopback listener, while a normal in-scope path still works.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestScopedEngineRejectsEncodedTraversalRedirect(t *testing.T) {
	cases := []struct {
		name     string
		location string
	}{
		{"encoded dot", "/app/%2e%2e/outside"},
		{"encoded slash", "/app%2f..%2foutside"},
		{"encoded backslash", "/app/%5c..%5coutside"},
		{"double encoded dot", "/app/%252e%252e/outside"},
		{"dot path parameter", "/app/..;/outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var outsideHits atomic.Int64
			var startHits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.RequestURI {
				case "/app/start":
					startHits.Add(1)
					w.Header().Set("Location", tc.location)
					w.WriteHeader(http.StatusFound)
				default:
					if strings.Contains(r.RequestURI, "outside") {
						outsideHits.Add(1)
					}
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			eng := newScopedEngine(noFollowClient(t), appScope())
			_, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/app/start"))
			if !errors.Is(err, ErrOutOfScopeRedirect) {
				t.Fatalf("Do() error = %v, want ErrOutOfScopeRedirect", err)
			}
			if startHits.Load() == 0 {
				t.Fatal("the in-scope redirect response was never reached; the test proves nothing")
			}
			if outsideHits.Load() != 0 {
				t.Fatalf("encoded traversal Location %q reached the out-of-prefix listener %d time(s)", tc.location, outsideHits.Load())
			}
		})
	}
}

func TestScopedEngineAllowsNormalInScopePath(t *testing.T) {
	var okHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/app/ok" {
			http.NotFound(w, r)
			return
		}
		okHits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), appScope())
	resp, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/app/ok"))
	if err != nil {
		t.Fatalf("normal in-scope request: %v", err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "ok" {
		t.Fatalf("normal in-scope response = %d %q", resp.Status, resp.Body)
	}
	if okHits.Load() != 1 {
		t.Fatalf("normal in-scope listener hits = %d, want 1", okHits.Load())
	}
}
