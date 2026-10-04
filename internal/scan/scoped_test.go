package scan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// Internal tests for scopedEngine: scope is checked before every request and on
// every redirect hop.

type pathLog struct {
	mu    sync.Mutex
	paths []string
}

func (p *pathLog) add(path string) {
	p.mu.Lock()
	p.paths = append(p.paths, path)
	p.mu.Unlock()
}

func (p *pathLog) saw(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, x := range p.paths {
		if x == path {
			return true
		}
	}
	return false
}

func noFollowClient(t *testing.T) *httpengine.Client {
	t.Helper()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false // REQUIRED by scopedEngine
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func scopedTestServer(t *testing.T, log *pathLog) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/ok", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/app/hop1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/ok", http.StatusFound)
	})
	mux.HandleFunc("/app/escape", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/outside/landing", http.StatusFound)
	})
	mux.HandleFunc("/app/post302", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/echo", http.StatusFound)
	})
	mux.HandleFunc("/app/echo", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Method) })
	mux.HandleFunc("/app/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/loop", http.StatusFound)
	})
	mux.HandleFunc("/outside/landing", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "out") })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func appScope() domain.Scope {
	return domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}
}

func TestScopedEngineBlocksOutOfScopeRequest(t *testing.T) {
	var log pathLog
	srv := scopedTestServer(t, &log)
	eng := newScopedEngine(noFollowClient(t), appScope())

	_, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/outside/landing"))
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope, got %v", err)
	}
	if log.saw("/outside/landing") {
		t.Fatal("an out-of-scope request reached the server")
	}
}

func TestScopedEngineBlocksRedirectOutOfScope(t *testing.T) {
	var log pathLog
	srv := scopedTestServer(t, &log)
	eng := newScopedEngine(noFollowClient(t), appScope())

	_, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/app/escape"))
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope for an escaping redirect, got %v", err)
	}
	if !log.saw("/app/escape") {
		t.Fatal("the in-scope request should have been sent")
	}
	if log.saw("/outside/landing") {
		t.Fatal("redirect hop to an out-of-scope URL was requested (scope leak)")
	}
}

func TestScopedEngineFollowsInScopeRedirects(t *testing.T) {
	var log pathLog
	srv := scopedTestServer(t, &log)
	eng := newScopedEngine(noFollowClient(t), appScope())

	resp, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/app/hop1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" || resp.Status != 200 {
		t.Fatalf("redirect not followed: status=%d body=%q", resp.Status, resp.Body)
	}
	if len(resp.RedirectChain) != 1 || resp.FinalURL != srv.URL+"/app/ok" {
		t.Fatalf("chain=%v final=%q", resp.RedirectChain, resp.FinalURL)
	}
}

func TestScopedEngineRedirectMethodSemantics(t *testing.T) {
	var log pathLog
	srv := scopedTestServer(t, &log)
	eng := newScopedEngine(noFollowClient(t), appScope())

	// POST + 302 becomes GET.
	req := &httpengine.Request{Method: "POST", URL: srv.URL + "/app/post302", Body: []byte("x=1"), ContentType: "application/x-www-form-urlencoded"}
	resp, err := eng.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "GET" {
		t.Fatalf("POST after 302 should become GET, server saw %q", resp.Body)
	}
	if req.Method != "POST" || len(req.Body) == 0 {
		t.Fatal("caller's request must not be mutated")
	}
}

func TestScopedEngineRedirectLoopBounded(t *testing.T) {
	var log pathLog
	srv := scopedTestServer(t, &log)
	eng := newScopedEngine(noFollowClient(t), appScope())

	_, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/app/loop"))
	if !errors.Is(err, httpengine.ErrTooManyRedirects) {
		t.Fatalf("expected ErrTooManyRedirects, got %v", err)
	}
}
