package scan

// A redirect is the easiest way for a request to leave the origin a scope
// authorized: the first hop is in scope, the Location points at another port or
// scheme of the same host. scopedEngine re-checks every hop against Permits, so
// the origin list must apply there too — and the second origin must receive no
// request at all.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

func scopeOriginFor(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return domain.ScopeOrigin{Scheme: u.Scheme, Host: u.Hostname(), Port: port}.String()
}

func TestScopedEngineEnforcesOriginOnEveryRedirectHop(t *testing.T) {
	var hitsSecond atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsSecond.Add(1)
		_, _ = io.WriteString(w, "out")
	}))
	defer second.Close()

	var hitsFirst atomic.Int32
	var first *httptest.Server
	first = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsFirst.Add(1)
		switch r.URL.Path {
		case "/same-origin":
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/to-other-port":
			http.Redirect(w, r, second.URL+"/landing", http.StatusFound)
		case "/to-https":
			u, _ := url.Parse(first.URL)
			http.Redirect(w, r, "https://"+u.Host+"/landing", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer first.Close()

	sc := domain.Scope{
		IncludeHosts:   []string{"127.0.0.1"},
		AllowedOrigins: []string{scopeOriginFor(t, first.URL)},
	}
	// The scope must really be origin-restricted before this test means
	// anything (it uses two servers on the same host, different ports).
	if d := sc.Permits(second.URL + "/"); d.Allowed {
		t.Fatalf("setup: the second port is already permitted: %+v", d)
	}
	engine := newScopedEngine(noFollowClient(t), sc)
	ctx := context.Background()

	// Control: a same-origin redirect still follows.
	resp, err := engine.Do(ctx, &httpengine.Request{Method: http.MethodGet, URL: first.URL + "/same-origin"})
	if err != nil {
		t.Fatalf("same-origin redirect failed: %v", err)
	}
	if resp.Status != http.StatusOK || len(resp.RedirectChain) != 1 {
		t.Fatalf("same-origin redirect: status %d chain %v", resp.Status, resp.RedirectChain)
	}

	// A hop to another port of the same host is refused before it is sent.
	_, err = engine.Do(ctx, &httpengine.Request{Method: http.MethodGet, URL: first.URL + "/to-other-port"})
	if !errors.Is(err, ErrOutOfScopeRedirect) {
		t.Fatalf("redirect to another port = %v, want ErrOutOfScopeRedirect", err)
	}
	if got := hitsSecond.Load(); got != 0 {
		t.Fatalf("the undeclared origin received %d request(s)", got)
	}

	// A hop that changes the scheme (https on the declared port) is refused
	// for the same reason, and no TLS connection is attempted.
	before := hitsFirst.Load()
	_, err = engine.Do(ctx, &httpengine.Request{Method: http.MethodGet, URL: first.URL + "/to-https"})
	if !errors.Is(err, ErrOutOfScopeRedirect) {
		t.Fatalf("redirect to another scheme = %v, want ErrOutOfScopeRedirect", err)
	}
	if got := hitsFirst.Load(); got != before+1 {
		t.Fatalf("first server got %d requests, want exactly the initial hop", got-before)
	}
}

func TestScopedEngineRefusesAnUndeclaredInitialOrigin(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	// Authorize the same host on a different port, so only the origin rule can
	// be what refuses this request.
	sc := domain.Scope{
		IncludeHosts: []string{"127.0.0.1"},
		AllowedOrigins: []string{
			domain.ScopeOrigin{Scheme: "http", Host: "127.0.0.1", Port: port + 1}.String(),
		},
	}
	engine := newScopedEngine(noFollowClient(t), sc)
	_, err := engine.Do(context.Background(), &httpengine.Request{Method: http.MethodGet, URL: srv.URL + "/"})
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("undeclared initial origin = %v, want ErrOutOfScope", err)
	}
	if hits.Load() != 0 {
		t.Fatal("an out-of-origin request was sent")
	}
}
