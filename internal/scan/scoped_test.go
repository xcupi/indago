package scan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// --- session cookies: HTTP-level testing carries the same authenticated
// session browser verification uses ---

func writeStorageState(t *testing.T, cookies string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"cookies":[`+cookies+`],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Playwright serializes host-only domains without a leading dot and explicit
// Domain cookies with one (verified using the installed Chromium/Playwright).
// Keep every host's cookie here; scopedEngine decides which one may be sent to
// each request URL.
func TestSessionCookiesRetainsHostOnlyAndDomainCookies(t *testing.T) {
	path := writeStorageState(t, `
		{"name":"sid","value":"abc","domain":"example.com","path":"/"},
		{"name":"sub","value":"xyz","domain":".example.com","path":"/"},
		{"name":"other","value":"no","domain":"other.test","path":"/"}`)

	got := sessionCookies(path)
	if len(got) != 3 {
		t.Fatalf("cookies = %d, want all 3 saved cookies", len(got))
	}
	byName := make(map[string]*http.Cookie, len(got))
	for _, c := range got {
		byName[c.Name] = c
	}
	if byName["sid"].Domain != "example.com" || byName["sub"].Domain != ".example.com" {
		t.Fatalf("Playwright domain notation not preserved: host-only=%q domain=%q", byName["sid"].Domain, byName["sub"].Domain)
	}
}

func TestSessionCookiesEmptyOrUnreadableYieldsNil(t *testing.T) {
	if got := sessionCookies(""); got != nil {
		t.Fatalf("empty path should yield nil, got %v", got)
	}
	if got := sessionCookies("/nonexistent/path/state.json"); got != nil {
		t.Fatalf("unreadable path should yield nil, got %v", got)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sessionCookies(bad); got != nil {
		t.Fatalf("malformed JSON should yield nil, got %v", got)
	}
}

func TestScopedEngineWithSessionCookiesSendsThem(t *testing.T) {
	var sawCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil {
			sawCookie = c.Value
		}
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), domain.Scope{IncludeHosts: []string{"127.0.0.1"}}).
		WithSessionCookies([]*http.Cookie{{Name: "sid", Value: "authed-123", Domain: "127.0.0.1", Path: "/"}})
	if _, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/")); err != nil {
		t.Fatal(err)
	}
	if sawCookie != "authed-123" {
		t.Fatalf("session cookie not sent: %q", sawCookie)
	}
}

// A request-specific cookie (a Cookie-location injection point's override —
// see buildRequest in executor.go) must win over a session cookie of the
// SAME name, never be silently shadowed by it. This is the realistic case
// for a Cookie injection point: its name came from the scan's own session
// cookie jar in the first place (see discovery's registerCookieInjectionPoints),
// so the two names collide by construction on every real request.
func TestScopedEngineRequestCookieWinsOverSameNameSessionCookie(t *testing.T) {
	var sawCookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			if c.Name == "pref" {
				sawCookies = append(sawCookies, c.Value)
			}
		}
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), domain.Scope{IncludeHosts: []string{"127.0.0.1"}}).
		WithSessionCookies([]*http.Cookie{{Name: "pref", Value: "blue", Domain: "127.0.0.1", Path: "/"}})
	req := httpengine.GET(srv.URL + "/")
	req.Cookies = []*http.Cookie{{Name: "pref", Value: "MARKER"}}
	if _, err := eng.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(sawCookies) != 1 || sawCookies[0] != "MARKER" {
		t.Fatalf("pref cookie values seen = %v, want exactly [MARKER] (the injection override, not the shadowed session value)", sawCookies)
	}
}

type cookieObservation struct {
	url     string
	cookies []*http.Cookie
}

type cookieRedirectEngine struct {
	redirects map[string]string
	requests  []cookieObservation
}

func (e *cookieRedirectEngine) Do(_ context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	cookies := append([]*http.Cookie(nil), req.Cookies...)
	e.requests = append(e.requests, cookieObservation{url: req.URL, cookies: cookies})
	resp := &httpengine.Response{Status: http.StatusOK, Headers: make(http.Header)}
	if target := e.redirects[req.URL]; target != "" {
		resp.Status = http.StatusFound
		resp.Headers.Set("Location", target)
	}
	return resp, nil
}

func cookieTestScope() domain.Scope {
	return domain.Scope{IncludeHosts: []string{"app.example.test", "api.example.test", "example.test", "evil-example.test"}}
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c != nil && c.Name == name {
			return true
		}
	}
	return false
}

func TestScopedEngineSessionCookieHostOnlyAndDomainMatching(t *testing.T) {
	t.Run("host-only is exact host", func(t *testing.T) {
		inner := &cookieRedirectEngine{}
		eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{{Name: "host", Value: "one", Domain: "app.example.test", Path: "/"}})
		if _, err := eng.Do(context.Background(), httpengine.GET("http://api.example.test/")); err != nil {
			t.Fatal(err)
		}
		if hasCookie(inner.requests[0].cookies, "host") {
			t.Fatal("host-only cookie for app.example.test was sent to api.example.test")
		}

		if _, err := eng.Do(context.Background(), httpengine.GET("http://app.example.test/")); err != nil {
			t.Fatal(err)
		}
		if !hasCookie(inner.requests[1].cookies, "host") {
			t.Fatal("host-only cookie was not sent to its exact host")
		}
	})

	t.Run("domain cookie matches domain and subdomains only", func(t *testing.T) {
		inner := &cookieRedirectEngine{}
		eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{{Name: "domain", Value: "two", Domain: ".example.test", Path: "/"}})
		for _, target := range []struct {
			url  string
			want bool
		}{
			{"http://example.test/", true},
			{"http://api.example.test/", true},
			{"http://evil-example.test/", false},
		} {
			if _, err := eng.Do(context.Background(), httpengine.GET(target.url)); err != nil {
				t.Fatal(err)
			}
			got := hasCookie(inner.requests[len(inner.requests)-1].cookies, "domain")
			if got != target.want {
				t.Errorf("cookie sent to %s = %v, want %v", target.url, got, target.want)
			}
		}
	})
}

func TestScopedEngineSessionCookiePathMatching(t *testing.T) {
	inner := &cookieRedirectEngine{}
	eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{{Name: "private", Value: "secret", Domain: "app.example.test", Path: "/private"}})
	for _, target := range []struct {
		url  string
		want bool
	}{
		{"http://app.example.test/private", true},
		{"http://app.example.test/private/account", true},
		{"http://app.example.test/public", false},
		{"http://app.example.test/privateer", false},
	} {
		if _, err := eng.Do(context.Background(), httpengine.GET(target.url)); err != nil {
			t.Fatal(err)
		}
		got := hasCookie(inner.requests[len(inner.requests)-1].cookies, "private")
		if got != target.want {
			t.Errorf("cookie sent to %s = %v, want %v", target.url, got, target.want)
		}
	}
}

func TestScopedEngineSessionCookieSecureAndExpiry(t *testing.T) {
	t.Run("secure requires HTTPS", func(t *testing.T) {
		inner := &cookieRedirectEngine{}
		eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{{Name: "secure", Value: "yes", Domain: "app.example.test", Path: "/", Secure: true}})
		for _, target := range []struct {
			url  string
			want bool
		}{
			{"http://app.example.test/", false},
			{"https://app.example.test/", true},
		} {
			if _, err := eng.Do(context.Background(), httpengine.GET(target.url)); err != nil {
				t.Fatal(err)
			}
			got := hasCookie(inner.requests[len(inner.requests)-1].cookies, "secure")
			if got != target.want {
				t.Errorf("secure cookie sent to %s = %v, want %v", target.url, got, target.want)
			}
		}
	})

	t.Run("expired cookie is withheld", func(t *testing.T) {
		inner := &cookieRedirectEngine{}
		eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{{Name: "expired", Value: "old", Domain: "app.example.test", Path: "/", Expires: time.Unix(1, 0)}})
		if _, err := eng.Do(context.Background(), httpengine.GET("http://app.example.test/")); err != nil {
			t.Fatal(err)
		}
		if hasCookie(inner.requests[0].cookies, "expired") {
			t.Fatal("expired cookie was sent")
		}
	})
}

func TestScopedEngineRechecksSessionCookieScopeOnRedirects(t *testing.T) {
	cases := []struct {
		name       string
		start      string
		redirectTo string
		cookie     *http.Cookie
		wantFinal  bool
	}{
		{
			name:       "host-only cookie withheld on other in-scope host",
			start:      "http://app.example.test/private/start",
			redirectTo: "http://api.example.test/private/final",
			cookie:     &http.Cookie{Name: "sid", Value: "host", Domain: "app.example.test", Path: "/private"},
			wantFinal:  false,
		},
		{
			name:       "path cookie withheld on nonmatching path",
			start:      "http://app.example.test/private/start",
			redirectTo: "http://app.example.test/public/final",
			cookie:     &http.Cookie{Name: "sid", Value: "path", Domain: "app.example.test", Path: "/private"},
			wantFinal:  false,
		},
		{
			name:       "allowed same-host path redirect retains cookie",
			start:      "http://app.example.test/private/start",
			redirectTo: "http://app.example.test/private/final",
			cookie:     &http.Cookie{Name: "sid", Value: "allowed", Domain: "app.example.test", Path: "/private"},
			wantFinal:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &cookieRedirectEngine{redirects: map[string]string{tc.start: tc.redirectTo}}
			eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{tc.cookie})
			if _, err := eng.Do(context.Background(), httpengine.GET(tc.start)); err != nil {
				t.Fatal(err)
			}
			if len(inner.requests) != 2 {
				t.Fatalf("requests = %d, want initial plus redirected request", len(inner.requests))
			}
			got := hasCookie(inner.requests[1].cookies, "sid")
			if got != tc.wantFinal {
				t.Fatalf("session cookie reached redirected URL %s = %v, want %v", inner.requests[1].url, got, tc.wantFinal)
			}
		})
	}
}

func TestSessionCookiesPreservesStorageStateFields(t *testing.T) {
	path := writeStorageState(t, `{"name":"sid","value":"abc","domain":"app.example.test","path":"/private","expires":4102444800,"httpOnly":true,"secure":true,"sameSite":"Strict"}`)
	got := sessionCookies(path)
	if len(got) != 1 {
		t.Fatalf("cookies = %d, want 1", len(got))
	}
	c := got[0]
	if c.Name != "sid" || c.Value != "abc" || c.Domain != "app.example.test" || c.Path != "/private" || !c.Expires.Equal(time.Unix(4102444800, 0)) || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("storage-state cookie fields were not preserved: %#v", c)
	}
}

func TestSessionCookiesRetainsCookiesForOtherSavedHosts(t *testing.T) {
	path := writeStorageState(t, `
		{"name":"app","value":"a","domain":"app.example.test","path":"/"},
		{"name":"api","value":"b","domain":"api.example.test","path":"/"},
		{"name":"shared","value":"c","domain":".example.test","path":"/"}`)
	got := sessionCookies(path)
	if len(got) != 3 {
		t.Fatalf("cookies = %d, want all 3 stored host/domain cookies retained for per-request scoping", len(got))
	}
}

func TestSessionCookiesSkipsMalformedScopesAndAttributes(t *testing.T) {
	path := writeStorageState(t, `
		{"name":"valid","value":"v","domain":"app.example.test","path":"/","expires":-1,"sameSite":"Lax"},
		{"name":"missing-domain","value":"v","path":"/"},
		{"name":"missing-path","value":"v","domain":"app.example.test"},
		{"name":"bad-domain","value":"v","domain":"..example.test","path":"/"},
		{"name":"bad-expiry","value":"v","domain":"app.example.test","path":"/","expires":-2},
		{"name":"bad-same-site","value":"v","domain":"app.example.test","path":"/","sameSite":"Other"},
		{"name":"partitioned","value":"v","domain":"app.example.test","path":"/","partitionKey":"https://top.example"}`)
	got := sessionCookies(path)
	if len(got) != 1 || got[0].Name != "valid" || !got[0].Expires.IsZero() || got[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("malformed cookies were not skipped conservatively: %#v", got)
	}
}

func TestScopedEngineLiveRedirectCookieScope(t *testing.T) {
	seen := make(map[string]string)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/private/to-public":
			http.Redirect(w, r, "/public/final", http.StatusFound)
			return
		case "/private/to-localhost":
			http.Redirect(w, r, "http://localhost"+strings.TrimPrefix(server.URL, "http://127.0.0.1")+"/private/final", http.StatusFound)
			return
		case "/private/to-private":
			http.Redirect(w, r, "/private/final", http.StatusFound)
			return
		}
		c, err := r.Cookie("sid")
		if err == nil {
			seen[r.Host+r.URL.Path] = c.Value
		} else {
			seen[r.Host+r.URL.Path] = ""
		}
	}))
	defer server.Close()

	eng := newScopedEngine(noFollowClient(t), domain.Scope{IncludeHosts: []string{"127.0.0.1", "localhost"}}).
		WithSessionCookies([]*http.Cookie{{Name: "sid", Value: "state", Domain: "127.0.0.1", Path: "/private"}})
	for _, path := range []string{"/private/to-public", "/private/to-localhost", "/private/to-private"} {
		if _, err := eng.Do(context.Background(), httpengine.GET(server.URL+path)); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}
	portSuffix := strings.TrimPrefix(server.URL, "http://127.0.0.1")
	for _, target := range []struct {
		key  string
		want string
	}{
		{"127.0.0.1" + portSuffix + "/public/final", ""},
		{"localhost" + portSuffix + "/private/final", ""},
		{"127.0.0.1" + portSuffix + "/private/final", "state"},
	} {
		if got := seen[target.key]; got != target.want {
			t.Errorf("redirect handler %s saw cookie value %q, want %q", target.key, got, target.want)
		}
	}
}

func TestScopedEngineRequestCookieOverrideRespectsSessionScopeOnRedirect(t *testing.T) {
	cases := []struct {
		name       string
		start      string
		redirectTo string
		wantFinal  bool
	}{
		{"off-host override is withheld", "http://app.example.test/private/start", "http://api.example.test/private/final", false},
		{"off-path override is withheld", "http://app.example.test/private/start", "http://app.example.test/public/final", false},
		{"allowed redirect keeps the override", "http://app.example.test/private/start", "http://app.example.test/private/final", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &cookieRedirectEngine{redirects: map[string]string{tc.start: tc.redirectTo}}
			eng := newScopedEngine(inner, cookieTestScope()).WithSessionCookies([]*http.Cookie{
				{Name: "pref", Value: "saved", Domain: "app.example.test", Path: "/private"},
				{Name: "apiOnly", Value: "api-session", Domain: "api.example.test", Path: "/"},
			})
			req := httpengine.GET(tc.start)
			req.Cookies = []*http.Cookie{{Name: "pref", Value: "MARKER"}}
			if _, err := eng.Do(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if !hasCookie(inner.requests[0].cookies, "pref") || inner.requests[0].cookies[0].Value != "MARKER" {
				t.Fatalf("targeted injection override was not used on initial request: %#v", inner.requests[0].cookies)
			}
			if hasCookie(inner.requests[0].cookies, "apiOnly") {
				t.Fatal("unrelated api.example.test session cookie leaked to app.example.test")
			}
			gotFinal := hasCookie(inner.requests[1].cookies, "pref")
			if gotFinal != tc.wantFinal {
				t.Fatalf("override reached redirected URL %s = %v, want %v", inner.requests[1].url, gotFinal, tc.wantFinal)
			}
			if tc.wantFinal && inner.requests[1].cookies[0].Value != "MARKER" {
				t.Fatalf("same-named session cookie shadowed redirected override: %#v", inner.requests[1].cookies)
			}
			wantAPICookie := strings.Contains(tc.redirectTo, "api.example.test")
			if got := hasCookie(inner.requests[1].cookies, "apiOnly"); got != wantAPICookie {
				t.Fatalf("api-only session cookie on redirected URL = %v, want %v", got, wantAPICookie)
			}
		})
	}
}

func TestScopedEngineRejectsPublicSuffixDomainCookie(t *testing.T) {
	inner := &cookieRedirectEngine{}
	scope := domain.Scope{IncludeHosts: []string{"api.example.com"}}
	eng := newScopedEngine(inner, scope).WithSessionCookies([]*http.Cookie{{Name: "broad", Value: "secret", Domain: ".com", Path: "/"}})
	if _, err := eng.Do(context.Background(), httpengine.GET("https://api.example.com/")); err != nil {
		t.Fatal(err)
	}
	if hasCookie(inner.requests[0].cookies, "broad") {
		t.Fatal("a cookie scoped to a public suffix was sent to its registrable subdomain")
	}
}
