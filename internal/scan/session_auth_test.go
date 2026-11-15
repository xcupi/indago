package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func writeAuthState(t *testing.T, origins any) string {
	t.Helper()
	return writeAuthStateWithCookies(t, []any{}, origins)
}

func writeAuthStateWithCookies(t *testing.T, cookies, origins any) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "state-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(f).Encode(map[string]any{"cookies": cookies, "origins": origins}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestSessionAuthHeadersReadsJWTFromLocalStorage(t *testing.T) {
	state := writeAuthState(t, []any{map[string]any{
		"origin": "https://app.example.test",
		"localStorage": []any{
			map[string]any{"name": "access_token", "value": "aaaaa.bbbbb.ccccc"},
			map[string]any{"name": "theme", "value": "aaaaa.bbbbb.ccccc"},
			map[string]any{"name": "token", "value": "not-a-jwt"},
		},
	}})
	headers := sessionAuthHeaders(state)
	if len(headers) != 1 {
		t.Fatalf("headers = %+v, want one recognized JWT", headers)
	}
	if headers[0].Origin != "https://app.example.test" || headers[0].Value != "Bearer aaaaa.bbbbb.ccccc" {
		t.Fatalf("unexpected header: %+v", headers[0])
	}
	if headers[0].HostOnly {
		t.Fatal("a localStorage token is not host-only: it is bound to its exact origin")
	}
}

func TestSessionAuthHeadersReadsCookieJWTAsHostFallback(t *testing.T) {
	jwt := "aaaaa.bbbbb.ccccc"
	state := writeAuthStateWithCookies(t, []any{
		map[string]any{"name": "token", "value": jwt, "domain": "127.0.0.1", "path": "/"},
		map[string]any{"name": "theme", "value": jwt, "domain": "127.0.0.1", "path": "/"},
		map[string]any{"name": "token", "value": "not-a-jwt", "domain": "shop.example.test", "path": "/"},
		map[string]any{"name": "token", "value": jwt, "domain": ".app.example.test", "path": "/"},
	}, []any{})
	headers := sessionAuthHeaders(state)
	if len(headers) != 2 {
		t.Fatalf("headers = %+v, want the 127.0.0.1 and app.example.test cookie tokens", headers)
	}
	byHost := map[string]sessionAuthHeader{}
	for _, h := range headers {
		byHost[h.Origin] = h
	}
	for _, host := range []string{"127.0.0.1", "app.example.test"} {
		h, ok := byHost[host]
		if !ok {
			t.Fatalf("no header for host %q: %+v", host, headers)
		}
		if !h.HostOnly {
			t.Fatalf("%s: a cookie token must be host-scoped, not exact-origin", host)
		}
		if h.Value != "Bearer "+jwt {
			t.Fatalf("%s: value = %q, want Bearer %s", host, h.Value, jwt)
		}
	}
}

func TestScopedEngineAppliesCookieJWTToItsHost(t *testing.T) {
	seen := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	jwt := "aaaaa.bbbbb.ccccc"
	headers := sessionAuthHeaders(writeAuthStateWithCookies(t, []any{
		map[string]any{"name": "token", "value": jwt, "domain": "127.0.0.1", "path": "/"},
	}, []any{}))
	if len(headers) != 1 {
		t.Fatalf("headers = %+v, want one cookie fallback", headers)
	}

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders(headers)
	if _, err := eng.Do(t.Context(), httpengine.GET(target.URL+"/api/whoami")); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "Bearer "+jwt {
		t.Fatalf("Authorization = %q, want the cookie's bearer token", got)
	}
}

func TestScopedEnginePrefersOriginTokenOverCookieFallback(t *testing.T) {
	seen := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: target.URL, Value: "Bearer from-origin"},
		{Origin: "127.0.0.1", Value: "Bearer from-cookie", HostOnly: true},
	})
	if _, err := eng.Do(t.Context(), httpengine.GET(target.URL+"/api/whoami")); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "Bearer from-origin" {
		t.Fatalf("Authorization = %q, want the exact-origin token to win", got)
	}
}

func TestSessionBearerForNeverCrossesHosts(t *testing.T) {
	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: "app.example.test", Value: "Bearer from-cookie", HostOnly: true},
	})
	if got := eng.sessionBearerFor("https://app.example.test/api/me"); got != "Bearer from-cookie" {
		t.Fatalf("same-host token = %q, want the cookie fallback", got)
	}
	// A trailing-dot or subdomain difference is a different host for a
	// host-only cookie: the token must not leak.
	for _, u := range []string{
		"https://shop.example.test/api/me",
		"https://evil-app.example.test/api/me",
		"https://app.example.test.evil.test/api/me",
	} {
		if got := eng.sessionBearerFor(u); got != "" {
			t.Fatalf("%s: token leaked across hosts: %q", u, got)
		}
	}
}

func TestScopedEngineAppliesAuthOnlyToExactOrigin(t *testing.T) {
	seen := make(chan string, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: target.URL, Value: "Bearer tested"},
	})
	resp, err := eng.Do(t.Context(), httpengine.GET(target.URL+"/api"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	if got := <-seen; got != "Bearer tested" {
		t.Fatalf("Authorization = %q, want Bearer tested", got)
	}

	// Same host but a different scheme is a different origin: no token.
	eng = newScopedEngine(noFollowClient(t), openScope()).WithSessionAuthHeaders([]sessionAuthHeader{
		{Origin: strings.Replace(target.URL, "http://", "https://", 1), Value: "Bearer wrong"},
	})
	// The test server is HTTP, so use its actual origin with a different value
	// would still match; instead exercise the predicate directly.
	if sameURLOrigin(target.URL, strings.Replace(target.URL, "http://", "https://", 1)) {
		t.Fatal("http and https must not be considered the same origin")
	}
}
