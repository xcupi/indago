package scan

// Cookie-continuity scope tests: the ephemeral replay set a page-disclosure
// probe may carry must obey host/domain, path, Secure, expiry and — stricter
// than RFC 6265 cookie scope — same-origin rules. Nothing here is about the
// scan's authenticated session, which has its own, separate path.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func continuityNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

func continuityHeader(values ...string) http.Header {
	return http.Header{"Set-Cookie": values}
}

func equalNames(got []string, want ...string) bool {
	sort.Strings(want)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestContinuityCookiesObeyBrowserScope is the required lower-level proof that
// replayed response cookies keep normal browser scope: no path leak, no Secure
// downgrade, no expired cookie, no partitioned cookie, and a Domain attribute
// that never covers the host that set it is refused outright.
func TestContinuityCookiesObeyBrowserScope(t *testing.T) {
	const app = "http://app.example.test"
	tests := []struct {
		name        string
		responseURL string
		setCookie   []string
		targetURL   string
		want        []string
	}{
		{
			name:        "host-only cookie reaches a deeper path",
			responseURL: app + "/",
			setCookie:   []string{"sid=v"},
			targetURL:   app + "/admin-abc",
			want:        []string{"sid"},
		},
		{
			name:        "default path keeps a subdirectory cookie out of /admin",
			responseURL: app + "/account/login",
			setCookie:   []string{"sid=v"},
			targetURL:   app + "/admin-abc",
			want:        nil,
		},
		{
			name:        "default path still reaches its own subtree",
			responseURL: app + "/account/login",
			setCookie:   []string{"sid=v"},
			targetURL:   app + "/account/profile",
			want:        []string{"sid"},
		},
		{
			name:        "explicit Path covers its subtree",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Path=/admin"},
			targetURL:   app + "/admin/x",
			want:        []string{"sid"},
		},
		{
			name:        "explicit Path excludes other paths",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Path=/admin"},
			targetURL:   app + "/other",
			want:        nil,
		},
		{
			name:        "Secure cookie is sent over https",
			responseURL: "https://app.example.test/",
			setCookie:   []string{"sid=v; Secure"},
			targetURL:   "https://app.example.test/admin",
			want:        []string{"sid"},
		},
		{
			name:        "Secure cookie is never downgraded to http",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Secure"},
			targetURL:   app + "/admin",
			want:        nil,
		},
		{
			name:        "Max-Age=0 deletes rather than replays",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Max-Age=0"},
			targetURL:   app + "/admin",
			want:        nil,
		},
		{
			name:        "past Expires is not replayed",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Expires=Thu, 01 Jan 1970 00:00:00 GMT"},
			targetURL:   app + "/admin",
			want:        nil,
		},
		{
			name:        "future Max-Age is replayed",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Max-Age=3600"},
			targetURL:   app + "/admin",
			want:        []string{"sid"},
		},
		{
			name:        "partitioned cookie has no raw-HTTP equivalent",
			responseURL: "https://app.example.test/",
			setCookie:   []string{"sid=v; Secure; Partitioned"},
			targetURL:   "https://app.example.test/admin",
			want:        nil,
		},
		{
			name:        "Domain attribute without a leading dot still covers the host",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Domain=example.test"},
			targetURL:   app + "/admin-abc",
			want:        []string{"sid"},
		},
		{
			name:        "Domain attribute naming an IP host is replayed host-only",
			responseURL: "http://127.0.0.1/",
			setCookie:   []string{"sid=v; Domain=127.0.0.1"},
			targetURL:   "http://127.0.0.1/admin",
			want:        []string{"sid"},
		},
		{
			name:        "Domain attribute for a foreign domain is refused",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Domain=evil.test"},
			targetURL:   app + "/admin",
			want:        nil,
		},
		{
			name:        "each cookie is scoped on its own",
			responseURL: app + "/",
			setCookie:   []string{"sid=v; Path=/", "pref=x; Path=/prefs"},
			targetURL:   app + "/admin",
			want:        []string{"sid"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := continuityNames(continuityCookies(tc.responseURL, continuityHeader(tc.setCookie...), tc.targetURL))
			if !equalNames(got, tc.want...) {
				t.Fatalf("cookies for %s from %s = %v, want %v", tc.targetURL, tc.responseURL, got, tc.want)
			}
		})
	}
}

// TestContinuityCookiesNeverCrossOrigins is the required cross-origin proof:
// even a Domain attribute that WOULD reach a sibling host is refused, because
// the replay set never leaves the origin that issued it.
func TestContinuityCookiesNeverCrossOrigins(t *testing.T) {
	const set = "sid=v; Domain=.example.test"
	tests := []struct {
		name        string
		responseURL string
		targetURL   string
	}{
		{"sibling host", "http://app.example.test/", "http://admin.example.test/admin"},
		{"other port", "http://app.example.test:80/", "http://app.example.test:81/admin"},
		{"other scheme", "https://app.example.test/", "http://app.example.test/admin"},
		{"unrelated host", "http://app.example.test/", "http://evil.test/admin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := continuityCookies(tc.responseURL, continuityHeader(set), tc.targetURL)
			if len(got) != 0 {
				t.Fatalf("cookie issued by %s was replayed to %s: %+v", tc.responseURL, tc.targetURL, got)
			}
		})
	}
	// ...while the same Domain cookie IS usable on the origin that set it, so
	// the refusals above are about the origin boundary, not a blanket rejection.
	got := continuityCookies("http://app.example.test/", continuityHeader(set), "http://app.example.test/admin")
	if len(got) != 1 || got[0].Name != "sid" {
		t.Fatalf("same-origin domain cookie = %+v, want the sid cookie", got)
	}
}

// TestContinuityCookiesAreBounded: the replay set is a bounded probe input, not
// a browser cookie store. A response that sets dozens of cookies cannot make
// the follow-up probe carry all of them.
func TestContinuityCookiesAreBounded(t *testing.T) {
	const app = "http://app.example.test"
	set := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		set = append(set, fmt.Sprintf("c%02d=v; Path=/", i))
	}
	got := continuityCookies(app+"/", continuityHeader(set...), app+"/admin")
	if len(got) != maxContinuityCookies {
		t.Fatalf("replay set = %d cookies, want the %d-cookie cap", len(got), maxContinuityCookies)
	}
	if got[0].Name != "c00" || got[len(got)-1].Name != fmt.Sprintf("c%02d", maxContinuityCookies-1) {
		t.Fatalf("replay set must be the first %d cookies in response order, got %s..%s",
			maxContinuityCookies, got[0].Name, got[len(got)-1].Name)
	}
}

// TestScopedEngineJarlessRequestSendsOnlyItsOwnCookies proves the isolation a
// continuity probe relies on: no session cookie, no jar content, nothing from a
// previous response — and the issued cookie is not stored for later requests
// (not by this scan, not by another engine sharing the same client).
func TestScopedEngineJarlessRequestSendsOnlyItsOwnCookies(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		switch r.URL.Path {
		case "/warm":
			http.SetCookie(w, &http.Cookie{Name: "jar", Value: "j1", Path: "/"})
		case "/probe":
			http.SetCookie(w, &http.Cookie{Name: "from-probe", Value: "p1", Path: "/"})
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := noFollowClient(t) // shared by both engines, as in production
	scope := openScope()
	session := newScopedEngine(client, scope).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: "session", Domain: "127.0.0.1", Path: "/"},
	})
	if _, err := session.Do(context.Background(), httpengine.GET(srv.URL+"/warm")); err != nil {
		t.Fatalf("warm: %v", err)
	}

	probe := httpengine.GET(srv.URL + "/probe")
	probe.Jarless = true
	probe.Cookies = []*http.Cookie{{Name: "anon", Value: "issued", Domain: "127.0.0.1", Path: "/"}}
	if _, err := session.Do(context.Background(), probe); err != nil {
		t.Fatalf("jarless probe: %v", err)
	}
	if got := seen["/probe"]; got != "anon=issued" {
		t.Fatalf("jarless request carried %q, want exactly the supplied cookie", got)
	}

	// The issued cookie must not have been stored anywhere: an ordinary request
	// afterwards still sees only the session cookie plus the jar.
	if _, err := session.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatalf("ordinary request: %v", err)
	}
	ordinary := seen["/probe"]
	if strings.Contains(ordinary, "anon=issued") {
		t.Fatalf("jarless cookie was persisted into later request state: %q", ordinary)
	}
	if !strings.Contains(ordinary, "sid=session") {
		t.Fatalf("ordinary request lost its session cookie: %q", ordinary)
	}

	// Another scan's engine (same underlying client) never sees it either.
	other := newScopedEngine(client, scope)
	if _, err := other.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatalf("other scan request: %v", err)
	}
	if got := seen["/probe"]; strings.Contains(got, "anon=issued") {
		t.Fatalf("another engine inherited the issued cookie: %q", got)
	}
}

// TestScopedEngineJarlessCookieStopsAtAnOriginBoundary proves the replay set
// follows a same-origin redirect but is dropped the moment a hop leaves the
// origin that issued it (a different port is a different origin).
func TestScopedEngineJarlessCookieStopsAtAnOriginBoundary(t *testing.T) {
	var mu sync.Mutex
	cookieAtLanding := "unset"
	landing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookieAtLanding = r.Header.Get("Cookie")
		mu.Unlock()
		_, _ = io.WriteString(w, "landed")
	}))
	defer landing.Close()

	var cookieAtSameOrigin string
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hop":
			http.Redirect(w, r, "/landing", http.StatusFound)
		default:
			mu.Lock()
			cookieAtSameOrigin = r.Header.Get("Cookie")
			mu.Unlock()
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer same.Close()

	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, landing.URL+"/landed", http.StatusFound)
	}))
	defer crossOrigin.Close()

	eng := newScopedEngine(noFollowClient(t), openScope())
	run := func(start string) {
		req := httpengine.GET(start)
		req.Jarless = true
		req.Cookies = []*http.Cookie{{Name: "anon", Value: "issued", Domain: "127.0.0.1", Path: "/"}}
		if _, err := eng.Do(context.Background(), req); err != nil {
			t.Fatalf("do %s: %v", start, err)
		}
	}

	run(same.URL + "/hop")
	if cookieAtSameOrigin != "anon=issued" {
		t.Fatalf("same-origin redirect hop carried %q, want the issued cookie", cookieAtSameOrigin)
	}

	run(crossOrigin.URL + "/start")
	mu.Lock()
	defer mu.Unlock()
	if cookieAtLanding != "" {
		t.Fatalf("cross-origin redirect hop received %q, want no cookie", cookieAtLanding)
	}
}

// TestScopedEngineNoJarKeepsExplicitSessionAndHidesTheJar proves the two halves
// a jar-isolated disclosure fetch needs: the scan's EXPLICIT saved session
// cookies are still attached (an authenticated page must stay fetchable), while
// the shared cookie jar contributes nothing and receives nothing. This is what
// separates NoJar from Jarless, which deliberately excludes the session too.
func TestScopedEngineNoJarKeepsExplicitSessionAndHidesTheJar(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		switch r.URL.Path {
		case "/warm":
			http.SetCookie(w, &http.Cookie{Name: "jar", Value: "j1", Path: "/"})
		case "/probe":
			http.SetCookie(w, &http.Cookie{Name: "issued", Value: "job-local", Path: "/"})
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := noFollowClient(t) // shared by every engine, as in production
	eng := newScopedEngine(client, openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: "session", Domain: "127.0.0.1", Path: "/"},
	})
	if _, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/warm")); err != nil {
		t.Fatalf("warm: %v", err)
	}

	probe := httpengine.GET(srv.URL + "/probe")
	probe.NoJar = true
	if _, err := eng.Do(context.Background(), probe); err != nil {
		t.Fatalf("no-jar probe: %v", err)
	}
	mu.Lock()
	got := seen["/probe"]
	mu.Unlock()
	if strings.Contains(got, "jar=j1") {
		t.Fatalf("NoJar request inherited the shared jar: %q", got)
	}
	if !strings.Contains(got, "sid=session") {
		t.Fatalf("NoJar request lost the scan's explicit session cookie: %q", got)
	}

	// The probe's own Set-Cookie stays job-local: an ordinary request after it
	// sees the jar/session state, never the issued cookie.
	mu.Lock()
	delete(seen, "/probe")
	mu.Unlock()
	if _, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatalf("ordinary request: %v", err)
	}
	mu.Lock()
	ordinary := seen["/probe"]
	mu.Unlock()
	if strings.Contains(ordinary, "issued=job-local") {
		t.Fatalf("NoJar response cookie was stored in the shared jar: %q", ordinary)
	}
	if !strings.Contains(ordinary, "sid=session") || !strings.Contains(ordinary, "jar=j1") {
		t.Fatalf("ordinary request lost its normal session/jar state: %q", ordinary)
	}
}
