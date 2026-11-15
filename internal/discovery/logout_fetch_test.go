package discovery_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// logoutSite serves a page that links to a session-ending endpoint and counts
// how many requests actually reach it. The count is the contract: registering
// or not registering the endpoint is not enough, because the request itself is
// what ends the session.
func logoutSite(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page(`<a href="/account">account</a> <a href="/logout">Logout</a>`)(w, r)
	})
	mux.HandleFunc("/account", page(`<a href="/auth/sign-out">sign out</a><form action="/profile" method="get"><input name="name"></form>`))
	mux.HandleFunc("/profile", page("ok"))
	for _, p := range []string{"/logout", "/auth/sign-out"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			page("bye")(w, r)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func runLogoutDiscovery(t *testing.T, srv *httptest.Server, authenticated bool, seeds []string, wordlist []string) map[string]domain.DiscoverySource {
	t.Helper()
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 3
	cfg.Wordlist = wordlist
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()
	p := discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: seeds}
	if authenticated {
		p.SessionStatePath = "authenticated-session-state.json"
	}
	res, err := m.Run(context.Background(), p)
	if err != nil {
		t.Fatalf("run: %v (errors: %v)", err, res.Errors)
	}
	return endpointURLs(t, st, scanID)
}

func TestAuthenticatedDiscoveryNeverRequestsSessionTerminatingLinks(t *testing.T) {
	srv, hits := logoutSite(t)
	// The wordlist deliberately contains a logout path: content discovery
	// probes candidate paths with a GET before it registers anything.
	eps := runLogoutDiscovery(t, srv, true, []string{srv.URL}, []string{"logout", "profile"})
	if got := hits.Load(); got != 0 {
		t.Fatalf("an authenticated scan sent %d request(s) to a session-terminating endpoint", got)
	}
	// The guard must not starve discovery of everything else.
	for _, want := range []string{"/account", "/profile"} {
		if !hasSuffixKey(eps, want) {
			t.Errorf("expected %q to still be discovered; have %v", want, keys(eps))
		}
	}
	for _, banned := range []string{"/logout", "/auth/sign-out"} {
		if hasSuffixKey(eps, banned) {
			t.Errorf("session-terminating %q was registered on an authenticated scan", banned)
		}
	}
}

func TestOperatorSeedMayStillTargetALogoutEndpoint(t *testing.T) {
	srv, hits := logoutSite(t)
	runLogoutDiscovery(t, srv, true, []string{srv.URL + "/logout"}, nil)
	if hits.Load() == 0 {
		t.Fatal("an explicit operator seed is intent and must still be requested")
	}
}

func TestAnonymousDiscoveryStillFollowsLogoutLinks(t *testing.T) {
	srv, hits := logoutSite(t)
	runLogoutDiscovery(t, srv, false, []string{srv.URL}, nil)
	if hits.Load() == 0 {
		t.Fatal("an anonymous scan has no session to lose and must keep crawling every in-scope link")
	}
}

// A sitemap index is document content, so the nested sitemap URL it lists is
// untrusted: it was requested without any guard or scope check.
func sitemapIndexSite(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>home</p>")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0"?><sitemapindex><sitemap><loc>http://`+r.Host+`/user_logout</loc></sitemap></sitemapindex>`)
	})
	mux.HandleFunc("/user_logout", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0"?><urlset></urlset>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestAuthenticatedSitemapIndexNeverRequestsSessionTerminatingSitemap(t *testing.T) {
	srv, hits := sitemapIndexSite(t)
	runLogoutDiscovery(t, srv, true, []string{srv.URL}, nil)
	if got := hits.Load(); got != 0 {
		t.Fatalf("a nested sitemap pointing at a session-terminating URL was requested %d time(s) on an authenticated scan", got)
	}
}

func TestAnonymousSitemapIndexStillFollowsNestedSitemaps(t *testing.T) {
	srv, hits := sitemapIndexSite(t)
	runLogoutDiscovery(t, srv, false, []string{srv.URL}, nil)
	if hits.Load() == 0 {
		t.Fatal("control: an anonymous scan must still follow nested sitemaps, otherwise the authenticated test proves nothing")
	}
}

// sessionActionSite serves links whose logout action lives in the query string
// (?action=logout) and in a session-destroy path (/session/end), next to an
// ordinary /account and /blog/out link that must keep being discovered. The
// counters are the contract: the guard must stop the request itself, not just
// the registration.
func sessionActionSite(t *testing.T) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var queryHits, pathHits atomic.Int64
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page(`<a href="/account">account</a> <a href="/account?action=logout">Logout</a> `+
			`<a href="/session/end">end session</a> <a href="/blog/out">blog</a>`)(w, r)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.URL.Query().Get("action"), "logout") {
			queryHits.Add(1)
		}
		page("account")(w, r)
	})
	mux.HandleFunc("/session/end", func(w http.ResponseWriter, r *http.Request) {
		pathHits.Add(1)
		page("bye")(w, r)
	})
	mux.HandleFunc("/blog/out", page("out"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &queryHits, &pathHits
}

func TestAuthenticatedDiscoveryNeverRequestsQueryStringLogout(t *testing.T) {
	srv, queryHits, pathHits := sessionActionSite(t)
	eps := runLogoutDiscovery(t, srv, true, []string{srv.URL}, nil)
	if got := queryHits.Load(); got != 0 {
		t.Fatalf("an authenticated scan followed a ?action=logout link %d time(s)", got)
	}
	if got := pathHits.Load(); got != 0 {
		t.Fatalf("an authenticated scan requested /session/end %d time(s)", got)
	}
	for key := range eps {
		if strings.Contains(key, "action=logout") || strings.Contains(strings.ToLower(key), "/session/end") {
			t.Errorf("session-terminating URL %q was registered on an authenticated scan", key)
		}
	}
	// The guard must not starve discovery: the same page's ordinary links,
	// including one whose path merely contains "out", are still found.
	for _, want := range []string{"/account", "/blog/out"} {
		if !hasSuffixKey(eps, want) {
			t.Errorf("expected %q to still be discovered; have %v", want, keys(eps))
		}
	}
}

func TestAnonymousDiscoveryStillFollowsQueryStringLogout(t *testing.T) {
	srv, queryHits, pathHits := sessionActionSite(t)
	runLogoutDiscovery(t, srv, false, []string{srv.URL}, nil)
	if queryHits.Load() == 0 {
		t.Fatal("control: an anonymous scan has no session to lose and must still follow ?action=logout")
	}
	if pathHits.Load() == 0 {
		t.Fatal("control: an anonymous scan must still request /session/end")
	}
}

// recordingBrowser records every URL Render was asked to load. A logout route
// is never requested as a URL of its own, so the only observable harm is the
// render: the test asserts the route the browser was asked to visit.
type recordingBrowser struct {
	mu       sync.Mutex
	rendered []string
	html     string
}

func (b *recordingBrowser) Render(_ context.Context, rawURL string, _ browser.RenderOptions) (*browser.RenderResult, error) {
	b.mu.Lock()
	b.rendered = append(b.rendered, rawURL)
	b.mu.Unlock()
	return &browser.RenderResult{FinalURL: rawURL, Status: 200, HTML: b.html}, nil
}

func (b *recordingBrowser) Close() error { return nil }

func (b *recordingBrowser) renderedAny(substr string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, u := range b.rendered {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

// spaLogoutSite serves a seed page whose SPA navigation has both a logout route
// and an ordinary one; the browser source renders hash routes it finds there.
func spaLogoutSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<p>app</p><a href="#/logout">Logout</a> <a href="#/profile">Profile</a>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runBrowserDiscovery(t *testing.T, srv *httptest.Server, b browser.Browser, authenticated bool) {
	t.Helper()
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 0 // seeds only: the browser source still renders the seed and its routes
	m, _, _ := newManagerFor(t, cfg, b)
	scanID := domain.NewID()
	p := discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}
	if authenticated {
		p.SessionStatePath = "authenticated-session-state.json"
	}
	if _, err := m.Run(context.Background(), p); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestAuthenticatedDiscoveryNeverRendersLogoutSPARoute(t *testing.T) {
	srv := spaLogoutSite(t)
	b := &recordingBrowser{html: `<a href="#/logout">Logout</a> <a href="#/profile">Profile</a>`}
	runBrowserDiscovery(t, srv, b, true)
	if b.renderedAny("#/logout") {
		t.Fatalf("an authenticated scan rendered the logout SPA route; rendered=%v", b.rendered)
	}
	if !b.renderedAny("#/profile") {
		t.Fatalf("control: the ordinary SPA route was not rendered; rendered=%v", b.rendered)
	}
}

func TestAnonymousDiscoveryStillRendersLogoutSPARoute(t *testing.T) {
	srv := spaLogoutSite(t)
	b := &recordingBrowser{html: `<a href="#/logout">Logout</a> <a href="#/profile">Profile</a>`}
	runBrowserDiscovery(t, srv, b, false)
	if !b.renderedAny("#/logout") {
		t.Fatalf("control: an anonymous scan has no session to lose and must still render #/logout; rendered=%v", b.rendered)
	}
}
