package discovery_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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
