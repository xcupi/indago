package discovery_test

// Loopback tests for the default data-mutation guard: a crawler must never
// send a GET to a link that names a destructive/write action, while ordinary
// read routes on the same page keep being discovered and requested. The hit
// counters are the contract — skipping registration alone is not enough,
// because the request itself is what changes the target's data.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

type mutatingSite struct {
	srv        *httptest.Server
	deleteHits atomic.Int64
	updateHits atomic.Int64
	actionHits atomic.Int64
	logoutHits atomic.Int64
	searchHits atomic.Int64
}

// newMutatingSite serves one page that links to destructive actions next to
// ordinary read routes, and counts every request that reaches a destructive
// handler.
func newMutatingSite(t *testing.T) *mutatingSite {
	t.Helper()
	site := &mutatingSite{}
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
		page(`<a href="/account">account</a>
<a href="/blog/post-1">post</a>
<a href="/delete?id=1">delete</a>
<a href="/users/42/update?id=42">update</a>
<a href="/account?action=delete">delete via action</a>
<a href="/search?q=delete">search</a>
<a href="/logout">Logout</a>`)(w, r)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.URL.Query().Get("action"), "delete") {
			site.actionHits.Add(1)
		}
		page("account")(w, r)
	})
	mux.HandleFunc("/blog/post-1", page("post"))
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		site.searchHits.Add(1)
		page("results")(w, r)
	})
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		site.deleteHits.Add(1)
		page("deleted")(w, r)
	})
	mux.HandleFunc("/users/42/update", func(w http.ResponseWriter, r *http.Request) {
		site.updateHits.Add(1)
		page("updated")(w, r)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		site.logoutHits.Add(1)
		page("bye")(w, r)
	})
	site.srv = httptest.NewServer(mux)
	t.Cleanup(site.srv.Close)
	return site
}

// runMutatingDiscovery runs real discovery against the loopback site and
// returns the discovered endpoints plus their methods.
func runMutatingDiscovery(t *testing.T, srv *httptest.Server, authenticated bool, mutate func(*discovery.Config)) (map[string]domain.DiscoverySource, []*domain.Endpoint) {
	t.Helper()
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 3
	if mutate != nil {
		mutate(&cfg)
	}
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()
	p := discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}
	if authenticated {
		p.SessionStatePath = "authenticated-session-state.json"
	}
	res, err := m.Run(context.Background(), p)
	if err != nil {
		t.Fatalf("run: %v (errors: %v)", err, res.Errors)
	}
	eps, err := st.Endpoints().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	return endpointURLs(t, st, scanID), eps
}

// Default (anonymous) discovery must not GET destructive links, and the guard
// must not starve the crawl of ordinary read routes or of a query that merely
// searches for the word "delete".
func TestDiscoverySkipsDestructiveGETLinksByDefault(t *testing.T) {
	site := newMutatingSite(t)
	eps, _ := runMutatingDiscovery(t, site.srv, false, nil)

	if got := site.deleteHits.Load(); got != 0 {
		t.Fatalf("default discovery requested /delete?id=1 %d time(s)", got)
	}
	if got := site.updateHits.Load(); got != 0 {
		t.Fatalf("default discovery requested /users/42/update %d time(s)", got)
	}
	if got := site.actionHits.Load(); got != 0 {
		t.Fatalf("default discovery requested ?action=delete %d time(s)", got)
	}

	// Controls: reads stay reachable, including ?q=delete which is data, not
	// an action.
	if site.searchHits.Load() == 0 {
		t.Fatal("control: the crawler no longer follows an ordinary search link")
	}
	for _, want := range []string{"/account", "/blog/post-1", "/search"} {
		if !hasSuffixKey(eps, want) {
			t.Errorf("expected read route %q to still be discovered; have %v", want, keys(eps))
		}
	}
	for _, banned := range []string{"/delete", "/users/42/update", "action=delete"} {
		if hasSuffixKey(eps, banned) {
			t.Errorf("destructive URL %q was registered as a test target", banned)
		}
	}
}

// On an authenticated scan the session-termination guard and the
// data-mutation guard apply together: delete, update and logout links are all
// left unrequested, while the page's read links are still crawled.
func TestAuthenticatedDiscoverySkipsDestructiveAndLogoutLinks(t *testing.T) {
	site := newMutatingSite(t)
	eps, _ := runMutatingDiscovery(t, site.srv, true, nil)

	if got := site.deleteHits.Load(); got != 0 {
		t.Fatalf("authenticated discovery requested /delete?id=1 %d time(s)", got)
	}
	if got := site.updateHits.Load(); got != 0 {
		t.Fatalf("authenticated discovery requested /users/42/update %d time(s)", got)
	}
	if got := site.actionHits.Load(); got != 0 {
		t.Fatalf("authenticated discovery requested ?action=delete %d time(s)", got)
	}
	if got := site.logoutHits.Load(); got != 0 {
		t.Fatalf("authenticated discovery requested /logout %d time(s)", got)
	}
	for _, want := range []string{"/account", "/blog/post-1", "/search"} {
		if !hasSuffixKey(eps, want) {
			t.Errorf("expected read route %q to still be discovered; have %v", want, keys(eps))
		}
	}
	for _, banned := range []string{"/delete", "/users/42/update", "/logout", "action=delete"} {
		if hasSuffixKey(eps, banned) {
			t.Errorf("guarded URL %q was registered as a test target", banned)
		}
	}
}

// Registration is passive and method-aware: a form's POST target on a
// destructive-looking path is kept for the executor's explicit opt-in, while a
// GET form action on such a path is refused. Neither is submitted by
// discovery.
func TestDiscoveryRegistersPOSTFormTargetOnDestructivePathWithoutRequesting(t *testing.T) {
	var deleteHits, destroyHits atomic.Int64
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
		page(`<a href="/account">account</a>
<form action="/delete" method="post"><input name="id"></form>
<form action="/destroy" method="get"><input name="id"></form>`)(w, r)
	})
	mux.HandleFunc("/account", page("account"))
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		deleteHits.Add(1)
		page("deleted")(w, r)
	})
	mux.HandleFunc("/destroy", func(w http.ResponseWriter, r *http.Request) {
		destroyHits.Add(1)
		page("destroyed")(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, eps := runMutatingDiscovery(t, srv, false, nil)
	if got := deleteHits.Load(); got != 0 {
		t.Fatalf("discovery requested a form target %d time(s)", got)
	}
	if got := destroyHits.Load(); got != 0 {
		t.Fatalf("discovery requested a destructive GET form action %d time(s)", got)
	}
	var postDelete bool
	for _, ep := range eps {
		if strings.Contains(ep.URL, "/destroy") {
			t.Errorf("GET form action on a destructive path was registered: %+v", ep)
		}
		if strings.Contains(ep.URL, "/delete") && ep.Method == domain.MethodPOST {
			postDelete = true
		}
	}
	if !postDelete {
		t.Fatalf("POST form target /delete was not registered for the executor's opt-in; endpoints=%v", keys(endpointURLsOf(eps)))
	}
}

// Content discovery probes with a GET before registering anything; the same
// guard applies to those requests.
func TestContentDiscoveryProbesSkipDestructiveWordlistPaths(t *testing.T) {
	site := newMutatingSite(t)
	eps, _ := runMutatingDiscovery(t, site.srv, false, func(c *discovery.Config) {
		c.Wordlist = []string{"delete", "update", "account"}
	})
	if got := site.deleteHits.Load(); got != 0 {
		t.Fatalf("content discovery probed /delete %d time(s)", got)
	}
	if got := site.updateHits.Load(); got != 0 {
		t.Fatalf("content discovery probed /update %d time(s)", got)
	}
	if !hasSuffixKey(eps, "/account") {
		t.Fatalf("control: content discovery stopped probing ordinary paths; have %v", keys(eps))
	}
}

// The sink-level contract, without a crawler: a read navigation to a
// destructive action is refused on an anonymous scan, a POST form target is
// still registered, and an operator-provided seed is explicit intent.
func TestCollectorAddEndpointGuardsReadMethodsOnly(t *testing.T) {
	c, _, _, _ := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/delete?id=1", Method: domain.MethodGET, Source: domain.SourceCrawler,
	})
	if err != nil || id != "" {
		t.Fatalf("anonymous crawler GET /delete: id=%q err=%v, want a silent skip", id, err)
	}

	id, err = c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/delete?id=1", Method: domain.MethodPOST, Source: domain.SourceForm,
	})
	if err != nil || id == "" {
		t.Fatalf("POST form target should stay registered for the executor's opt-in: id=%q err=%v", id, err)
	}

	id, err = c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/delete?id=1", Method: domain.MethodGET, Source: domain.SourceUserProvided,
	})
	if err != nil || id == "" {
		t.Fatalf("an explicit operator seed must still be registered: id=%q err=%v", id, err)
	}
}

// endpointURLsOf is a small test-side view over endpoints for failure messages.
func endpointURLsOf(eps []*domain.Endpoint) map[string]domain.DiscoverySource {
	out := make(map[string]domain.DiscoverySource, len(eps))
	for _, ep := range eps {
		out[ep.URL] = ep.Source
	}
	return out
}
