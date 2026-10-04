package discovery_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

// newSite builds a small, linked test site. base is filled after the server
// starts so sitemap/robots can reference absolute URLs.
func newSite(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	html := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		html(w, `<a href="/a">a</a> <a href="/search?q=1">s</a>
			<form action="/find" method="get"><input name="term"></form>
			<form action="/submit" method="post"><input name="body"></form>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		html(w, `<a href="/c">c</a>`)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		html(w, `<form action="/deep" method="get"><input name="deepparam"></form>`)
	})
	for _, p := range []string{"/search", "/find", "/submit", "/deep", "/secret", "/sm-page"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { html(w, "ok") })
	}
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>%s/sm-page</loc></url></urlset>`, base)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nDisallow: /secret\nSitemap: %s/sitemap.xml\n", base)
	})

	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func scopeFor(srv *httptest.Server) domain.Scope {
	info, _ := discovery.Normalize(srv.URL)
	return domain.Scope{IncludeHosts: []string{info.Host}}
}

func newManagerFor(t *testing.T, cfg discovery.Config, b browser.Browser) (*discovery.Manager, *memory.Store, *queue.Memory) {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	reg := discovery.NewRealRegistry(httpengine.NewDefault(), b, cfg)
	m := discovery.NewManager(st, q, reg, cfg, quiet())
	return m, st, q
}

func endpointURLs(t *testing.T, st store.Store, scanID domain.ID) map[string]domain.DiscoverySource {
	t.Helper()
	eps, err := st.Endpoints().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]domain.DiscoverySource{}
	for _, e := range eps {
		out[e.URL] = e.Source
	}
	return out
}

func hasParam(t *testing.T, st store.Store, scanID domain.ID, name string) bool {
	t.Helper()
	params, _ := st.Parameters().ListByScan(context.Background(), scanID)
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestManagerCrawlDiscovers(t *testing.T) {
	srv := newSite(t)
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 2
	m, st, q := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()

	res, err := m.Run(context.Background(), discovery.RunParams{
		ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("run: %v (errors: %v)", err, res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("source errors: %v", res.Errors)
	}

	eps := endpointURLs(t, st, scanID)
	for _, want := range []string{"/a", "/c", "/find", "/submit", "/search", "/deep", "/sm-page", "/secret"} {
		if !hasSuffixKey(eps, want) {
			t.Errorf("expected endpoint %q discovered; have %v", want, keys(eps))
		}
	}

	// Parameters from query strings, GET form, POST form, and a deep form.
	for _, p := range []string{"q", "term", "body", "deepparam"} {
		if !hasParam(t, st, scanID, p) {
			t.Errorf("expected parameter %q discovered", p)
		}
	}

	// Testing can start immediately: jobs were enqueued during discovery.
	stats, _ := q.Stats(context.Background(), scanID)
	if stats.Queued == 0 {
		t.Fatal("expected test jobs enqueued during discovery")
	}
	if res.Jobs == 0 {
		t.Fatal("expected job count > 0")
	}
}

func TestManagerDepthLimit(t *testing.T) {
	srv := newSite(t)

	// Depth 1: /c is seen (on /a) but not fetched, so its form param is missing.
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 1
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()
	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if hasParam(t, st, scanID, "deepparam") {
		t.Fatal("deepparam should NOT be discovered at MaxDepth=1 (/c not fetched)")
	}
	// /c is still emitted as an endpoint (seen as a link on /a).
	if !hasSuffixKey(endpointURLs(t, st, scanID), "/c") {
		t.Fatal("/c should be emitted as an endpoint even if not fetched")
	}

	// Depth 2: /c is fetched, so deepparam appears.
	cfg2 := discovery.DefaultConfig()
	cfg2.MaxDepth = 2
	m2, st2, _ := newManagerFor(t, cfg2, nil)
	scanID2 := domain.NewID()
	if _, err := m2.Run(context.Background(), discovery.RunParams{ScanID: scanID2, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if !hasParam(t, st2, scanID2, "deepparam") {
		t.Fatal("deepparam should be discovered at MaxDepth=2")
	}
}

func TestManagerEndpointLimit(t *testing.T) {
	srv := newSite(t)
	cfg := discovery.DefaultConfig()
	cfg.MaxEndpoints = 3
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()

	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	eps, _ := st.Endpoints().ListByScan(context.Background(), scanID)
	if len(eps) != 3 {
		t.Fatalf("expected endpoints capped at 3, got %d", len(eps))
	}
}

func TestManagerParamWordlist(t *testing.T) {
	srv := newSite(t)
	cfg := discovery.DefaultConfig()
	cfg.MaxDepth = 1
	cfg.ParamWordlist = []string{"id", "debug"}
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()

	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if !hasParam(t, st, scanID, "id") || !hasParam(t, st, scanID, "debug") {
		t.Fatal("param wordlist entries should be registered on discovered endpoints")
	}
	// Provenance of a wordlist param is param-discovery.
	params, _ := st.Parameters().ListByScan(context.Background(), scanID)
	for _, p := range params {
		if p.Name == "debug" && p.Source != domain.SourceParamDiscovery {
			t.Fatalf("wordlist param provenance = %s, want param_discovery", p.Source)
		}
	}
}

// fakeBrowser returns canned network observations.
type fakeBrowser struct{ xhr []browser.NetworkEvent }

func (f fakeBrowser) Render(_ context.Context, url string, _ browser.RenderOptions) (*browser.RenderResult, error) {
	return &browser.RenderResult{FinalURL: url, Status: 200, Network: f.xhr}, nil
}
func (fakeBrowser) Close() error { return nil }

func TestManagerNetworkDiscovery(t *testing.T) {
	srv := newSite(t)
	cfg := discovery.DefaultConfig()
	fb := fakeBrowser{xhr: []browser.NetworkEvent{
		{URL: srv.URL + "/api/data", Method: "GET"},
		{URL: "https://evil.com/exfil", Method: "POST"}, // out of scope
	}}

	// Registry with only the network source to isolate it.
	reg := discovery.NewRegistry()
	reg.Register(discovery.NewNetworkSource(fb, cfg))
	st := memory.New()
	q := queue.NewMemory()
	m := discovery.NewManager(st, q, reg, cfg, quiet())
	scanID := domain.NewID()

	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
	eps := endpointURLs(t, st, scanID)
	if src, ok := eps[srv.URL+"/api/data"]; !ok || src != domain.SourceBrowserNetwork {
		t.Fatalf("expected XHR endpoint discovered via network source: %v", keys(eps))
	}
	if hasSuffixKey(eps, "evil.com/exfil") {
		t.Fatal("out-of-scope XHR endpoint must not be discovered")
	}
}

func TestManagerCancellation(t *testing.T) {
	// A server whose root blocks, so the crawl cannot finish quickly.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	m, _, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := m.Run(ctx, discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("cancellation was not prompt: %s", time.Since(start))
	}
}

func TestManagerPauseResume(t *testing.T) {
	srv := newSite(t)
	cfg := discovery.DefaultConfig()
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()

	m.Pause()
	done := make(chan struct{})
	go func() {
		_, _ = m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}})
		close(done)
	}()

	// While paused, no endpoints should be persisted.
	time.Sleep(150 * time.Millisecond)
	if eps, _ := st.Endpoints().ListByScan(context.Background(), scanID); len(eps) != 0 {
		t.Fatalf("discovery progressed while paused: %d endpoints", len(eps))
	}

	m.Resume()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not complete after resume")
	}
	if eps, _ := st.Endpoints().ListByScan(context.Background(), scanID); len(eps) == 0 {
		t.Fatal("expected endpoints after resume")
	}
}

// --- small helpers ---

func keys(m map[string]domain.DiscoverySource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasSuffixKey(m map[string]domain.DiscoverySource, suffix string) bool {
	for k := range m {
		if strings.Contains(k, suffix) {
			return true
		}
	}
	return false
}
