package discovery_test

// QA bug 1: with a small -max-endpoints budget (-max-endpoints 4 or 5), the
// speculative wordlist probes filled the cap before the crawler registered the
// <form> endpoints it had observed in the seed page's own HTML, so the reachable
// surface (POST /commandi.php, POST /product/stock, …) was never tested.
//
// The rule these tests pin down: guessed endpoints (wordlist paths, archive
// history) may claim at most a quarter of the endpoint cap. Observed endpoints —
// the seed page, the pages and forms the crawler actually sees — can use the
// whole cap, so a speculative probe can never starve them out of it.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// guessed adds one wordlist endpoint, returning the error the source would see.
func guessed(ctx context.Context, c *discovery.Collector, url string) (domain.ID, error) {
	return c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: url, Method: domain.MethodGET, Source: domain.SourceContentDiscovery,
		Provenance: &discovery.ReconProvenance{List: "paths", Level: discovery.ReconSafe},
	})
}

// The Collector itself must refuse to let guessed endpoints take the whole cap:
// the form observed in the crawled page still gets a slot.
func TestCollectorReservesEndpointCapForObservedForms(t *testing.T) {
	cfg := discovery.DefaultConfig()
	cfg.MaxEndpoints = 4
	c, st, _, scanID := newCollector(t, cfg)
	ctx := context.Background()

	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/", Method: domain.MethodGET, Source: domain.SourceUserProvided,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The wordlist source wins the race and probes four directories.
	registered := 0
	for _, p := range []string{"/admin/", "/documents/", "/images/", "/passwords/"} {
		id, err := guessed(ctx, c, "http://example.com"+p)
		if err != nil && !errors.Is(err, discovery.ErrLimitReached) {
			t.Fatalf("%s: unexpected error %v", p, err)
		}
		if id != "" {
			registered++
		}
	}
	if registered != 1 {
		t.Fatalf("%d speculative endpoints registered with a cap of 4, want 1 (a quarter)", registered)
	}

	// The <form> observed in the seed page HTML must still be registered.
	formID, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/commandi.php", Method: domain.MethodPOST, Source: domain.SourceForm,
	})
	if err != nil {
		t.Fatalf("form: %v", err)
	}
	if formID == "" {
		t.Fatal("form endpoint refused: speculative probes exhausted the endpoint budget")
	}
	// ... and so must the second page the crawler saw.
	if id, _ := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/product/stock", Method: domain.MethodPOST, Source: domain.SourceForm,
	}); id == "" {
		t.Fatal("second observed form refused after a single speculative endpoint")
	}
	// The cap itself is still enforced: the budget is now spent.
	if _, err := guessed(ctx, c, "http://example.com/backup/"); !errors.Is(err, discovery.ErrLimitReached) {
		t.Fatalf("guessed endpoint error = %v, want ErrLimitReached", err)
	}

	eps, err := st.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	if len(eps) != 4 {
		t.Fatalf("%d endpoints persisted, want the cap of 4: %v", len(eps), endpointPaths(eps))
	}
	for _, want := range []string{"/", "/commandi.php", "/product/stock"} {
		if !hasEndpointPath(eps, want) {
			t.Fatalf("observed endpoint %s missing from %v", want, endpointPaths(eps))
		}
	}
}

// A resumed scan must not hand the wordlist source a fresh share: the guessed
// share is restored from what is already persisted.
func TestCollectorRestoresSpeculativeShareOnHydrate(t *testing.T) {
	cfg := discovery.DefaultConfig()
	cfg.MaxEndpoints = 8 // quarter share = 2 guessed endpoints
	first, st, q, scanID := newCollector(t, cfg)
	ctx := context.Background()

	for _, u := range []string{"http://example.com/admin/", "http://example.com/documents/"} {
		if _, err := guessed(ctx, first, u); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://example.com/", "http://example.com/login"} {
		if _, err := first.AddEndpoint(ctx, discovery.EndpointCandidate{
			URL: u, Method: domain.MethodGET, Source: domain.SourceCrawler,
		}); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}

	// A restart: a new collector over the same persisted scan.
	second := discovery.NewCollector(st, q, scanID,
		domain.Scope{IncludeHosts: []string{"example.com"}}, false, cfg, quiet())
	if err := second.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if _, err := guessed(ctx, second, "http://example.com/images/"); !errors.Is(err, discovery.ErrLimitReached) {
		t.Fatalf("guessed endpoint after hydrate = %v, want ErrLimitReached (share already spent)", err)
	}
	if id, err := second.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/account", Method: domain.MethodGET, Source: domain.SourceCrawler,
	}); err != nil || id == "" {
		t.Fatalf("observed endpoint refused after hydrate: id=%q err=%v", id, err)
	}
}

// The whole discovery run, in the order QA measured it: the wordlist probes
// answer first (the seed page renders slowly), and the forms observed in that
// page must still be registered.
func TestDiscoveryRegistersCrawledFormsBeforeSpeculativeDirectories(t *testing.T) {
	dirs := []string{"admin/", "documents/", "images/", "passwords/"}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The seed page renders after the wordlist probes have answered, so
		// the speculative source wins the race — exactly the ordering QA saw.
		time.Sleep(250 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>
			<form action="/commandi.php" method="post"><input name="cmd"></form>
			<form action="/product/stock" method="post"><input name="stockApi"></form>
		</body></html>`)
	})
	for _, d := range dirs {
		path := "/" + d
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			// A real-looking page distinct from the 404 calibration baseline.
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body><h1>"+path+"</h1>"+strings.Repeat("x", 300)+"</body></html>")
		})
	}

	seedInfo, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatalf("normalize seed: %v", err)
	}
	cfg := discovery.DefaultConfig()
	cfg.MaxEndpoints = 4
	cfg.MaxDepth = 1
	cfg.Wordlist = dirs // an explicit wordlist runs even at ReconOff

	eng := &countingEngine{inner: httpengine.NewDefault()}
	registry := discovery.NewRegistry()
	registry.Register(discovery.NewSeedSource())
	registry.Register(discovery.NewCrawlSource(eng, cfg))
	registry.Register(discovery.NewContentSource(eng, cfg))

	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{seedInfo.Host}}
	mgr := discovery.NewManager(st, q, registry, cfg, quiet())
	res, err := mgr.Run(context.Background(), discovery.RunParams{
		ScanID: scanID, Scope: scope, SeedURLs: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("discovery run: %v", err)
	}

	eps, err := st.Endpoints().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	for _, want := range []string{"/commandi.php", "/product/stock"} {
		if !hasEndpointPath(eps, want) {
			t.Fatalf("form endpoint %s not registered (cap %d reached with %v); recon tally %v",
				want, cfg.MaxEndpoints, endpointPaths(eps), res.Recon)
		}
	}
	guessedCount := 0
	for _, e := range eps {
		if e.Source == domain.SourceContentDiscovery {
			guessedCount++
		}
	}
	if guessedCount > cfg.MaxEndpoints/4 {
		t.Fatalf("%d speculative endpoints registered, want at most %d", guessedCount, cfg.MaxEndpoints/4)
	}
	if len(eps) > cfg.MaxEndpoints {
		t.Fatalf("%d endpoints persisted, over the cap of %d", len(eps), cfg.MaxEndpoints)
	}
}

func endpointPaths(eps []*domain.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, string(e.Method)+" "+e.URL)
	}
	return out
}

func hasEndpointPath(eps []*domain.Endpoint, path string) bool {
	for _, e := range eps {
		if strings.HasSuffix(e.URL, path) {
			return true
		}
	}
	return false
}
