package discovery_test

// QA bug 2: a GraphQL target scanned with a conservative profile discovered
// nothing at /graphql, so the GraphQL engine was never handed an endpoint and
// never ran — even though the engine was enabled. A GraphQL API is one POST URL
// that no link points at, which makes the well-known probe the ONLY discovery
// path for it on a scan without wordlist recon.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// knownEndpointSink implements the optional endpointLookup capability, standing
// in for a Collector that already registered an endpoint.
type knownEndpointSink struct {
	*recordingSink
	known []string
}

func (s *knownEndpointSink) AnyEndpoint(match func(rawURL string) bool) bool {
	for _, u := range s.known {
		if match(u) {
			return true
		}
	}
	return false
}

// probeRecorder records the requests a source actually sends.
type probeRecorder struct {
	mu   sync.Mutex
	reqs []string
}

func (p *probeRecorder) add(r *http.Request) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r.Method+" "+r.URL.RequestURI())
	p.mu.Unlock()
}

func (p *probeRecorder) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.reqs...)
}

// graphQLServer serves a GraphQL API at /graphql (the DVGA shape) and 404
// everywhere else, recording every request it sees.
func graphQLServer(t *testing.T) (*httptest.Server, *probeRecorder) {
	t.Helper()
	rec := &probeRecorder{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		w.WriteHeader(http.StatusNotFound)
	})
	return srv, rec
}

// The probe must run at EVERY recon level — including off, which is the
// conservative profile's default — with exactly one request below standard, and
// it must register the endpoint so the GraphQL engine has a target.
func TestWellKnownProbesGraphQLLightlyBelowStandard(t *testing.T) {
	for _, level := range []discovery.ReconLevel{discovery.ReconOff, discovery.ReconSafe} {
		t.Run(string(level), func(t *testing.T) {
			srv, rec := graphQLServer(t)
			defer srv.Close()

			cfg := discovery.DefaultConfig()
			cfg.ReconLevel = level
			sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

			got := sink.endpointURLs()
			if len(got) != 1 || !strings.HasSuffix(got[0], "/graphql") {
				t.Fatalf("endpoints = %v, want exactly the /graphql endpoint", got)
			}
			if sink.eps[0].Method != domain.MethodGET {
				t.Fatalf("registered method = %q, want GET (the request that proved the path)", sink.eps[0].Method)
			}
			probes := rec.snapshot()
			if len(probes) != 1 {
				t.Fatalf("level %q sent %d request(s) %v, want exactly one /graphql probe", level, len(probes), probes)
			}
			if want := "GET /graphql?query=%7B__typename%7D"; probes[0] != want {
				t.Fatalf("probe = %q, want %q (a read-only {__typename} query)", probes[0], want)
			}
		})
	}
}

// At standard the full conventional path set still runs (opt-in recon keeps its
// previous coverage) — only the below-standard path is the single lightweight one.
func TestWellKnownProbesAllGraphQLPathsAtStandard(t *testing.T) {
	var mu sync.Mutex
	var requested []string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// /v1/graphql is the only path that speaks GraphQL here.
	mux.HandleFunc("/v1/graphql", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	})

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	got := sink.endpointURLs()
	if len(got) != 1 || !strings.HasSuffix(got[0], "/v1/graphql") {
		t.Fatalf("endpoints = %v, want the /v1/graphql endpoint", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"} {
		probed := false
		for _, p := range requested {
			if p == want {
				probed = true
				break
			}
		}
		if !probed {
			t.Fatalf("standard level did not probe %s (got %v)", want, requested)
		}
	}
}

// An endpoint the scan already knows (a crawled link, an observed XHR, a spec)
// makes the probe redundant: it must not be sent again.
func TestWellKnownSkipsGraphQLProbeWhenEndpointAlreadyKnown(t *testing.T) {
	srv, rec := graphQLServer(t)
	defer srv.Close()

	seedInfo, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatalf("normalize seed: %v", err)
	}
	sink := &knownEndpointSink{
		recordingSink: &recordingSink{},
		known:         []string{seedInfo.Scheme + "://" + seedInfo.HostPort + "/graphql"},
	}
	cfg := discovery.DefaultConfig() // ReconOff: the light probe is the whole run
	src := discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg)
	if err := src.Run(context.Background(), discovery.Input{
		SeedURLs: []string{srv.URL},
		Scope:    domain.Scope{IncludeHosts: []string{seedInfo.Host}},
	}, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if probes := rec.snapshot(); len(probes) != 0 {
		t.Fatalf("probe re-sent for an endpoint the scan already knew: %v", probes)
	}
	if got := sink.endpointURLs(); len(got) != 0 {
		t.Fatalf("source re-registered %v", got)
	}
}

// Skipping the GraphQL engine (domain.ScanConfig.SkipGraphQL) must also skip the
// discovery probe: there would be nothing to test it with.
func TestWellKnownGraphQLProbeHonoursSkipFlag(t *testing.T) {
	srv, rec := graphQLServer(t)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.SkipGraphQLProbe = true
	sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	if probes := rec.snapshot(); len(probes) != 0 {
		t.Fatalf("probe sent despite SkipGraphQLProbe: %v", probes)
	}
	if got := sink.endpointURLs(); len(got) != 0 {
		t.Fatalf("endpoint registered despite SkipGraphQLProbe: %v", got)
	}
}

// Scope is checked BEFORE the probe is sent, so a seed whose host is outside the
// scan's scope produces no traffic at all (the source must not rely on the
// engine to refuse it, because a test/source may be handed a bare engine).
func TestWellKnownGraphQLProbeHonoursScope(t *testing.T) {
	srv, rec := graphQLServer(t)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	src := discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg)
	if err := src.Run(context.Background(), discovery.Input{
		SeedURLs: []string{srv.URL},
		Scope:    domain.Scope{IncludeHosts: []string{"in-scope.example.test"}},
	}, &recordingSink{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if probes := rec.snapshot(); len(probes) != 0 {
		t.Fatalf("probed an out-of-scope origin: %v", probes)
	}
}
