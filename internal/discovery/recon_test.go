package discovery_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// countingEngine counts every request the recon source sends, which is what
// the level and budget contracts are stated in.
type countingEngine struct {
	inner httpengine.Engine
	n     atomic.Int64
}

func (e *countingEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	e.n.Add(1)
	return e.inner.Do(ctx, req)
}

// recordingSink records candidates without persisting them (there is no scan
// here), so tests assert on exactly what recon proposed.
type recordingSink struct {
	mu     sync.Mutex
	eps    []discovery.EndpointCandidate
	params []discovery.ParamCandidate
}

func (s *recordingSink) AddEndpoint(_ context.Context, ep discovery.EndpointCandidate) (domain.ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eps = append(s.eps, ep)
	return domain.NewID(), nil
}

func (s *recordingSink) AddParameter(_ context.Context, p discovery.ParamCandidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = append(s.params, p)
	return nil
}

func (s *recordingSink) endpointURLs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.eps))
	for _, ep := range s.eps {
		out = append(out, ep.URL)
	}
	return out
}

// runRecon runs the content source once against srv with the given config.
func runRecon(t *testing.T, srv *httptest.Server, cfg discovery.Config) (*recordingSink, int64) {
	t.Helper()
	sink := &recordingSink{}
	eng := &countingEngine{inner: httpengine.NewDefault()}
	info, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatalf("normalize seed: %v", err)
	}
	scope := domain.Scope{IncludeHosts: []string{info.Host}}
	src := discovery.NewContentSource(eng, cfg)
	if err := src.Run(context.Background(), discovery.Input{SeedURLs: []string{srv.URL}, Scope: scope}, sink); err != nil {
		t.Fatalf("recon run: %v", err)
	}
	return sink, eng.n.Load()
}

// A default scan (ReconLevel zero value == off) must send nothing at all.
func TestReconLevelOffSendsNoRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	if cfg.ReconLevel != discovery.ReconOff {
		t.Fatalf("default recon level = %q, want off", cfg.ReconLevel)
	}
	sink, n := runRecon(t, srv, cfg)
	if n != 0 || hits.Load() != 0 {
		t.Fatalf("off level sent %d request(s) (fixture saw %d), want 0", n, hits.Load())
	}
	if len(sink.eps) != 0 {
		t.Fatalf("off level recorded %d endpoint(s)", len(sink.eps))
	}
}

// A site that answers 200 for EVERY path must yield no endpoints: without
// soft-404 calibration every word in the list would look like a real page.
func TestReconWildcardSiteRecordsNoEndpoints(t *testing.T) {
	for _, echo := range []bool{false, true} {
		t.Run(fmt.Sprintf("echo=%v", echo), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				body := "<html><body><h1>Nothing to see here</h1></body></html>"
				if echo {
					// Wildcard pages commonly echo the requested path; the
					// calibration must still recognise them as the same page.
					body = "<html><body><h1>Nothing to see here: " + r.URL.Path + "</h1></body></html>"
				}
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()

			cfg := discovery.DefaultConfig()
			cfg.ReconLevel = discovery.ReconSafe
			sink, n := runRecon(t, srv, cfg)
			if n < 10 {
				t.Fatalf("only %d request(s) sent: the wordlist was not probed at all", n)
			}
			if urls := sink.endpointURLs(); len(urls) != 0 {
				t.Fatalf("wildcard site produced endpoints: %v", urls)
			}
		})
	}
}

// Parameter mining must keep only the name whose response actually changed.
func TestReconParamMiningRecordsOnlyChangedName(t *testing.T) {
	const panel = "<div id=\"debug\">debug panel enabled</div>" + // ~40 bytes
		"debug-output-line debug-output-line debug-output-line debug-output-line " +
		"debug-output-line debug-output-line debug-output-line debug-output-line"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		body := "<html><body>home</body></html>"
		if _, ok := r.URL.Query()["debug"]; ok {
			body += panel
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	cfg.Wordlist = []string{"not-a-real-path"} // keep the path phase tiny
	cfg.ParamWordlist = []string{"debug", "nope"}

	sink, _ := runRecon(t, srv, cfg)
	if len(sink.params) != 1 {
		t.Fatalf("recorded %d parameter(s) %v, want only debug", len(sink.params), sink.params)
	}
	p := sink.params[0]
	if p.Name != "debug" {
		t.Fatalf("recorded parameter %q, want debug", p.Name)
	}
	if p.Source != domain.SourceParamDiscovery {
		t.Fatalf("source = %s, want param_discovery", p.Source)
	}
	if p.Provenance == nil || p.Provenance.List != "params" || p.Provenance.Level != discovery.ReconStandard {
		t.Fatalf("provenance = %+v, want {params standard}", p.Provenance)
	}
}

// A page that changes on every request (CSRF token, live counter) cannot be
// used as a baseline: mining it would report every name as a hit.
func TestReconParamMiningSkipsUnstableBaseline(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>nonce=%d</body></html>", n.Add(1))
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	cfg.Wordlist = []string{"not-a-real-path"}
	cfg.ParamWordlist = []string{"debug", "nope"}

	sink, _ := runRecon(t, srv, cfg)
	if len(sink.params) != 0 {
		t.Fatalf("unstable baseline produced parameters: %v", sink.params)
	}
}

// Standard level applies the extension probes to a discovered file-like path,
// and both endpoints carry which list produced them.
func TestReconExtensionsRecordProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"openapi":"3.0.0","paths":{}}`)
		case "/swagger.json.bak":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "backup copy of the api description: "+strings.Repeat("b", 64))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	cfg.Wordlist = []string{"swagger.json"}

	sink, _ := runRecon(t, srv, cfg)
	got := map[string]*discovery.ReconProvenance{}
	for _, ep := range sink.eps {
		got[ep.URL] = ep.Provenance
	}
	base := srv.URL + "/swagger.json"
	backup := srv.URL + "/swagger.json.bak"
	if got[base] == nil || got[base].List != "paths" {
		t.Fatalf("provenance for %s = %+v, want list paths", base, got[base])
	}
	if got[backup] == nil {
		t.Fatalf("extension probe endpoint %s was not recorded (got %v)", backup, sink.endpointURLs())
	}
	if got[backup].List != "paths:extensions" || got[backup].Level != discovery.ReconStandard {
		t.Fatalf("provenance for %s = %+v, want paths:extensions/standard", backup, got[backup])
	}
}

// Aggressive level probes one level deeper under a discovered directory.
func TestReconAggressiveRecursesOneLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>admin index</body></html>")
		case "/admin/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>admin login form</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconAggressive
	cfg.Wordlist = []string{"admin/"}

	sink, _ := runRecon(t, srv, cfg)
	want := srv.URL + "/admin/login"
	for _, ep := range sink.eps {
		if ep.URL == want {
			if ep.Provenance == nil || ep.Provenance.List != "paths:recursive" {
				t.Fatalf("provenance = %+v, want paths:recursive", ep.Provenance)
			}
			return
		}
	}
	t.Fatalf("recursive probe did not find %s; recorded %v", want, sink.endpointURLs())
}

// The per-scan request cap is hard, regardless of how much work the level
// would otherwise do.
func TestReconRequestCapIsHonoured(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconAggressive
	cfg.MaxReconRequests = 10
	cfg.Wordlist = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t"}

	_, n := runRecon(t, srv, cfg)
	if n != 10 || hits.Load() != 10 {
		t.Fatalf("recon sent %d request(s) (fixture saw %d) with a cap of 10", n, hits.Load())
	}
}

func TestParseReconLevel(t *testing.T) {
	cases := map[string]discovery.ReconLevel{
		"":            discovery.ReconOff,
		"off":         discovery.ReconOff,
		"SAFE":        discovery.ReconSafe,
		"standard":    discovery.ReconStandard,
		" Aggressive": discovery.ReconAggressive,
	}
	for in, want := range cases {
		got, err := discovery.ParseReconLevel(in)
		if err != nil || got != want {
			t.Fatalf("ParseReconLevel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := discovery.ParseReconLevel("loud"); err == nil {
		t.Fatal("unknown level must be an error")
	}
}
