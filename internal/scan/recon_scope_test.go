package scan

// Recon scope test: wordlist probing goes through the same scope-enforcing
// engine as every other discovery request, so a probe that redirects
// out-of-scope is neither followed nor recorded. GET/HEAD only.

import (
	"context"
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

// reconScopeSink records the candidates recon proposes.
type reconScopeSink struct {
	mu  sync.Mutex
	eps []discovery.EndpointCandidate
}

func (s *reconScopeSink) AddEndpoint(_ context.Context, ep discovery.EndpointCandidate) (domain.ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eps = append(s.eps, ep)
	return domain.NewID(), nil
}

func (s *reconScopeSink) AddParameter(context.Context, discovery.ParamCandidate) error { return nil }

func TestReconDoesNotFollowOrRecordOutOfScopeRedirect(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		_, _ = w.Write([]byte("out of scope"))
	}))
	defer outside.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			// Different HOSTNAME (localhost vs 127.0.0.1): out of scope even
			// though it is the same machine.
			http.Redirect(w, r, strings.Replace(outside.URL, "127.0.0.1", "localhost", 1)+"/landing", http.StatusFound)
		case "/moved":
			// Positive control: an IN-SCOPE redirect must still be followed,
			// so a pass on /admin cannot be vacuous.
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>in-scope target page</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	info, err := discovery.Normalize(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{IncludeHosts: []string{info.Host}}

	inner, err := httpengine.New(httpengine.Config{FollowRedirects: false})
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	eng := newScopedEngine(inner, scope)

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconSafe
	cfg.Wordlist = []string{"admin", "moved"}
	sink := &reconScopeSink{}
	src := discovery.NewContentSource(eng, cfg)
	if err := src.Run(context.Background(), discovery.Input{SeedURLs: []string{srv.URL}, Scope: scope}, sink); err != nil {
		t.Fatalf("recon run: %v", err)
	}

	if got := outsideHits.Load(); got != 0 {
		t.Fatalf("recon followed an out-of-scope redirect: %d request(s) reached the other origin", got)
	}
	foundInScope := false
	for _, ep := range sink.eps {
		if strings.HasSuffix(ep.URL, "/admin") {
			t.Fatalf("out-of-scope redirect target was recorded as an endpoint: %s", ep.URL)
		}
		if strings.HasSuffix(ep.URL, "/moved") {
			foundInScope = true
		}
	}
	if !foundInScope {
		t.Fatalf("in-scope redirect was not followed/recorded; recorded %v", sink.eps)
	}
}
