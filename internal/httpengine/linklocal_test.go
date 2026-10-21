package httpengine_test

// The raw engine refuses to connect to link-local addresses at dial time (cloud
// instance-metadata range). The check runs in net.Dialer.Control, before the
// socket connects, so these tests send no packet to the address they name.
// Documented in docs/scope-semantics.md.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestEngineRefusesLinkLocalDestinations(t *testing.T) {
	cfg := httpengine.DefaultConfig()
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.0.1:8080/",
		"http://[fe80::1]/",
	} {
		_, err := c.Do(context.Background(), &httpengine.Request{URL: target})
		if err == nil || !strings.Contains(err.Error(), "link-local") {
			t.Errorf("%s: want a link-local refusal, got %v", target, err)
		}
	}
}

// A redirect hop that lands on a link-local address is refused too, whichever
// hostname produced it. The loopback server proves the engine still works.
func TestEngineRefusesLinkLocalRedirectHopButReachesLoopback(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/bounce" {
			http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := httpengine.New(httpengine.DefaultConfig()) // default follows redirects
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if resp, err := c.Do(context.Background(), &httpengine.Request{URL: srv.URL + "/ok"}); err != nil || resp.Status != 200 {
		t.Fatalf("control: the loopback server must be reachable: %v", err)
	}
	_, err = c.Do(context.Background(), &httpengine.Request{URL: srv.URL + "/bounce"})
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("redirect to the metadata address must be refused, got %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected the control request and the bounce to reach the loopback server, got %d hits", hits.Load())
	}
}
