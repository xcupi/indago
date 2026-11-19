package httpengine_test

// The Host override: net/http writes the request's Host line from
// Request.Host and ignores a "Host" entry in the header map, so the read-only
// host-header inspection depends on this field actually reaching the wire and
// on the capture recording it as evidence.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

func TestRequestHostOverrideReachesTheWire(t *testing.T) {
	const canary = "indago-host-check.invalid"
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	defer c.Close()

	req := httpengine.GET(srv.URL + "/probe")
	req.Host = canary
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if gotHost != canary {
		t.Fatalf("server saw Host %q, want %q", gotHost, canary)
	}
	if resp.Request == nil || resp.Request.Headers.Get("Host") != canary {
		t.Fatalf("captured request does not record the Host override: %+v", resp.Request)
	}
}

// A "Host" entry in the header map alone does NOT override the Host line; the
// test pins that Go behaviour so a future refactor cannot silently rely on it.
func TestRequestHeaderMapHostDoesNotOverride(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	defer c.Close()

	req := httpengine.GET(srv.URL+"/probe").WithHeader("Host", "indago-host-check.invalid")
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("do: %v", err)
	}
	if gotHost == "indago-host-check.invalid" {
		t.Fatal(`a Headers["Host"] entry unexpectedly overrode the Host line; the Host field is the supported override`)
	}
}
