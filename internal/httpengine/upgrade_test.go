package httpengine_test

// Protocol-upgrade transports: a 101 response has no body to read (the
// connection becomes a raw tunnel), and an Upgrade handshake cannot be carried
// by HTTP/2, so both behaviours are pinned here rather than assumed.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/httpengine"
)

// TestDoReturnsSwitchingProtocolsWithoutReadingBody pins the transport rule a
// read-only Upgrade probe depends on: a 101 is returned as soon as its headers
// are read, even though the hijacked connection stays open and never sends a
// body. Reading until EOF would block until the request deadline.
func TestDoReturnsSwitchingProtocolsWithoutReadingBody(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("response writer is not a Hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n"); err != nil {
			return
		}
		if err := buf.Flush(); err != nil {
			return
		}
		// Hold the tunnel open: a client that tries to read a body blocks here.
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	c, err := httpengine.New(httpengine.Config{
		Timeout:         10 * time.Second,
		FollowRedirects: false,
		MaxBodyBytes:    httpengine.DefaultMaxBodyBytes,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(c.Close)

	req := httpengine.GET(srv.URL+"/ws").
		WithHeader("Upgrade", "websocket").
		WithHeader("Connection", "Upgrade").
		WithHeader("Sec-WebSocket-Version", "13")
	start := time.Now()
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.Status)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("body = %q, want empty for a protocol switch", resp.Body)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Do took %s: it waited for the upgraded connection instead of returning the 101", elapsed)
	}
	if got := resp.Headers.Get("Upgrade"); got != "websocket" {
		t.Fatalf("Upgrade header = %q, want websocket", got)
	}
}

// TestHTTP1OnlyAvoidsHTTP2 pins the flag a handshake probe needs: the same TLS
// server answers HTTP/2 to an ordinary request but HTTP/1.1 to an HTTP1Only
// one, because an h2 connection refuses Upgrade/Connection headers outright.
func TestHTTP1OnlyAvoidsHTTP2(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.ProtoMajor
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c, err := httpengine.New(httpengine.Config{
		Timeout:            10 * time.Second,
		FollowRedirects:    false,
		InsecureSkipVerify: true,
		MaxBodyBytes:       httpengine.DefaultMaxBodyBytes,
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(c.Close)

	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/normal")); err != nil {
		t.Fatalf("normal request: %v", err)
	}
	forced := httpengine.GET(srv.URL + "/forced")
	forced.HTTP1Only = true
	resp, err := c.Do(context.Background(), forced)
	if err != nil {
		t.Fatalf("HTTP1Only request: %v", err)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("forced response proto = %q, want HTTP/1.1", resp.Proto)
	}

	mu.Lock()
	normal, forcedProto := seen["/normal"], seen["/forced"]
	mu.Unlock()
	if forcedProto != 1 {
		t.Fatalf("server saw HTTP/%d for the forced request, want HTTP/1", forcedProto)
	}
	if normal == 1 {
		t.Skip("this environment did not negotiate HTTP/2 for the control request; the forced HTTP/1.1 assertion above still holds")
	}
	if normal != 2 {
		t.Fatalf("control request used HTTP/%d, want HTTP/2", normal)
	}
}
