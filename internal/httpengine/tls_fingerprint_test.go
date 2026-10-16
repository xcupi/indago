package httpengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRandomizeTLSFingerprint_RejectsProxyCombo proves New fails loudly
// instead of silently building a client where the flag would have no
// effect — see the mutual-exclusivity comment on Config.RandomizeTLSFingerprint.
func TestRandomizeTLSFingerprint_RejectsProxyCombo(t *testing.T) {
	cases := []Config{
		{RandomizeTLSFingerprint: true, ProxyURL: "http://127.0.0.1:9"},
		{RandomizeTLSFingerprint: true, ProxyPool: []string{"http://127.0.0.1:9"}},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v): expected an error rejecting the proxy+fingerprint combination, got nil", cfg)
		} else if !strings.Contains(err.Error(), "cannot both be set") {
			t.Fatalf("New(%+v): error = %q, want it to explain the mutual exclusivity", cfg, err)
		}
	}
}

// TestRandomizeTLSFingerprint_RealHandshake proves the randomized-ClientHello
// dial path actually completes a real TLS handshake against a real TLS
// server and round-trips a request/response — not just that it compiles.
func TestRandomizeTLSFingerprint_RealHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := New(Config{RandomizeTLSFingerprint: true, InsecureSkipVerify: true, Timeout: 10e9})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("resp = %+v, want 200/\"ok\"", resp)
	}
	// Known limitation documented on randomizedTLSDialer: ALPN/h2 is never
	// surfaced to Transport through a non-stdlib tls.Conn, so this always
	// negotiates HTTP/1.1 — assert that explicitly so a future uTLS/stdlib
	// change that silently breaks (or fixes) this doesn't go unnoticed.
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("resp.Proto = %q, want HTTP/1.1 (see the documented ALPN limitation)", resp.Proto)
	}
}
