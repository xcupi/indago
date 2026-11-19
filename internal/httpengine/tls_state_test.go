package httpengine

// TLS capture tests: the transport records the negotiated protocol, cipher and
// peer certificate facts on every response that came over TLS, and nothing at
// all for plain HTTP. The values are facts, not verdicts — the method/TLS
// hygiene engine (internal/scan/methodtls.go) decides what is acceptable.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoCapturesTLSState(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.InsecureSkipVerify = true // httptest's certificate is self-signed
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer c.Close()

	resp, err := c.Do(context.Background(), GET(srv.URL))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.TLS == nil {
		t.Fatal("no TLS state captured for an https response")
	}
	if resp.TLS.VersionName == "" || resp.TLS.CipherSuiteName == "" {
		t.Fatalf("tls state = %+v, want a named protocol and cipher", resp.TLS)
	}
	if resp.TLS.Verified {
		t.Fatalf("tls state = %+v, want Verified=false with InsecureSkipVerify", resp.TLS)
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificate captured")
	}
	leaf := resp.TLS.PeerCertificates[0]
	if !leaf.SelfSigned {
		t.Fatalf("leaf = %+v, want httptest's self-signed certificate", leaf)
	}
	if leaf.NotAfter.IsZero() || leaf.Subject == "" {
		t.Fatalf("leaf = %+v, want its validity window and subject", leaf)
	}
}

func TestDoPlainHTTPHasNoTLSState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewDefault()
	defer c.Close()
	resp, err := c.Do(context.Background(), GET(srv.URL))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.TLS != nil {
		t.Fatalf("tls state = %+v, want nil for a plain-HTTP response", resp.TLS)
	}
}

func TestCaptureTLSStateNil(t *testing.T) {
	if got := captureTLSState(nil); got != nil {
		t.Fatalf("captureTLSState(nil) = %+v, want nil", got)
	}
}
