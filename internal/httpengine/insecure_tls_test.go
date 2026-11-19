package httpengine

// Opt-in TLS relaxation for authorized lab/staging targets
// (domain.ScanConfig.AllowInsecureTLS -> Config.InsecureSkipVerify).
//
// The contract these tests pin, in order:
//  1. strict certificate verification is the DEFAULT — httptest.NewTLSServer's
//     self-signed certificate is refused, so a production target is never
//     silently accepted;
//  2. the explicit InsecureSkipVerify opt-in lets the SAME request complete,
//     and the response still reports the connection as unverified (the capture
//     is honest about what happened — verification was off, it did not pass).

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// tlsEchoServer is an HTTPS origin whose certificate is self-signed.
func tlsEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStrictTLSVerificationRejectsSelfSignedCertificateByDefault(t *testing.T) {
	srv := tlsEchoServer(t)

	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(c.Close)

	if _, err := c.Do(context.Background(), GET(srv.URL)); err == nil {
		t.Fatal("Do succeeded against a self-signed certificate with the default config; strict verification must be the default")
	} else {
		var verr *tls.CertificateVerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("err = %v, want a TLS certificate verification error", err)
		}
	}
}

func TestInsecureSkipVerifyAcceptsSelfSignedCertificate(t *testing.T) {
	srv := tlsEchoServer(t)

	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	cfg.InsecureSkipVerify = true // domain.ScanConfig.AllowInsecureTLS
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(c.Close)

	resp, err := c.Do(context.Background(), GET(srv.URL))
	if err != nil {
		t.Fatalf("Do with InsecureSkipVerify = %v, want the self-signed handshake to complete", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	if resp.TLS == nil {
		t.Fatal("no TLS state captured for the https response")
	}
	if resp.TLS.Verified {
		t.Fatalf("tls state = %+v, want Verified=false: verification was skipped, not passed", resp.TLS)
	}
	if len(resp.TLS.PeerCertificates) == 0 || !resp.TLS.PeerCertificates[0].SelfSigned {
		t.Fatalf("peer certificates = %+v, want the self-signed leaf recorded", resp.TLS.PeerCertificates)
	}
}
