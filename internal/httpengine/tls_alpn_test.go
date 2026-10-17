package httpengine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Transport cannot dispatch HTTP/2 for a *utls.UConn. Never offer a protocol
// that it cannot speak, including via ALPS application settings.
func TestRandomizedClientHelloAdvertisesOnlyHTTP1(t *testing.T) {
	withALPN := 0
	for i := 0; i < 1000; i++ {
		spec, err := randomizedClientHelloSpec()
		if err != nil {
			t.Fatal(err)
		}
		for _, extension := range spec.Extensions {
			switch e := extension.(type) {
			case *utls.ALPNExtension:
				withALPN++
				if !slices.Equal(e.AlpnProtocols, []string{"http/1.1"}) {
					t.Fatalf("ALPN = %v, want only http/1.1", e.AlpnProtocols)
				}
			case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
				t.Fatalf("randomized HTTP/1.1 hello must not advertise ALPS: %T", e)
			}
		}
	}
	if withALPN == 0 {
		t.Fatal("randomization lost ALPN entirely instead of offering http/1.1")
	}
}

func TestConstrainHTTP1PreservesUnrelatedExtensions(t *testing.T) {
	for _, withALPN := range []bool{false, true} {
		sni := &utls.SNIExtension{ServerName: "example.invalid"}
		curves := &utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519}}
		spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{sni,
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}, curves,
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
		}}
		want := []utls.TLSExtension{sni, curves}
		if withALPN {
			alpn := &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
			spec.Extensions = append(spec.Extensions, alpn)
			want = append(want, alpn)
		}
		for i := 0; i < 2; i++ { // Normalization is idempotent.
			constrainHTTP1(&spec)
			if !slices.Equal(spec.Extensions, want) {
				t.Fatalf("withALPN=%v: unrelated extension order/identity changed: %v", withALPN, spec.Extensions)
			}
		}
	}
}

func TestRandomizedTLSStillRejectsUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS must fail before sending an HTTP request")
	}))
	defer srv.Close()
	c, err := New(Config{RandomizeTLSFingerprint: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Do(context.Background(), &Request{URL: srv.URL})
	var certError x509.UnknownAuthorityError
	if !errors.As(err, &certError) {
		t.Fatalf("Do error = %v, want certificate verification failure", err)
	}
}

func TestRandomizedTLSRoundTripAgainstHTTP2Server(t *testing.T) {
	for _, version := range []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"default", tls.VersionTLS12, tls.VersionTLS13},
		{"tls12", tls.VersionTLS12, tls.VersionTLS12},
	} {
		t.Run(version.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != "HTTP/1.1" {
					t.Errorf("server received %s, want HTTP/1.1", r.Proto)
				}
				w.Write([]byte("round-trip-ok"))
			}))
			srv.EnableHTTP2 = true
			srv.TLS = &tls.Config{MinVersion: version.min, MaxVersion: version.max}
			srv.StartTLS()
			defer srv.Close()
			if !slices.Contains(srv.TLS.NextProtos, "h2") {
				t.Fatal("fixture does not advertise HTTP/2")
			}
			c, err := New(Config{RandomizeTLSFingerprint: true, InsecureSkipVerify: true, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.transport.DisableKeepAlives = true // One real handshake per request.
			for i := 0; i < 100; i++ {
				resp, err := c.Do(context.Background(), &Request{URL: srv.URL})
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				if resp.Proto != "HTTP/1.1" || resp.Status != http.StatusOK || string(resp.Body) != "round-trip-ok" {
					t.Fatalf("request %d: response = %+v", i, resp)
				}
			}
		})
	}
}
