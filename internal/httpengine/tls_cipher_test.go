package httpengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// These PRNG seeds were found by enumerating SHA256("indago-tls-investigation-N").
// All produce TLS1.2-only hellos missing every default-server-compatible cipher
// for the indicated certificate type. Replay them instead of waiting for luck.
var cipherGapSeeds = []struct {
	name  string
	seed  string
	ecdsa bool
}{
	{"rsa-57744", "5e4ecff9bcc20daed1a3b113d3a4a5422375154d776749fea7b6c4a5226fe750", false},
	{"rsa-126896", "28198ba313be83ebd61716ab77c531984b72bd83ab665e7ba6c8f507562ba279", false},
	{"rsa-128509", "fc7ece72470e530977f11a39eceb8b088b98f8d00b463a027f9a028a3ecda7bb", false},
	{"ecdsa-118781", "bea34d2ec327bae27cc700975577bfc18b89f4c25999015a159ac72890bf326d", true},
	{"ecdsa-253463", "5891c69f5201ad9b197af44e7dda9eacfb66ef1c1fe82d1ced915f6f62789107", true},
}

func seededHelloID(t *testing.T, encoded string) utls.ClientHelloID {
	t.Helper()
	data, err := hex.DecodeString(encoded)
	if err != nil || len(data) != utls.PRNGSeedLength {
		t.Fatalf("invalid fixture seed %q: %v", encoded, err)
	}
	var seed utls.PRNGSeed
	copy(seed[:], data)
	id := utls.HelloRandomized
	id.Seed = &seed
	return id
}

func testECDSACertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Round-trip the actual generated spec with certificate verification enabled.
// Only the test's connection dialer is replaced to replay its seed; production
// still requests fresh random seeds per connection, with no global mutation.
func roundTripSeededSpec(t *testing.T, spec utls.ClientHelloSpec, srv *httptest.Server) error {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		u := utls.UClient(raw, &utls.Config{ServerName: "127.0.0.1", RootCAs: roots}, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, err
		}
		if err := u.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return u, nil
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/1.1" || string(body) != "seed-replay-ok" {
		return fmt.Errorf("unexpected response: %s %s %q", resp.Proto, resp.Status, body)
	}
	return nil
}

func TestEnsureTLS12AEADCiphers(t *testing.T) {
	const rsa = utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	const ecdsa = utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	for _, tc := range []struct {
		name        string
		input, want []uint16
		min         uint16
	}{
		{"missing RSA", []uint16{ecdsa}, []uint16{ecdsa, rsa}, utls.VersionTLS12},
		{"missing ECDSA", []uint16{rsa}, []uint16{rsa, ecdsa}, utls.VersionTLS12},
		{"RSA ChaCha kept when ECDSA missing", []uint16{utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}, []uint16{utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ecdsa}, utls.VersionTLS12},
		{"ECDSA AES256 kept when RSA missing", []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, rsa}, utls.VersionTLS12},
		{"both missing", []uint16{utls.TLS_RSA_WITH_AES_128_GCM_SHA256}, []uint16{utls.TLS_RSA_WITH_AES_128_GCM_SHA256, rsa, ecdsa}, utls.VersionTLS12},
		{"CBC is not the AEAD floor", []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ecdsa}, []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ecdsa, rsa}, utls.VersionTLS12},
		{"keep GCM variety", []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}, []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}, utls.VersionTLS12},
		{"keep ChaCha variety", []uint16{utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}, []uint16{utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}, utls.VersionTLS12},
		{"TLS1.3-only unchanged", []uint16{utls.TLS_AES_128_GCM_SHA256}, []uint16{utls.TLS_AES_128_GCM_SHA256}, utls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := utls.ClientHelloSpec{CipherSuites: slices.Clone(tc.input), TLSVersMin: tc.min, TLSVersMax: utls.VersionTLS13}
			for n := 0; n < 2; n++ {
				ensureTLS12AEADCiphers(&spec)
				if !slices.Equal(spec.CipherSuites, tc.want) {
					t.Fatalf("suites = %x, want %x", spec.CipherSuites, tc.want)
				}
				if spec.TLSVersMin != tc.min || spec.TLSVersMax != utls.VersionTLS13 {
					t.Fatal("normalization changed TLS versions")
				}
			}
		})
	}
}

func TestRandomizedTLSKnownCipherGapSeedsRoundTrip(t *testing.T) {
	for _, tc := range cipherGapSeeds {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("seed-replay-ok"))
			}))
			srv.EnableHTTP2 = true
			// RSA cases use httptest's default RSA certificate, ECDSA cases use
			// a short-lived in-memory cert. Never relax server cipher policy.
			if tc.ecdsa {
				srv.TLS = &tls.Config{Certificates: []tls.Certificate{testECDSACertificate(t)}}
			}
			srv.StartTLS()
			defer srv.Close()
			raw, err := utls.UTLSIdToSpec(seededHelloID(t, tc.seed))
			if err != nil {
				t.Fatal(err)
			}
			family := []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
			if tc.ecdsa {
				family = []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
			}
			for _, suite := range family {
				if slices.Contains(raw.CipherSuites, suite) {
					t.Fatalf("fixture no longer has the intended cipher gap (upstream changed?): suite %x already present", suite)
				}
			}
			spec, err := randomizedClientHelloSpec(seededHelloID(t, tc.seed))
			if err != nil {
				t.Fatal(err)
			}
			if spec.TLSVersMax != utls.VersionTLS12 {
				t.Fatalf("fixture stopped being TLS1.2-only: max=%x", spec.TLSVersMax)
			}
			if err := roundTripSeededSpec(t, spec, srv); err != nil {
				t.Fatalf("known cipher-gap seed must round-trip without retries: %v", err)
			}
		})
	}
}
