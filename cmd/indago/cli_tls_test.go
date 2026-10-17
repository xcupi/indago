package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

const tlsTestToken = "indago-test-token-4b1e9a7c03d2f8e65a0b9c1d7e3f2a48" // dummy

// unsetEnv removes an environment variable for the duration of the test.
func unsetEnv(t *testing.T, k string) {
	t.Helper()
	t.Setenv(k, "")
	os.Unsetenv(k)
}

// tlsObserver records, for every request the TLS test server receives,
// whether it arrived over TLS and whether it carried a bearer token.
type tlsObserver struct {
	mu            sync.Mutex
	plain         int // requests that arrived without TLS
	bearerOverTLS int // requests with an Authorization header over TLS
}

// newTLSTestServer serves the real web handler over HTTPS with a throwaway
// self-signed certificate. It returns the base URL and the PEM path to trust.
// A non-empty token turns on the API bearer-token requirement.
func newTLSTestServer(t *testing.T, token string) (base, caPath string, obs *tlsObserver) {
	t.Helper()
	certPath, keyPath := writeTestTLSPair(t, t.TempDir(), "srv")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	st, q := memory.New(), queue.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := scan.NewController(st, q, log, "test", scan.Options{IdlePoll: 10 * time.Millisecond, PollInterval: 20 * time.Millisecond})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	if token != "" {
		if err := h.SetAPIToken(token); err != nil {
			t.Fatal(err)
		}
	}

	obs = &tlsObserver{}
	routes := h.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.mu.Lock()
		if r.TLS == nil {
			obs.plain++
		} else if r.Header.Get("Authorization") != "" {
			obs.bearerOverTLS++
		}
		obs.mu.Unlock()
		routes.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL, certPath, obs
}

func TestDefaultServerHonoursINDAGOServerURLEnv(t *testing.T) {
	unsetEnv(t, "INDAGO_SERVER_URL")
	unsetEnv(t, "INDAGO_SERVER")
	if got := defaultServer(); got != "http://127.0.0.1:8750" {
		t.Errorf("no env: defaultServer() = %q, want the local default", got)
	}

	t.Setenv("INDAGO_SERVER_URL", "https://indago.example.internal:8750")
	if got := defaultServer(); got != "https://indago.example.internal:8750" {
		t.Errorf("INDAGO_SERVER_URL: defaultServer() = %q, want the override", got)
	}

	t.Setenv("INDAGO_SERVER_URL", "")
	t.Setenv("INDAGO_SERVER", "http://10.0.0.7:8750")
	if got := defaultServer(); got != "http://10.0.0.7:8750" {
		t.Errorf("INDAGO_SERVER alone: defaultServer() = %q, want it honoured", got)
	}
}

func TestCLIOverHTTPSNeedsINDAGOCACert(t *testing.T) {
	base, caPath, _ := newTLSTestServer(t, "")
	unsetEnv(t, "INDAGO_API_TOKEN")

	// No trust configured: the self-signed server certificate is refused.
	unsetEnv(t, "INDAGO_CA_CERT")
	c := newCLI(base, io.Discard)
	_, err := c.getRaw("/healthz")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("https without INDAGO_CA_CERT: want a TLS verification error, got %v", err)
	}

	// The private CA bundle makes the same server trusted.
	t.Setenv("INDAGO_CA_CERT", caPath)
	c = newCLI(base, io.Discard)
	body, err := c.getRaw("/healthz")
	if err != nil {
		t.Fatalf("https with INDAGO_CA_CERT: %v", err)
	}
	if !bytes.Contains(body, []byte(`"ok"`)) {
		t.Errorf("healthz over https: body %q", body)
	}
}

func TestCLICACertErrorsNameTheFileNotItsContents(t *testing.T) {
	base, _, _ := newTLSTestServer(t, "")
	unsetEnv(t, "INDAGO_API_TOKEN")

	missing := t.TempDir() + "/no-such-ca.pem"
	t.Setenv("INDAGO_CA_CERT", missing)
	if _, err := newCLI(base, io.Discard).getRaw("/healthz"); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing CA file: want an error naming %s, got %v", missing, err)
	}

	const marker = "NOT-A-CERT-MARKER-5e8a1c"
	junk := t.TempDir() + "/junk.pem"
	if err := os.WriteFile(junk, []byte(marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INDAGO_CA_CERT", junk)
	_, err := newCLI(base, io.Discard).getRaw("/healthz")
	if err == nil || !strings.Contains(err.Error(), junk) {
		t.Errorf("CA file without certificates: want an error naming %s, got %v", junk, err)
	}
	if err != nil && strings.Contains(err.Error(), marker) {
		t.Errorf("CA error echoes file contents: %v", err)
	}
}

func TestCLIBearerTokenSentOverTLSAndRejectedWithoutIt(t *testing.T) {
	base, caPath, obs := newTLSTestServer(t, tlsTestToken)
	t.Setenv("INDAGO_CA_CERT", caPath)

	t.Setenv("INDAGO_API_TOKEN", tlsTestToken)
	c := newCLI(base, io.Discard)
	var projects []any
	if err := c.call(http.MethodGet, "/api/projects", nil, &projects); err != nil {
		t.Fatalf("token over https: %v", err)
	}

	// Without the token the API answers 401 over TLS, and the CLI says why.
	unsetEnv(t, "INDAGO_API_TOKEN")
	c = newCLI(base, io.Discard)
	err := c.call(http.MethodGet, "/api/projects", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("no token over https: want HTTP 401, got %v", err)
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.bearerOverTLS != 1 {
		t.Errorf("bearer requests over TLS = %d, want 1", obs.bearerOverTLS)
	}
	if obs.plain != 0 {
		t.Errorf("%d request(s) reached the TLS server in plaintext", obs.plain)
	}
}
