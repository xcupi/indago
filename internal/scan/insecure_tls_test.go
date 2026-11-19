package scan

// AllowInsecureTLS is an explicit, per-scan opt-in for authorized lab/staging
// HTTPS targets whose certificate is self-signed or hostname-mismatched. These
// tests pin both halves of its contract through the REAL scan wiring (not a
// hand-built engine):
//
//   - with the flag OFF (the default) the scan's own HTTP engine keeps strict
//     certificate verification and refuses httptest.NewTLSServer's certificate;
//   - with the flag ON the same engine completes the handshake, and the passive
//     engines still do their job over it: securityheaders sees the missing HSTS
//     and weak cookie, methodtls records the self-signed certificate WITHOUT
//     turning it into a finding (self-signed is a lab trust choice, not a
//     transport weakness), and neither produces a spurious TLS finding.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// allowInsecureTLSSite is a self-signed HTTPS lab origin that is deliberately
// weak in exactly the ways the passive engines look for — no HSTS and a session
// cookie without Secure/HttpOnly — while its OPTIONS/TRACE surface stays clean,
// so methodtls has no unrelated finding to make.
func allowInsecureTLSSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodTrace:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Add("Set-Cookie", "lab_session=abc123; Path=/")
			_, _ = w.Write([]byte("<html><body>lab</body></html>"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// insecureTLSController builds a controller whose base HTTP config is the
// production default (strict verification). scanHTTPEngine derives the scan's
// own client from it.
func insecureTLSController(t *testing.T) *Controller {
	t.Helper()
	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatalf("shared engine: %v", err)
	}
	base := httpengine.DefaultConfig()
	base.FollowRedirects = false // the scan's engine checks every redirect hop
	c := NewController(memory.New(), queue.NewMemory(), execLog(), "test",
		Options{HTTP: shared, HTTPConfig: base})
	t.Cleanup(c.Shutdown)
	return c
}

func hasSecurityHeadersSignalKind(signals []securityHeadersSignal, kind string) bool {
	for _, s := range signals {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// With AllowInsecureTLS at its default (false), the scan's engine must be the
// shared, strictly-verifying one, and a self-signed origin must fail the
// handshake — never be silently accepted.
func TestScanHTTPEngineStaysStrictByDefault(t *testing.T) {
	srv := allowInsecureTLSSite(t)
	c := insecureTLSController(t)

	eng, closeEng, err := c.scanHTTPEngine(&domain.Scan{ID: domain.NewID()})
	if err != nil {
		t.Fatalf("scanHTTPEngine = %v", err)
	}
	defer closeEng()
	if eng != httpengine.Engine(c.opts.HTTP) {
		t.Fatal("a scan without AllowInsecureTLS must share the strict engine, not build a relaxed one")
	}

	_, err = newScopedEngine(eng, openScope()).Do(context.Background(), httpengine.GET(srv.URL+"/"))
	if err == nil {
		t.Fatal("the default scan engine accepted a self-signed certificate; strict verification is the default")
	}
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want a TLS certificate verification error", err)
	}
}

// AllowInsecureTLS must produce a dedicated engine that actually completes the
// handshake, and the response must still record the connection as unverified.
func TestScanHTTPEngineAllowInsecureTLSCompletesSelfSignedHandshake(t *testing.T) {
	srv := allowInsecureTLSSite(t)
	c := insecureTLSController(t)

	sc := &domain.Scan{ID: domain.NewID(), Config: domain.ScanConfig{AllowInsecureTLS: true}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	if err != nil {
		t.Fatalf("scanHTTPEngine with AllowInsecureTLS = %v", err)
	}
	defer closeEng()
	if eng == httpengine.Engine(c.opts.HTTP) {
		t.Fatal("AllowInsecureTLS must build a scan-scoped client, not reuse the shared strict engine")
	}
	if _, ok := eng.(*httpengine.Client); !ok {
		t.Fatalf("engine = %T, want *httpengine.Client", eng)
	}

	resp, err := newScopedEngine(eng, openScope()).Do(context.Background(), httpengine.GET(srv.URL+"/"))
	if err != nil {
		t.Fatalf("insecure engine refused the self-signed origin: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	if resp.TLS == nil || resp.TLS.Verified {
		t.Fatalf("tls state = %+v, want an unverified TLS capture (verification was skipped, not passed)", resp.TLS)
	}
}

// securityheaders and methodtls must inspect a self-signed HTTPS origin
// cleanly: the weaknesses are still reported, the certificate is recorded, and
// the certificate by itself never becomes a finding.
func TestAllowInsecureTLSPassiveEnginesInspectSelfSignedOrigin(t *testing.T) {
	srv := allowInsecureTLSSite(t)
	env := newScanEnv(t)
	c := insecureTLSController(t)

	sc := &domain.Scan{ID: env.scanID, Config: domain.ScanConfig{AllowInsecureTLS: true}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	if err != nil {
		t.Fatalf("scanHTTPEngine: %v", err)
	}
	defer closeEng()
	eng = newScopedEngine(eng, openScope())

	ep := env.endpoint(srv.URL+"/", domain.MethodGET)

	// Security headers / cookie policy: the response is readable and its real
	// weaknesses are reported over the self-signed handshake.
	tc := runSecurityHeaders(t, env, eng, ep, ExecutorConfig{})
	d := shDetailOf(t, tc)
	if d.Skipped {
		t.Fatalf("security headers skipped the HTTPS origin: %s", d.SkipReason)
	}
	if d.HTTPStatus != http.StatusOK {
		t.Fatalf("security headers observed status %d, want 200 over the insecure handshake", d.HTTPStatus)
	}
	if !hasSecurityHeadersSignalKind(d.Signals, shKindMissingHSTS) {
		t.Fatalf("signals = %+v, want missing HSTS reported for the self-signed HTTPS origin", d.Signals)
	}
	if !hasSecurityHeadersSignalKind(d.Signals, shKindCookieSecurityAttrs) {
		t.Fatalf("signals = %+v, want the weak Set-Cookie attributes reported", d.Signals)
	}
	if got := findingsByClass(t, env, domain.VulnSecurityHeaders); len(got) == 0 {
		t.Fatal("no security-headers finding was recorded for the weak HTTPS origin")
	}

	// Method/TLS hygiene: the self-signed certificate is recorded, and is NOT a
	// finding. No other TLS signal applies (TLS 1.2+, modern cipher, valid date).
	mtc := runMethodTLS(t, env, eng, ep, ExecutorConfig{})
	md := mtDetailOf(t, mtc)
	if md.Skipped {
		t.Fatalf("method/TLS skipped the HTTPS origin: %s", md.SkipReason)
	}
	if md.TLS == nil || md.TLS.Certificate == nil || !md.TLS.Certificate.SelfSigned {
		t.Fatalf("tls observation = %+v, want the self-signed certificate recorded", md.TLS)
	}
	if len(md.Signals) != 0 {
		t.Fatalf("signals = %+v, want none for a valid self-signed certificate", md.Signals)
	}
	if got := mtFindings(t, env, domain.VulnHTTPMethods); len(got) != 0 {
		t.Fatalf("method findings = %d, want 0: %+v", len(got), got)
	}
	if got := mtFindings(t, env, domain.VulnTLSConfig); len(got) != 0 {
		t.Fatalf("TLS findings = %d, want 0 (a self-signed certificate alone is not reported): %+v", len(got), got)
	}
}

// Enabling the opt-in must never be silent: a scan that starts with TLS
// verification disabled logs a WARN naming the scan and target.
func TestLaunchWarnsWhenTLSVerificationIsDisabled(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatalf("shared engine: %v", err)
	}
	base := httpengine.DefaultConfig()
	base.FollowRedirects = false
	c := NewController(memory.New(), queue.NewMemory(), logger, "test",
		Options{HTTP: shared, HTTPConfig: base})
	t.Cleanup(c.Shutdown)

	sc := &domain.Scan{
		ID:        domain.NewID(),
		State:     domain.ScanRunning,
		Discovery: domain.DiscoveryComplete, // skip the crawl: launch only
		Config:    domain.ScanConfig{AllowInsecureTLS: true, RequestsPerSecond: 1},
	}
	ex, err := c.launch(context.Background(), sc, openScope(), nil)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	c.stopExecution(ex, true)

	if !strings.Contains(logs.String(), "TLS certificate verification DISABLED") {
		t.Fatalf("launch with AllowInsecureTLS logged no WARN; got:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "allow_insecure_tls") {
		t.Fatalf("the WARN does not name the allow_insecure_tls option; got:\n%s", logs.String())
	}
}
