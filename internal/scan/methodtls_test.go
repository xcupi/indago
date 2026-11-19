package scan

// Method & TLS transport-hygiene engine tests: the pure analyzer (Allow
// parsing, the TRACE echo rule, the API/auth suppressions, the TLS
// protocol/cipher/certificate judgements) and the executor against real
// httptest servers (clean origin, TRACE echo, OPTIONS write-method
// advertisement, TLS 1.0-only origin, expired certificate, per-origin
// deduplication, throttling, state-changing skips, bounded enqueue).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mtEngineFor returns a scope-enforcing engine suitable for an httptest server.
// insecure is required for a self-signed certificate's handshake to complete.
func mtEngineFor(t *testing.T, insecure bool) httpengine.Engine {
	t.Helper()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false // REQUIRED by scopedEngine
	cfg.InsecureSkipVerify = insecure
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatalf("http engine: %v", err)
	}
	t.Cleanup(c.Close)
	return newScopedEngine(c, openScope())
}

// runMethodTLS executes one JobMethodTLS for ep and returns that job's test
// case.
func runMethodTLS(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobMethodTLS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newMethodTLSExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	for _, tc := range cases {
		if tc.JobID == job.ID {
			return tc
		}
	}
	t.Fatalf("no test case recorded for job %s", job.ID)
	return nil
}

func mtDetailOf(t *testing.T, tc *domain.TestCase) methodTLSDetail {
	t.Helper()
	var d methodTLSDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func mtFindings(t *testing.T, env *scanEnv, class domain.VulnClass) []*domain.Finding {
	t.Helper()
	var out []*domain.Finding
	for _, f := range scanFindings(t, env) {
		if f.VulnClass == class {
			out = append(out, f)
		}
	}
	return out
}

func mtFindingDetail(t *testing.T, f *domain.Finding) methodTLSDetail {
	t.Helper()
	var d methodTLSDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v (%s)", err, string(f.Detail))
	}
	return d
}

// mtSelfSignedServer starts an HTTPS server whose leaf certificate is
// self-signed with the given validity window. The client must skip
// verification for the handshake to complete.
func mtSelfSignedServer(t *testing.T, handler http.Handler, notBefore, notAfter time.Time) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "indago-method-tls.example.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"127.0.0.1", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// cleanMethodHandler is a correctly configured page: no TRACE, and OPTIONS
// advertises nothing but read methods.
func cleanMethodHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodTrace:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

func TestMTAllowMethodsParsesEveryHeaderAndDedupes(t *testing.T) {
	h := http.Header{}
	h.Add("Allow", "GET, HEAD")
	h.Add("Allow", "options , get")
	got := mtAllowMethods(h)
	want := []string{"GET", "HEAD", "OPTIONS"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("allow = %v, want %v", got, want)
	}
}

// TRACE must never be inferred from an Allow entry: it is decided by the
// echo, so a server that advertises TRACE but refuses it stays silent.
func TestMTDangerousAllowedExcludesTrace(t *testing.T) {
	if got := mtDangerousAllowed([]string{"GET", "HEAD", "OPTIONS", "TRACE"}); len(got) != 0 {
		t.Fatalf("dangerous = %v, want none (TRACE is decided by the echo)", got)
	}
	got := mtDangerousAllowed([]string{"GET", "PUT", "DELETE", "PATCH"})
	if strings.Join(got, ",") != "PUT,DELETE,PATCH" {
		t.Fatalf("dangerous = %v, want PUT,DELETE,PATCH", got)
	}
}

func TestMTAPIPath(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://app.example.test/", false},
		{"https://app.example.test/search?q=1", false},
		{"https://app.example.test/orders/42", false},
		{"https://app.example.test/api", true},
		{"https://app.example.test/api/items", true},
		{"https://app.example.test/backend/api/items", true},
		{"https://app.example.test/v2/customers", true},
		{"https://app.example.test/graphql", true},
	}
	for _, tc := range cases {
		if got := mtAPIPath(tc.url); got != tc.want {
			t.Errorf("mtAPIPath(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestMTTRACEEchoes(t *testing.T) {
	marker := "mtmdeadbeef"
	target := "/page?indago_method_check=abc"
	echo := "TRACE " + target + " HTTP/1.1\r\nHost: app.test\r\nX-Indago-Trace: " + marker + "\r\n\r\n"
	cases := []struct {
		name string
		resp *httpengine.Response
		want bool
	}{
		{"request line and marker echoed", &httpengine.Response{Status: 200, Body: []byte(echo)}, true},
		{"message/http dump with marker", &httpengine.Response{
			Status: 200, Headers: http.Header{"Content-Type": []string{"message/http"}},
			Body: []byte("Host: app.test\r\nX-Indago-Trace: " + marker + "\r\n"),
		}, true},
		{"marker reflected without the request line", &httpengine.Response{
			Status: 200, Body: []byte("<p>your header was " + marker + "</p>"),
		}, false},
		{"request line echoed without the marker", &httpengine.Response{
			Status: 200, Body: []byte("TRACE " + target + " HTTP/1.1\r\n"),
		}, false},
		{"TRACE refused", &httpengine.Response{Status: 405, Body: []byte(echo)}, false},
		{"nil response", nil, false},
	}
	for _, tc := range cases {
		if got := mtTRACEEchoes(tc.resp, marker, target); got != tc.want {
			t.Errorf("%s: mtTRACEEchoes = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMTMethodSignalsCleanProbesProduceNothing(t *testing.T) {
	probes := []methodTLSProbe{
		{Method: http.MethodOptions, URL: "https://app.example.test/", Status: 204, Allow: []string{"GET", "HEAD", "OPTIONS"}},
		{Method: http.MethodTrace, URL: "https://app.example.test/", Status: 405, Blocked: "disabled"},
	}
	if got := mtMethodSignals("https://app.example.test", probes, false); len(got) != 0 {
		t.Fatalf("signals = %+v, want none", got)
	}
}

func TestMTMethodSignalsOptionsWriteMethodsOnlyForAnAnonymousNonAPIpage(t *testing.T) {
	probes := []methodTLSProbe{
		{Method: http.MethodOptions, URL: "https://app.example.test/orders", Status: 200,
			Allow: []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}},
	}
	origin := "https://app.example.test"
	signals := mtMethodSignals(origin, probes, false)
	if len(signals) != 1 || signals[0].Kind != mtKindOptionsWriteMethods {
		t.Fatalf("signals = %+v, want one %s signal", signals, mtKindOptionsWriteMethods)
	}
	if signals[0].Category != mtCategoryMethod || signals[0].Key != methodTLSDedupKey(origin, mtCategoryMethod, mtKindOptionsWriteMethods) {
		t.Fatalf("signal = %+v, want the method category and its origin-keyed dedup key", signals[0])
	}

	// An authenticated scan: advertising write methods is normal.
	if got := mtMethodSignals(origin, probes, true); len(got) != 0 {
		t.Fatalf("authenticated scan produced %+v, want none", got)
	}
	// An API surface: PUT/DELETE there is the documented interface.
	apiProbes := []methodTLSProbe{
		{Method: http.MethodOptions, URL: "https://app.example.test/api/orders", Status: 200,
			Allow: []string{"GET", "PUT", "DELETE"}},
	}
	if got := mtMethodSignals(origin, apiProbes, false); len(got) != 0 {
		t.Fatalf("API origin produced %+v, want none", got)
	}
	// A refused OPTIONS (401/403/405) says nothing about the resource.
	refused := []methodTLSProbe{
		{Method: http.MethodOptions, URL: "https://app.example.test/orders", Status: 401,
			Allow: []string{"PUT", "DELETE"}},
	}
	if got := mtMethodSignals(origin, refused, false); len(got) != 0 {
		t.Fatalf("refused OPTIONS produced %+v, want none", got)
	}
}

func TestMTTLSVersionUnsupported(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		want bool
	}{
		{`Get "https://app.test/": remote error: tls: protocol version not supported`, true},
		{`remote error: tls: handshake failure`, false},
		{`x509: certificate has expired or is not yet valid`, false},
	} {
		if got := mtTLSVersionUnsupported(tc.msg); got != tc.want {
			t.Errorf("mtTLSVersionUnsupported(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestMTTLSSignalsCleanTransport(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	obs := &methodTLSObservation{
		Scheme: "https", Version: tls.VersionTLS13, VersionName: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Certificate: &methodTLSCert{NotAfter: now.Add(90 * 24 * time.Hour)},
	}
	if got := mtTLSSignals("https://app.example.test", obs, now); len(got) != 0 {
		t.Fatalf("signals = %+v, want none", got)
	}
	// Plain HTTP has no transport judgement at all.
	if got := mtTLSSignals("http://app.example.test", &methodTLSObservation{Scheme: "http"}, now); len(got) != 0 {
		t.Fatalf("plain-HTTP signals = %+v, want none", got)
	}
}

func TestMTTLSSignalsWeakTransport(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	origin := "https://app.example.test"

	legacy := mtTLSSignals(origin, &methodTLSObservation{
		Scheme: "https", Version: tls.VersionTLS11, VersionName: "TLS 1.1",
		CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}, now)
	if len(legacy) != 1 || legacy[0].Kind != mtKindLegacyTLS || legacy[0].Category != mtCategoryTLS {
		t.Fatalf("legacy signals = %+v, want one %s", legacy, mtKindLegacyTLS)
	}
	if legacy[0].Severity != domain.SeverityMedium || legacy[0].Confidence != domain.ConfidenceHigh {
		t.Fatalf("legacy signal = %+v, want medium/high", legacy[0])
	}

	weakCipher := mtTLSSignals(origin, &methodTLSObservation{
		Scheme: "https", Version: tls.VersionTLS12, VersionName: "TLS 1.2",
		CipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	}, now)
	if len(weakCipher) != 1 || weakCipher[0].Kind != mtKindWeakCipher {
		t.Fatalf("cipher signals = %+v, want one %s", weakCipher, mtKindWeakCipher)
	}

	expired := mtTLSSignals(origin, &methodTLSObservation{
		Scheme: "https", Version: tls.VersionTLS13, VersionName: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Certificate: &methodTLSCert{NotAfter: now.Add(-time.Hour), SelfSigned: true},
	}, now)
	if len(expired) != 1 || expired[0].Kind != mtKindExpiredCertificate {
		t.Fatalf("certificate signals = %+v, want one %s", expired, mtKindExpiredCertificate)
	}

	refused := mtTLSSignals(origin, &methodTLSObservation{
		Scheme: "https", HandshakeError: "remote error: tls: protocol version not supported",
	}, now)
	if len(refused) != 1 || refused[0].Kind != mtKindTLSProtocolRefused {
		t.Fatalf("refused signals = %+v, want one %s", refused, mtKindTLSProtocolRefused)
	}
}

// A self-signed certificate is recorded but is not a transport finding: the
// operator's own lab servers use one on purpose. Only an expired certificate
// is reported.
func TestMTTLSSignalsSelfSignedIsRecordedNotReported(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	obs := &methodTLSObservation{
		Scheme: "https", Version: tls.VersionTLS13, VersionName: "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Certificate: &methodTLSCert{NotAfter: now.Add(365 * 24 * time.Hour), SelfSigned: true},
	}
	if got := mtTLSSignals("https://app.example.test", obs, now); len(got) != 0 {
		t.Fatalf("signals = %+v, want none for a valid self-signed certificate", got)
	}
	if obs.Certificate == nil || !obs.Certificate.SelfSigned {
		t.Fatal("the self-signed certificate should still be recorded in the observation")
	}
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

// A clean GET/HEAD/POST/OPTIONS origin produces no finding at all.
func TestMethodTLSCleanOriginHasNoFindings(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		cleanMethodHandler(w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q (note %q), want completed", tc.Status, tc.Note)
	}
	d := mtDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected || len(d.Signals) != 0 {
		t.Fatalf("detail = %+v, want a negative verdict with no signals", d)
	}
	if len(d.Probes) != 2 {
		t.Fatalf("probes = %+v, want the OPTIONS and TRACE probes", d.Probes)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0 on a clean origin", len(got))
	}
	// Baseline GET + OPTIONS + TRACE, and nothing else.
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("target hits = %d, want exactly 3 read-only requests", got)
	}
}

// A TRACE that echoes the request back is the cross-site tracing primitive and
// must be reported with evidence.
func TestMethodTLSTraceEchoProducesFindingWithEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS, TRACE")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodTrace:
			w.Header().Set("Content-Type", "message/http")
			fmt.Fprintf(w, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
			for name, values := range r.Header {
				for _, v := range values {
					fmt.Fprintf(w, "%s: %s\r\n", name, v)
				}
			}
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/app", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q (note %q), want completed", tc.Status, tc.Note)
	}
	d := mtDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (signals %+v)", d.Verdict, d.Signals)
	}
	if len(d.Signals) != 1 || d.Signals[0].Kind != mtKindTraceEnabled {
		t.Fatalf("signals = %+v, want exactly one %s", d.Signals, mtKindTraceEnabled)
	}
	var traceProbe *methodTLSProbe
	for i := range d.Probes {
		if d.Probes[i].Method == http.MethodTrace {
			traceProbe = &d.Probes[i]
		}
	}
	if traceProbe == nil || !traceProbe.Echoed {
		t.Fatalf("probes = %+v, want the TRACE probe marked as echoed", d.Probes)
	}
	if len(tc.EvidenceIDs) < 2 {
		t.Fatalf("evidence ids = %v, want the request/response pairs persisted", tc.EvidenceIDs)
	}

	findings := mtFindings(t, env, domain.VulnHTTPMethods)
	if len(findings) != 1 {
		t.Fatalf("http_methods findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityLow {
		t.Fatalf("finding = %+v, want confirmed/low", f)
	}
	if fd := mtFindingDetail(t, f); fd.DedupKey != methodTLSDedupKey(methodTLSOrigin(srv.URL+"/app"), mtCategoryMethod, mtKindTraceEnabled) {
		t.Fatalf("finding dedup key = %q, want the origin-keyed TRACE key", fd.DedupKey)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("a method finding must carry the evidence that proves it")
	}
	if !strings.Contains(f.Title, "TRACE") {
		t.Fatalf("title = %q, want it to name TRACE", f.Title)
	}
}

// An unauthenticated OPTIONS response advertising write methods on a non-API
// page is reported once, from the Allow header alone.
func TestMethodTLSOptionsAdvertisesWriteMethods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})
	if d := mtDetailOf(t, tc); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (signals %+v)", d.Verdict, d.Signals)
	}
	findings := mtFindings(t, env, domain.VulnHTTPMethods)
	if len(findings) != 1 {
		t.Fatalf("http_methods findings = %d, want 1", len(findings))
	}
	fd := mtFindingDetail(t, findings[0])
	if fd.DedupKey != methodTLSDedupKey(methodTLSOrigin(srv.URL+"/orders"), mtCategoryMethod, mtKindOptionsWriteMethods) {
		t.Fatalf("dedup key = %q, want the OPTIONS write-methods key", fd.DedupKey)
	}
	if !strings.Contains(fd.Reason, "PUT") {
		t.Fatalf("reason = %q, want it to name the advertised methods", fd.Reason)
	}
}

// The same advertisement is NOT a finding on an API surface or for an
// authenticated scan: both make write methods expected.
func TestMethodTLSOptionsWriteMethodsSuppressedOnAPIAndAuthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, PUT, DELETE")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	t.Run("api path", func(t *testing.T) {
		env := newScanEnv(t)
		ep := env.endpoint(srv.URL+"/api/orders", domain.MethodGET)
		runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})
		if got := scanFindings(t, env); len(got) != 0 {
			t.Fatalf("findings = %d, want 0 on an API path", len(got))
		}
	})
	t.Run("authenticated scan", func(t *testing.T) {
		env := newScanEnv(t)
		ep := env.endpoint(srv.URL+"/orders", domain.MethodGET)
		runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{Authenticated: true})
		if got := scanFindings(t, env); len(got) != 0 {
			t.Fatalf("findings = %d, want 0 for an authenticated scan", len(got))
		}
	})
}

// An HTTPS origin whose handshake can only agree on TLS 1.0 is reported as a
// TLS transport finding, even though no HTTP response is ever produced.
func TestMethodTLSLegacyProtocolOnlyOrigin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "legacy.example.test"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(cleanMethodHandler))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
	}
	srv.StartTLS()
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, true), ep, ExecutorConfig{})

	d := mtDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (signals %+v, note %q)", d.Verdict, d.Signals, tc.Note)
	}
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %q, want completed: the refused handshake is the observation", tc.Status)
	}
	if d.TLS == nil || d.TLS.HandshakeError == "" {
		t.Fatalf("tls observation = %+v, want the recorded handshake error", d.TLS)
	}
	findings := mtFindings(t, env, domain.VulnTLSConfig)
	if len(findings) != 1 {
		t.Fatalf("tls_config findings = %d, want 1", len(findings))
	}
	if fd := mtFindingDetail(t, findings[0]); fd.Signals[0].Kind != mtKindTLSProtocolRefused {
		t.Fatalf("signal = %+v, want %s", fd.Signals[0], mtKindTLSProtocolRefused)
	}
}

// An expired certificate is observable through the transport capture when the
// scan's engine skips verification (the usual lab setting) and is reported.
func TestMethodTLSExpiredCertificate(t *testing.T) {
	now := time.Now()
	srv := mtSelfSignedServer(t, http.HandlerFunc(cleanMethodHandler), now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, true), ep, ExecutorConfig{})

	d := mtDetailOf(t, tc)
	if d.TLS == nil || d.TLS.Certificate == nil {
		t.Fatalf("tls observation = %+v, want the leaf certificate", d.TLS)
	}
	if !d.TLS.Certificate.SelfSigned {
		t.Fatalf("certificate = %+v, want it recorded as self-signed", d.TLS.Certificate)
	}
	findings := mtFindings(t, env, domain.VulnTLSConfig)
	if len(findings) != 1 {
		t.Fatalf("tls_config findings = %d, want 1 (signals %+v)", len(findings), d.Signals)
	}
	if fd := mtFindingDetail(t, findings[0]); fd.Signals[0].Kind != mtKindExpiredCertificate {
		t.Fatalf("signal = %+v, want %s", fd.Signals[0], mtKindExpiredCertificate)
	}
}

// A valid self-signed certificate on an HTTPS lab origin is recorded in the
// detail and produces no finding.
func TestMethodTLSValidSelfSignedCertificateIsNotAFinding(t *testing.T) {
	now := time.Now()
	srv := mtSelfSignedServer(t, http.HandlerFunc(cleanMethodHandler), now.Add(-time.Hour), now.Add(365*24*time.Hour))

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	runMethodTLS(t, env, mtEngineFor(t, true), ep, ExecutorConfig{})

	findings := scanFindings(t, env)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 for a valid self-signed certificate (%+v)", len(findings), findings)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	d := mtDetailOf(t, cases[0])
	if d.TLS == nil || d.TLS.Certificate == nil || !d.TLS.Certificate.SelfSigned {
		t.Fatalf("tls observation = %+v, want the self-signed certificate recorded", d.TLS)
	}
}

// Two endpoints on ONE origin collapse into a single finding that unions
// evidence and counts both attempts.
func TestMethodTLSDeduplicatesPerOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			w.Header().Set("Content-Type", "message/http")
			fmt.Fprintf(w, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
			for name, values := range r.Header {
				for _, v := range values {
					fmt.Fprintf(w, "%s: %s\r\n", name, v)
				}
			}
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	eng := mtEngineFor(t, false)
	first := env.endpoint(srv.URL+"/one", domain.MethodGET)
	second := env.endpoint(srv.URL+"/two", domain.MethodGET)
	runMethodTLS(t, env, eng, first, ExecutorConfig{})
	runMethodTLS(t, env, eng, second, ExecutorConfig{})

	findings := mtFindings(t, env, domain.VulnHTTPMethods)
	if len(findings) != 1 {
		t.Fatalf("http_methods findings = %d, want 1 across two endpoints of one origin", len(findings))
	}
	if fd := mtFindingDetail(t, findings[0]); fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
	if len(findings[0].EvidenceIDs) < 4 {
		t.Fatalf("evidence ids = %d, want both attempts' evidence unioned", len(findings[0].EvidenceIDs))
	}
}

// 429/503 is backpressure, not a judgement: nothing is reported and no further
// probe is sent.
func TestMethodTLSThrottledOriginIsNotJudged(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})

	d := mtDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want the throttle recorded", d)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("signals = %+v, want none from a throttled origin", d.Signals)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("target hits = %d, want 1: a throttled baseline sends nothing more", got)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestMethodTLSStateChangingEndpointIsSkipped(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodPUT)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("skip note = %q, want it to explain the method guard", tc.Note)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

// A job carrying only a URL (no discovered endpoint) is still actionable.
func TestMethodTLSURLEOnlyJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(cleanMethodHandler))
	defer srv.Close()

	env := newScanEnv(t)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobMethodTLS,
		Target: domain.JobTarget{URL: srv.URL + "/detached"}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newMethodTLSExecutor(env.st, mtEngineFor(t, false), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	if d := mtDetailOf(t, cases[0]); d.Origin != methodTLSOrigin(srv.URL) {
		t.Fatalf("origin = %q, want %q", d.Origin, methodTLSOrigin(srv.URL))
	}
}

// Cookie values and credentials never reach the evidence store: the response
// dump redacts Set-Cookie before it is persisted.
func TestMethodTLSEvidenceRedactsSecrets(t *testing.T) {
	const secret = "supersecret-session-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid="+secret+"; Path=/; HttpOnly")
		cleanMethodHandler(w, r)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runMethodTLS(t, env, mtEngineFor(t, false), ep, ExecutorConfig{})

	if len(tc.EvidenceIDs) == 0 {
		t.Fatal("no evidence was stored")
	}
	for _, id := range tc.EvidenceIDs {
		row, err := env.st.Evidence().Get(context.Background(), id)
		if err != nil {
			t.Fatalf("evidence %s: %v", id, err)
		}
		rc, err := env.ev.Open(row.BlobPath)
		if err != nil {
			t.Fatalf("open evidence %s: %v", id, err)
		}
		blob, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read evidence %s: %v", id, err)
		}
		if strings.Contains(string(blob), secret) {
			t.Fatalf("evidence %s carries the raw cookie value", id)
		}
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// One job per ORIGIN, never one per URL, and the skip switch disables the pass.
func TestEnqueueMethodTLSProbesDeduplicatesPerOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		skip bool
		want int
	}{
		{"enabled", false, 2},
		{"skipped", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipMethodTLS: tc.skip}, CreatedAt: now, UpdatedAt: now}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{
				"https://app.example.test/",
				"https://app.example.test/login",
				"https://app.example.test/api/items?page=2",
				"https://other.example.test/",
			} {
				ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: raw,
					Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}
			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueMethodTLSProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			if tc.want == 0 {
				return
			}
			origins := map[string]bool{}
			for _, job := range jobs {
				if job.Type != domain.JobMethodTLS || job.Priority != methodTLSPriority {
					t.Fatalf("job = %+v, want a priority-%d method_tls_hygiene job", job, methodTLSPriority)
				}
				if job.Target.EndpointID.Empty() {
					t.Fatalf("job %s carries no endpoint id", job.ID)
				}
				origins[methodTLSOrigin(job.Target.URL)] = true
			}
			if len(origins) != 2 {
				t.Fatalf("origins = %v, want exactly the two distinct origins", origins)
			}
		})
	}
}

// A state-changing endpoint never gets the one job for its origin either: the
// executor would only skip it.
func TestEnqueueMethodTLSSkipsStateChangingEndpoints(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	now := time.Now()
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/orders",
		Method: domain.MethodPOST, Source: domain.SourceCrawler, CreatedAt: now}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	ctrl := NewController(st, q, execLog(), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctrl.enqueueMethodTLSProbes(ctx, sc.ID)

	jobs, err := q.Jobs(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("jobs = %d, want 0 for a state-changing-only origin", len(jobs))
	}
}
