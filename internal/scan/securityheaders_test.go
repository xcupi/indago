package scan

// Security-headers / cookie-policy engine tests: the pure analyzer (HTTPS-only
// HSTS, weak values, version disclosure, cookie heuristics) and the executor
// against real httptest servers (clean site, missing headers, weak Set-Cookie
// flags, per-origin deduplication, throttling, skips).

import (
	"context"
	"encoding/json"
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

// shEngineFor returns a scope-enforcing engine suitable for an httptest server.
// insecure is required for httptest.NewTLSServer's self-signed certificate.
func shEngineFor(t *testing.T, insecure bool) httpengine.Engine {
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

// runSecurityHeaders executes one JobSecurityHeaders for ep and returns that
// job's test case. Extra cases from earlier runs are ignored.
func runSecurityHeaders(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSecurityHeaders,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newSecurityHeadersExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
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

func shDetailOf(t *testing.T, tc *domain.TestCase) securityHeadersDetail {
	t.Helper()
	var d securityHeadersDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

// findingsByClass returns the scan's findings of one class.
func findingsByClass(t *testing.T, env *scanEnv, class domain.VulnClass) []*domain.Finding {
	t.Helper()
	var out []*domain.Finding
	for _, f := range scanFindings(t, env) {
		if f.VulnClass == class {
			out = append(out, f)
		}
	}
	return out
}

// findingDetail decodes a finding's engine detail.
func shFindingDetail(t *testing.T, f *domain.Finding) securityHeadersDetail {
	t.Helper()
	var d securityHeadersDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v (%s)", err, string(f.Detail))
	}
	return d
}

// cleanSiteHeaders are the headers a correctly configured HTTPS site sends.
func cleanSiteHeaders(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

// ---------------------------------------------------------------------------
// pure analyzer
// ---------------------------------------------------------------------------

func TestAnalyzeSecurityHeadersCleanResponse(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Add("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")

	signals, cookies := analyzeSecurityHeaders("https://app.example.test", "https://app.example.test/", h)
	if len(signals) != 0 {
		t.Fatalf("a correctly configured response produced %d signal(s): %+v", len(signals), signals)
	}
	if len(cookies) != 1 || len(cookies[0].Missing) != 0 {
		t.Fatalf("cookies = %+v, want one fully flagged cookie", cookies)
	}
	if cookies[0].SameSite != "Lax" || !cookies[0].HTTPOnly || !cookies[0].Secure {
		t.Fatalf("cookie flags = %+v", cookies[0])
	}
}

func TestAnalyzeSecurityHeadersMissingHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")

	signals, _ := analyzeSecurityHeaders("https://app.example.test", "https://app.example.test/", h)
	byKind := map[string]securityHeadersSignal{}
	for _, s := range signals {
		byKind[s.Kind] = s
	}
	for _, kind := range []string{shKindMissingHSTS, shKindMissingXCTO, shKindMissingCSPAndFrames} {
		s, ok := byKind[kind]
		if !ok {
			t.Fatalf("missing %s in %+v", kind, signals)
		}
		if s.Key == "" || s.Remediation == "" || s.Reason == "" || s.Category != shCategoryHeader {
			t.Fatalf("%s = %+v, want key/reason/remediation and the header category", kind, s)
		}
		if s.Confidence != domain.ConfidenceHigh {
			t.Fatalf("%s confidence = %q, want high", kind, s.Confidence)
		}
	}
	if got := byKind[shKindMissingHSTS].Severity; got != domain.SeverityMedium {
		t.Fatalf("missing HSTS severity = %q, want medium", got)
	}
	if got := byKind[shKindMissingXCTO].Severity; got != domain.SeverityLow {
		t.Fatalf("missing nosniff severity = %q, want low", got)
	}
}

// HSTS is only meaningful over HTTPS: a browser ignores it on a plain-HTTP
// response, so reporting it there would be a false positive.
func TestAnalyzeSecurityHeadersHSTSOnlyOnHTTPS(t *testing.T) {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")

	plain, _ := analyzeSecurityHeaders("http://app.example.test", "http://app.example.test/", h)
	for _, s := range plain {
		if s.Subject == "Strict-Transport-Security" {
			t.Fatalf("an HTTP response produced an HSTS finding: %+v", s)
		}
	}
	secure, _ := analyzeSecurityHeaders("https://app.example.test", "https://app.example.test/", h)
	found := false
	for _, s := range secure {
		if s.Kind == shKindMissingHSTS {
			found = true
		}
	}
	if !found {
		t.Fatalf("an HTTPS response with no HSTS produced no finding: %+v", secure)
	}
}

func TestAnalyzeSecurityHeadersWeakValues(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=0")
	h.Set("X-Content-Type-Options", "sniff")
	h.Set("X-Frame-Options", "ALLOW-FROM https://partner.example.test")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Server", "Apache/2.4.41 (Ubuntu)")
	h.Set("X-Powered-By", "PHP/7.4.3")

	signals, _ := analyzeSecurityHeaders("https://app.example.test", "https://app.example.test/", h)
	byKind := map[string]securityHeadersSignal{}
	for _, s := range signals {
		byKind[s.Kind] = s
		if s.Observed == "" {
			t.Fatalf("%s carries no observed value: %+v", s.Kind, s)
		}
	}
	for _, kind := range []string{shKindHSTSDisabled, shKindWeakXCTO, shKindWeakFrames, shKindServerVersion, shKindPoweredByVersion} {
		if _, ok := byKind[kind]; !ok {
			t.Fatalf("missing %s in %+v", kind, signals)
		}
	}
	if _, ok := byKind[shKindMissingCSPAndFrames]; ok {
		t.Fatal("CSP was present; it must not be reported as missing")
	}
}

// A bare product name discloses software, not a patch level, so it is not a
// version-disclosure finding.
func TestContainsVersion(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"Apache/2.4.41 (Ubuntu)", true},
		{"nginx/1.18.0", true},
		{"Microsoft-IIS/10.0", true},
		{"PHP/7.4.3", true},
		{"nginx", false},
		{"AmazonS3", false},
		{"ASP.NET", false},
		{"", false},
	} {
		if got := containsVersion(tc.value); got != tc.want {
			t.Errorf("containsVersion(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsSessionLikeCookieName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"sessionid", true},
		{"JSESSIONID", true},
		{"PHPSESSID", true},
		{"connect.sid", true},
		{"auth_token", true},
		{"remember_me", true},
		{"theme", false},
		{"consider", false},
		{"lang", false},
	} {
		if got := isSessionLikeCookieName(tc.name); got != tc.want {
			t.Errorf("isSessionLikeCookieName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAnalyzeSetCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "connect.sid=s%3Asecret; Path=/")
	h.Add("Set-Cookie", "theme=dark; Path=/; HttpOnly; SameSite=Lax")
	h.Add("Set-Cookie", "duplicate=1; Path=/")
	h.Add("Set-Cookie", "duplicate=2; Path=/; HttpOnly")

	// Plain HTTP: Secure is not required (the cookie would never be sent back
	// over http), so only HttpOnly/SameSite are reported.
	cookies := analyzeSetCookies(false, h)
	if len(cookies) != 3 {
		t.Fatalf("cookies = %+v, want 3 (the duplicate name collapses)", cookies)
	}
	byName := map[string]securityHeadersCookie{}
	for _, c := range cookies {
		byName[c.Name] = c
	}
	sid := byName["connect.sid"]
	if !sid.SessionLike || strings.Join(sid.Missing, ",") != "HttpOnly,SameSite" {
		t.Fatalf("connect.sid = %+v, want a session-like cookie missing HttpOnly+SameSite", sid)
	}
	theme := byName["theme"]
	if theme.SessionLike || len(theme.Missing) != 0 {
		t.Fatalf("theme = %+v, want a fully flagged non-session cookie", theme)
	}

	// Over HTTPS the same cookies must also carry Secure.
	secure := analyzeSetCookies(true, h)
	for _, c := range secure {
		if !c.Secure && !shContains(c.Missing, "Secure") {
			t.Fatalf("cookie %q over HTTPS does not report the missing Secure flag: %+v", c.Name, c)
		}
	}
}

func shContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// The analyzer never returns a cookie value anywhere in its output.
func TestAnalyzeSecurityHeadersNeverKeepsCookieValues(t *testing.T) {
	const secret = "s3cr3t-session-value"
	h := http.Header{}
	h.Add("Set-Cookie", "sessionid="+secret+"; Path=/")
	signals, cookies := analyzeSecurityHeaders("https://app.example.test", "https://app.example.test/", h)
	blob, err := json.Marshal(struct {
		Signals []securityHeadersSignal `json:"signals"`
		Cookies []securityHeadersCookie `json:"cookies"`
	}{signals, cookies})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("the analysis output leaked the cookie value: %s", blob)
	}
}

// ---------------------------------------------------------------------------
// executor against a real server
// ---------------------------------------------------------------------------

// (a) A clean HTTPS site: no findings at all.
func TestSecurityHeadersCleanSiteProducesNoFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanSiteHeaders(w)
		w.Header().Add("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runSecurityHeaders(t, env, shEngineFor(t, true), ep, ExecutorConfig{})

	d := shDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("signals = %+v, want none", d.Signals)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatalf("a clean site produced findings: %+v", scanFindings(t, env))
	}
	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("test case = %s/%s, want completed/success", tc.Status, tc.Outcome)
	}
}

// (b) Missing security headers: one finding per header, each backed by the
// stored request/response evidence.
func TestSecurityHeadersMissingHeadersProduceFindingsWithEvidence(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>bare</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/app", domain.MethodGET)
	tc := runSecurityHeaders(t, env, shEngineFor(t, true), ep, ExecutorConfig{})

	d := shDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed || d.HTTPStatus != http.StatusOK {
		t.Fatalf("detail = %+v, want confirmed with the baseline status", d)
	}
	if len(tc.EvidenceIDs) != 2 {
		t.Fatalf("test case evidence = %d, want a request+response pair", len(tc.EvidenceIDs))
	}
	// The evidence blob really is the response that proved the headers absent.
	_, body := env.evidenceBlob(tc.EvidenceIDs[1])
	if !strings.Contains(body, "HTTP/1.1 200 OK") {
		t.Fatalf("stored response evidence does not look like the raw response:\n%s", body)
	}
	if strings.Contains(strings.ToLower(body), "strict-transport-security:") {
		t.Fatalf("the stored response claims an HSTS header the test server never sent:\n%s", body)
	}

	findings := findingsByClass(t, env, domain.VulnSecurityHeaders)
	kinds := map[string]*domain.Finding{}
	for _, f := range findings {
		fd := shFindingDetail(t, f)
		if len(fd.Signals) != 1 {
			t.Fatalf("finding detail signals = %+v, want exactly the one signal", fd.Signals)
		}
		kinds[fd.Signals[0].Kind] = f
		if f.Verdict != domain.VerdictInconclusive || f.Confidence != domain.ConfidenceLow {
			t.Fatalf("finding %s = %s/%s, want inconclusive/low", f.Title, f.Verdict, f.Confidence)
		}
		if len(f.EvidenceIDs) < 2 {
			t.Fatalf("finding %q carries no request/response evidence: %+v", f.Title, f.EvidenceIDs)
		}
		if !strings.Contains(f.Title, "127.0.0.1") {
			t.Fatalf("finding title %q does not name the origin host", f.Title)
		}
		if f.Summary == "" {
			t.Fatalf("finding %q has no summary", f.Title)
		}
	}
	for _, kind := range []string{shKindMissingHSTS, shKindMissingXCTO, shKindMissingCSPAndFrames} {
		if kinds[kind] == nil {
			t.Fatalf("no finding for %s: %+v", kind, kinds)
		}
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want exactly 3 header findings (%+v)", len(findings), kinds)
	}
}

// (c) Weak Set-Cookie flags: one finding per cookie name, classified as
// cookie_policy, never carrying the cookie value.
func TestSecurityHeadersWeakCookieFlagsProduceFinding(t *testing.T) {
	const secret = "supersecret-session-token"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanSiteHeaders(w)
		w.Header().Add("Set-Cookie", "sessionid="+secret+"; Path=/")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/login", domain.MethodGET)
	tc := runSecurityHeaders(t, env, shEngineFor(t, true), ep, ExecutorConfig{})

	cookieFindings := findingsByClass(t, env, domain.VulnCookiePolicy)
	if len(cookieFindings) != 1 {
		t.Fatalf("cookie findings = %d, want 1 (%+v)", len(cookieFindings), cookieFindings)
	}
	f := cookieFindings[0]
	if f.Verdict != domain.VerdictInconclusive || f.Severity != domain.SeverityInfo {
		t.Fatalf("finding = %s/%s, want inconclusive/info", f.Verdict, f.Severity)
	}
	if !strings.Contains(f.Title, "sessionid") {
		t.Fatalf("finding title %q does not name the cookie", f.Title)
	}
	if len(f.EvidenceIDs) < 2 {
		t.Fatalf("cookie finding carries no request/response evidence: %+v", f.EvidenceIDs)
	}
	fd := shFindingDetail(t, f)
	if len(fd.Cookies) != 1 || fd.Cookies[0].Name != "sessionid" {
		t.Fatalf("finding cookies = %+v", fd.Cookies)
	}
	for _, missing := range []string{"HttpOnly", "Secure", "SameSite"} {
		if !shContains(fd.Cookies[0].Missing, missing) {
			t.Fatalf("cookie detail does not report missing %s: %+v", missing, fd.Cookies[0])
		}
	}

	// The secret must not survive in the test case, the finding, or the
	// stored evidence.
	for _, blob := range [][]byte{tc.Detail, f.Detail} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("a persisted record leaked the cookie value: %s", blob)
		}
	}
	for _, id := range tc.EvidenceIDs {
		_, body := env.evidenceBlob(id)
		if strings.Contains(body, secret) {
			t.Fatalf("stored evidence leaked the cookie value:\n%s", body)
		}
	}
}

// (d) Two endpoints on ONE origin: the findings do not multiply; the second
// run absorbs into the same rows, unions evidence and counts occurrences.
func TestSecurityHeadersDeduplicateAcrossEndpointsOnSameOrigin(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>" + r.URL.Path + "</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	eng := shEngineFor(t, true)
	first := env.endpoint(srv.URL+"/a", domain.MethodGET)
	second := env.endpoint(srv.URL+"/b", domain.MethodGET)

	runSecurityHeaders(t, env, eng, first, ExecutorConfig{})
	afterFirst := len(scanFindings(t, env))
	if afterFirst == 0 {
		t.Fatal("the bare origin produced no findings")
	}
	runSecurityHeaders(t, env, eng, second, ExecutorConfig{})

	findings := scanFindings(t, env)
	if len(findings) != afterFirst {
		t.Fatalf("findings = %d after a second endpoint on the same origin, want %d (deduplicated)",
			len(findings), afterFirst)
	}
	for _, f := range findings {
		fd := shFindingDetail(t, f)
		if fd.Occurrences != 2 {
			t.Fatalf("finding %q occurrences = %d, want 2", f.Title, fd.Occurrences)
		}
		if len(fd.TestCaseIDs) != 2 {
			t.Fatalf("finding %q test cases = %d, want both contributing cases", f.Title, len(fd.TestCaseIDs))
		}
		if len(f.EvidenceIDs) != 4 {
			t.Fatalf("finding %q evidence = %d, want 4 (2 per run, unioned)", f.Title, len(f.EvidenceIDs))
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("origin received %d requests, want one per job", hits.Load())
	}
}

// A throttled response is backpressure, not a header verdict: nothing is
// reported and the scan is told the target asked for less traffic.
func TestSecurityHeadersThrottledOriginReportsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/limited", domain.MethodGET)
	tc := runSecurityHeaders(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := shDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want throttled", d)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatalf("a throttled response produced findings: %+v", scanFindings(t, env))
	}
}

// A state-changing endpoint is skipped without a single request.
func TestSecurityHeadersSkipsStateChangingEndpoint(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodPOST)
	tc := runSecurityHeaders(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("skip note = %q, want it to explain the method guard", tc.Note)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", hits.Load())
	}
}

// A job carrying only a URL (no discovered endpoint) is still actionable.
func TestSecurityHeadersURLEOnlyJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSecurityHeaders,
		Target: domain.JobTarget{URL: srv.URL + "/detached"}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newSecurityHeadersExecutor(env.st, shEngineFor(t, false), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	if d := shDetailOf(t, cases[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed", d.Verdict)
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// One job per ORIGIN, never one per URL, and the skip switch disables the pass.
func TestEnqueueSecurityHeadersProbesDeduplicatesPerOrigin(t *testing.T) {
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
				Config: domain.ScanConfig{SkipSecurityHeaders: tc.skip}, CreatedAt: now, UpdatedAt: now}
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
			ctrl.enqueueSecurityHeadersProbes(ctx, sc.ID)

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
				if job.Type != domain.JobSecurityHeaders || job.Priority != securityHeadersPriority {
					t.Fatalf("job = %+v, want a priority-%d security_headers job", job, securityHeadersPriority)
				}
				if job.Target.EndpointID.Empty() {
					t.Fatalf("job %s carries no endpoint id", job.ID)
				}
				origins[securityHeadersOrigin(job.Target.URL)] = true
			}
			if len(origins) != 2 {
				t.Fatalf("origins = %v, want exactly the two distinct origins", origins)
			}
		})
	}
}
