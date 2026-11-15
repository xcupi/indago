package scan

// CORS engine tests: the pure classifier and origin-set derivation, plus the
// executor against real httptest servers (reflection, null origin, wildcard,
// preflight-only middleware, throttling, redirects, skips and correlation).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func corsJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	env.t.Helper()
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
}

func runCORS(t *testing.T, env *scanEnv, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	ex := newCORSExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), corsJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("test cases = %d, want 1", len(cases))
	}
	return cases[0]
}

func corsDetailOf(t *testing.T, tc *domain.TestCase) corsDetail {
	t.Helper()
	var d corsDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func scanFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// --- pure classification ---

func TestClassifyCORSProbe(t *testing.T) {
	cases := []struct {
		name          string
		probe         corsProbe
		misconfigured bool
		kind          string
		severity      domain.Severity
	}{
		{
			name:          "arbitrary origin with credentials",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: corsCanaryOrigin, AllowCredentials: "true"},
			misconfigured: true, kind: corsKindArbitraryOrigin, severity: domain.SeverityHigh,
		},
		{
			name:          "arbitrary origin without credentials",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: corsCanaryOrigin},
			misconfigured: true, kind: corsKindArbitraryOrigin, severity: domain.SeverityMedium,
		},
		{
			name:          "null origin with credentials",
			probe:         corsProbe{Origin: "null", Variant: corsVariantNull, AllowOrigin: "null", AllowCredentials: "true"},
			misconfigured: true, kind: corsKindNullOrigin, severity: domain.SeverityHigh,
		},
		{
			name:          "null origin answered to a named origin probe",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: "null", AllowCredentials: "true"},
			misconfigured: true, kind: corsKindNullOrigin, severity: domain.SeverityHigh,
		},
		{
			name:          "prefix bypass with credentials",
			probe:         corsProbe{Origin: "https://app.example.test.evil-canary.invalid", Variant: corsVariantPrefix, AllowOrigin: "https://app.example.test.evil-canary.invalid", AllowCredentials: "true"},
			misconfigured: true, kind: corsKindPrefixBypass, severity: domain.SeverityHigh,
		},
		{
			name:          "subdomain trust with credentials",
			probe:         corsProbe{Origin: "https://indago-canary.app.example.test", Variant: corsVariantSubdomain, AllowOrigin: "https://indago-canary.app.example.test", AllowCredentials: "true"},
			misconfigured: true, kind: corsKindSubdomainTrust, severity: domain.SeverityMedium,
		},
		{
			name:          "subdomain trust without credentials is recorded only",
			probe:         corsProbe{Origin: "https://indago-canary.app.example.test", Variant: corsVariantSubdomain, AllowOrigin: "https://indago-canary.app.example.test"},
			misconfigured: false, kind: corsKindSubdomainNoCreds,
		},
		{
			name:          "wildcard with credentials",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: "*", AllowCredentials: "true"},
			misconfigured: true, kind: corsKindWildcardCredentials, severity: domain.SeverityMedium,
		},
		{
			name:          "wildcard without credentials is intentional",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: "*"},
			misconfigured: false, kind: corsKindWildcardPublic,
		},
		{
			name:          "no CORS headers",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary},
			misconfigured: false, kind: corsKindNoCORS,
		},
		{
			name:          "unrelated constant origin",
			probe:         corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, AllowOrigin: "https://app.example.test", AllowCredentials: "true"},
			misconfigured: false, kind: corsKindUnrelatedOrigin,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.probe
			classifyCORSProbe(&p)
			if p.Misconfigured != tc.misconfigured {
				t.Fatalf("misconfigured = %v, want %v (%s)", p.Misconfigured, tc.misconfigured, p.Reason)
			}
			if p.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", p.Kind, tc.kind)
			}
			if tc.misconfigured && p.Severity != tc.severity {
				t.Fatalf("severity = %q, want %q", p.Severity, tc.severity)
			}
			if tc.misconfigured && p.Reason == "" {
				t.Fatal("a misconfiguration must carry a reason")
			}
		})
	}
}

func TestCORSProbeOriginsAreBoundedAndDerivedFromTheHost(t *testing.T) {
	t.Run("domain target", func(t *testing.T) {
		got := corsProbeOrigins("https://app.example.test/path?x=1")
		if len(got) != 4 {
			t.Fatalf("origins = %d, want 4: %+v", len(got), got)
		}
		want := []struct {
			origin  string
			variant corsVariant
		}{
			{corsCanaryOrigin, corsVariantCanary},
			{"null", corsVariantNull},
			{"https://app.example.test.evil-canary.invalid", corsVariantPrefix},
			{"https://indago-canary.app.example.test", corsVariantSubdomain},
		}
		for i, w := range want {
			if got[i].Origin != w.origin || got[i].Variant != w.variant {
				t.Fatalf("origin[%d] = %+v, want %+v", i, got[i], w)
			}
		}
	})
	t.Run("ip target has no subdomain space", func(t *testing.T) {
		got := corsProbeOrigins("http://127.0.0.1:8080/x")
		if len(got) != 2 {
			t.Fatalf("origins = %d, want 2: %+v", len(got), got)
		}
	})
	t.Run("single label host has no subdomain space", func(t *testing.T) {
		if got := corsProbeOrigins("http://localhost:8080/x"); len(got) != 2 {
			t.Fatalf("origins = %d, want 2: %+v", len(got), got)
		}
	})
}

// --- executor against real servers ---

func TestCORSReflectedOriginWithCredentialsIsConfirmed(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "account data")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/account", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})

	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("test case = %s/%s, want completed/success", tc.Status, tc.Outcome)
	}
	if tc.VulnClass != vulnClassCORS {
		t.Fatalf("vuln class = %q", tc.VulnClass)
	}
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("detail verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	if len(d.Probes) != 2 {
		t.Fatalf("probes = %d, want 2 (one per generated origin for an IP host)", len(d.Probes))
	}
	if d.Baseline == nil || d.Baseline.AllowOrigin != "" {
		t.Fatalf("baseline = %+v, want a request with no Origin and no ACAO", d.Baseline)
	}

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityHigh || f.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding = %s/%s/%s, want confirmed/high/high", f.Verdict, f.Severity, f.Confidence)
	}
	if f.VulnClass != vulnClassCORS {
		t.Fatalf("finding class = %q", f.VulnClass)
	}
	if !strings.Contains(f.Title, "arbitrary origin") || !strings.Contains(f.Title, "127.0.0.1") {
		t.Fatalf("title = %q, want the signal and the host", f.Title)
	}
	if !strings.Contains(f.Summary, "Access-Control-Allow-Credentials") {
		t.Fatalf("summary = %q", f.Summary)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("finding carries no evidence")
	}
	var fd corsDetail
	if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
		t.Fatalf("finding detail = %s (err %v)", string(f.Detail), err)
	}
	// 1 baseline + 2 origin probes; a signal was found, so no preflight is spent.
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3", got)
	}
	if len(tc.EvidenceIDs) != 6 {
		t.Fatalf("evidence rows = %d, want 6 (request+response for 3 requests)", len(tc.EvidenceIDs))
	}
	rows, err := env.st.Evidence().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	baseline := 0
	for _, row := range rows {
		if strings.HasPrefix(row.Note, domain.EvidenceNoteBaselinePrefix) {
			baseline++
		}
	}
	if baseline != 2 {
		t.Fatalf("baseline-role evidence rows = %d, want 2", baseline)
	}
}

func TestCORSNullOriginWithCredentialsIsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "null")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/me", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed || d.Severity != domain.SeverityHigh {
		t.Fatalf("detail = %s/%s (%s)", d.Verdict, d.Severity, d.Reason)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "null origin") {
		t.Fatalf("findings = %+v, want one null-origin finding", findings)
	}
}

func TestCORSWildcardWithCredentialsIsReportedAsMisconfiguration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/data", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed || d.Severity != domain.SeverityMedium {
		t.Fatalf("detail = %s/%s (%s)", d.Verdict, d.Severity, d.Reason)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "wildcard") {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCORSWildcardWithoutCredentialsIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "public data")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/public", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("detail verdict = %q, want rejected", d.Verdict)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a wildcard allow-origin without credentials must not be reported")
	}
	found := false
	for _, p := range d.Probes {
		if p.Kind == corsKindWildcardPublic {
			found = true
		}
	}
	if !found {
		t.Fatalf("probes = %+v, want one wildcard_public observation", d.Probes)
	}
}

func TestCORSWithoutHeadersIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "same-origin only")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/page", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("no CORS headers must not produce a finding")
	}
}

func TestCORSReflectionWithoutCredentialsIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/public", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	if d := corsDetailOf(t, tc); d.Severity != domain.SeverityMedium {
		t.Fatalf("severity = %q, want medium (%s)", d.Severity, d.Reason)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || findings[0].Severity != domain.SeverityMedium {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCORSPreflightOnlyMiddlewareIsDetected(t *testing.T) {
	var options atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			options.Add(1)
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/preflight", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	if options.Load() != 1 {
		t.Fatalf("OPTIONS requests = %d, want exactly 1", options.Load())
	}
	if len(d.Probes) != 3 || d.Probes[2].Method != http.MethodOptions {
		t.Fatalf("probes = %+v, want 2 GET + 1 OPTIONS", d.Probes)
	}
	if got := d.Probes[2].AllowOrigin; got != corsCanaryOrigin {
		t.Fatalf("preflight ACAO = %q, want the canary origin", got)
	}
}

func TestCORSProbeDoesNotFollowRedirects(t *testing.T) {
	var landing atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landing", http.StatusFound)
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, r *http.Request) {
		landing.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		fmt.Fprint(w, "landing")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/start", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	if landing.Load() != 0 {
		t.Fatalf("the redirect target received %d requests; a CORS probe must measure the endpoint itself", landing.Load())
	}
	if d := corsDetailOf(t, tc); d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a redirect must not be attributed to this endpoint's CORS policy")
	}
}

func TestCORSThrottledBaselineSendsNoOriginProbes(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/limited", domain.MethodGET)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	d := corsDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want throttled", d)
	}
	if len(d.Probes) != 0 {
		t.Fatalf("probes = %d, want 0 after a throttled baseline", len(d.Probes))
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want only the baseline", got)
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a throttled target must not produce a finding")
	}
}

func TestCORSSkipsStateChangingEndpoint(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/update", domain.MethodPOST)
	tc := runCORS(t, env, ep, ExecutorConfig{})
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "state-changing") {
		t.Fatalf("note = %q", tc.Note)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want none", requests.Load())
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatal("a skipped probe must not produce a finding")
	}
}

func TestCORSCorrelatesRepeatedRunsIntoOneFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/account", domain.MethodGET)
	ex := newCORSExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	for i := 0; i < 2; i++ {
		if err := ex.Handle(context.Background(), corsJob(env, ep)); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1 correlated finding", len(findings))
	}
	var fd corsDetail
	if err := json.Unmarshal(findings[0].Detail, &fd); err != nil {
		t.Fatal(err)
	}
	if fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
}

func TestCORSURLEndpointWithoutDiscoveryRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ex := newCORSExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Target: domain.JobTarget{URL: srv.URL + "/direct"},
		Attempts: 1, MaxAttempts: 2,
	}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings := scanFindings(t, env)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed finding for a URL-only job", findings)
	}
}
