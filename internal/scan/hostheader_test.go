package scan

// Host-header inspection tests: the pure analyzer (baseline subtraction, URL
// boundary) and the executor against real httptest servers (clean site,
// reflection in a Location / body, the Host override, baseline false-positive
// suppression, per-origin deduplication, throttling, skips, cache-busting).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// runHostHeader executes one JobHostHeader for ep and returns that job's test
// case. Extra cases from earlier runs are ignored.
func runHostHeader(t *testing.T, env *scanEnv, eng httpengine.Engine, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobHostHeader,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newHostHeaderExecutor(env.st, eng, env.ev, cfg, execLog(), nil)
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

func hhDetailOf(t *testing.T, tc *domain.TestCase) hostHeaderDetail {
	t.Helper()
	var d hostHeaderDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func hhFindingDetail(t *testing.T, f *domain.Finding) hostHeaderDetail {
	t.Helper()
	var d hostHeaderDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("unmarshal finding detail: %v (%s)", err, string(f.Detail))
	}
	return d
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

func TestAnalyzeHostHeaderCleanResponseHasNoVector(t *testing.T) {
	baseline := hhResponse{Status: 200}
	control := hhResponse{Status: 200}
	if got := analyzeHostHeader(baseline, control, hhCanaryHost); len(got) != 0 {
		t.Fatalf("vectors = %v, want none", got)
	}
}

// The baseline subtraction: a vector that already carried the canary before the
// control header was sent is NOT attributable to that header.
func TestAnalyzeHostHeaderSubtractsTheBaseline(t *testing.T) {
	control := hhResponse{
		Status: 302,
		Header: http.Header{"Location": []string{"http://" + hhCanaryHost + "/login"}},
		Body:   []byte(`<a href="http://` + hhCanaryHost + `/x">x</a>`),
	}
	// Baseline carries the body vector but not the Location one.
	baseline := hhResponse{Status: 200, Body: []byte(`<a href="http://` + hhCanaryHost + `/x">x</a>`)}
	got := analyzeHostHeader(baseline, control, hhCanaryHost)
	if len(got) != 1 || got[0] != hhKindLocation {
		t.Fatalf("vectors = %v, want only %q (the body URL was already there)", got, hhKindLocation)
	}

	// When the baseline carries the same vector too, nothing is reported.
	baseline.Header = http.Header{"Location": []string{"http://" + hhCanaryHost + "/login"}}
	if got := analyzeHostHeader(baseline, control, hhCanaryHost); len(got) != 0 {
		t.Fatalf("vectors = %v, want none (every vector was already in the baseline)", got)
	}
}

func TestAnalyzeHostHeaderRefreshVector(t *testing.T) {
	control := hhResponse{Status: 200, Header: http.Header{"Refresh": []string{"0; url=https://" + hhCanaryHost + "/next"}}}
	if got := analyzeHostHeader(hhResponse{Status: 200}, control, hhCanaryHost); len(got) != 1 || got[0] != hhKindRefresh {
		t.Fatalf("vectors = %v, want [%q]", got, hhKindRefresh)
	}
}

func TestHHBodyHasAbsoluteURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"absolute http URL", `<a href="http://` + hhCanaryHost + `/reset">x</a>`, true},
		{"absolute https URL, upper case", `<a href="HTTPS://` + strings.ToUpper(hhCanaryHost) + `/reset">x</a>`, true},
		{"absolute URL with a port", `{"next":"http://` + hhCanaryHost + `:8443/x"}`, true},
		{"bare host with no scheme", `host=` + hhCanaryHost, false},
		{"a longer host that merely starts with the canary", `http://` + hhCanaryHost + `.evil.test/x`, false},
		{"relative URL", `<a href="/` + hhCanaryHost + `/x">x</a>`, false},
		{"empty body", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hhBodyHasAbsoluteURL([]byte(tc.body), hhCanaryHost); got != tc.want {
				t.Fatalf("hhBodyHasAbsoluteURL(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// Every probe URL must be cache-busted without disturbing the original query.
func TestHHCacheBusted(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://app.test/a", "http://app.test/a?" + hhCacheBusterParam + "=tok"},
		{"http://app.test/a?x=1", "http://app.test/a?x=1&" + hhCacheBusterParam + "=tok"},
		{"http://app.test/a?", "http://app.test/a?" + hhCacheBusterParam + "=tok"},
		{"http://app.test/a?x=1#frag", "http://app.test/a?x=1&" + hhCacheBusterParam + "=tok#frag"},
	} {
		if got := hhCacheBusted(tc.in, "tok"); got != tc.want {
			t.Errorf("hhCacheBusted(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// executor against a real server
// ---------------------------------------------------------------------------

// (a) A clean site: no findings, and every request carried a distinct
// cache-buster so no shared cache was read or written.
func TestHostHeaderCleanSiteProducesNoFinding(t *testing.T) {
	var mu sync.Mutex
	var busters []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		busters = append(busters, r.URL.Query().Get(hhCacheBusterParam))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected (%s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) != 0 {
		t.Fatalf("signals = %+v, want none", d.Signals)
	}
	if len(d.Probes) != len(hhControlHeaders) {
		t.Fatalf("probes = %d, want %d", len(d.Probes), len(hhControlHeaders))
	}
	for _, p := range d.Probes {
		if p.Reflected {
			t.Fatalf("probe %+v reports a reflection on a clean site", p)
		}
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatalf("a clean site produced findings: %+v", scanFindings(t, env))
	}
	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("test case = %s/%s, want completed/success", tc.Status, tc.Outcome)
	}
	mu.Lock()
	bustersCopy := append([]string(nil), busters...)
	mu.Unlock()
	if len(bustersCopy) != 1+len(hhControlHeaders) {
		t.Fatalf("requests = %d, want one baseline plus one control per header", len(bustersCopy))
	}
	seen := map[string]bool{}
	for _, b := range bustersCopy {
		if b == "" {
			t.Fatalf("a probe was sent without a cache-buster: %v", bustersCopy)
		}
		if seen[b] {
			t.Fatalf("a cache-buster was reused (%q): %v", b, bustersCopy)
		}
		seen[b] = true
	}
}

// (b) X-Forwarded-Host reflected in a Location redirect: a confirmed finding
// backed by the stored request/response evidence.
func TestHostHeaderReflectedInLocationProducesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			w.Header().Set("Location", "http://"+xfh+"/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/account", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) != 1 || d.Signals[0].Kind != hhKindLocation || d.Signals[0].Header != "X-Forwarded-Host" {
		t.Fatalf("signals = %+v, want one X-Forwarded-Host Location signal", d.Signals)
	}
	if len(tc.EvidenceIDs) < 2 {
		t.Fatalf("test case evidence = %d, want at least the request+response pair", len(tc.EvidenceIDs))
	}
	foundEvidence := false
	for _, id := range tc.EvidenceIDs {
		_, body := env.evidenceBlob(id)
		if strings.Contains(body, "Location: http://"+hhCanaryHost) {
			foundEvidence = true
		}
	}
	if !foundEvidence {
		t.Fatal("no stored evidence blob contains the reflected Location header")
	}

	findings := findingsByClass(t, env, domain.VulnHostHeader)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (%+v)", len(findings), findings)
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityMedium || f.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding = %s/%s/%s, want confirmed/medium/high", f.Verdict, f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "127.0.0.1") {
		t.Fatalf("finding title %q does not name the origin host", f.Title)
	}
	if len(f.EvidenceIDs) < 2 {
		t.Fatalf("finding carries no request/response evidence: %+v", f.EvidenceIDs)
	}
	fd := hhFindingDetail(t, f)
	if fd.DedupKey != hostHeaderDedupKey(d.Origin) || fd.Occurrences != 1 {
		t.Fatalf("finding detail = %+v, want the origin dedup key and one occurrence", fd)
	}
	if len(fd.Signals) != 1 || fd.Signals[0].Observed == "" {
		t.Fatalf("finding signals = %+v, want the observed Location", fd.Signals)
	}
}

// (c) The canary reflected into an absolute URL in the response body.
func TestHostHeaderReflectedInBodyProducesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			_, _ = w.Write([]byte(`<html><body><a href="https://` + xfh + `/reset">reset</a></body></html>`))
			return
		}
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/forgot", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	if len(d.Signals) != 1 || d.Signals[0].Kind != hhKindBodyURL {
		t.Fatalf("signals = %+v, want one body-URL signal", d.Signals)
	}
	if len(findingsByClass(t, env, domain.VulnHostHeader)) != 1 {
		t.Fatal("the reflected body URL produced no finding")
	}
}

// (d) The real Host header (httpengine.Request.Host) is honoured: a server that
// trusts r.Host must be caught by the same check.
func TestHostHeaderHostOverrideIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == hhCanaryHost {
			w.Header().Set("Location", "http://"+r.Host+"/next")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/admin", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (%s)", d.Verdict, d.Reason)
	}
	var hostProbe *hostHeaderProbe
	for i := range d.Probes {
		if d.Probes[i].Header == "Host" {
			hostProbe = &d.Probes[i]
		}
	}
	if hostProbe == nil || !hostProbe.Reflected {
		t.Fatalf("probes = %+v, want the Host probe reflected", d.Probes)
	}
	if len(hostProbe.Vectors) != 1 || hostProbe.Vectors[0] != hhKindLocation {
		t.Fatalf("Host probe vectors = %v, want [%q]", hostProbe.Vectors, hhKindLocation)
	}
}

// (e) The canary already present in the baseline is not a finding: the check
// only reports what APPEARED because of the control header.
func TestHostHeaderBaselineAlreadyContainsCanaryProducesNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>docs: use http://` + hhCanaryHost + `/ when testing</body></html>`))
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/docs", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected || len(d.Signals) != 0 {
		t.Fatalf("detail = %+v, want rejected with no signal", d)
	}
	if findings := findingsByClass(t, env, domain.VulnHostHeader); len(findings) != 0 {
		t.Fatalf("a baseline-only occurrence produced findings: %+v", findings)
	}
}

// (f) Two jobs on ONE origin collapse into one finding: correlation never
// multiplies one origin's host handling into near-duplicate rows.
func TestHostHeaderDeduplicatesPerOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			w.Header().Set("Location", "http://"+xfh+"/x")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	eng := shEngineFor(t, false)
	first := env.endpoint(srv.URL+"/a", domain.MethodGET)
	second := env.endpoint(srv.URL+"/b", domain.MethodGET)

	tc1 := runHostHeader(t, env, eng, first, ExecutorConfig{})
	afterFirst := len(scanFindings(t, env))
	if afterFirst != 1 {
		t.Fatalf("findings after the first origin job = %d, want 1", afterFirst)
	}
	tc2 := runHostHeader(t, env, eng, second, ExecutorConfig{})

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d after a second job on the same origin, want 1 (deduplicated)", len(findings))
	}
	fd := hhFindingDetail(t, findings[0])
	if fd.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", fd.Occurrences)
	}
	if len(fd.TestCaseIDs) != 2 {
		t.Fatalf("test cases = %d, want both contributing cases (%v)", len(fd.TestCaseIDs), fd.TestCaseIDs)
	}
	wantEvidence := len(tc1.EvidenceIDs) + len(tc2.EvidenceIDs)
	if len(findings[0].EvidenceIDs) != wantEvidence {
		t.Fatalf("finding evidence = %d, want %d (unioned, never discarded)", len(findings[0].EvidenceIDs), wantEvidence)
	}
}

// A throttled baseline is backpressure, not a verdict: nothing is reported and
// no control request is sent.
func TestHostHeaderThrottledBaselineSendsNoControl(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/limited", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want throttled", d)
	}
	if len(d.Probes) != 0 {
		t.Fatalf("probes = %+v, want none after a throttled baseline", d.Probes)
	}
	if hits.Load() != 1 {
		t.Fatalf("target hits = %d, want only the baseline", hits.Load())
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatalf("a throttled response produced findings: %+v", scanFindings(t, env))
	}
}

// A throttled control stops the pass and never becomes a finding.
func TestHostHeaderThrottledControlIsNotAFinding(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Forwarded-Host") != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/limited", domain.MethodGET)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

	d := hhDetailOf(t, tc)
	if !d.Throttled || d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("detail = %+v, want throttled+inconclusive", d)
	}
	if hits.Load() != 2 {
		t.Fatalf("target hits = %d, want the baseline plus the first control only", hits.Load())
	}
	if len(scanFindings(t, env)) != 0 {
		t.Fatalf("a throttled control produced findings: %+v", scanFindings(t, env))
	}
}

// A state-changing endpoint is skipped without a single request.
func TestHostHeaderSkipsStateChangingEndpoint(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/orders", domain.MethodPOST)
	tc := runHostHeader(t, env, shEngineFor(t, false), ep, ExecutorConfig{})

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
func TestHostHeaderURLEOnlyJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Host") != "" {
			w.Header().Set("Location", "http://"+r.Header.Get("X-Forwarded-Host")+"/x")
			w.WriteHeader(http.StatusFound)
			return
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobHostHeader,
		Target: domain.JobTarget{URL: srv.URL + "/detached"}, Attempts: 1, MaxAttempts: 2,
	}
	ex := newHostHeaderExecutor(env.st, shEngineFor(t, false), env.ev, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (err %v), want 1", len(cases), err)
	}
	if d := hhDetailOf(t, cases[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed", d.Verdict)
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// One job per ORIGIN, never one per URL, and the skip switch disables the pass.
func TestEnqueueHostHeaderProbesDeduplicatesPerOrigin(t *testing.T) {
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
				Config: domain.ScanConfig{SkipHostHeader: tc.skip}, CreatedAt: now, UpdatedAt: now}
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
			ctrl.enqueueHostHeaderProbes(ctx, sc.ID)

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
				if job.Type != domain.JobHostHeader || job.Priority != hostHeaderPriority {
					t.Fatalf("job = %+v, want a priority-%d host_header job", job, hostHeaderPriority)
				}
				if job.Target.EndpointID.Empty() {
					t.Fatalf("job %s carries no endpoint id", job.ID)
				}
				origins[hostHeaderOrigin(job.Target.URL)] = true
			}
			if len(origins) != 2 {
				t.Fatalf("origins = %v, want exactly the two distinct origins", origins)
			}
		})
	}
}
