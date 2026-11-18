package scan

// Path traversal / file inclusion engine tests: payload wire form, Unix and
// Windows confirmation, the baseline and negative-control false-positive
// guards, evidence/finding persistence, and the two policy switches
// (SkipWriteEndpoints, SkipPathTraversal).
//
// Everything is hermetic: targets are httptest servers that return a
// well-known file's content for the value they are given. No test reads a real
// file, reaches a real network, or writes anything to a target.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

const (
	ptModeUnix     = "unix"
	ptModeWindows  = "windows"
	ptModeAlways   = "always"
	ptModeNegative = "negative"
	ptModeNone     = "none"
)

// ptPasswdContent / ptWinINIContent are the multi-token file signatures the
// engine confirms on. They match the real files closely enough that a
// regression in the token count or the section list fails a test.
const (
	ptPasswdContent = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
	ptWinINIContent = "[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n"
	ptPlainPage     = "<html><body><h1>Product page</h1><p>Nothing to see here.</p></body></html>"
)

// ptTarget is a file-reading endpoint: it serves the file whose path appears in
// the focused parameter. mode controls how faithfully it behaves.
type ptTarget struct {
	srv    *httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	raw    []string
	values []string
	mode   string
}

func newPTTarget(t *testing.T, mode string) *ptTarget {
	t.Helper()
	tg := &ptTarget{mode: mode}
	tg.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tg.hits.Add(1)
		value := ptTargetValue(r)
		tg.mu.Lock()
		tg.raw = append(tg.raw, r.URL.RawQuery)
		tg.values = append(tg.values, value)
		tg.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch {
		case mode == ptModeAlways:
			_, _ = io.WriteString(w, ptPasswdContent)
		case mode == ptModeNegative && strings.Contains(value, "indago-nonexistent"):
			// An endpoint that serves a default file for a path it cannot find:
			// the negative control must catch this.
			_, _ = io.WriteString(w, ptPasswdContent)
		case mode == ptModeUnix && strings.Contains(value, "etc/passwd"):
			_, _ = io.WriteString(w, ptPasswdContent)
		case mode == ptModeWindows && strings.Contains(strings.ToLower(value), "win.ini"):
			_, _ = io.WriteString(w, ptWinINIContent)
		default:
			_, _ = io.WriteString(w, ptPlainPage)
		}
	}))
	t.Cleanup(tg.srv.Close)
	return tg
}

func (tg *ptTarget) rawQueries() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.raw...)
}

// ptTargetValue reads the tested value wherever the engine put it: the file or
// page query/form parameter, the URL path (a path-segment injection point), then
// any query value.
func ptTargetValue(r *http.Request) string {
	for _, name := range []string{"file", "page"} {
		if v := r.FormValue(name); v != "" {
			return v
		}
	}
	if r.URL.RawQuery == "" && r.URL.Path != "" {
		return r.URL.Path
	}
	for _, vs := range r.URL.Query() {
		if len(vs) > 0 {
			return vs[0]
		}
	}
	return r.URL.Path
}

type ptRun struct {
	env      *scanEnv
	tc       *domain.TestCase
	detail   ptDetail
	findings []*domain.Finding
}

func ptExercise(t *testing.T, tg *ptTarget, name string, loc domain.ParamLocation, method domain.HTTPMethod, cfg ExecutorConfig) ptRun {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(tg.srv.URL+"/download", method)
	focus := env.param(ep, name, loc, "index.html")
	ip := env.injection(ep, focus)
	ex := newPathTraversalExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobPathTraversal,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("test cases = %d, want 1", len(cases))
	}
	var d ptDetail
	if len(cases[0].Detail) > 0 {
		if err := json.Unmarshal(cases[0].Detail, &d); err != nil {
			t.Fatalf("decode detail: %v (raw %s)", err, string(cases[0].Detail))
		}
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return ptRun{env: env, tc: cases[0], detail: d, findings: findings}
}

// --- confirmation --------------------------------------------------------

func TestPathTraversalConfirmsUnixPasswd(t *testing.T) {
	tg := newPTTarget(t, ptModeUnix)
	run := ptExercise(t, tg, "file", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	if run.tc.Status != domain.TestCaseCompleted || run.tc.VulnClass != domain.VulnPathTraversal {
		t.Fatalf("test case = %+v, want a completed path_traversal case", run.tc)
	}
	if run.detail.Verdict != domain.VerdictConfirmed || run.detail.ConfirmSignature != ptConfirmUnixPasswd {
		t.Fatalf("verdict/signature = %s/%q, want confirmed/unix_passwd (%+v)", run.detail.Verdict, run.detail.ConfirmSignature, run.detail)
	}
	if !run.detail.NegativeControlSeen {
		t.Fatal("a confirmation must be backed by a completed negative control")
	}
	if len(run.tc.EvidenceIDs) == 0 {
		t.Fatal("no evidence was attached to the confirmed case")
	}
	if len(run.findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1", len(run.findings))
	}
	f := run.findings[0]
	if f.VulnClass != domain.VulnPathTraversal || f.Verdict != domain.VerdictConfirmed || f.Severity != domain.SeverityHigh {
		t.Fatalf("finding = %+v, want a confirmed high-severity path_traversal", f)
	}
	if f.ParameterID == "" || len(f.EvidenceIDs) == 0 {
		t.Fatalf("finding is missing parameter/evidence provenance: %+v", f)
	}
	if ptDetailOfFinding(t, f).DedupKey == "" {
		t.Fatal("confirmed finding carries no dedup key")
	}
}

// The encoding-trick payload must reach the wire ONCE encoded; a double-encoded
// "..%252f" would test nothing. A clean target keeps every payload in play, so
// the raw shape is observable.
func TestPathTraversalSendsRawEncodingPayloadVerbatim(t *testing.T) {
	tg := newPTTarget(t, ptModeNone)
	ptExercise(t, tg, "file", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	sawEncoded := false
	for _, raw := range tg.rawQueries() {
		if strings.Contains(raw, "%252f") || strings.Contains(raw, "%252F") {
			t.Fatalf("payload was double-encoded on the wire: %q", raw)
		}
		if strings.Contains(raw, "..%2f") || strings.Contains(raw, "..%2F") {
			sawEncoded = true
		}
	}
	if !sawEncoded {
		t.Fatalf("the ..%%2f payload never reached the wire verbatim: %v", tg.rawQueries())
	}
}

// A path-segment injection point is recorded as a coverage boundary, never
// attacked: the scope validator refuses every traversal shape in a request path,
// so sending a payload there would only produce an out-of-scope error.
func TestPathTraversalSkipsPathSegmentInjectionPoint(t *testing.T) {
	tg := newPTTarget(t, ptModeUnix)
	env := newScanEnv(t)
	ep := env.endpoint(tg.srv.URL+"/download/123", domain.MethodGET)
	focus := env.param(ep, discovery.PathSegmentParamName(1), domain.LocationPath, "123")
	ip := env.injection(ep, focus)
	ex := newPathTraversalExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobPathTraversal,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].Status != domain.TestCaseSkipped || !strings.Contains(cases[0].Note, "path-segment injection point") {
		t.Fatalf("cases = %+v, want one skipped path-segment case", cases)
	}
	if hits := tg.hits.Load(); hits != 0 {
		t.Fatalf("target hits = %d, want 0: the scope layer would refuse every traversal path", hits)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestPathTraversalConfirmsWindowsINI(t *testing.T) {
	tg := newPTTarget(t, ptModeWindows)
	run := ptExercise(t, tg, "page", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	if run.detail.Verdict != domain.VerdictConfirmed || run.detail.ConfirmSignature != ptConfirmWindowsINI {
		t.Fatalf("verdict/signature = %s/%q, want confirmed/windows_win.ini (%+v)", run.detail.Verdict, run.detail.ConfirmSignature, run.detail)
	}
	if len(run.findings) != 1 || run.findings[0].VulnClass != domain.VulnPathTraversal {
		t.Fatalf("findings = %+v, want one path_traversal finding", run.findings)
	}
}

// A page that simply serves passwd content for EVERY value (including the
// untouched baseline) is not traversal: nothing can be attributed to a payload.
func TestPathTraversalBaselineSignatureSuppressesFinding(t *testing.T) {
	tg := newPTTarget(t, ptModeAlways)
	run := ptExercise(t, tg, "file", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	if run.detail.Verdict != domain.VerdictRejected || !strings.Contains(run.detail.Reason, "baseline") {
		t.Fatalf("verdict = %s (%s), want rejected because the baseline already matched", run.detail.Verdict, run.detail.Reason)
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(run.findings))
	}
	if run.detail.SentCount != 0 || len(run.detail.Attempts) != 0 {
		t.Fatalf("no payload may be sent once the baseline matches: sent=%d attempts=%d", run.detail.SentCount, len(run.detail.Attempts))
	}
	if hits := tg.hits.Load(); hits != 1 {
		t.Fatalf("target hits = %d, want 1 (baseline only)", hits)
	}
}

// An endpoint that returns a fixed file for a path it cannot find would look
// exactly like traversal without the control.
func TestPathTraversalNegativeControlSuppressesFinding(t *testing.T) {
	tg := newPTTarget(t, ptModeNegative)
	run := ptExercise(t, tg, "file", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	if run.detail.Verdict != domain.VerdictRejected || !strings.Contains(run.detail.Reason, "nonexistent") {
		t.Fatalf("verdict = %s (%s), want rejected because the control matched", run.detail.Verdict, run.detail.Reason)
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(run.findings))
	}
	if run.detail.SentCount != 0 || len(run.detail.Attempts) != 0 {
		t.Fatalf("no payload may be sent once the control matches: sent=%d", run.detail.SentCount)
	}
	if hits := tg.hits.Load(); hits != 2 {
		t.Fatalf("target hits = %d, want 2 (baseline + control)", hits)
	}
}

// A clean target produces a rejected case with evidence and no finding.
func TestPathTraversalCleanTargetIsRejected(t *testing.T) {
	tg := newPTTarget(t, ptModeNone)
	run := ptExercise(t, tg, "file", domain.LocationQuery, domain.MethodGET, ExecutorConfig{})

	if run.detail.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", run.detail.Verdict)
	}
	if run.detail.SentCount != len(ptPayloads()) {
		t.Fatalf("sent = %d, want the whole bounded set (%d)", run.detail.SentCount, len(ptPayloads()))
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(run.findings))
	}
	if len(run.tc.EvidenceIDs) == 0 {
		t.Fatal("a rejected case still keeps its request/response evidence")
	}
}

// --- policy --------------------------------------------------------------

func TestPathTraversalSkipWriteEndpoints(t *testing.T) {
	tg := newPTTarget(t, ptModeUnix)
	run := ptExercise(t, tg, "file", domain.LocationForm, domain.MethodPOST,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: true})

	if run.tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", run.tc.Status)
	}
	if !strings.Contains(run.tc.Note, "skip_write_endpoints") {
		t.Fatalf("skip note = %q, want it to name the policy", run.tc.Note)
	}
	if hits := tg.hits.Load(); hits != 0 {
		t.Fatalf("target hits = %d, want 0: a skipped write endpoint must receive nothing", hits)
	}
	if len(run.findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(run.findings))
	}
}

// Without AllowStateChanging the engine refuses a POST endpoint even when
// SkipWriteEndpoints is off — the read-only pass never sends a write itself.
func TestPathTraversalRefusesStateChangingEndpointWithoutOptIn(t *testing.T) {
	tg := newPTTarget(t, ptModeUnix)
	run := ptExercise(t, tg, "file", domain.LocationForm, domain.MethodPOST, ExecutorConfig{})

	if run.tc.Status != domain.TestCaseSkipped || !strings.Contains(strings.ToLower(run.tc.Note), "allowstatechanging is off") {
		t.Fatalf("case = %+v, want a skipped case naming AllowStateChanging", run.tc)
	}
	if tg.hits.Load() != 0 {
		t.Fatalf("target hits = %d, want 0", tg.hits.Load())
	}
}

// SkipPathTraversal stops the pass before any job is queued.
func TestSkipPathTraversalEnqueuesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		skip bool
		want int
	}{
		{"enabled", false, 1},
		{"skipped", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipPathTraversal: tc.skip}, CreatedAt: now, UpdatedAt: now}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}
			ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: "https://example.test/download?id=1",
				Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
			if err := st.Endpoints().Create(ctx, ep); err != nil {
				t.Fatal(err)
			}
			p := &domain.Parameter{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID, Name: "file",
				Location: domain.LocationQuery, Example: "report.pdf", Source: domain.SourceForm, CreatedAt: now}
			if err := st.Parameters().Create(ctx, p); err != nil {
				t.Fatal(err)
			}
			ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID,
				ParameterID: p.ID, Location: p.Location, CreatedAt: now}
			if err := st.InjectionPoints().Create(ctx, ip); err != nil {
				t.Fatal(err)
			}

			ctrl := NewController(st, q, execLog(), "test", Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueuePathTraversalProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			if tc.want > 0 {
				if jobs[0].Type != domain.JobPathTraversal || jobs[0].Priority != 45 {
					t.Fatalf("job = %+v, want a priority-45 path_traversal job", jobs[0])
				}
			}
		})
	}
}

// A generic endpoint whose parameters are not file selectors must not be
// queued: the pass is name/shape gated, never sprayed.
func TestEnqueuePathTraversalProbesSkipsUnrelatedParameters(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	now := time.Now()
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: "https://example.test/users",
		Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	p := &domain.Parameter{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID, Name: "sort",
		Location: domain.LocationQuery, Example: "asc", Source: domain.SourceForm, CreatedAt: now}
	if err := st.Parameters().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID,
		ParameterID: p.ID, Location: p.Location, CreatedAt: now}
	if err := st.InjectionPoints().Create(ctx, ip); err != nil {
		t.Fatal(err)
	}
	ctrl := NewController(st, q, execLog(), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctrl.enqueuePathTraversalProbes(ctx, sc.ID)
	jobs, err := q.Jobs(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("jobs = %d, want 0 for a non-file parameter on a generic endpoint", len(jobs))
	}
}

// Path-segment points are queued under their own small cap so a target full of
// them can never starve the budget testable query/form points need.
func TestEnqueuePathTraversalProbesCapsPathSegmentSkips(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	now := time.Now()
	sc := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: now, UpdatedAt: now}
	if err := st.Scans().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: sc.ID, URL: "https://example.test/download/42",
		Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}
	addParam := func(name string, loc domain.ParamLocation, example string) *domain.InjectionPoint {
		t.Helper()
		p := &domain.Parameter{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID, Name: name,
			Location: loc, Example: example, Source: domain.SourceForm, CreatedAt: now}
		if err := st.Parameters().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: sc.ID, EndpointID: ep.ID,
			ParameterID: p.ID, Location: loc, CreatedAt: now}
		if err := st.InjectionPoints().Create(ctx, ip); err != nil {
			t.Fatal(err)
		}
		return ip
	}
	testable := map[domain.ID]bool{}
	for _, name := range []string{"file", "page"} {
		testable[addParam(name, domain.LocationQuery, "report.pdf").ID] = true
	}
	for i := 1; i <= maxPathSegmentSkips+3; i++ {
		addParam(discovery.PathSegmentParamName(i), domain.LocationPath, "42")
	}

	ctrl := NewController(st, q, execLog(), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctrl.enqueuePathTraversalProbes(ctx, sc.ID)

	jobs, err := q.Jobs(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != len(testable)+maxPathSegmentSkips {
		t.Fatalf("jobs = %d, want %d (every testable point + the capped path-segment skips)", len(jobs), len(testable)+maxPathSegmentSkips)
	}
	seen := map[domain.ID]bool{}
	for _, j := range jobs {
		if j.Type != domain.JobPathTraversal {
			t.Fatalf("job type = %s, want path_traversal", j.Type)
		}
		seen[j.Target.InjectionPointID] = true
	}
	for ip := range testable {
		if !seen[ip] {
			t.Fatal("a testable query point was crowded out by path-segment points")
		}
	}
}

// --- applicability and signatures ---------------------------------------

func TestPathTraversalParameterNames(t *testing.T) {
	for _, name := range []string{
		"file", "filename", "file_name", "filePath", "path", "page", "template",
		"view", "doc", "document", "include", "lang", "language", "locale",
		"dir", "folder", "download", "read", "load", "report", "resource",
		"src", "url", "name", "templateName",
	} {
		if !ptParamName(name) {
			t.Errorf("ptParamName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"id", "q", "sort", "username", "profile", "csrf_token", "email"} {
		if ptParamName(name) {
			t.Errorf("ptParamName(%q) = true, want false", name)
		}
	}
}

func TestPathTraversalEndpointShapes(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://example.test/download.php?id=1", true},
		{"https://example.test/view/doc", true},
		{"https://example.test/files/report", true},
		{"https://example.test/page/home", true},
		{"https://example.test/include/main", true},
		{"https://example.test/users/42/profile", false},
	} {
		ep := &domain.Endpoint{ID: domain.NewID(), URL: tc.url, Method: domain.MethodGET, CreatedAt: now}
		if got := ptEndpointFileShape(ep); got != tc.want {
			t.Errorf("ptEndpointFileShape(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestPathTraversalSignatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"passwd", ptPasswdContent, ptConfirmUnixPasswd},
		{"win.ini", ptWinINIContent, ptConfirmWindowsINI},
		{"plain page", ptPlainPage, ""},
		{"one passwd token is not enough", "root:x:0:0:root:/root:/bin/bash\n", ""},
		{"fonts alone is not enough", "[fonts]\r\n", ""},
		{"a quoted traversal payload is not a file", "../../../../etc/passwd", ""},
	} {
		if got := ptFileSignature(tc.body); got != tc.want {
			t.Errorf("%s: ptFileSignature = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// ptDetailOfFinding decodes the engine detail blob a Finding carries.
func ptDetailOfFinding(t *testing.T, f *domain.Finding) ptDetail {
	t.Helper()
	var d ptDetail
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatalf("decode finding detail: %v", err)
	}
	return d
}
