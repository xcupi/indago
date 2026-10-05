package scan

// Verify-executor tests: enqueueing a Finding+JobVerify when a candidate
// reflects, outcome mapping (confirmed/rejected/inconclusive/timeout/
// cancelled/skipped), state-changing and GET/HEAD-only guards, session/scope
// pass-through, and evidence/Finding persistence — all against a FAKE
// verification.Verifier so these run fast and deterministically. Real-browser
// behavior (the signal itself, authenticated navigation, scope-gated
// subresources) is covered by internal/verification's own integration tests.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/verification"
)

// --- fake verifier ---

type fakeVerifier struct {
	mu     sync.Mutex
	calls  []verification.Input
	result *verification.Result
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, in verification.Input) (*verification.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	f.mu.Unlock()
	return f.result, f.err
}

func (f *fakeVerifier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeVerifier) lastInput() verification.Input {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func confirmedResult(signal verification.Signal) *verification.Result {
	return &verification.Result{
		Verdict: domain.VerdictConfirmed, Confidence: domain.ConfidenceHigh, Notes: "execution verified",
		Report:   &verification.Report{Engine: "browser-verification", Signal: signal},
		Evidence: verification.ResultEvidence{Screenshot: []byte("\x89PNG-fake"), DOMHTML: "<html>fake</html>", BrowserLog: []string{"ReferenceError: x"}},
	}
}

func rejectedResult() *verification.Result {
	return &verification.Result{
		Verdict: domain.VerdictRejected, Confidence: domain.ConfidenceHigh, Notes: "reflection only",
		Report: &verification.Report{Engine: "browser-verification", Signal: verification.SignalNone, MarkerInDOM: true},
	}
}

func inconclusiveResult() *verification.Result {
	return &verification.Result{
		Verdict: domain.VerdictInconclusive, Confidence: domain.ConfidenceLow, Notes: "could not confirm",
		Report: &verification.Report{Engine: "browser-verification", Signal: verification.SignalNone},
	}
}

// --- fixtures ---

// scanEnv extends execEnv with a persisted Scan row (enqueueVerification needs
// one to resolve ProjectID) and helpers for verify-job plumbing.
type scanEnv struct {
	*execEnv
	sc *domain.Scan
}

func newScanEnv(t *testing.T) *scanEnv {
	t.Helper()
	e := newExecEnv(t)
	sc := &domain.Scan{ID: e.scanID, ProjectID: domain.NewID(), State: domain.ScanRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.st.Scans().Create(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	return &scanEnv{execEnv: e, sc: sc}
}

func (e *scanEnv) verifyExec(v verification.Verifier, scope domain.Scope, cfg ExecutorConfig) *verifyExecutor {
	return newVerifyExecutor(e.st, v, e.ev, scope, cfg, execLog(), nil)
}

func (e *scanEnv) verifyJobFor(target domain.JobTarget, cand detection.Candidate, findingID domain.ID) *domain.TestJob {
	e.t.Helper()
	payload, err := json.Marshal(verifyJob{Candidate: cand, Marker: "mk", FindingID: findingID})
	if err != nil {
		e.t.Fatal(err)
	}
	return &domain.TestJob{ID: domain.NewID(), ScanID: e.scanID, Type: domain.JobVerify, Target: target, Payload: payload, Attempts: 1, MaxAttempts: 3}
}

func (e *scanEnv) pendingFinding(ep *domain.Endpoint, ip *domain.InjectionPoint) *domain.Finding {
	e.t.Helper()
	now := time.Now()
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: e.scanID, ProjectID: e.sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: domain.VerdictPending, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceLow,
		EndpointID: ep.ID, InjectionPointID: ip.ID, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.st.Findings().Create(context.Background(), f); err != nil {
		e.t.Fatal(err)
	}
	return f
}

func basicCandidate() detection.Candidate {
	return detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=mk>", Priority: 90, DedupKey: "k"}
}

// --- enqueueVerification: triggered by a reflected candidate ---

func TestEnqueueVerificationOnReflectedCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := detection.NewProbe(env.scanID, ip.ID).Token

	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{})
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %v (err %v), want exactly 1", findings, err)
	}
	f := findings[0]
	if f.Verdict != domain.VerdictPending || f.VulnClass != domain.VulnReflectedXSS || f.EndpointID != ep.ID || f.InjectionPointID != ip.ID {
		t.Fatalf("pending finding wrong: %+v", f)
	}

	vj, err := q.Lease(context.Background(), "w", env.scanID, []domain.JobType{domain.JobVerify}, time.Minute)
	if err != nil {
		t.Fatalf("no verify job enqueued: %v", err)
	}
	cj, err := parseVerifyJob(vj)
	if err != nil {
		t.Fatalf("verify job payload: %v", err)
	}
	if cj.FindingID != f.ID || cj.Candidate.Value != cand.Value || cj.Marker != m {
		t.Fatalf("verify job payload wrong: %+v", cj)
	}
	if vj.Priority != cand.Priority || vj.Target.EndpointID != ep.ID || vj.Target.InjectionPointID != ip.ID {
		t.Fatalf("verify job target/priority wrong: %+v", vj)
	}
}

// A candidate reflecting on a state-changing (POST) endpoint never gets browser
// verification in this phase: navigation carries no body.
// A candidate reflecting on a POST endpoint still gets a Pending finding (it
// is just as real a candidate as a GET one), but — unlike a GET/HEAD one — no
// browser-verify job is ever enqueued for it: browser navigation has no
// request body, so it can never confirm/reject a POST candidate regardless of
// AllowStateChanging. The finding simply stays Pending forever (see
// docs/scan-orchestration.md).
func TestEnqueueVerificationSkippedForStateChangingEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		b, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "<p>"+string(b)+"</p>")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	ip := env.injection(ep, focus)
	m := detection.NewProbe(env.scanID, ip.ID).Token

	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{AllowStateChanging: true})
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	findings, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictPending {
		t.Fatalf("expected exactly one Pending finding for the POST candidate, got %+v", findings)
	}
	if st, _ := q.Stats(context.Background(), env.scanID); st.Total() != 0 {
		t.Fatalf("no verify job should be enqueued for a POST candidate, queue total = %d", st.Total())
	}
}

// --- verifyExecutor.Handle: outcome mapping ---

func TestVerifyHandleConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)

	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if fv.callCount() != 1 {
		t.Fatalf("verifier called %d times, want 1", fv.callCount())
	}

	tc := env.only()
	if tc.Outcome != domain.OutcomeSuccess || tc.VulnClass != domain.VulnReflectedXSS {
		t.Fatalf("test case: outcome=%s vuln=%s", tc.Outcome, tc.VulnClass)
	}
	if len(tc.Detail) == 0 {
		t.Fatal("expected a marshaled verification report in Detail")
	}
	if len(tc.EvidenceIDs) != 3 { // screenshot + DOM + browser log
		t.Fatalf("evidence ids = %v, want 3 (screenshot/dom/log)", tc.EvidenceIDs)
	}
	for _, id := range tc.EvidenceIDs {
		row, text := env.evidenceBlob(id)
		if row.SHA256 == "" || text == "" {
			t.Fatalf("evidence blob incomplete: %+v", row)
		}
	}

	got, err := env.st.Findings().Get(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed || got.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding not promoted: %+v", got)
	}
	if len(got.EvidenceIDs) != 3 || got.Provenance.VerifiedAt == nil {
		t.Fatalf("finding evidence/provenance not updated: %+v", got)
	}
}

func TestVerifyHandleRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: rejectedResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", got.Verdict)
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("a rejected verdict is still a SUCCESSFUL execution, got outcome=%s", tc.Outcome)
	}
}

func TestVerifyHandleInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: inconclusiveResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive", got.Verdict)
	}
}

func TestVerifyHandleTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{err: context.DeadlineExceeded}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	err := vx.Handle(context.Background(), job)
	if err == nil {
		t.Fatal("a timeout should be a retryable (non-nil) error")
	}

	tc := env.only()
	if tc.Outcome != domain.OutcomeTimeout || tc.Status != domain.TestCaseFailed {
		t.Fatalf("test case: outcome=%s status=%s", tc.Outcome, tc.Status)
	}
	// A timed-out attempt does not touch the pending finding.
	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictPending {
		t.Fatalf("finding should remain pending after a timeout, got %s", got.Verdict)
	}
}

func TestVerifyHandleCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{err: context.Canceled}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Handle runs
	err := vx.Handle(ctx, job)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeCancelled || tc.Status != domain.TestCaseCancelled {
		t.Fatalf("test case: outcome=%s status=%s", tc.Outcome, tc.Status)
	}
	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictPending {
		t.Fatalf("finding should remain pending after cancellation, got %s", got.Verdict)
	}
}

// verification.ErrNotImplemented (no browser configured for the scan) must be a
// clean skip, not a failure, and must leave the finding untouched.
func TestVerifyHandleNoBrowserConfiguredSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	vx := env.verifyExec(verification.Stub{}, openScope(), ExecutorConfig{}) // newVerifyExecutor also defaults nil->Stub
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("a skipped job must succeed, got %v", err)
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictPending {
		t.Fatalf("finding should remain pending when no browser is configured, got %s", got.Verdict)
	}
}

// --- guards ---

func TestVerifyHandleStateChangingGuard(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{}) // AllowStateChanging off
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("skipped job must succeed: %v", err)
	}
	if fv.callCount() != 0 {
		t.Fatal("the verifier must not be called when the endpoint is state-changing and AllowStateChanging is off")
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
}

// Even with AllowStateChanging on, browser verification itself only supports
// GET/HEAD navigation (no request body) — a defensive second gate independent
// of the one in executor.go that decides whether to enqueue at all.
func TestVerifyHandleNonGETSkippedEvenIfAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{AllowStateChanging: true})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatalf("skipped job must succeed: %v", err)
	}
	if fv.callCount() != 0 {
		t.Fatal("a POST target must never reach the browser verifier (no request body in navigation)")
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped", tc.Status)
	}
}

// --- pass-through: scope and authenticated session reach verification.Input ---

func TestVerifyPassesScopeAndSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	now := time.Now()
	sess := &domain.Session{ID: domain.NewID(), ScanID: env.scanID, StatePath: "/tmp/indago-session.json", CreatedAt: now, UpdatedAt: now}
	if err := env.st.Sessions().Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/s"}}
	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, scope, ExecutorConfig{})
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	in := fv.lastInput()
	if in.SessionStatePath != sess.StatePath {
		t.Fatalf("session state path = %q, want %q", in.SessionStatePath, sess.StatePath)
	}
	if len(in.Scope.IncludeHosts) != 1 || in.Scope.IncludeHosts[0] != "127.0.0.1" {
		t.Fatalf("scope not passed through: %+v", in.Scope)
	}
	if in.Marker != "mk" || in.Candidate.Value != basicCandidate().Value {
		t.Fatalf("candidate/marker not passed through: %+v", in)
	}
}

// --- malformed/missing payload ---

func TestVerifyHandleBadPayload(t *testing.T) {
	env := newScanEnv(t)
	fv := &fakeVerifier{}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobVerify, Attempts: 1, MaxAttempts: 3} // no payload
	err := vx.Handle(context.Background(), job)
	if err == nil {
		t.Fatal("expected an error for a verify job with no payload")
	}
	if fv.callCount() != 0 {
		t.Fatal("the verifier must not be called for a malformed job")
	}
}
