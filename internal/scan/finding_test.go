package scan

// Finding correlation tests: confirmed/pending/rejected/inconclusive creation,
// duplicate correlation, distinct parameters/contexts, provenance, and
// evidence linkage (request/response + browser/DOM/screenshot, unioned across
// correlated attempts without ever discarding raw evidence).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// newOKServer starts a trivial 200-OK httptest server and returns its URL.
func newOKServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

// --- pure: dedup key / verdict ordering / set helpers ---

func candAt(category detection.CandidateCategory, ctx detection.Context, value string) detection.Candidate {
	return detection.Candidate{Source: detection.SourceBuiltin, Category: category, Context: ctx, Value: value, DedupKey: value, Priority: 90}
}

func TestFindingDedupKeySameSiteCorrelates(t *testing.T) {
	ip := domain.NewID()
	a := findingDedupKey(ip, candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m1>"))
	b := findingDedupKey(ip, candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>"))
	if a != b {
		t.Fatalf("two candidates at the same injection point/category/context must share a dedup key: %q vs %q", a, b)
	}
}

func TestFindingDedupKeyDistinctParameter(t *testing.T) {
	cand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	a := findingDedupKey(domain.NewID(), cand)
	b := findingDedupKey(domain.NewID(), cand)
	if a == b {
		t.Fatal("different injection points (parameters) must not share a dedup key")
	}
}

func TestFindingDedupKeyDistinctContext(t *testing.T) {
	ip := domain.NewID()
	htmlText := findingDedupKey(ip, candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>"))
	jsString := findingDedupKey(ip, candAt(detection.CatJS, detection.CtxJSString, "';m//"))
	if htmlText == jsString {
		t.Fatal("different reflection contexts at the same injection point must not share a dedup key")
	}
}

func TestVerdictRankOrdering(t *testing.T) {
	order := []domain.Verdict{domain.VerdictPending, domain.VerdictInconclusive, domain.VerdictRejected, domain.VerdictConfirmed}
	for i := 1; i < len(order); i++ {
		if verdictRank(order[i]) <= verdictRank(order[i-1]) {
			t.Fatalf("rank(%s)=%d should exceed rank(%s)=%d", order[i], verdictRank(order[i]), order[i-1], verdictRank(order[i-1]))
		}
	}
}

func TestAppendUniqueIDDedupsAndSkipsEmpty(t *testing.T) {
	ids := appendUniqueID(nil, domain.ID("a"))
	ids = appendUniqueID(ids, domain.ID("a"))
	ids = appendUniqueID(ids, domain.ID("b"))
	ids = appendUniqueID(ids, domain.ID(""))
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want [a b]", ids)
	}
}

func TestAppendUniqueCandidateDedupsByValue(t *testing.T) {
	c1 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	c2 := c1 // identical
	c3 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>")
	cands := appendUniqueCandidate(nil, c1)
	cands = appendUniqueCandidate(cands, c2)
	cands = appendUniqueCandidate(cands, c3)
	if len(cands) != 2 {
		t.Fatalf("candidates = %v, want 2 distinct", cands)
	}
}

// --- upsertPendingFinding: creation, correlation, distinct parameters/contexts, provenance ---

func TestUpsertPendingFindingCreatesNewWithProvenance(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	ep.Source = domain.SourceCrawler
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	cand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	candTC := domain.NewID()

	f, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, candTC)
	if err != nil {
		t.Fatal(err)
	}
	if f.Verdict != domain.VerdictPending || f.VulnClass != domain.VulnReflectedXSS {
		t.Fatalf("finding = %+v", f)
	}
	if f.EndpointID != ep.ID || f.InjectionPointID != ip.ID || f.ParameterID != focus.ID || f.Location != focus.Location {
		t.Fatalf("provenance chain incomplete: %+v", f)
	}
	if f.ProjectID != env.sc.ProjectID {
		t.Fatalf("project id not propagated from scan: %q", f.ProjectID)
	}
	if f.Provenance.Engine != "reflected-xss" || f.Provenance.DiscoverySource != domain.SourceCrawler || f.Provenance.DetectedAt.IsZero() {
		t.Fatalf("provenance wrong: %+v", f.Provenance)
	}
	if f.Provenance.AIAssisted {
		t.Fatal("candidate detection/planning is never AI-assisted here")
	}

	d := decodeFindingDetail(f.Detail)
	if d.Occurrences != 1 || len(d.TestCaseIDs) != 1 || d.TestCaseIDs[0] != candTC || len(d.Candidates) != 1 {
		t.Fatalf("detail wrong: %+v", d)
	}
	if d.ParameterName != "q" || d.Method != domain.MethodGET {
		t.Fatalf("detail parameter/method wrong: %+v", d)
	}
}

func TestUpsertPendingFindingCorrelatesDuplicate(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)

	c1 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	c2 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>") // same site, different candidate
	tc1, tc2 := domain.NewID(), domain.NewID()

	f1, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, c1, tc1)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, c2, tc2)
	if err != nil {
		t.Fatal(err)
	}
	if f1.ID != f2.ID {
		t.Fatalf("two candidates at the same site must correlate into one finding: %s vs %s", f1.ID, f2.ID)
	}

	all, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(all) != 1 {
		t.Fatalf("expected exactly one finding after correlation, got %d", len(all))
	}

	d := decodeFindingDetail(f2.Detail)
	if d.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", d.Occurrences)
	}
	if len(d.TestCaseIDs) != 2 || len(d.Candidates) != 2 {
		t.Fatalf("raw evidence lost on correlation: test_cases=%d candidates=%d", len(d.TestCaseIDs), len(d.Candidates))
	}
}

// Re-correlating the EXACT same candidate (e.g. a retried job) must not
// duplicate it in the raw-evidence list, even though it is still a distinct
// TestCase attempt.
func TestUpsertPendingFindingCorrelatesExactRetryWithoutDuplicatingCandidate(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	cand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")

	if _, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, domain.NewID()); err != nil {
		t.Fatal(err)
	}
	f2, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	d := decodeFindingDetail(f2.Detail)
	if d.Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2 (both attempts counted)", d.Occurrences)
	}
	if len(d.Candidates) != 1 {
		t.Fatalf("the same candidate value must not be duplicated in raw evidence: %v", d.Candidates)
	}
	if len(d.TestCaseIDs) != 2 {
		t.Fatalf("both attempts' test cases must be tracked: %v", d.TestCaseIDs)
	}
}

func TestUpsertPendingFindingDistinctParametersDoNotCorrelate(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "hi")
	r := env.param(ep, "r", domain.LocationQuery, "hi")
	ipQ := env.injection(ep, q)
	ipR := env.injection(ep, r)
	cand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")

	fq, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ipQ.ID, q, cand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	fr, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ipR.ID, r, cand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if fq.ID == fr.ID {
		t.Fatal("different parameters must produce distinct findings even with an identical candidate")
	}
	all, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(all) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(all))
	}
}

func TestUpsertPendingFindingDistinctContextsDoNotCorrelate(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)

	htmlCand := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	jsCand := candAt(detection.CatJS, detection.CtxJSString, "';m//")

	f1, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, htmlCand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	f2, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, jsCand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if f1.ID == f2.ID {
		t.Fatal("two genuinely different reflection contexts at the same injection point must be distinct findings")
	}
}

// --- correlateVerification: confirmed/rejected/inconclusive, monotonic confirm, evidence linkage ---

// buildVerifyJob constructs a JobVerify TestJob carrying CandidateTestCaseID,
// which the shared verifyJobFor test helper (verify_test.go) does not set.
func buildVerifyJob(t *testing.T, scanID domain.ID, target domain.JobTarget, cand detection.Candidate, findingID, candTestCaseID domain.ID) *domain.TestJob {
	t.Helper()
	payload, err := json.Marshal(verifyJob{Candidate: cand, Marker: "mk", FindingID: findingID, CandidateTestCaseID: candTestCaseID})
	if err != nil {
		t.Fatal(err)
	}
	return &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobVerify, Target: target, Payload: payload, Attempts: 1, MaxAttempts: 3}
}

// candidateTestCase persists a TestCase with its own (HTTP) evidence, standing
// in for the candidate execution step that ran before verification.
func (e *scanEnv) candidateTestCase(ip *domain.InjectionPoint, evidenceIDs ...domain.ID) *domain.TestCase {
	e.t.Helper()
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: e.scanID, InjectionPointID: ip.ID, VulnClass: domain.VulnReflectedXSS,
		Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess, EvidenceIDs: evidenceIDs,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.st.TestCases().Create(context.Background(), tc); err != nil {
		e.t.Fatal(err)
	}
	return tc
}

func (e *scanEnv) evidenceRow(kind domain.EvidenceKind) domain.ID {
	e.t.Helper()
	id := domain.NewID()
	ev := &domain.Evidence{ID: id, ScanID: e.scanID, Kind: kind, BlobPath: "x", Size: 1, SHA256: "x", CreatedAt: time.Now()}
	if err := e.st.Evidence().Create(context.Background(), ev); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestCorrelateVerificationConfirmedLinksAllEvidence(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	cand := basicCandidate()

	reqEv, respEv := env.evidenceRow(domain.EvidenceRequest), env.evidenceRow(domain.EvidenceResponse)
	candTC := env.candidateTestCase(ip, reqEv, respEv)
	f, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, candTC.ID)
	if err != nil {
		t.Fatal(err)
	}

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := buildVerifyJob(t, env.scanID, domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand, f.ID, candTC.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	got, err := env.st.Findings().Get(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed", got.Verdict)
	}
	if got.Provenance.VerifiedAt == nil {
		t.Fatal("verified_at not set")
	}
	// request + response (candidate) + screenshot + dom + browser log (verification) = 5.
	if len(got.EvidenceIDs) != 5 {
		t.Fatalf("evidence ids = %v, want 5 (request/response + screenshot/dom/log)", got.EvidenceIDs)
	}
	for _, want := range []domain.ID{reqEv, respEv} {
		found := false
		for _, id := range got.EvidenceIDs {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("candidate's own HTTP evidence %s missing from finding evidence %v", want, got.EvidenceIDs)
		}
	}
}

func TestCorrelateVerificationRejectedDoesNotConfirm(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	cand := basicCandidate()
	candTC := env.candidateTestCase(ip)
	f, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, candTC.ID)

	fv := &fakeVerifier{result: rejectedResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := buildVerifyJob(t, env.scanID, domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand, f.ID, candTC.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", got.Verdict)
	}
}

func TestCorrelateVerificationInconclusiveStaysUnconfirmed(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	cand := basicCandidate()
	candTC := env.candidateTestCase(ip)
	f, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, candTC.ID)

	fv := &fakeVerifier{result: inconclusiveResult()}
	vx := env.verifyExec(fv, openScope(), ExecutorConfig{})
	job := buildVerifyJob(t, env.scanID, domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand, f.ID, candTC.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	got, _ := env.st.Findings().Get(context.Background(), f.ID)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want inconclusive", got.Verdict)
	}
}

// Monotonic confirmation: once a correlated finding is Confirmed, a LATER
// verification of a different candidate at the SAME site that comes back
// Rejected/Inconclusive must never downgrade it — but its evidence (including
// from a run that merely observed unrelated/non-matching browser activity)
// is still linked, never discarded.
func TestCorrelateVerificationConfirmedIsStickyAgainstLaterWeakerResult(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	target := domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}

	cand1 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	cand2 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>")
	tc1 := env.candidateTestCase(ip, env.evidenceRow(domain.EvidenceRequest))
	tc2 := env.candidateTestCase(ip, env.evidenceRow(domain.EvidenceRequest))

	f1, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand1, tc1.ID)
	f2, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand2, tc2.ID)
	if f1.ID != f2.ID {
		t.Fatal("setup: both candidates must correlate into the same finding")
	}

	vx1 := env.verifyExec(&fakeVerifier{result: confirmedResult(verification.SignalPageError)}, openScope(), ExecutorConfig{})
	job1 := buildVerifyJob(t, env.scanID, target, cand1, f1.ID, tc1.ID)
	if err := vx1.Handle(context.Background(), job1); err != nil {
		t.Fatal(err)
	}
	afterFirst, _ := env.st.Findings().Get(context.Background(), f1.ID)
	if afterFirst.Verdict != domain.VerdictConfirmed {
		t.Fatalf("setup: expected confirmed after the first verification, got %s", afterFirst.Verdict)
	}
	evidenceAfterFirst := len(afterFirst.EvidenceIDs)

	vx2 := env.verifyExec(&fakeVerifier{result: rejectedResult()}, openScope(), ExecutorConfig{})
	job2 := buildVerifyJob(t, env.scanID, target, cand2, f1.ID, tc2.ID)
	if err := vx2.Handle(context.Background(), job2); err != nil {
		t.Fatal(err)
	}

	final, _ := env.st.Findings().Get(context.Background(), f1.ID)
	if final.Verdict != domain.VerdictConfirmed {
		t.Fatalf("a confirmed finding must stay confirmed, got %s", final.Verdict)
	}
	if len(final.EvidenceIDs) <= evidenceAfterFirst {
		t.Fatalf("the second attempt's evidence must still be linked (got %d, had %d)", len(final.EvidenceIDs), evidenceAfterFirst)
	}
}

// Inconclusive/Rejected → Confirmed is an allowed UPGRADE: a later candidate at
// the same site that genuinely executes must still promote the finding.
func TestCorrelateVerificationUpgradesToConfirmed(t *testing.T) {
	srv := newOKServer(t)
	env := newScanEnv(t)
	ep := env.endpoint(srv, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	target := domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}

	cand1 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<mx>")
	cand2 := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	tc1 := env.candidateTestCase(ip)
	tc2 := env.candidateTestCase(ip)
	f1, _ := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand1, tc1.ID)

	vx1 := env.verifyExec(&fakeVerifier{result: inconclusiveResult()}, openScope(), ExecutorConfig{})
	if err := vx1.Handle(context.Background(), buildVerifyJob(t, env.scanID, target, cand1, f1.ID, tc1.ID)); err != nil {
		t.Fatal(err)
	}

	vx2 := env.verifyExec(&fakeVerifier{result: confirmedResult(verification.SignalPageError)}, openScope(), ExecutorConfig{})
	if err := vx2.Handle(context.Background(), buildVerifyJob(t, env.scanID, target, cand2, f1.ID, tc2.ID)); err != nil {
		t.Fatal(err)
	}

	final, _ := env.st.Findings().Get(context.Background(), f1.ID)
	if final.Verdict != domain.VerdictConfirmed {
		t.Fatalf("expected an upgrade to confirmed, got %s", final.Verdict)
	}
}

// Candidate source (builtin vs a future advisory llm source) must survive
// correlation unchanged, alongside the builtin one at the same site, so a
// report can always tell which engine proposed which breakout.
func TestUpsertPendingFindingPreservesCandidateSource(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)

	builtin := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<svg onload=m>")
	llm := candAt(detection.CatHTMLText, detection.CtxHTMLText, "<m2x>")
	llm.Source = detection.SourceLLM

	f1, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, builtin, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	f2, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, llm, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if f1.ID != f2.ID {
		t.Fatal("setup: both candidates must correlate into the same finding")
	}

	d := decodeFindingDetail(f2.Detail)
	var sawBuiltin, sawLLM bool
	for _, c := range d.Candidates {
		switch c.Source {
		case detection.SourceBuiltin:
			sawBuiltin = true
		case detection.SourceLLM:
			sawLLM = true
		}
	}
	if !sawBuiltin || !sawLLM {
		t.Fatalf("candidate sources not preserved: %+v", d.Candidates)
	}
}
