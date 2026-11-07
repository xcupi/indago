package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

func completedEscalationJob(t *testing.T, q queue.Queue, scanID domain.ID, job *domain.TestJob) {
	t.Helper()
	if err := q.Enqueue(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	leased, err := q.Lease(context.Background(), "test", scanID, []domain.JobType{domain.JobTest}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if leased.ID != job.ID {
		t.Fatalf("leased job = %s, want %s", leased.ID, job.ID)
	}
	if err := q.Complete(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
}

// evasionController has a real (test-double) verifier rather than the default
// no-browser Stub. Automatic escalation is only meaningful when a candidate
// could still produce the product's deterministic confirmation signal.
func evasionController(env *scanEnv, q queue.Queue) *Controller {
	return NewController(env.st, q, execLog(), "test", Options{Verification: &fakeVerifier{result: rejectedResult()}})
}

func escalationParent(t *testing.T, env *scanEnv, q queue.Queue, ep *domain.Endpoint, ip *domain.InjectionPoint) (*domain.TestJob, *detection.ReflectionReport) {
	t.Helper()
	probe := detection.NewProbe(env.scanID, ip.ID)
	body := []byte("<p>" + probe.Value() + "</p>")
	rep := detection.AnalyzeReflection(probe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	detection.PlanCandidates(&rep, detection.PlanOptions{
		ScanID:           env.scanID,
		InjectionPointID: ip.ID,
		Profile:          detection.ProfileSpec{Name: detection.ProfileStandard, MaxPerInjectionPoint: 8},
	})
	if rep.Plan == nil || len(rep.Plan.Candidates) == 0 {
		t.Fatal("setup: canonical plan is empty")
	}

	parent := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, MaxAttempts: 3,
	}
	completedEscalationJob(t, q, env.scanID, parent)
	detail, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := env.st.TestCases().Create(context.Background(), &domain.TestCase{
		ID: domain.NewID(), ScanID: env.scanID, JobID: parent.ID, InjectionPointID: ip.ID,
		VulnClass: domain.VulnReflectedXSS, Status: domain.TestCaseCompleted,
		Outcome: domain.OutcomeSuccess, Detail: detail, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return parent, &rep
}

func TestEnqueueEvasionEscalationCandidates_QueuesOneBoundedTechniquePassAfterCanonicalSuccesses(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)

	// Each canonical candidate completed with durable execution evidence and
	// without producing a confirmation.
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	c := evasionController(env, q)
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

	jobs, err := q.Jobs(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	var automatic []detection.Candidate
	for _, job := range jobs {
		cand, ok, err := parseCandidateJob(job)
		if err != nil || !ok || cand.Technique == "" {
			continue
		}
		automatic = append(automatic, cand)
	}
	if len(automatic) == 0 {
		t.Fatal("canonical failures did not enqueue an automatic evasion pass")
	}
	if len(automatic) > detection.MaxEvasionCandidatesPerInjectionPoint {
		t.Fatalf("automatic pass has %d candidates, ceiling is %d", len(automatic), detection.MaxEvasionCandidatesPerInjectionPoint)
	}
	for _, cand := range automatic {
		if cand.InjectionPointID != ip.ID || cand.ScanID != env.scanID {
			t.Fatalf("automatic candidate lost provenance: %+v", cand)
		}
		if cand.Variation != "" {
			t.Fatalf("automatic pass must be technique-only, got variation %q", cand.Variation)
		}
	}

	// The same quiet-tick/restart reconciliation must not enqueue a second pass.
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)
	after, err := q.Jobs(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(jobs) {
		t.Fatalf("second automatic escalation changed job count: first=%d second=%d", len(jobs), len(after))
	}
}

func TestEvaluateRunsAutomaticEvasionBeforeOtherQuietQueueFallbacks(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	c := evasionController(env, q)
	ex := &execution{scanID: env.scanID}
	ex.discFinished.Store(true)
	if done := c.evaluate(ctx, ex); done {
		t.Fatal("quiet evaluation completed the scan instead of starting the automatic evasion fallback")
	}
	if !ex.evasionPassDone.Load() {
		t.Fatal("quiet evaluation did not record that the automatic evasion pass ran")
	}
	if ex.combinedPassDone.Load() {
		t.Fatal("automatic evasion must run before the unrelated combined-candidate fallback")
	}
	jobs, err := q.Jobs(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		cand, ok, err := parseCandidateJob(job)
		if err == nil && ok && cand.Technique != "" {
			return
		}
	}
	t.Fatal("evaluate queued no automatic evasion candidate")
}

// canonicalCandidateJob is the child job the reflection step would have
// enqueued for cand at this exact injection point.
func canonicalCandidateJob(t *testing.T, env *scanEnv, ep *domain.Endpoint, ip *domain.InjectionPoint, cand detection.Candidate) *domain.TestJob {
	t.Helper()
	payload, err := json.Marshal(candidateJob{Candidate: cand})
	if err != nil {
		t.Fatal(err)
	}
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target:  domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID},
		Payload: payload, MaxAttempts: 3,
	}
}

// completedCanonicalEscalationJob mirrors a real candidate run's durable
// evidence: Queue.JobSucceeded is not sufficient because a skipped handler
// also completes its queue job without sending the candidate request.
func completedCanonicalEscalationJob(t *testing.T, env *scanEnv, q queue.Queue, ep *domain.Endpoint, ip *domain.InjectionPoint, cand detection.Candidate) *domain.TestJob {
	t.Helper()
	job := canonicalCandidateJob(t, env, ep, ip, cand)
	completedEscalationJob(t, q, env.scanID, job)
	now := time.Now()
	if err := env.st.TestCases().Create(context.Background(), &domain.TestCase{
		ID: domain.NewID(), ScanID: env.scanID, JobID: job.ID, InjectionPointID: ip.ID,
		VulnClass: domain.VulnReflectedXSS, Status: domain.TestCaseCompleted,
		Outcome: domain.OutcomeSuccess, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return job
}

// automaticTechniqueCandidates returns only the Technique-tagged candidate
// jobs the queue holds — the automatic escalation's own output, never the
// canonical children the test enqueued itself.
func automaticTechniqueCandidates(t *testing.T, q queue.Queue, scanID domain.ID) []detection.Candidate {
	t.Helper()
	jobs, err := q.Jobs(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	var out []detection.Candidate
	for _, job := range jobs {
		cand, ok, err := parseCandidateJob(job)
		if err != nil || !ok || cand.Technique == "" {
			continue
		}
		out = append(out, cand)
	}
	return out
}

func drainQueuedTestJobs(t *testing.T, q queue.Queue, scanID domain.ID) {
	t.Helper()
	for {
		job, err := q.Lease(context.Background(), "test", scanID, []domain.JobType{domain.JobTest}, time.Minute)
		if errors.Is(err, queue.ErrNoJobs) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Complete(context.Background(), job.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnqueueEvasionEscalationCandidates_FailsClosedOnConfirmedFinding(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}
	now := time.Now()
	if err := env.st.Findings().Create(ctx, &domain.Finding{
		ID: domain.NewID(), ScanID: env.scanID, ProjectID: env.sc.ProjectID,
		VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		EndpointID: ep.ID, InjectionPointID: ip.ID, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	c := evasionController(env, q)
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("confirmed injection point still escalated: %+v", got)
	}
}

func TestEnqueueEvasionEscalationCandidates_FailsClosedOnIncompleteCanonicalChild(t *testing.T) {
	for _, mode := range []string{"missing", "queued", "dead"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			env := newScanEnv(t)
			ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
			p := env.param(ep, "q", domain.LocationQuery, "hello")
			ip := env.injection(ep, p)
			q := queue.NewMemory()
			_, rep := escalationParent(t, env, q, ep, ip)
			last := len(rep.Plan.Candidates) - 1
			for i, cand := range rep.Plan.Candidates {
				if i != last {
					completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
					continue
				}
				job := canonicalCandidateJob(t, env, ep, ip, cand)
				if mode == "missing" {
					// The plan says this candidate exists, but its child job
					// never reached the queue (e.g. a crash between planning
					// and enqueueing): treat the point as incomplete.
					continue
				}
				if err := q.Enqueue(ctx, job); err != nil {
					t.Fatal(err)
				}
				if mode == "dead" {
					if _, err := q.Lease(ctx, "test", env.scanID, []domain.JobType{domain.JobTest}, time.Minute); err != nil {
						t.Fatal(err)
					}
					if err := q.Fail(ctx, job.ID, "transport error", false); err != nil {
						t.Fatal(err)
					}
				}
			}

			c := evasionController(env, q)
			c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

			if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
				t.Fatalf("incomplete canonical plan still escalated: %+v", got)
			}
		})
	}
}

func TestEnqueueEvasionEscalationCandidates_SkipsExplicitEnableEvasionScan(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}
	sc, err := env.st.Scans().Get(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	sc.Config.EnableEvasion = true
	if err := env.st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}

	c := evasionController(env, q)
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

	// An explicit scan already planned its bypass set eagerly; the automatic
	// pass must never add a second copy on top.
	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("explicit EnableEvasion scan got a duplicate automatic pass: %+v", got)
	}
}

func TestEnqueueEvasionEscalationCandidates_FailsClosedOnMalformedTechniqueJob(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}
	// A prior automatic pass whose record cannot be decoded must be treated as
	// "already attempted", not as an absent technique job — otherwise a restart
	// would re-send the same bypass shapes.
	if err := q.Enqueue(ctx, &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target:  domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID},
		Payload: []byte("{not valid json"), MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}

	c := evasionController(env, q)
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("malformed existing technique job did not suppress escalation: %+v", got)
	}
}

func TestEnqueueEvasionEscalationCandidates_FailsClosedOnUnattributableTechniqueJob(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}
	// A decodable technique job that carries no injection point cannot be
	// reconciled with any plan; it must suppress the whole pass, not be
	// silently ignored.
	payload, err := json.Marshal(candidateJob{Candidate: detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText,
		Value: "<svg onload=x>", Technique: "case_variation", DedupKey: "tech",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID}, Payload: payload, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	before, err := q.Jobs(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}

	c := evasionController(env, q)
	c.enqueueEvasionEscalationCandidates(ctx, env.scanID)

	after, err := q.Jobs(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("unattributable technique job did not suppress escalation: before=%d after=%d", len(before), len(after))
	}
}

func TestEvaluateRunsCombinedFallbackOnlyAfterAutomaticEvasionDrained(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	c := evasionController(env, q)
	ex := &execution{scanID: env.scanID}
	ex.discFinished.Store(true)
	if done := c.evaluate(ctx, ex); done {
		t.Fatal("first quiet evaluation completed the scan")
	}
	first := automaticTechniqueCandidates(t, q, env.scanID)
	if len(first) == 0 {
		t.Fatal("first quiet evaluation enqueued no automatic evasion candidate")
	}

	// Let the automatic jobs drain; the NEXT quiet tick is the combined pass,
	// never a second evasion pass.
	drainQueuedTestJobs(t, q, env.scanID)
	if done := c.evaluate(ctx, ex); done {
		t.Fatal("second quiet evaluation completed the scan before the combined fallback")
	}
	if !ex.combinedPassDone.Load() {
		t.Fatal("combined fallback did not run after the automatic evasion pass drained")
	}
	if again := automaticTechniqueCandidates(t, q, env.scanID); len(again) != len(first) {
		t.Fatalf("automatic evasion ran twice: first=%d second=%d", len(first), len(again))
	}
}

func TestEnqueueEvasionEscalationCandidates_SkipsCaptchaDiagnostic(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}
	now := time.Now()
	captcha := findingDetail{DedupKey: captchaFindingDedupKey(ip.ID), CaptchaSuspected: true}
	if err := env.st.Findings().Create(ctx, &domain.Finding{
		ID: domain.NewID(), ScanID: env.scanID, ProjectID: env.sc.ProjectID,
		VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictInconclusive,
		EndpointID: ep.ID, InjectionPointID: ip.ID, Detail: captcha.encode(),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)
	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("CAPTCHA diagnostic must suppress automatic evasion, got %+v", got)
	}
}

func TestEnqueueEvasionEscalationCandidates_FillsMissingTechniqueJobsAfterRestart(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	want := detection.EvasionEscalationCandidates(rep, detection.PlanOptions{
		ScanID: env.scanID, InjectionPointID: ip.ID,
		Profile: detection.ProfileSpec{Name: detection.ProfileStandard, MaxPerInjectionPoint: 8},
	})
	if len(want) < 2 {
		t.Fatalf("setup: need at least two technique candidates, got %+v", want)
	}
	payload, err := json.Marshal(candidateJob{Candidate: want[0]})
	if err != nil {
		t.Fatal(err)
	}
	// A prior execution already persisted one of the fallback jobs before it
	// stopped. Restart reconciliation must preserve it and enqueue only the
	// remaining DedupKeys, not abandon the tail or duplicate the first job.
	if err := q.Enqueue(ctx, &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, Payload: payload, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)
	got := automaticTechniqueCandidates(t, q, env.scanID)
	gotKeys := map[string]int{}
	for _, cand := range got {
		gotKeys[cand.DedupKey]++
	}
	if len(gotKeys) != len(want) {
		t.Fatalf("restart reconciliation got %d technique keys, want %d: %+v", len(gotKeys), len(want), got)
	}
	for _, cand := range want {
		if gotKeys[cand.DedupKey] != 1 {
			t.Fatalf("technique %q count=%d, want exactly one after restart reconciliation", cand.DedupKey, gotKeys[cand.DedupKey])
		}
	}
}

func TestEnqueueEvasionEscalationCandidates_RequiresARealVerifier(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	NewController(env.st, q, execLog(), "test", Options{}).enqueueEvasionEscalationCandidates(ctx, env.scanID)
	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("Stub verifier cannot confirm execution; automatic evasion must not add target requests: %+v", got)
	}
}

func TestEnqueueEvasionEscalationCandidates_RequiresCompletedCandidateEvidence(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		// JobSucceeded alone is not evidence that the candidate request ran:
		// Handle returns nil for a state-changing skip. No completed-success
		// TestCase is deliberately persisted for this fixture.
		completedEscalationJob(t, q, env.scanID, canonicalCandidateJob(t, env, ep, ip, cand))
	}

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)
	if got := automaticTechniqueCandidates(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("candidate jobs without completed-success evidence still escalated: %+v", got)
	}
}
