package scan

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// evasionEscalationSource is one completed, canonical reflected-XSS plan that
// is eligible for exactly one automatic fallback pass. parent is retained so
// the child jobs inherit the exact endpoint, injection point, and retry budget
// that the canonical plan used.
type evasionEscalationSource struct {
	parent          *domain.TestJob
	report          *detection.ReflectionReport
	techniqueQueued map[string]bool
}

// enqueueEvasionEscalationCandidates enqueues a single, bounded filter-bypass
// pass only after all canonical candidates for an injection point completed
// without a confirmed Reflected-XSS finding. It runs from execution.evaluate's
// quiet tick, so no canonical candidate or browser-verification job is still
// pending when this decision is made.
//
// An explicit EnableEvasion scan retains its established behavior: it already
// planned the bypass set at the start, so this fallback must not duplicate it.
// The durable Technique-job ledger records already-enqueued DedupKeys; after a
// restart an interrupted pass queues only its missing tail, which keeps it
// idempotent without replaying a bypass shape the target already received.
func (c *Controller) enqueueEvasionEscalationCandidates(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("evasion escalation: load scan", "scan", scanID, "err", err)
		return
	}
	if sc.Config.EnableEvasion {
		return
	}
	profile, err := detection.ResolveProfile(sc.Config.CandidateProfile, sc.Config.MaxCandidates)
	if err != nil {
		c.log.Warn("evasion escalation: invalid candidate profile; using standard", "scan", scanID, "err", err)
		profile, _ = detection.ResolveProfile("", 0)
	}

	cases, err := c.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("evasion escalation: list test cases", "scan", scanID, "err", err)
		return
	}
	jobs, err := c.queue.Jobs(ctx, scanID)
	if err != nil {
		c.log.Warn("evasion escalation: list jobs", "scan", scanID, "err", err)
		return
	}
	findings, err := c.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("evasion escalation: list findings", "scan", scanID, "err", err)
		return
	}

	n := 0
	for _, src := range selectEvasionEscalationSources(cases, jobs, findings) {
		if !c.evasionEscalationCanVerify(ctx, src.parent) {
			continue
		}
		candidates := detection.EvasionEscalationCandidates(src.report, detection.PlanOptions{
			ScanID:           scanID,
			InjectionPointID: src.parent.Target.InjectionPointID,
			Profile:          profile,
		})
		for _, cand := range candidates {
			// A restart can happen after only a prefix of the pass was
			// persisted. The durable queue is the ledger: retain every existing
			// Technique job (even dead/cancelled) and enqueue only the missing
			// shapes. That completes one interrupted pass without replaying a
			// bypass the target already received.
			if src.techniqueQueued[cand.DedupKey] {
				continue
			}
			if c.enqueueEvasionEscalationCandidate(ctx, src.parent, cand) {
				n++
			}
		}
	}
	if n > 0 {
		c.log.Info("evasion escalation: enqueued", "scan", scanID, "candidates", n)
	}
}

// selectEvasionEscalationSources is the fail-closed eligibility gate. A source
// qualifies only when its persisted parent reflection succeeded, every one of
// its canonical child jobs reached JobSucceeded, no confirmed finding exists at
// that injection point, and no prior Technique-tagged candidate was enqueued.
// A missing/malformed record is therefore a reason to skip escalation, never a
// reason to send more target-facing requests.
func selectEvasionEscalationSources(cases []*domain.TestCase, jobs []*domain.TestJob, findings []*domain.Finding) []evasionEscalationSource {
	jobsByID := make(map[domain.ID]*domain.TestJob, len(jobs))
	completedTestCase := make(map[domain.ID]bool, len(cases))
	for _, tc := range cases {
		if tc != nil && tc.Status == domain.TestCaseCompleted && tc.Outcome == domain.OutcomeSuccess {
			completedTestCase[tc.JobID] = true
		}
	}
	canonicalSucceeded := map[domain.ID]map[string]bool{}
	techniqueQueued := map[domain.ID]map[string]bool{}
	malformedInjection := map[domain.ID]bool{}
	malformedUnattributed := false
	for _, job := range jobs {
		if job == nil {
			continue
		}
		jobsByID[job.ID] = job
		if job.Type != domain.JobTest || len(job.Payload) == 0 {
			continue
		}
		cand, hasCandidate, err := parseCandidateJob(job)
		if err != nil || !hasCandidate {
			// A candidate-shaped job whose payload cannot be decoded may be a
			// prior automatic pass. Fail closed for its point (or the whole
			// pass when it cannot even be attributed) rather than guess that no
			// bypass was tried and re-send one.
			if job.Target.InjectionPointID.Empty() {
				malformedUnattributed = true
			} else {
				malformedInjection[job.Target.InjectionPointID] = true
			}
			continue
		}
		if job.Target.InjectionPointID.Empty() {
			// Every candidate job is created for one injection point; a
			// candidate record without one cannot be reconciled with a plan.
			malformedUnattributed = true
			continue
		}
		if cand.Technique != "" {
			if techniqueQueued[job.Target.InjectionPointID] == nil {
				techniqueQueued[job.Target.InjectionPointID] = map[string]bool{}
			}
			techniqueQueued[job.Target.InjectionPointID][cand.DedupKey] = true
			continue
		}
		if cand.Variation != "" || cand.Combined || job.State != domain.JobSucceeded || !completedTestCase[job.ID] {
			continue
		}
		if canonicalSucceeded[job.Target.InjectionPointID] == nil {
			canonicalSucceeded[job.Target.InjectionPointID] = map[string]bool{}
		}
		canonicalSucceeded[job.Target.InjectionPointID][cand.DedupKey] = true
	}
	// An unattributable malformed candidate record means the stored plan cannot
	// be trusted at all: skip escalation for the whole scan.
	if malformedUnattributed {
		return nil
	}

	confirmed := map[domain.ID]bool{}
	captchaSuspected := map[domain.ID]bool{}
	throttled := map[domain.ID]bool{}
	for _, finding := range findings {
		if finding == nil || finding.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		d := decodeFindingDetail(finding.Detail)
		if finding.Verdict == domain.VerdictConfirmed {
			confirmed[finding.InjectionPointID] = true
		}
		// CAPTCHA handling stays detect-only. A CAPTCHA diagnostic is not a
		// normal filter miss to escalate through: automatic payload-shape
		// retries there would contradict AGENTS.md §2.2's absolute boundary.
		if d.CaptchaSuspected {
			captchaSuspected[finding.InjectionPointID] = true
		}
		// A 429/503 point was throttled or unavailable, so its canonical
		// misses say nothing about the filter. Re-sending bypass shapes
		// there would ignore the target's own backpressure and record
		// meaningless "rejected" attempts; a 403 stays eligible because that
		// IS a filter deciding on the payload (AGENTS.md §2.2).
		if d.Throttled {
			throttled[finding.InjectionPointID] = true
		}
	}

	byInjection := map[domain.ID]evasionEscalationSource{}
	for _, tc := range cases {
		if tc == nil || tc.VulnClass != domain.VulnReflectedXSS || tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess || tc.InjectionPointID.Empty() || len(tc.Detail) == 0 {
			continue
		}
		parent := jobsByID[tc.JobID]
		if parent == nil || parent.Type != domain.JobTest || len(parent.Payload) != 0 || parent.State != domain.JobSucceeded {
			continue
		}
		if confirmed[tc.InjectionPointID] || captchaSuspected[tc.InjectionPointID] || throttled[tc.InjectionPointID] || malformedInjection[tc.InjectionPointID] {
			continue
		}
		report, err := detection.ParseReflection(tc.Detail)
		if err != nil || report == nil || report.Candidate != nil || report.Plan == nil || !report.Reflected || !allCanonicalCandidatesSucceeded(report.Plan, canonicalSucceeded[tc.InjectionPointID]) {
			continue
		}
		// At most one plan per injection point. Parent jobs/test cases are
		// persisted in creation order, but sort below makes the result stable
		// even for store implementations that do not promise that ordering.
		if _, exists := byInjection[tc.InjectionPointID]; !exists {
			byInjection[tc.InjectionPointID] = evasionEscalationSource{
				parent:          parent,
				report:          report,
				techniqueQueued: techniqueQueued[tc.InjectionPointID],
			}
		}
	}

	out := make([]evasionEscalationSource, 0, len(byInjection))
	for _, src := range byInjection {
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].parent.Target.InjectionPointID < out[j].parent.Target.InjectionPointID
	})
	return out
}

// evasionEscalationCanVerify keeps the fallback tied to the product's evidence
// contract. A stub verifier or a request shape that the browser-verification
// engine cannot replay would turn the extra probe traffic into a blind retry,
// so those cases are deliberately ineligible.
func (c *Controller) evasionEscalationCanVerify(ctx context.Context, parent *domain.TestJob) bool {
	if parent == nil || parent.Target.EndpointID.Empty() || parent.Target.InjectionPointID.Empty() {
		return false
	}
	if c.opts.Verification == nil && c.browserManager() == nil {
		return false
	}
	ip, err := c.store.InjectionPoints().Get(ctx, parent.Target.InjectionPointID)
	if err != nil || ip == nil || ip.EndpointID != parent.Target.EndpointID {
		return false
	}
	ep, err := c.store.Endpoints().Get(ctx, parent.Target.EndpointID)
	if err != nil || ep == nil || !canBrowserVerify(ep.Method, ip.Location) {
		return false
	}
	if !c.opts.Executor.AllowStateChanging && !isSafeMethod(ep.Method) {
		return false
	}
	return true
}

func allCanonicalCandidatesSucceeded(plan *detection.CandidatePlan, completed map[string]bool) bool {
	if plan == nil || len(plan.Candidates) == 0 {
		return false
	}
	n := 0
	for _, cand := range plan.Candidates {
		// An automatic pass only follows a canonical plan. A Technique or
		// Variation marker here means this was produced by an explicit option
		// or a newer planner and cannot safely be treated as the prerequisite.
		if cand.Technique != "" || cand.Variation != "" || cand.Combined {
			return false
		}
		n++
		if completed == nil || !completed[cand.DedupKey] {
			return false
		}
	}
	return n > 0
}

func (c *Controller) enqueueEvasionEscalationCandidate(ctx context.Context, parent *domain.TestJob, cand detection.Candidate) bool {
	if parent == nil || cand.Technique == "" {
		return false
	}
	payload, err := json.Marshal(candidateJob{Candidate: cand})
	if err != nil {
		c.log.Warn("evasion escalation: marshal candidate", "scan", parent.ScanID, "candidate", cand.DedupKey, "err", err)
		return false
	}
	maxAttempts := parent.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	now := time.Now()
	job := &domain.TestJob{
		ID:          domain.NewID(),
		ScanID:      parent.ScanID,
		Type:        domain.JobTest,
		State:       domain.JobQueued,
		Priority:    cand.Priority,
		Target:      parent.Target,
		Payload:     payload,
		MaxAttempts: maxAttempts,
		AvailableAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := c.queue.Enqueue(ctx, job); err != nil {
		c.log.Warn("evasion escalation: enqueue candidate", "scan", parent.ScanID, "candidate", cand.DedupKey, "err", err)
		return false
	}
	return true
}
