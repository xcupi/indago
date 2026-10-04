package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// This file executes the candidate plan the reflection step produces. After a
// reflection job classifies an injection point and plans candidates, it enqueues
// one child test job per candidate (enqueueCandidates). Each child sends its
// single candidate — the benign-marker breakout — into the SAME injection point,
// keeping every other parameter at its observed value, and re-runs reflection
// analysis on the response.
//
// Boundaries (preserved here):
//   - One request per candidate, through the scope-enforcing engine the executor
//     was given; the state-changing safeguard is re-checked in run().
//   - The candidate is a detection probe embedding a benign marker, not an
//     exploit; nothing is weaponized here.
//   - No verdict and no browser verification: the child records whether the
//     marker reflected and in what context, nothing more.

// candidateJob is the queue payload for a candidate test job: the one planned
// candidate to send at this injection point. The candidate carries its own
// source (builtin / llm), so the two remain distinguishable end to end.
type candidateJob struct {
	Candidate detection.Candidate `json:"candidate"`
}

// parseCandidateJob decodes a candidate from a job's payload. It returns
// (_, false, nil) for a job with no payload (a baseline or reflection job) and an
// error only when a payload is present but unusable.
func parseCandidateJob(job *domain.TestJob) (detection.Candidate, bool, error) {
	if len(job.Payload) == 0 {
		return detection.Candidate{}, false, nil
	}
	var cj candidateJob
	if err := json.Unmarshal(job.Payload, &cj); err != nil {
		return detection.Candidate{}, false, fmt.Errorf("decode candidate job payload: %w", err)
	}
	if cj.Candidate.Value == "" {
		return detection.Candidate{}, false, fmt.Errorf("candidate job payload has no candidate value")
	}
	return cj.Candidate, true, nil
}

// enqueueCandidates enqueues one child test job per planned candidate, with the
// candidate carried in the job payload. It runs before the parent reflection job
// completes, so the scan's completion policy waits for the children.
//
// Children keep the parent's target (same endpoint + injection point) and are
// given the candidate's priority, so the queue leases higher-priority candidates
// first — the plan's deterministic order. A nil queue (unit tests) is a no-op.
func (e *executor) enqueueCandidates(ctx context.Context, parent *domain.TestJob, plan *detection.CandidatePlan) {
	if e.queue == nil || plan == nil || len(plan.Candidates) == 0 {
		return
	}
	for i := range plan.Candidates {
		cand := plan.Candidates[i]
		payload, err := json.Marshal(candidateJob{Candidate: cand})
		if err != nil {
			e.log.Warn("marshal candidate job", "job", parent.ID, "err", err)
			continue
		}
		now := time.Now()
		child := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      parent.ScanID,
			Type:        domain.JobTest,
			State:       domain.JobQueued,
			Priority:    cand.Priority,
			Target:      parent.Target,
			Payload:     payload,
			MaxAttempts: parent.MaxAttempts,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := e.queue.Enqueue(ctx, child); err != nil {
			// The reflection result is already persisted; a failed enqueue drops one
			// candidate but does not fail the parent job.
			e.log.Warn("enqueue candidate job", "job", parent.ID, "candidate", cand.DedupKey, "err", err)
		}
	}
}

// runCandidate sends one candidate into its injection point and re-runs reflection
// analysis on the response. It makes NO verdict and performs NO browser
// verification; it records whether — and in what context — the marker reflected.
func (e *executor) runCandidate(ctx context.Context, tc *domain.TestCase, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter, cand detection.Candidate) result {
	tc.VulnClass = domain.VulnReflectedXSS
	note := fmt.Sprintf("candidate %s/%s; parameter %s (%s)", cand.Source, cand.Category, focus.Name, focus.Location)

	// Baseline (shared with the reflection step via the same per-endpoint cache).
	baseReq, err := buildRequest(ep, params, nil)
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: note, vulnClass: domain.VulnReflectedXSS}
	}
	bl, outcome, err := e.baseline(ctx, tc.ScanID, baseReq)
	if outcome != domain.OutcomeSuccess {
		return result{
			outcome:   outcome,
			permanent: outcome == domain.OutcomeError && isPermanentRequestError(err),
			err:       err,
			note:      note + " (baseline failed)",
			vulnClass: domain.VulnReflectedXSS,
		}
	}

	// Mutated request: the candidate value goes ONLY into the focused parameter;
	// all other parameters keep their observed values.
	mutReq, err := buildRequest(ep, params, &injection{param: focus, value: cand.Value})
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: note, vulnClass: domain.VulnReflectedXSS, sharedEvidence: bl.evidenceIDs()}
	}
	tc.URL = mutReq.URL

	resp, outcome, err, dur := e.send(ctx, mutReq)
	r := result{
		note:           note,
		duration:       dur,
		vulnClass:      domain.VulnReflectedXSS,
		req:            capturedFrom(mutReq, resp),
		resp:           resp,
		sharedEvidence: bl.evidenceIDs(),
	}
	if outcome != domain.OutcomeSuccess {
		r.outcome = outcome
		r.err = err
		r.permanent = outcome == domain.OutcomeError && isPermanentRequestError(err)
		return r
	}

	// Re-run reflection analysis for the SAME marker (the candidate embeds the
	// injection point's probe token). It records whether and where the marker came
	// back; it does NOT re-plan candidates and makes no verdict.
	probe := detection.NewProbe(tc.ScanID, tc.InjectionPointID)
	report := detection.AnalyzeReflection(probe, bl.body, resp.Body)
	report.Parameter = focus.Name
	report.Location = focus.Location
	report.Baseline = detection.ResponseSummary{Status: bl.status, BodyLen: bl.bodyLen}
	report.Mutated = detection.ResponseSummary{Status: resp.Status, BodyLen: len(resp.Body)}
	report.Candidate = &cand // mark this as a candidate re-analysis, not a fresh probe
	detection.ClassifyContexts(&report, resp.Body, detection.ContextOptions{
		ContentType: resp.Headers.Get("Content-Type"),
	})

	r.outcome = domain.OutcomeSuccess
	if report.Reflected {
		r.note = fmt.Sprintf("%s: reflected at %d location(s); %s", note, report.Count, contextSummary(&report))
	} else {
		r.note = note + ": not reflected"
	}
	r.reflection = &report
	r.baselineReq, r.baselineResp = bl.reqEvidence, bl.respEvidence
	return r
}
