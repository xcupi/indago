package scan

// This file is the browser-verification half of Reflected XSS: it turns a
// candidate that reflected into a Finding, and runs the JobVerify job that
// confirms or rejects it using a real, authenticated browser (via
// verification.Verifier) instead of ever trusting an HTTP-only result.
//
// Boundaries (preserved here, see AGENTS.md §2):
//   - A reflected candidate is Pending, nothing more, until browser verification
//     runs. The verdict itself is decided by verification (deterministic Go
//     code), never by this file and never by an LLM.
//   - Scope is enforced for every verification request via the same
//     domain.Scope the HTTP engine uses, passed straight through to the browser's
//     AllowRequest gate.
//   - Browser navigation carries no request body, so only a GET/HEAD-navigable
//     candidate is verified (enforced by the caller in executor.go and, as
//     defense in depth, inside verification.BrowserVerifier itself).
//   - No LLM, no new payloads: the candidate's Value is replayed unchanged.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
	"github.com/indago/indago/internal/worker"
)

// verifyJob is the queue payload for a JobVerify job: which candidate to
// verify, its probe marker, the Finding it will correlate into, and the
// candidate's own TestCase (for request/response evidence linkage — see
// finding.go's correlateVerification).
type verifyJob struct {
	Candidate           detection.Candidate `json:"candidate"`
	Marker              string              `json:"marker"`
	FindingID           domain.ID           `json:"finding_id"`
	CandidateTestCaseID domain.ID           `json:"candidate_test_case_id,omitempty"`
}

func parseVerifyJob(job *domain.TestJob) (verifyJob, error) {
	var vj verifyJob
	if len(job.Payload) == 0 {
		return vj, errors.New("verify job has no payload")
	}
	if err := json.Unmarshal(job.Payload, &vj); err != nil {
		return vj, fmt.Errorf("decode verify job payload: %w", err)
	}
	if vj.Candidate.Value == "" || vj.Marker == "" || vj.FindingID.Empty() {
		return vj, errors.New("verify job payload incomplete")
	}
	return vj, nil
}

// enqueueVerification correlates a candidate that reflected into a Finding
// (creating one at VerdictPending, or absorbing this candidate into an
// existing finding at the same site — see upsertPendingFinding) and enqueues
// the JobVerify job that will confirm or reject it. Best-effort: failures are
// logged, not fatal — the candidate's own TestCase result (already persisted)
// is unaffected either way.
func (e *executor) enqueueVerification(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, cand detection.Candidate, focus *domain.Parameter, candTestCaseID domain.ID) {
	if e.queue == nil || e.store == nil {
		return
	}
	f, err := upsertPendingFinding(ctx, e.store, job.ScanID, ep, job.Target.InjectionPointID, focus, cand, candTestCaseID)
	if err != nil {
		e.log.Warn("enqueue verification: upsert finding", "job", job.ID, "err", err)
		return
	}

	now := time.Now()
	payload, err := json.Marshal(verifyJob{
		Candidate: cand, Marker: detection.NewProbe(job.ScanID, job.Target.InjectionPointID).Token,
		FindingID: f.ID, CandidateTestCaseID: candTestCaseID,
	})
	if err != nil {
		e.log.Warn("marshal verify job", "job", job.ID, "err", err)
		return
	}
	child := &domain.TestJob{
		ID: domain.NewID(), ScanID: job.ScanID, Type: domain.JobVerify, State: domain.JobQueued,
		Priority: cand.Priority, Target: job.Target, Payload: payload, MaxAttempts: job.MaxAttempts,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.queue.Enqueue(ctx, child); err != nil {
		e.log.Warn("enqueue verify job", "job", job.ID, "candidate", cand.DedupKey, "err", err)
	}
}

// ---------------------------------------------------------------------------
// verify executor: runs JobVerify jobs
// ---------------------------------------------------------------------------

// verifyExecutor runs JobVerify jobs: it resolves the job's target, replays the
// EXACT candidate into its injection point through a real browser, and persists
// the outcome, evidence, and the resulting Finding verdict.
type verifyExecutor struct {
	store    store.Store
	verifier verification.Verifier
	evidence evidence.Store // nil: outcomes are recorded without evidence blobs
	scope    domain.Scope
	cfg      ExecutorConfig // reuses AllowStateChanging + RequestTimeout semantics
	log      *slog.Logger
}

func newVerifyExecutor(st store.Store, v verification.Verifier, ev evidence.Store, scope domain.Scope, cfg ExecutorConfig, log *slog.Logger) *verifyExecutor {
	if v == nil {
		v = verification.Stub{}
	}
	return &verifyExecutor{store: st, verifier: v, evidence: ev, scope: scope, cfg: cfg.withDefaults(), log: log}
}

var _ worker.Handler = (*verifyExecutor)(nil)

// Handle implements worker.Handler, mirroring executor.Handle's outcome→job
// state mapping exactly (see its doc comment).
func (e *verifyExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	tc := &domain.TestCase{
		ID:               domain.NewID(),
		ScanID:           job.ScanID,
		JobID:            job.ID,
		Attempt:          job.Attempts,
		InjectionPointID: job.Target.InjectionPointID,
		VulnClass:        domain.VulnReflectedXSS,
		Status:           domain.TestCaseRunning,
		URL:              job.Target.URL,
		StartedAt:        &started,
		CreatedAt:        started,
		UpdatedAt:        started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist verify test case: %w", err)
	}

	res := e.run(ctx, job, tc)

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	e.finish(wctx, job, tc, res)

	switch {
	case res.skipped, res.outcome == domain.OutcomeSuccess:
		return nil
	case res.outcome == domain.OutcomeCancelled:
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.Canceled
	case res.permanent:
		return fmt.Errorf("%w: %w", worker.ErrPermanent, res.err)
	default:
		return res.err
	}
}

// verifyResult is the outcome of one verification attempt.
type verifyResult struct {
	outcome   domain.TestOutcome
	skipped   bool
	permanent bool
	err       error
	note      string
	result    *verification.Result
}

func (e *verifyExecutor) run(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) verifyResult {
	vj, err := parseVerifyJob(job)
	if err != nil {
		return verifyResult{outcome: domain.OutcomeError, permanent: true, err: err}
	}

	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return verifyResult{outcome: domain.OutcomeError, permanent: true, err: err}
	}
	if focus == nil {
		return verifyResult{outcome: domain.OutcomeError, permanent: true, err: errors.New("verify job has no injection point")}
	}
	tc.Method, tc.URL = string(ep.Method), ep.URL

	note := fmt.Sprintf("browser verification; candidate %s/%s; parameter %s (%s)", vj.Candidate.Source, vj.Candidate.Category, focus.Name, focus.Location)
	if !e.cfg.AllowStateChanging && !isSafeMethod(ep.Method) {
		return verifyResult{skipped: true, note: fmt.Sprintf("%s skipped: %s is state-changing and AllowStateChanging is off", note, ep.Method)}
	}

	req, err := buildRequest(ep, params, &injection{param: focus, value: vj.Candidate.Value})
	if err != nil {
		return verifyResult{outcome: domain.OutcomeError, permanent: true, err: err, note: note}
	}
	tc.URL = req.URL
	if req.Method != "GET" && req.Method != "HEAD" {
		return verifyResult{skipped: true, note: note + ": browser verification supports GET/HEAD-navigable candidates only in this phase"}
	}

	var statePath string
	if sess, err := e.store.Sessions().GetByScan(ctx, job.ScanID); err == nil && sess != nil {
		statePath = sess.StatePath
	}

	in := verification.Input{
		ScanID: job.ScanID, VulnClass: domain.VulnReflectedXSS,
		InjectionPoint:   domain.InjectionPoint{ID: job.Target.InjectionPointID, ScanID: job.ScanID, EndpointID: job.Target.EndpointID},
		Candidate:        vj.Candidate,
		Marker:           vj.Marker,
		Method:           req.Method,
		URL:              req.URL,
		Scope:            e.scope,
		SessionStatePath: statePath,
	}

	vres, err := e.verifier.Verify(ctx, in)
	if err != nil {
		switch {
		case errors.Is(err, verification.ErrNotImplemented):
			return verifyResult{skipped: true, note: note + ": browser verification unavailable (no browser configured for this scan)"}
		case errors.Is(err, verification.ErrUnsupportedMethod):
			return verifyResult{skipped: true, note: note + ": browser verification supports GET/HEAD-navigable candidates only"}
		case ctx.Err() != nil:
			return verifyResult{outcome: domain.OutcomeCancelled, err: ctx.Err(), note: note}
		case errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err):
			return verifyResult{outcome: domain.OutcomeTimeout, err: err, note: note + " (timed out)"}
		default:
			return verifyResult{outcome: domain.OutcomeError, err: err, note: note + ": verification failed"}
		}
	}

	switch vres.Verdict {
	case domain.VerdictConfirmed:
		note += ": execution verified (" + string(vres.Report.Signal) + ")"
	case domain.VerdictRejected:
		note += ": reflection only (no execution signal observed)"
	default:
		note += ": verification inconclusive"
	}
	return verifyResult{outcome: domain.OutcomeSuccess, note: note, result: vres}
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// finish persists the attempt's result: the TestCase, its evidence, and the
// Finding's promotion/rejection.
func (e *verifyExecutor) finish(ctx context.Context, job *domain.TestJob, tc *domain.TestCase, r verifyResult) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Note = r.note

	vj, _ := parseVerifyJob(job) // already parsed successfully in run() for any non-permanent-parse-error path

	switch {
	case r.skipped:
		tc.Status = domain.TestCaseSkipped
	default:
		tc.Outcome = r.outcome
		switch r.outcome {
		case domain.OutcomeSuccess:
			tc.Status = domain.TestCaseCompleted
		case domain.OutcomeCancelled:
			tc.Status = domain.TestCaseCancelled
		default:
			tc.Status = domain.TestCaseFailed
		}
		if r.err != nil {
			tc.Error = truncate(r.err.Error(), 1024)
		}
	}

	var evidenceIDs []domain.ID
	if r.result != nil {
		if detail, err := json.Marshal(r.result.Report); err == nil {
			tc.Detail = detail
		} else {
			e.log.Warn("marshal verification report", "job", tc.JobID, "err", err)
		}
		if e.evidence != nil {
			evidenceIDs = e.persistVerificationEvidence(ctx, tc.ScanID, tc.ID, r.result.Evidence)
		}
	}
	tc.EvidenceIDs = evidenceIDs

	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Error("persist verify test case result", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}

	if !vj.FindingID.Empty() && r.result != nil {
		e.correlateVerification(ctx, vj.FindingID, vj.CandidateTestCaseID, r.result, tc.ID, evidenceIDs)
	}
}

// persistVerificationEvidence stores the screenshot, rendered DOM, and browser
// log as evidence blobs, returning the IDs of whichever were captured.
func (e *verifyExecutor) persistVerificationEvidence(ctx context.Context, scanID, tcID domain.ID, ev verification.ResultEvidence) []domain.ID {
	var ids []domain.ID
	note := "test_case=" + string(tcID)
	if len(ev.Screenshot) > 0 {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceScreenshot, ".png", "image/png", ev.Screenshot, note+" screenshot"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("persist screenshot evidence", "err", err)
		}
	}
	if ev.DOMHTML != "" {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceDOM, ".html", "text/html", []byte(ev.DOMHTML), note+" rendered DOM"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("persist DOM evidence", "err", err)
		}
	}
	if len(ev.BrowserLog) > 0 {
		data := []byte(joinLines(ev.BrowserLog))
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceBrowserLog, ".log", "text/plain", data, note+" browser log"); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("persist browser log evidence", "err", err)
		}
	}
	return ids
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
