package scan

// Access-control engine (function/role-level authorization): probes a path
// that discovery found through /robots.txt or an exposed sitemap and asks a
// single question — does an ANONYMOUS request receive a page that actually
// exposes privileged administrative actions (a user list, delete-user
// controls)?
//
// The probe is a two-request differential: an anonymous GET (NoCookies, so
// neither the scan's saved session nor the HTTP client's cookie jar can leak
// into it) and, when the scan has a session, the same GET as the authenticated
// non-admin. The pure rules in internal/accesscontrol decide the verdict from
// the response bodies; a 200 status alone is never a finding, and a path that
// answers with a login page is rejected.
//
// Read-only by construction: only GET requests are sent, no state-changing
// method is ever used, and no response body leaves the scan's evidence store.
// The engine never guesses a path: candidates come from discovery provenance
// (robots/sitemap) and a fixed administrative-path vocabulary. See
// docs/access-control.md for the slice boundaries.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// maxAccessControlProbesPerScan bounds the one-time pass. Each candidate costs
// at most two GETs (anonymous + non-admin), so the pass is capped at 40
// requests per execution regardless of how many paths robots.txt mentions.
const maxAccessControlProbesPerScan = 20

// accessControlDetail is the TestCase/Finding detail record for one probe.
type accessControlDetail struct {
	Engine            string                        `json:"engine"`
	Method            domain.HTTPMethod             `json:"method,omitempty"`
	URL               string                        `json:"url"`
	DiscoverySource   domain.DiscoverySource        `json:"discovery_source,omitempty"`
	AnonymousStatus   int                           `json:"anonymous_status,omitempty"`
	AnonymousFinalURL string                        `json:"anonymous_final_url,omitempty"`
	AnonymousLogin    bool                          `json:"anonymous_login,omitempty"`
	Actions           []accesscontrol.Action        `json:"actions,omitempty"`
	Verdict           domain.Verdict                `json:"verdict,omitempty"`
	Reason            string                        `json:"reason,omitempty"`
	Compared          bool                          `json:"compared,omitempty"`
	NonAdminStatus    int                           `json:"non_admin_status,omitempty"`
	NonAdminLogin     bool                          `json:"non_admin_login,omitempty"`
	NonAdminActions   []accesscontrol.Action        `json:"non_admin_actions,omitempty"`
	AnonymousEvidence []domain.ID                   `json:"anonymous_evidence,omitempty"`
	NonAdminEvidence  []domain.ID                   `json:"non_admin_evidence,omitempty"`
	Skipped           bool                          `json:"skipped,omitempty"`
	SkipReason        string                        `json:"skip_reason,omitempty"`
}

// accessControlFindingDetail is the correlated Finding's detail record. It
// carries the same evidence trail plus the dedup key and occurrence count the
// correlation layer needs.
type accessControlFindingDetail struct {
	Engine            string                 `json:"engine"`
	Method            domain.HTTPMethod      `json:"method,omitempty"`
	URL               string                 `json:"url"`
	DiscoverySource   domain.DiscoverySource `json:"discovery_source,omitempty"`
	AnonymousStatus   int                    `json:"anonymous_status,omitempty"`
	AnonymousFinalURL string                 `json:"anonymous_final_url,omitempty"`
	Actions           []accesscontrol.Action `json:"actions,omitempty"`
	Verdict           domain.Verdict         `json:"verdict,omitempty"`
	Reason            string                 `json:"reason,omitempty"`
	Compared          bool                   `json:"compared,omitempty"`
	NonAdminStatus    int                    `json:"non_admin_status,omitempty"`
	NonAdminActions   []accesscontrol.Action `json:"non_admin_actions,omitempty"`
	AnonymousEvidence []domain.ID            `json:"anonymous_evidence,omitempty"`
	NonAdminEvidence  []domain.ID            `json:"non_admin_evidence,omitempty"`
	DedupKey          string                 `json:"dedup_key,omitempty"`
	Occurrences       int                    `json:"occurrences,omitempty"`
	TestCaseIDs       []domain.ID            `json:"test_case_ids,omitempty"`
}

// accessControlExecutor runs JobAccessControl jobs.
type accessControlExecutor struct {
	store    store.Store
	engine   httpengine.Engine
	evidence evidence.Store
	cfg      ExecutorConfig
	log      *slog.Logger
	// findingsMu serializes Finding correlation with every other engine's
	// correlation in this scan.
	findingsMu *sync.Mutex
	// hasSession says the scan carries authenticated storage state, so the
	// non-admin comparison request is meaningful. Without it the anonymous
	// exposure alone is still a finding (nobody had to authenticate).
	hasSession bool
}

func newAccessControlExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex, hasSession bool) *accessControlExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &accessControlExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(),
		log: log, findingsMu: findingsMu, hasSession: hasSession}
}

var _ worker.Handler = (*accessControlExecutor)(nil)

// Handle implements worker.Handler with the same return-value contract as the
// other executors: skipped/completed → nil; cancellation → context error;
// transport errors → retryable; permanent resolution errors → ErrPermanent.
func (e *accessControlExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnAccessControl, Status: domain.TestCaseRunning, URL: job.Target.URL,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist test case: %w", err)
	}

	d, outcome, err, permanent, skipped := e.run(ctx, job, tc)

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e.finish(wctx, tc, d, outcome, err, skipped)

	switch {
	case skipped, outcome == domain.OutcomeSuccess:
		return nil
	case outcome == domain.OutcomeCancelled:
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return context.Canceled
	case permanent:
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	default:
		return err
	}
}

// run performs the two-request differential and decides the verdict.
func (e *accessControlExecutor) run(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	ep, _, _, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return accessControlDetail{Engine: "access_control"}, domain.OutcomeError, err, true, false
	}
	d := accessControlDetail{Engine: "access_control", Method: ep.Method, URL: ep.URL, DiscoverySource: ep.Source}
	tc.Method, tc.URL = string(ep.Method), ep.URL

	skip := func(reason string) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason = true, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}
	// A path outside the candidate set is never requested: the pass only
	// enqueues robots/sitemap-derived admin-like GET paths, and a job for
	// anything else would be a request nobody authorized.
	if !isAccessControlCandidate(ep) {
		return skip("not a robots/sitemap-discovered admin-like GET path")
	}

	// Request 1: genuinely anonymous. NoCookies suppresses both the scan's
	// saved session cookies and the HTTP client's jar, which may hold cookies
	// set by an earlier response.
	anonReq := httpengine.GET(ep.URL)
	anonReq.NoCookies = true
	anonResp, anonOutcome, anonErr, _ := e.send(ctx, anonReq)
	if anonOutcome != domain.OutcomeSuccess {
		return d, anonOutcome, anonErr, false, false
	}
	d.AnonymousStatus, d.AnonymousFinalURL = anonResp.Status, anonResp.FinalURL
	if ids, evErr := e.persistPair(ctx, tc, anonResp, "access control anonymous"); evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | anonymous evidence incomplete: " + truncate(evErr.Error(), 200))
	} else {
		d.AnonymousEvidence = ids
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	}
	anonObs := accesscontrol.Analyze(acSnapshot(anonResp))
	d.AnonymousLogin = anonObs.LoginPage
	d.Actions = anonObs.Actions

	// Request 2: the same path as the scan's authenticated (non-admin)
	// session. It is only useful when the anonymous response itself could be
	// a finding; a rejected anonymous response needs no comparison.
	var nonAdmin *accesscontrol.Snapshot
	if e.hasSession && anonResp.Status >= 200 && anonResp.Status < 300 && len(anonObs.Actions) > 0 {
		authResp, authOutcome, _, _ := e.send(ctx, httpengine.GET(ep.URL))
		if authOutcome == domain.OutcomeSuccess && authResp != nil {
			d.Compared, d.NonAdminStatus = true, authResp.Status
			if ids, evErr := e.persistPair(ctx, tc, authResp, "access control non-admin session"); evErr != nil {
				tc.Note = strings.TrimSpace(tc.Note + " | non-admin evidence incomplete: " + truncate(evErr.Error(), 200))
			} else {
				d.NonAdminEvidence = ids
				tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
			}
			snap := acSnapshot(authResp)
			d.NonAdminLogin = accesscontrol.Analyze(snap).LoginPage
			d.NonAdminActions = accesscontrol.Analyze(snap).Actions
			nonAdmin = &snap
		}
	}

	dec := accesscontrol.Decide(acSnapshot(anonResp), nonAdmin)
	d.Verdict, d.Reason = verdictOf(dec.Outcome), dec.Reason
	d.Actions = dec.Privileged

	// Evidence integrity: a Confirmed finding must be reproducible from the
	// stored anonymous request/response pair (and the comparison pair when a
	// comparison was performed). Otherwise it is downgraded, never shipped
	// without the bytes that prove it.
	if d.Verdict == domain.VerdictConfirmed && e.evidence != nil {
		if len(d.AnonymousEvidence) < 2 || (d.Compared && len(d.NonAdminEvidence) < 2) {
			d.Verdict = domain.VerdictInconclusive
			d.Reason = "the anonymous response exposed a privileged action, but the request/response evidence could not all be stored; not Confirmed without reproducible evidence"
		}
	}

	if d.Verdict == domain.VerdictConfirmed {
		e.correlate(ctx, job.ScanID, ep, d, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// finish persists the probe result. Skipped probes still write a row so the
// report can say the candidate existed and why it was not tested.
func (e *accessControlExecutor) finish(ctx context.Context, tc *domain.TestCase, d accessControlDetail, outcome domain.TestOutcome, runErr error, skipped bool) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.VulnClass = domain.VulnAccessControl
	tc.Detail = encodeAccessControlDetail(d)
	switch {
	case skipped:
		tc.Status = domain.TestCaseSkipped
		tc.Note = "access control skipped: " + d.SkipReason
	case outcome == domain.OutcomeSuccess:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = outcome
		if d.Verdict == "" {
			d.Verdict = domain.VerdictInconclusive
			d.Reason = "no access-control decision was produced"
			tc.Detail = encodeAccessControlDetail(d)
		}
		tc.Note = fmt.Sprintf("access control: %s (%s)", d.Verdict, truncate(d.Reason, 300))
	default:
		tc.Outcome = outcome
		tc.Status = domain.TestCaseFailed
		if outcome == domain.OutcomeCancelled {
			tc.Status = domain.TestCaseCancelled
		}
		if runErr != nil {
			tc.Error = truncate(runErr.Error(), 1024)
		}
	}
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Error("persist access-control test case", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

func encodeAccessControlDetail(d accessControlDetail) []byte {
	b, _ := json.Marshal(d)
	return b
}

func encodeAccessControlFindingDetail(d accessControlFindingDetail) []byte {
	b, _ := json.Marshal(d)
	return b
}

// send executes one request through the scan's scope-enforcing engine with the
// per-request timeout.
func (e *accessControlExecutor) send(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error, time.Duration) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err, 0
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	t0 := time.Now()
	resp, err := e.engine.Do(ctx, &timed)
	dur := time.Since(t0)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil, resp.Duration
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err(), dur
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err, dur
	default:
		return nil, domain.OutcomeError, err, dur
	}
}

// persistPair stores the request and response of one probe as evidence.
func (e *accessControlExecutor) persistPair(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, role string) ([]domain.ID, error) {
	var ids []domain.ID
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return ids, nil
	}
	id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
		dumpRequest(resp.Request), "test_case="+string(tc.ID)+" "+role+" request")
	if err != nil {
		return ids, err
	}
	ids = append(ids, id)
	note := "test_case=" + string(tc.ID) + " " + role + " response"
	if resp.Truncated {
		note += " (body truncated at the engine's size cap)"
	}
	id, err = putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(resp), note)
	if err != nil {
		return ids, err
	}
	ids = append(ids, id)
	return ids, nil
}

// correlate upserts the Confirmed finding for one admin path. A later run at
// the same path (a resumed execution re-enqueues the pass) absorbs into the
// same finding and unions evidence instead of duplicating it.
func (e *accessControlExecutor) correlate(ctx context.Context, scanID domain.ID, ep *domain.Endpoint, d accessControlDetail, tcID domain.ID) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	key := accessControlFindingDedupKey(ep)
	fd := accessControlFindingDetail{
		Engine: "access_control", Method: ep.Method, URL: ep.URL, DiscoverySource: ep.Source,
		AnonymousStatus: d.AnonymousStatus, AnonymousFinalURL: d.AnonymousFinalURL,
		Actions: d.Actions, Verdict: domain.VerdictConfirmed, Reason: d.Reason,
		Compared: d.Compared, NonAdminStatus: d.NonAdminStatus, NonAdminActions: d.NonAdminActions,
		AnonymousEvidence: d.AnonymousEvidence, NonAdminEvidence: d.NonAdminEvidence,
		DedupKey: key, Occurrences: 1, TestCaseIDs: []domain.ID{tcID},
	}
	evidenceIDs := appendUniqueIDs(nil, d.AnonymousEvidence)
	evidenceIDs = appendUniqueIDs(evidenceIDs, d.NonAdminEvidence)

	existing, err := e.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		e.log.Warn("list findings for access-control correlation", "scan", scanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnAccessControl {
			continue
		}
		var prev accessControlFindingDetail
		_ = json.Unmarshal(f.Detail, &prev)
		if prev.DedupKey != key {
			continue
		}
		prev.Occurrences++
		prev.TestCaseIDs = appendUniqueID(prev.TestCaseIDs, tcID)
		prev.Verdict = domain.VerdictConfirmed
		prev.Reason = d.Reason
		prev.Actions = d.Actions
		prev.AnonymousEvidence = appendUniqueIDs(prev.AnonymousEvidence, d.AnonymousEvidence)
		prev.NonAdminEvidence = appendUniqueIDs(prev.NonAdminEvidence, d.NonAdminEvidence)
		prev.Compared = prev.Compared || d.Compared
		if d.NonAdminStatus != 0 {
			prev.NonAdminStatus = d.NonAdminStatus
		}
		f.Detail = encodeAccessControlFindingDetail(prev)
		f.Verdict = domain.VerdictConfirmed
		f.Summary = d.Reason
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, evidenceIDs)
		f.UpdatedAt = time.Now()
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("update access-control finding", "finding", f.ID, "err", err)
		}
		return
	}

	sc, err := e.store.Scans().Get(ctx, scanID)
	if err != nil {
		e.log.Warn("load scan for access-control finding", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnAccessControl,
		Verdict: domain.VerdictConfirmed, Severity: accessControlSeverity(d.Actions), Confidence: domain.ConfidenceHigh,
		Title:       fmt.Sprintf("Access control: anonymous access to admin actions at %s %s", ep.Method, endpointLabel(ep.URL)),
		Summary:     d.Reason,
		EndpointID:  ep.ID,
		EvidenceIDs: evidenceIDs,
		Provenance: domain.Provenance{Engine: "access_control", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:     encodeAccessControlFindingDetail(fd),
		CreatedAt:  now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("create access-control finding", "scan", scanID, "err", err)
	}
}

func accessControlSeverity(actions []accesscontrol.Action) domain.Severity {
	for _, a := range actions {
		if a.Kind == accesscontrol.ActionDeleteUser {
			return domain.SeverityHigh
		}
	}
	return domain.SeverityMedium
}

func accessControlFindingDedupKey(ep *domain.Endpoint) string {
	return "access_control\x00" + string(ep.Method) + "\x00" + ep.URL
}

// isAccessControlCandidate reports whether an endpoint is one this engine may
// probe: a GET path discovery actually disclosed through robots.txt or a
// sitemap, whose path looks administrative.
func isAccessControlCandidate(ep *domain.Endpoint) bool {
	if ep == nil || ep.Method != domain.MethodGET {
		return false
	}
	if ep.Source != domain.SourceRobots && ep.Source != domain.SourceSitemap {
		return false
	}
	return accesscontrol.AdminLikePath(ep.URL)
}

func acSnapshot(r *httpengine.Response) accesscontrol.Snapshot {
	if r == nil {
		return accesscontrol.Snapshot{}
	}
	return accesscontrol.Snapshot{Status: r.Status, FinalURL: r.FinalURL, Truncated: r.Truncated, Body: r.Body}
}

func verdictOf(o accesscontrol.Outcome) domain.Verdict {
	switch o {
	case accesscontrol.OutcomeConfirmed:
		return domain.VerdictConfirmed
	case accesscontrol.OutcomeRejected:
		return domain.VerdictRejected
	default:
		return domain.VerdictInconclusive
	}
}

// ---------------------------------------------------------------------------
// probe pass: one JobAccessControl per disclosed admin-like GET path
// ---------------------------------------------------------------------------

// enqueueAccessControlProbes runs once per execution when the ordinary queue
// goes quiet. It is bounded by what discovery actually disclosed (robots.txt
// Disallow/Allow entries and sitemap URLs) and by a fixed vocabulary of
// administrative path segments; it never guesses a path. No authentication is
// required to run it: an anonymous scan can still prove that an admin surface
// is reachable without a session.
func (c *Controller) enqueueAccessControlProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	seen := make(map[string]struct{})
	n := 0
	for _, ep := range endpoints {
		if !isAccessControlCandidate(ep) {
			continue
		}
		if _, dup := seen[ep.URL]; dup {
			continue
		}
		if n >= maxAccessControlProbesPerScan {
			c.log.Info("access-control probes: per-scan budget reached",
				"scan", scanID, "limit", maxAccessControlProbesPerScan)
			break
		}
		seen[ep.URL] = struct{}{}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 30, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("access-control probes: enqueue job", "scan", scanID, "url", ep.URL, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("access-control probes: enqueued", "scan", scanID, "jobs", n)
	}
}
