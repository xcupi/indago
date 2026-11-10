package scan

// IDOR engine (family A: broken object-level authorization). This file is the
// scan-side handler: it establishes the caller's identity from the target
// itself, sends the caller's own object request (A) and a bounded set of
// foreign object requests (B) through the scan's scope-enforcing engine, and
// correlates the differential into a Finding only when a response POSITIVELY
// names a different principal. See internal/idor for the pure decision rules
// and docs/idor.md for the slice boundaries.
//
// Read-only by construction: only GET/HEAD requests are ever sent, the
// candidate set is hard-capped, and no response body is ever exfiltrated —
// evidence stays in the scan's own evidence store, like every other engine.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// idorIdentityNote prefixes the TestCase that records the caller-identity
// baseline. The note is the durable, restart-safe lookup key: the baseline is
// recorded ONCE per scan with its own evidence, and every IDOR probe reads it
// back instead of re-fetching an account page.
const idorIdentityNote = "idor identity baseline"

// idorDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail. It keeps the evidence trail an operator needs to re-check a
// verdict: who the caller was established to be, which own-object request was
// the baseline, and every foreign identifier tried with its own outcome.
//
// On the identity-baseline TestCase it ALSO carries the harvested candidate
// set (Harvest/HarvestNote), so the identifiers the engine found on its own are
// a read-only, restart-safe fact rather than a transient in-memory list.
type idorDetail struct {
	Engine           string               `json:"engine"`
	Method           domain.HTTPMethod    `json:"method,omitempty"`
	Parameter        string               `json:"parameter,omitempty"`
	Location         domain.ParamLocation `json:"location,omitempty"`
	OwnValue         string               `json:"own_value,omitempty"`
	CallerIdentity   idor.Identity        `json:"caller_identity,omitempty"`
	IdentitySource   string               `json:"identity_source,omitempty"`
	IdentityEvidence []domain.ID          `json:"identity_evidence,omitempty"`
	BaselineEvidence []domain.ID          `json:"baseline_evidence,omitempty"`
	BaselineStatus   int                  `json:"baseline_status,omitempty"`
	HarvestedCount   int                  `json:"harvested_count,omitempty"`
	Harvest          []idor.Harvest       `json:"harvested_candidates,omitempty"`
	HarvestNote      string               `json:"harvest_note,omitempty"`
	Enumeration      bool                 `json:"enumeration,omitempty"`
	EnumerationNote  string               `json:"enumeration_note,omitempty"`
	ProbesBudget     int                  `json:"probes_budget,omitempty"`
	ProbesLeft       int                  `json:"probes_left,omitempty"`
	BudgetExhausted  bool                 `json:"probe_budget_exhausted,omitempty"`
	SessionBlocked   bool                 `json:"session_blocked,omitempty"`
	// RedirectBody records that the object was disclosed in the BODY of a
	// redirect (case 32): the response was replayed without following it.
	RedirectBody bool           `json:"redirect_body,omitempty"`
	Attempts     []idorAttempt  `json:"attempts,omitempty"`
	Verdict      domain.Verdict `json:"verdict,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	DedupKey     string         `json:"dedup_key,omitempty"`
	Occurrences  int            `json:"occurrences,omitempty"`
	TestCaseIDs  []domain.ID    `json:"test_case_ids,omitempty"`
	Skipped      bool           `json:"skipped,omitempty"`
	SkipReason   string         `json:"skip_reason,omitempty"`

	// Object family (case 34): the object this scan created, and the family it
	// named.
	ObjectFamily bool   `json:"object_family,omitempty"`
	ObjectField  string `json:"object_field,omitempty"`
	FamilyBase   string `json:"family_base,omitempty"`
	OwnObject    string `json:"own_object,omitempty"`
	CreateStatus int    `json:"create_status,omitempty"`
}

// idorAttempt is one foreign object request (B) and what it proved.
type idorAttempt struct {
	Candidate   string       `json:"candidate"`
	Source      string       `json:"source,omitempty"`
	Origin      *idor.Origin `json:"origin,omitempty"`
	URL         string       `json:"url,omitempty"`
	Status      int          `json:"status,omitempty"`
	Outcome     string       `json:"outcome"`
	Reason      string       `json:"reason,omitempty"`
	Foreign     *idor.Field  `json:"foreign,omitempty"`
	EvidenceIDs []domain.ID  `json:"evidence_ids,omitempty"`
}

// idorExecutor runs JobIDOR jobs.
type idorExecutor struct {
	store    store.Store
	engine   httpengine.Engine
	evidence evidence.Store
	cfg      ExecutorConfig
	log      *slog.Logger
	// findingsMu serializes Finding correlation with every other engine's
	// correlation in this scan (the same shared mutex defaultHandlers passes
	// to the XSS and DOM-XSS executors).
	findingsMu *sync.Mutex
	// identityMu serializes establishment of the per-scan identity baseline:
	// several IDOR jobs run concurrently on the HTTP worker group and must not
	// each fetch (and persist) their own baseline.
	identityMu sync.Mutex
	cached     *idorIdentity
	// harvestMu serializes the one-time harvest from the scan's own data (see
	// harvestCandidates). Harvesting is local I/O only: it never sends a
	// request, so it cannot change the pass's request count.
	harvestMu   sync.Mutex
	harvested   []idor.Harvest
	harvestNote string
	harvestDone bool
	supplied    []string
	// enum is the operator's bounded-enumeration opt-in. The zero value means
	// "off", which is the default and preserves the previous behaviour
	// exactly (see docs/idor.md).
	enum idor.EnumerationOptions
	// probes is the scan-wide foreign-object request budget, SHARED by the
	// derived-candidate pass and the enumeration pass. Several IDOR jobs run
	// concurrently, so it is mutex-guarded.
	probes *idorProbeBudget
	// loginMu guards the once-per-scan login-page note. A login page means the
	// session did not reach the object; reporting it per candidate would bury
	// the one fact the operator needs and waste probes.
	loginMu   sync.Mutex
	loginNote bool
}

// maxIDORProbesPerScan is the hard, scan-wide ceiling on foreign-object
// requests (request B of the differential), shared by every IDOR job of one
// execution and by both candidate sources. Per injection point the bound is
// MaxCandidates (5 derived) + MaxEnumerationPerSite (12 enumerated) = 17, and
// this scan-wide ceiling keeps a target with many parameters from ever
// multiplying that.
const maxIDORProbesPerScan = 60

// idorProbeBudget is a shared, concurrency-safe request budget.
type idorProbeBudget struct {
	mu   sync.Mutex
	left int
}

func newIDORProbeBudget(n int) *idorProbeBudget {
	if n < 0 {
		n = 0
	}
	return &idorProbeBudget{left: n}
}

// take reserves one foreign-object probe and reports whether one was left.
func (b *idorProbeBudget) take() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.left <= 0 {
		return false
	}
	b.left--
	return true
}

// remaining reports the probes left, for the persisted detail.
func (b *idorProbeBudget) remaining() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.left
}

type idorIdentity struct {
	Identity idor.Identity
	Source   string
	Evidence []domain.ID
	Reason   string // non-empty when no identity could be established
	// CaseID is the persisted identity-baseline TestCase; the harvested
	// candidate set is stored on it (see persistHarvest).
	CaseID domain.ID
	// Harvest/HarvestNote are read back from that TestCase on restart so a
	// resumed scan does not re-mine every stored body.
	Harvest     []idor.Harvest
	HarvestNote string
}

func newIDORExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex, supplied []string, enum idor.EnumerationOptions) *idorExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &idorExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu,
		supplied: append([]string(nil), supplied...), enum: enum, probes: newIDORProbeBudget(maxIDORProbesPerScan)}
}

var _ worker.Handler = (*idorExecutor)(nil)

// Handle implements worker.Handler with the same return-value contract as the
// other executors: skipped/completed → nil; cancellation → context error;
// transport errors → retryable; permanent resolution errors → ErrPermanent.
func (e *idorExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnIDOR, Status: domain.TestCaseRunning, URL: job.Target.URL,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist test case: %w", err)
	}

	var d idorDetail
	var outcome domain.TestOutcome
	var err error
	var permanent, skipped bool
	if idorPayloadMode(job) == idorModeObjectFamily {
		d, outcome, err, permanent, skipped = e.runObjectFamily(ctx, job, tc)
	} else {
		d, outcome, err, permanent, skipped = e.run(ctx, job, tc)
	}

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

// run performs the differential. It returns the detail to persist, the
// execution outcome, and (for retryable transport failures) the error.
func (e *idorExecutor) run(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (idorDetail, domain.TestOutcome, error, bool, bool) {
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return idorDetail{Engine: "idor"}, domain.OutcomeError, err, true, false
	}
	tc.Method, tc.URL = string(ep.Method), ep.URL

	d := idorDetail{Engine: "idor", Method: ep.Method}
	// skip records WHY a parameter was not tested, preserving anything already
	// established about it (e.g. how many identifiers were harvested).
	skip := func(reason string) (idorDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason = true, reason
		d.Verdict, d.Reason = domain.VerdictInconclusive, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}
	// noCandidate is the CLEAN conclusion for a parameter with nothing to try:
	// one informative, skipped test case and NOT a single request. It is a
	// success, not an inconclusive verdict — there is no probability judgement
	// to make when the engine never reached the target.
	noCandidate := func(detail string) (idorDetail, domain.TestOutcome, error, bool, bool) {
		reason := "no foreign object identifier available; supply -idor-candidates or enable -idor-enumerate"
		if detail != "" {
			reason += " (" + truncate(detail, 240) + ")"
		}
		d.Skipped, d.SkipReason, d.Reason = true, reason, reason
		d.Verdict = ""
		return d, domain.OutcomeSuccess, nil, false, true
	}

	if focus == nil {
		return idorDetail{Engine: "idor"}, domain.OutcomeError, fmt.Errorf("IDOR job has no injection point"), true, false
	}
	d.Parameter, d.Location = focus.Name, focus.Location

	// This slice is read-only: GET/HEAD only, never a body-carrying method,
	// even with the scan's state-changing opt-in (see AGENTS.md §3).
	if !isSafeMethod(ep.Method) {
		return skip(fmt.Sprintf("method %s is state-changing; the IDOR engine's current slice performs GET/HEAD reads only", ep.Method))
	}
	if focus.Location != domain.LocationQuery && focus.Location != domain.LocationPath {
		return skip(fmt.Sprintf("parameter %s is carried in a %s body/header; only query and path object identifiers are in this slice", focus.Name, focus.Location))
	}

	own := ownObjectValue(ep, focus)
	if own == "" {
		return skip(fmt.Sprintf("no caller-owned value was observed for parameter %s", focus.Name))
	}
	d.OwnValue = own

	// Candidate derivation is LOCAL work: the harvest reads only data the scan
	// already holds and enumeration is arithmetic. It therefore happens BEFORE
	// any request, so a parameter with no identifier to try never touches the
	// target — the live defect where an ordinary /product link was probed and
	// misreported as a login page cannot recur.
	known := e.knownIdentity(ctx, job.ScanID)
	harvested, harvestNote := e.harvestCandidates(ctx, job.ScanID, known, own)
	d.HarvestedCount, d.HarvestNote = len(harvested), harvestNote

	cands, deriveReason := e.deriveCandidates(own, harvested, &d)
	if len(cands) == 0 {
		return noCandidate(deriveReason)
	}

	ident, _ := e.identity(ctx, job.ScanID, ep)
	// The durable identity baseline now exists (positive or negative): attach
	// the harvested set to it so the report and a restarted scan can see what
	// the engine found, without re-mining the evidence store.
	e.persistHarvest(ctx, ident, harvested, harvestNote)
	if ident.Identity.Empty() {
		reason := ident.Reason
		if reason == "" {
			reason = "caller identity could not be established from the target with this session"
		}
		d.CallerIdentity = ident.Identity
		return skip(reason)
	}
	d.CallerIdentity, d.IdentitySource = ident.Identity, ident.Source
	d.IdentityEvidence = ident.Evidence

	// A harvested value that IS the caller's own identity is never a foreign
	// object. Derivation ran before the identity baseline (so a no-candidate
	// scan sends no request), so the filter is applied here.
	cands = filterCallerCandidates(cands, ident.Identity)
	if len(cands) == 0 {
		return noCandidate("every identifier derived for this parameter belongs to the caller")
	}

	// Request A: the caller's OWN object, exactly as observed. Its evidence is
	// half of the differential pair.
	baseAddr := *ep
	baseReq, err := buildRequest(&baseAddr, params, &injection{param: focus, value: own})
	if err != nil {
		return d, domain.OutcomeError, err, true, false
	}
	tc.URL = baseReq.URL
	baseResp, baseOutcome, baseErr, _ := e.send(ctx, baseReq)
	d.BaselineStatus = statusOf(baseResp)
	if baseOutcome != domain.OutcomeSuccess {
		return d, baseOutcome, baseErr, false, false
	}
	baseEvidence, err := e.persistPair(ctx, tc, baseResp, "idor baseline (own object)")
	if err != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(err.Error(), 200))
	}
	d.BaselineEvidence = baseEvidence
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, baseEvidence)

	// Guard: if the caller's OWN object does not identify as the established
	// identity, the identity baseline or the parameter interpretation is
	// wrong, and a foreign-looking response would be meaningless.
	if ownIdent := idor.ExtractIdentity(baseResp.Body); !ownIdent.Empty() {
		if same, ok := samePrincipal(d.CallerIdentity, ownIdent); !ok || !same {
			d.Verdict = domain.VerdictInconclusive
			d.Reason = "the caller's own-object baseline does not match the established identity; no differential is meaningful"
			return d, domain.OutcomeSuccess, nil, false, false
		}
	}
	if d.BaselineStatus == 401 || d.BaselineStatus == 403 {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = fmt.Sprintf("the caller's own-object baseline was denied (HTTP %d); the session cannot read the object at all", d.BaselineStatus)
		return d, domain.OutcomeSuccess, nil, false, false
	}

	// Request B: one bounded read per foreign identifier.
	d.ProbesBudget = maxIDORProbesPerScan
	verdict := domain.VerdictInconclusive
	var reasons []string
	for _, cand := range cands {
		// One scan-wide budget, spent by derived and enumerated candidates
		// alike: enumeration can never multiply the pass's request count.
		if !e.probes.take() {
			d.BudgetExhausted = true
			reasons = append(reasons, "the scan-wide IDOR probe budget was exhausted before every candidate was tried")
			break
		}
		addr := *ep
		req, err := buildRequest(&addr, params, &injection{param: focus, value: cand.Value})
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		resp, outcome, reqErr, _ := e.send(ctx, req)
		if outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
				return d, outcome, reqErr, false, false
			}
			d.Attempts = append(d.Attempts, idorAttempt{Candidate: cand.Value, Source: cand.Source,
				URL: req.URL, Outcome: string(domain.OutcomeError), Reason: "request failed: " + truncate(errText(reqErr), 200)})
			continue
		}
		// Case 32: the object can be disclosed in the BODY of the redirect that
		// sends the caller away (302 -> /login with the account page inside).
		// Following that redirect destroys the only copy of the evidence, so the
		// same request is replayed ONCE with redirects disabled and the 3xx body
		// is what the differential classifies. The replay spends one more probe
		// permit: when the budget is gone the original response stands.
		if len(resp.RedirectChain) > 0 && idor.LooksLikeLoginPage(resp.Body) && e.probes.take() {
			noRedirect := *req
			noRedirect.NoRedirects = true
			if r2, out2, _, _ := e.send(ctx, &noRedirect); out2 == domain.OutcomeSuccess && r2.Status >= 300 && r2.Status < 400 {
				resp = r2
				d.RedirectBody = true
			}
		}
		// Request B's request/response pair is stored BEFORE the decision is
		// recorded, so a Confirmed verdict can never exist without the
		// foreign-object evidence that proves it.
		var evIDs []domain.ID
		if ids, evErr := e.persistPair(ctx, tc, resp, "idor candidate "+cand.Value); evErr != nil {
			tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
		} else {
			evIDs = ids
			tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
		}
		dec := idor.DecideWithBaseline(d.CallerIdentity, cand.Value, resp.Status, resp.Body, baseResp.Body)
		if d.RedirectBody && dec.Outcome == idor.OutcomeConfirmed {
			dec.Reason = fmt.Sprintf("the redirect response (HTTP %d) leaked the object instead of sending only a Location: %s", resp.Status, dec.Reason)
		}
		// Evidence integrity: when an evidence store is configured, a
		// Confirmed verdict must be reproducible from stored request A and
		// request B blobs. A persistence failure downgrades the outcome
		// rather than shipping a finding nobody can re-check (AGENTS.md §2.6).
		if dec.Outcome == idor.OutcomeConfirmed && e.evidence != nil &&
			(len(d.BaselineEvidence) == 0 || len(evIDs) == 0) {
			dec = idor.Decision{Outcome: idor.OutcomeInconclusive,
				Reason: "the foreign-object response named a different principal, but the request/response evidence pair could not be stored; not Confirmed without reproducible evidence"}
		}
		// A harvested candidate's provenance travels with the attempt and into
		// the finding reason, so the report can say which value was tested and
		// where the scan found it. An operator-supplied candidate has none.
		//
		// A login page means the session never reached the object. It is
		// reported ONCE per scan: repeating it per candidate buried the one
		// fact the operator needs and wasted the request budget.
		loginPage := dec.Outcome == idor.OutcomeInconclusive && idor.LooksLikeLoginPage(resp.Body)
		attemptReason := dec.Reason
		if loginPage && !e.noteLoginPage() {
			attemptReason = "the session is still on the login page already reported by this scan; no further candidates were probed at this site"
		}
		if cand.Origin != nil {
			attemptReason += "; candidate " + cand.Origin.Describe()
		}
		a := idorAttempt{Candidate: cand.Value, Source: cand.Source, Origin: cand.Origin, URL: req.URL,
			Status: resp.Status, Outcome: string(dec.Outcome), Reason: attemptReason, Foreign: dec.Foreign, EvidenceIDs: evIDs}
		d.Attempts = append(d.Attempts, a)
		reasons = append(reasons, attemptReason)

		switch dec.Outcome {
		case idor.OutcomeConfirmed:
			verdict = domain.VerdictConfirmed
		case idor.OutcomeRejected:
			if verdict != domain.VerdictConfirmed {
				verdict = domain.VerdictRejected
			}
		}
		if verdict == domain.VerdictConfirmed {
			break // one positive mismatch is enough; stop reading further objects
		}
		if loginPage {
			// No further candidate at this site can succeed: stop instead of
			// spending the rest of the budget on the same login page.
			d.SessionBlocked = true
			break
		}
	}

	d.Verdict = verdict
	d.Reason = joinReasons(reasons)
	d.ProbesLeft = e.probes.remaining()
	if verdict == domain.VerdictConfirmed {
		e.correlate(ctx, job.ScanID, ep, focus, job.Target.InjectionPointID, d, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// noteLoginPage records the scan's single login-page observation and reports
// whether this call was the first.
func (e *idorExecutor) noteLoginPage() bool {
	e.loginMu.Lock()
	defer e.loginMu.Unlock()
	if e.loginNote {
		return false
	}
	e.loginNote = true
	return true
}

// send executes one request through the scan's scope-enforcing engine with the
// per-request timeout. Mirrors the XSS executor's send without sharing state
// with it.
func (e *idorExecutor) send(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error, time.Duration) {
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

// finish persists the probe result. Skipped probes still write a row: an
// operator must be able to see WHY a parameter was not tested.
func (e *idorExecutor) finish(ctx context.Context, tc *domain.TestCase, d idorDetail, outcome domain.TestOutcome, runErr error, skipped bool) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Detail = encodeIDORDetail(d)
	switch {
	case skipped:
		tc.Status = domain.TestCaseSkipped
		tc.Note = "idor skipped: " + d.SkipReason
	case outcome == domain.OutcomeSuccess:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = outcome
		if d.Verdict == "" {
			d.Verdict = domain.VerdictInconclusive
			d.Reason = "no differential result was produced"
			tc.Detail = encodeIDORDetail(d)
		}
		tc.Note = fmt.Sprintf("idor: %s (%s)", d.Verdict, truncate(d.Reason, 300))
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
		e.log.Error("persist IDOR test case", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

func encodeIDORDetail(d idorDetail) []byte {
	b, _ := json.Marshal(d)
	return b
}

func statusOf(r *httpengine.Response) int {
	if r == nil {
		return 0
	}
	return r.Status
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func joinReasons(reasons []string) string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reasons {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return truncate(strings.Join(out, "; "), 500)
}

// persistPair stores the request and response of one probe as evidence and
// returns their IDs (request A or B of the differential).
func (e *idorExecutor) persistPair(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, role string) ([]domain.ID, error) {
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

// ---------------------------------------------------------------------------
// identity baseline: who am I, established from the target itself
// ---------------------------------------------------------------------------

// loadIdentityCase reads the persisted identity baseline TestCase, if the scan
// already established one (positive or negative). It performs no request, so
// candidate derivation can use the caller's exclusions without touching the
// target.
func (e *idorExecutor) loadIdentityCase(ctx context.Context, scanID domain.ID) (*idorIdentity, bool) {
	cases, err := e.store.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		return nil, false
	}
	for _, tc := range cases {
		if tc.VulnClass != domain.VulnIDOR || !strings.HasPrefix(tc.Note, idorIdentityNote) {
			continue
		}
		var d idorDetail
		_ = json.Unmarshal(tc.Detail, &d)
		return &idorIdentity{Identity: d.CallerIdentity, Source: d.IdentitySource,
			Evidence: d.IdentityEvidence, Reason: d.SkipReason, CaseID: tc.ID,
			Harvest: d.Harvest, HarvestNote: d.HarvestNote}, true
	}
	return nil, false
}

// knownIdentity returns the caller baseline ONLY if this scan already
// established one. It never probes: the no-candidate path must be able to
// harvest with exclusions and then conclude without sending anything.
func (e *idorExecutor) knownIdentity(ctx context.Context, scanID domain.ID) *idorIdentity {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	if e.cached != nil {
		return e.cached
	}
	if ident, ok := e.loadIdentityCase(ctx, scanID); ok {
		e.cached = ident
		return ident
	}
	return nil
}

// maxIdentityPaths bounds the identity-page probes: four conventional paths
// plus at most four pages discovery already found on the same origin.
const maxIdentityPaths = 8

// identityPaths starts with the conventional account pages and adds
// application-specific profile/account pages the crawler already discovered.
// A target that calls its account page /profile_user otherwise forced the
// engine to skip every IDOR probe even though the page was in the scan's own
// endpoint registry. The additions are read-only GET/HEAD paths, same origin,
// bounded, and filtered away from admin/write/list surfaces.
func (e *idorExecutor) identityPaths(ctx context.Context, ep *domain.Endpoint) []string {
	paths := []string{"/my-account", "/profile", "/account", "/me"}
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	origin := originOf(ep.URL)
	if origin == "" {
		return paths
	}
	endpoints, err := e.store.Endpoints().ListByScan(ctx, ep.ScanID)
	if err != nil {
		return paths
	}
	for _, candidate := range endpoints {
		if candidate == nil || (candidate.Method != "" && candidate.Method != domain.MethodGET && candidate.Method != domain.MethodHEAD) {
			continue
		}
		u, err := url.Parse(candidate.URL)
		if err != nil || u.Scheme+"://"+u.Host != origin {
			continue
		}
		p := strings.TrimSuffix(u.Path, "/")
		if p == "" || p == "/" || len(p) > 80 || seen[p] || !isIdentityPath(p) {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
		if len(paths) >= maxIdentityPaths {
			break
		}
	}
	return paths
}

// isIdentityPath recognizes a page that is likely to identify the signed-in
// caller. It is deliberately narrow: a profile/account/me segment is required,
// and admin, list, mutation and API paths are excluded.
func isIdentityPath(path string) bool {
	p := strings.ToLower(strings.Trim(path, "/"))
	if p == "" || strings.Contains(p, "//") {
		return false
	}
	segments := strings.Split(p, "/")
	if len(segments) > 3 {
		return false
	}
	for _, seg := range segments {
		switch {
		case strings.Contains(seg, "logout"), strings.Contains(seg, "log-out"),
			strings.Contains(seg, "signout"), strings.Contains(seg, "sign-out"),
			strings.Contains(seg, "delete"), strings.Contains(seg, "remove"),
			strings.Contains(seg, "update"), strings.Contains(seg, "edit"),
			strings.Contains(seg, "store"), strings.Contains(seg, "create"),
			strings.Contains(seg, "upload"), strings.Contains(seg, "export"),
			strings.Contains(seg, "download"), strings.Contains(seg, "admin"),
			strings.Contains(seg, "api"), strings.Contains(seg, "list"):
			return false
		}
	}
	for _, seg := range segments {
		if strings.Contains(seg, "profile") || strings.Contains(seg, "account") {
			return true
		}
		if seg == "me" || seg == "my" || seg == "user" {
			return true
		}
	}
	return false
}

// identity returns the scan's caller-identity baseline, establishing and
// persisting it on first use. The baseline is read back from a TestCase so a
// restarted scan does not probe the account page again. Only bounded, common
// account paths on the endpoint's own origin are tried: no wordlist, no
// cross-host lookup.
func (e *idorExecutor) identity(ctx context.Context, scanID domain.ID, ep *domain.Endpoint) (*idorIdentity, bool) {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	if e.cached != nil {
		return e.cached, true
	}
	if ident, ok := e.loadIdentityCase(ctx, scanID); ok {
		e.cached = ident
		return e.cached, true
	}

	origin := originOf(ep.URL)
	var tried []string
	for _, path := range e.identityPaths(ctx, ep) {
		if origin == "" {
			break
		}
		tried = append(tried, path)
		req := httpengine.GET(origin + path)
		resp, outcome, _, _ := e.send(ctx, req)
		if outcome != domain.OutcomeSuccess || resp == nil || resp.Status < 200 || resp.Status >= 300 {
			continue
		}
		ident := idor.ExtractIdentity(resp.Body)
		if ident.Empty() {
			continue
		}
		e.cached = &idorIdentity{Identity: ident, Source: origin + path}
		e.cached.CaseID = e.persistIdentity(ctx, scanID, e.cached, resp)
		return e.cached, false
	}

	reason := fmt.Sprintf("caller identity could not be established from the target with this session (tried %s)",
		strings.Join(tried, ", "))
	e.cached = &idorIdentity{Reason: reason}
	e.cached.CaseID = e.persistIdentity(ctx, scanID, e.cached, nil)
	return e.cached, false
}

// persistIdentity records the baseline (positive or negative) as a TestCase
// with its own request/response evidence, and returns its ID so the harvested
// candidate set can be attached to the same durable row.
func (e *idorExecutor) persistIdentity(ctx context.Context, scanID domain.ID, id *idorIdentity, resp *httpengine.Response) domain.ID {
	now := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, VulnClass: domain.VulnIDOR,
		Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess,
		URL: id.Source, StartedAt: &now, FinishedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	d := idorDetail{Engine: "idor", CallerIdentity: id.Identity, IdentitySource: id.Source, Reason: id.Reason, SkipReason: id.Reason}
	tc.Note = idorIdentityNote
	if id.Identity.Empty() {
		tc.Note = idorIdentityNote + " unavailable: " + truncate(id.Reason, 200)
	}
	if resp != nil {
		if ids, err := e.persistPair(ctx, tc, resp, "idor identity baseline"); err == nil {
			tc.EvidenceIDs = ids
			id.Evidence = ids
			d.IdentityEvidence = ids
		} else {
			tc.Note += " | identity evidence incomplete: " + truncate(err.Error(), 200)
		}
	}
	tc.Detail = encodeIDORDetail(d)
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("persist IDOR identity baseline", "scan", scanID, "err", err)
		return ""
	}
	return tc.ID
}

// persistHarvest attaches the harvested candidate set to the identity-baseline
// TestCase. It is a read-only fact for the report/API — the engine itself never
// re-reads it within a run (the in-memory set is authoritative there).
func (e *idorExecutor) persistHarvest(ctx context.Context, ident *idorIdentity, harvested []idor.Harvest, note string) {
	if ident == nil || ident.CaseID.Empty() {
		return
	}
	tc, err := e.store.TestCases().Get(ctx, ident.CaseID)
	if err != nil {
		e.log.Warn("load identity baseline for harvest", "case", ident.CaseID, "err", err)
		return
	}
	var d idorDetail
	if len(tc.Detail) > 0 {
		_ = json.Unmarshal(tc.Detail, &d)
	}
	d.Harvest, d.HarvestNote = harvested, note
	tc.Detail = encodeIDORDetail(d)
	tc.UpdatedAt = time.Now()
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("persist IDOR harvest", "case", ident.CaseID, "err", err)
	}
}

// ---------------------------------------------------------------------------
// candidates and correlation
// ---------------------------------------------------------------------------

// ownObjectValue is the caller's own object identifier: the value discovery
// observed for the focused parameter with the scan's authenticated session.
func ownObjectValue(ep *domain.Endpoint, p *domain.Parameter) string {
	if v := strings.TrimSpace(p.Example); v != "" {
		return v
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return ""
	}
	if p.Location == domain.LocationPath {
		if idx, ok := pathSegmentIndex(p.Name); ok {
			segs := discovery.PathSegments(u.Path)
			if idx >= 0 && idx < len(segs) {
				return segs[idx]
			}
		}
		return ""
	}
	return u.Query().Get(p.Name)
}

// deriveCandidates merges the bounded candidate sources for one parameter:
// operator-supplied values, numeric neighbours and harvested identifiers
// (always), then — only when the operator explicitly opted in — the bounded
// enumeration set. The per-site bound is MaxCandidates for derived values plus
// MaxEnumerationPerSite for enumerated ones; the scan-wide probe budget is
// spent by both through the same counter.
func (e *idorExecutor) deriveCandidates(own string, harvested []idor.Harvest, d *idorDetail) ([]idor.Candidate, string) {
	if !e.enum.Enabled {
		// Off by default: exactly the previous behaviour, byte for byte.
		return idor.DeriveCandidatesFromHarvest(own, e.supplied, harvested, 0)
	}

	// Enumeration replaces the implicit numeric neighbours with a stated
	// arithmetic, so the two do not both run (the old unpadded neighbours would
	// contradict a padded set). Explicit values and harvested identifiers come
	// first; the bounded enumeration set follows, deduplicated.
	cands, reason := idor.DeriveExplicitAndHarvested(own, e.supplied, harvested, 0)
	extra := idor.EnumerateCandidates(own, e.enum.Neighbours)
	var added []idor.Candidate
	for _, c := range extra {
		if candidateValuePresent(cands, c.Value) {
			continue
		}
		cands = append(cands, c)
		added = append(added, c)
	}
	if len(extra) > 0 {
		values := make([]string, 0, len(added))
		for _, c := range added {
			values = append(values, c.Value)
		}
		d.Enumeration = true
		if len(added) == 0 {
			d.EnumerationNote = fmt.Sprintf("bounded enumeration of baseline %q with N=%d produced no new candidate (all already proposed by another source)",
				own, e.enum.ResolveNeighbours())
		} else {
			d.EnumerationNote = fmt.Sprintf("bounded enumeration of baseline %q with N=%d: tried %s",
				own, e.enum.ResolveNeighbours(), strings.Join(values, ", "))
		}
	}
	if len(cands) > 0 {
		return cands, ""
	}
	return nil, reason
}

func candidateValuePresent(cands []idor.Candidate, value string) bool {
	for _, c := range cands {
		if strings.EqualFold(strings.TrimSpace(c.Value), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

// filterCallerCandidates drops any candidate that is one of the caller's own
// identity values. The harvest may have been computed before the identity
// baseline was established, so this is the second, authoritative exclusion.
func filterCallerCandidates(cands []idor.Candidate, caller idor.Identity) []idor.Candidate {
	if len(caller.Fields) == 0 {
		return cands
	}
	excluded := make(map[string]bool, len(caller.Fields))
	for _, f := range caller.Fields {
		if v := strings.ToLower(strings.TrimSpace(f.Value)); v != "" {
			excluded[v] = true
		}
	}
	out := make([]idor.Candidate, 0, len(cands))
	for _, c := range cands {
		if excluded[strings.ToLower(strings.TrimSpace(c.Value))] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ---------------------------------------------------------------------------
// harvesting: identifiers mined from data the scan already holds
// ---------------------------------------------------------------------------

// maxHarvestBodies bounds how many stored response bodies are mined per scan.
// Harvesting adds no requests, but it must not read an unbounded number of
// blobs either.
const maxHarvestBodies = 200

// maxHarvestHeaderBytes bounds how much of an HTTP evidence dump is scanned
// for the header/body separator before the body is taken.
const maxHarvestHeaderBytes = 16 << 10

// harvestCandidates returns the scan's harvested candidate set, computing it
// once per execution and reusing the persisted set after a restart. It performs
// local reads only: no request is ever sent to build this list.
func (e *idorExecutor) harvestCandidates(ctx context.Context, scanID domain.ID, ident *idorIdentity, own string) ([]idor.Harvest, string) {
	e.harvestMu.Lock()
	defer e.harvestMu.Unlock()
	if e.harvestDone {
		return e.harvested, e.harvestNote
	}
	e.harvestDone = true

	// A resumed scan already has the set persisted on the identity baseline.
	if ident != nil && ident.HarvestNote != "" {
		e.harvested, e.harvestNote = ident.Harvest, ident.HarvestNote
		return e.harvested, e.harvestNote
	}

	exclude := e.harvestExclusions(ctx, scanID, ident)
	// The focused parameter's own value is the CALLER's object identifier: it
	// is never a foreign candidate, and proposing it would waste a probe (and
	// make an empty harvest look non-empty).
	if v := strings.TrimSpace(own); v != "" {
		exclude = append(exclude, v)
	}
	observations := e.harvestObservations(ctx, scanID)
	e.harvested = idor.HarvestCandidates(observations, exclude, 0)
	e.harvestNote = fmt.Sprintf("%d identifiers harvested from the scan's own data (cap %d, no extra requests)",
		len(e.harvested), idor.MaxHarvested)
	if len(e.harvested) == 0 {
		e.harvestNote = "no foreign identifier could be harvested from the scan's own data"
	}
	e.log.Debug("idor harvest", "scan", scanID, "candidates", len(e.harvested))
	return e.harvested, e.harvestNote
}

// harvestExclusions are values the harvester must never propose: the caller's
// own identity and the scan's own session cookies (session material is a
// credential, not a foreign object id).
func (e *idorExecutor) harvestExclusions(ctx context.Context, scanID domain.ID, ident *idorIdentity) []string {
	var out []string
	if ident != nil {
		for _, f := range ident.Identity.Fields {
			out = append(out, f.Value)
		}
	}
	if sess, err := e.store.Sessions().GetByScan(ctx, scanID); err == nil && sess != nil && sess.StatePath != "" {
		for _, c := range sessionCookies(sess.StatePath) {
			if c.Value != "" {
				out = append(out, c.Value)
			}
		}
	}
	return out
}

// harvestObservations converts the scan's already-collected data into harvest
// observations, deterministically ordered: endpoint URLs and object-id query
// values, discovered parameter examples, then stored response bodies.
func (e *idorExecutor) harvestObservations(ctx context.Context, scanID domain.ID) []idor.Observation {
	var obs []idor.Observation
	urlByEndpoint := map[domain.ID]string{}

	endpoints, err := e.store.Endpoints().ListByScan(ctx, scanID)
	if err == nil {
		sort.SliceStable(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
		for _, ep := range endpoints {
			urlByEndpoint[ep.ID] = ep.URL
			u, perr := url.Parse(ep.URL)
			if perr != nil {
				continue
			}
			// Path segments that are POSITIONALLY objects (/users/42, never
			// a bare /product route): precision first, so harvesting does
			// not propose the crawl's own route words.
			if segs := idor.ObjectPathSegments(u.Path); len(segs) > 0 {
				obs = append(obs, idor.Observation{Endpoint: ep.URL, Field: "path", Via: idor.ViaPath, Values: segs})
			}
			q := u.Query()
			names := make([]string, 0, len(q))
			for name := range q {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if !idor.ObjectIDParameter(name) {
					continue
				}
				obs = append(obs, idor.Observation{Endpoint: ep.URL, Field: name, Via: idor.ViaQuery, Values: q[name]})
			}
		}
	}

	params, err := e.store.Parameters().ListByScan(ctx, scanID)
	if err == nil {
		sort.SliceStable(params, func(i, j int) bool {
			if params[i].EndpointID != params[j].EndpointID {
				return params[i].EndpointID < params[j].EndpointID
			}
			return params[i].Name < params[j].Name
		})
		for _, p := range params {
			// Every DISTINCT value the crawl observed for this parameter, not
			// just the first. Endpoint dedup keeps one URL per path, so a
			// parameter's later values are the only record of the other users'
			// identifiers the crawl actually saw (measured: a lab whose other
			// users' GUIDs appear only as /blogs?userId=<uuid> link values).
			values := append([]string(nil), p.Examples...)
			if len(values) == 0 {
				if v := strings.TrimSpace(p.Example); v != "" {
					values = append(values, v)
				}
			}
			if len(values) == 0 {
				continue
			}
			obs = append(obs, idor.Observation{Endpoint: urlByEndpoint[p.EndpointID], Field: p.Name, Via: idor.ViaParameter, Values: values})
		}
	}

	obs = append(obs, e.harvestEvidenceBodies(ctx, scanID)...)
	return obs
}

// harvestEvidenceBodies reads the response bodies the scan already stored as
// evidence (HTML/JSON, bounded per body) and attributes each to the TestCase
// URL that produced it.
func (e *idorExecutor) harvestEvidenceBodies(ctx context.Context, scanID domain.ID) []idor.Observation {
	if e.evidence == nil {
		return nil
	}
	rows, err := e.store.Evidence().ListByScan(ctx, scanID)
	if err != nil {
		return nil
	}
	urlByCase := map[domain.ID]string{}
	if cases, cerr := e.store.TestCases().ListByScan(ctx, scanID); cerr == nil {
		for _, tc := range cases {
			if tc.URL != "" {
				urlByCase[tc.ID] = tc.URL
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.Before(rows[j].CreatedAt)
		}
		return rows[i].ID < rows[j].ID
	})

	var out []idor.Observation
	for _, row := range rows {
		if len(out) >= maxHarvestBodies {
			break
		}
		if row.Kind != domain.EvidenceResponse || !harvestableBody(row) {
			continue
		}
		body, ok := e.readEvidenceBody(row)
		if !ok || len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		source := urlByCase[evidenceTestCaseID(row.Note)]
		out = append(out, idor.Observation{Endpoint: source, BodyURL: source, Body: body})
	}
	return out
}

// harvestableBody keeps the harvest off binary artifacts (screenshots, HARs,
// blobs) and on the response bodies that can carry identity data.
func harvestableBody(row *domain.Evidence) bool {
	mt := strings.ToLower(row.MediaType)
	if strings.Contains(mt, "message/http") || strings.Contains(mt, "html") || strings.Contains(mt, "json") {
		return true
	}
	lower := strings.ToLower(row.BlobPath)
	for _, ext := range []string{".http", ".html", ".htm", ".json"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// readEvidenceBody returns the response body of one evidence blob, stripping
// the HTTP message headers every executor writes around it.
func (e *idorExecutor) readEvidenceBody(row *domain.Evidence) ([]byte, bool) {
	rc, err := e.evidence.Open(row.BlobPath)
	if err != nil {
		return nil, false
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, idor.MaxHarvestBodyBytes+maxHarvestHeaderBytes))
	if err != nil {
		return nil, false
	}
	if strings.EqualFold(row.MediaType, "message/http") || strings.HasSuffix(strings.ToLower(row.BlobPath), ".http") {
		idx := bytes.Index(data, []byte("\r\n\r\n"))
		if idx < 0 {
			return nil, false
		}
		data = data[idx+4:]
	}
	if len(data) > idor.MaxHarvestBodyBytes {
		data = data[:idor.MaxHarvestBodyBytes]
	}
	return data, true
}

// evidenceTestCaseID reads the "test_case=<id>" attribution every executor
// writes into an evidence note.
func evidenceTestCaseID(note string) domain.ID {
	const prefix = "test_case="
	i := strings.Index(note, prefix)
	if i < 0 {
		return ""
	}
	rest := note[i+len(prefix):]
	if j := strings.IndexAny(rest, " 	"); j >= 0 {
		rest = rest[:j]
	}
	return domain.ID(strings.TrimSpace(rest))
}

// idorFindingDedupKey identifies one broken-object-authorization site: the
// endpoint + parameter whose identifier can select another principal's
// object. Category/context do not apply the way they do for XSS.
func idorFindingDedupKey(ep *domain.Endpoint, focus *domain.Parameter) string {
	return string(ep.ID) + "\x00" + string(focus.ID) + "\x00idor"
}

// correlate creates or ratchets the Confirmed Finding for this site. Only a
// Confirmed differential ever creates a Finding; Rejected/Inconclusive
// outcomes stay in the TestCase detail so a report is never padded with
// per-parameter negatives.
func (e *idorExecutor) correlate(ctx context.Context, scanID domain.ID, ep *domain.Endpoint, focus *domain.Parameter, ipID domain.ID, d idorDetail, tcID domain.ID) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	key := idorFindingDedupKey(ep, focus)
	d.DedupKey = key
	d.TestCaseIDs = appendUniqueID(d.TestCaseIDs, tcID)

	var evidence []domain.ID
	evidence = append(evidence, d.IdentityEvidence...)
	evidence = append(evidence, d.BaselineEvidence...)
	for _, a := range d.Attempts {
		if a.Outcome == string(idor.OutcomeConfirmed) {
			evidence = append(evidence, a.EvidenceIDs...)
		}
	}

	existing, err := e.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		e.log.Warn("list findings for IDOR correlation", "scan", scanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnIDOR {
			continue
		}
		var fd idorDetail
		_ = json.Unmarshal(f.Detail, &fd)
		if fd.DedupKey != key {
			continue
		}
		fd.Occurrences++
		fd.TestCaseIDs = appendUniqueID(fd.TestCaseIDs, tcID)
		fd.Attempts = mergeIDORAttempts(fd.Attempts, d.Attempts)
		fd.Verdict = domain.VerdictConfirmed
		fd.Reason = d.Reason
		f.Detail = encodeIDORDetail(fd)
		f.Verdict = domain.VerdictConfirmed
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, evidence)
		f.UpdatedAt = time.Now()
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("update IDOR finding", "finding", f.ID, "err", err)
		}
		return
	}

	sc, err := e.store.Scans().Get(ctx, scanID)
	if err != nil {
		e.log.Warn("load scan for IDOR finding", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	foreign := firstForeign(d.Attempts)
	title := fmt.Sprintf("IDOR: parameter %q at %s %s returned another principal's data", focus.Name, ep.Method, endpointLabel(ep.URL))
	if foreign != "" {
		title = fmt.Sprintf("IDOR: parameter %q at %s %s returned another principal's data (%s)", focus.Name, ep.Method, endpointLabel(ep.URL), foreign)
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnIDOR,
		Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:            title,
		Summary:          d.Reason,
		EndpointID:       ep.ID,
		InjectionPointID: ipID,
		ParameterID:      focus.ID,
		Location:         focus.Location,
		EvidenceIDs:      appendUniqueIDs(nil, evidence),
		Provenance:       domain.Provenance{Engine: "idor", DiscoverySource: ep.Source, DetectedAt: now, AIAssisted: false},
		Detail:           encodeIDORDetail(d),
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("create IDOR finding", "scan", scanID, "err", err)
	}
}

func firstForeign(attempts []idorAttempt) string {
	for _, a := range attempts {
		if a.Foreign != nil {
			return a.Foreign.Value
		}
	}
	return ""
}

func mergeIDORAttempts(existing, add []idorAttempt) []idorAttempt {
	for _, a := range add {
		found := false
		for _, x := range existing {
			if x.Candidate == a.Candidate {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, a)
		}
	}
	return existing
}

// ---------------------------------------------------------------------------
// probe pass: one JobIDOR per object-identifier injection point
// ---------------------------------------------------------------------------

// idorCallerIdentity reports whether this scan has a REAL caller identity for
// the object-identifier differential to compare against: a session row that is
// authenticated (any mode except anonymous) and currently active. The identity
// itself is still established from the target (see establishIDORIdentity) — this
// only decides whether there is a session worth establishing it from, so a
// scan's own auth state stays the single source of truth.
func (c *Controller) idorCallerIdentity(ctx context.Context, sc *domain.Scan) bool {
	if sc == nil || sc.SessionID.Empty() {
		return false
	}
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil || sess == nil {
		return false
	}
	if sess.Mode == domain.AuthAnonymous || !sess.Mode.IsValid() {
		return false
	}
	return sess.State == domain.SessionActive
}

// enqueueIDORProbes runs once per execution, after the XSS and DOM-XSS passes.
// It is automatic: the only precondition is a real caller identity (see
// idorCallerIdentity). Bounded by the discovered parameters: it only queues
// GET/HEAD query/path object-id injection points.
func (c *Controller) enqueueIDORProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("idor probes: load scan", "scan", scanID, "err", err)
		return
	}
	// The engine is automatic: no opt-in flag decides this. What it needs is a
	// real caller identity (the differential compares the caller's own object
	// against a foreign one) and at least one object-identifier-shaped
	// parameter, which idorParameter enforces per parameter below. A scan with
	// no session has nobody to compare against, so it plans nothing — that is
	// the only gate left.
	// Case 34 is a different shape and has its own opt-in; it needs the same
	// real caller identity, so it is queued under the same gate.
	c.enqueueObjectFamilyProbes(ctx, scanID)
	if !c.idorCallerIdentity(ctx, sc) {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("idor probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	params, err := c.store.Parameters().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("idor probes: list parameters", "scan", scanID, "err", err)
		return
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("idor probes: list injection points", "scan", scanID, "err", err)
		return
	}
	byEndpoint := map[domain.ID][]*domain.Parameter{}
	for _, p := range params {
		byEndpoint[p.EndpointID] = append(byEndpoint[p.EndpointID], p)
	}
	ipByParam := map[domain.ID]domain.ID{}
	for _, ip := range ips {
		ipByParam[ip.ParameterID] = ip.ID
	}

	now := time.Now()
	n := 0
	for _, ep := range endpoints {
		if !isSafeMethod(ep.Method) {
			continue
		}
		for _, p := range byEndpoint[ep.ID] {
			if !idorParameter(p) {
				continue
			}
			ipID := ipByParam[p.ID]
			if ipID.Empty() {
				ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID,
					ParameterID: p.ID, Location: p.Location, CreatedAt: now}
				if err := c.store.InjectionPoints().Create(ctx, ip); err != nil {
					c.log.Warn("idor probes: create injection point", "scan", scanID, "param", p.Name, "err", err)
					continue
				}
				ipID = ip.ID
				ipByParam[p.ID] = ipID
			}
			job := &domain.TestJob{
				ID: domain.NewID(), ScanID: scanID, Type: domain.JobIDOR, State: domain.JobQueued,
				Priority: 30, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ipID, URL: ep.URL},
				MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
			}
			if err := c.queue.Enqueue(ctx, job); err != nil {
				c.log.Warn("idor probes: enqueue job", "scan", scanID, "param", p.Name, "err", err)
				continue
			}
			n++
		}
	}
	if n > 0 {
		c.log.Info("idor probes: enqueued", "scan", scanID, "jobs", n)
	}
}

// idorParameter reports whether a discovered parameter is an object
// identifier this engine may probe.
func idorParameter(p *domain.Parameter) bool {
	switch p.Location {
	case domain.LocationQuery:
		return idor.ObjectIDParameter(p.Name)
	case domain.LocationPath:
		return strings.TrimSpace(p.Example) != ""
	default:
		return false
	}
}

func pathSegmentIndex(name string) (int, bool) {
	return discovery.ParsePathSegmentParamName(name)
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// samePrincipal compares two extracted identities. ok is false when they
// share no comparable field (so no conclusion can be drawn).
func samePrincipal(a, b idor.Identity) (same bool, ok bool) {
	comparable := 0
	for _, af := range a.Fields {
		for _, bf := range b.Fields {
			if af.Kind != bf.Kind {
				continue
			}
			comparable++
			if !strings.EqualFold(strings.TrimSpace(af.Value), strings.TrimSpace(bf.Value)) {
				return false, true
			}
		}
	}
	if comparable == 0 {
		return false, false
	}
	return true, true
}
