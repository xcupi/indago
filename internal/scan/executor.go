package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// ExecutorConfig tunes the test-job executor.
type ExecutorConfig struct {
	// RequestTimeout bounds one request (default 20s). Exceeding it is a TIMEOUT.
	RequestTimeout time.Duration
	// AllowStateChanging permits executing methods other than GET/HEAD/OPTIONS
	// (POST, PUT, PATCH, DELETE). Off by default: replaying discovered forms
	// against a live target can change its state, so it is an explicit opt-in.
	// Jobs for such endpoints are recorded as SKIPPED, not failed.
	AllowStateChanging bool
}

func (c ExecutorConfig) withDefaults() ExecutorConfig {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 20 * time.Second
	}
	return c
}

// executor runs JobTest jobs: it resolves the job's endpoint, parameters, and
// injection point, executes the BASELINE request through the HTTP engine, and
// persists the result and request/response evidence.
//
// Boundaries:
//   - The engine it is given MUST enforce scope (the controller passes the
//     scan's scopedEngine). The executor never talks to the network any other way.
//   - It sends each parameter at its observed value. It performs no mutation, no
//     payload generation, and no vulnerability detection; a later phase attaches
//     those by deciding which parameter value to substitute.
type executor struct {
	store     store.Store
	engine    httpengine.Engine
	evidence  evidence.Store // nil: outcomes are recorded without evidence blobs
	queue     queue.Queue    // nil: candidate children are not enqueued (unit tests)
	cfg       ExecutorConfig
	log       *slog.Logger
	baselines *baselineCache // reuses a baseline across an endpoint's injection points
	// findingsMu serializes Finding correlation (upsertPendingFinding) against
	// both other candidates in this executor AND verifyExecutor's
	// correlateVerification for the same scan — see newExecutor's doc. Never
	// nil (the constructor defaults it).
	findingsMu *sync.Mutex
	// tokenMu — see withDynamicTokenLock in dynamic_params.go. MUST be the
	// same mutex given to this scan's verifyExecutor (see defaultHandlers):
	// a dynamic (rotating/single-use) token is tied to the whole session, not
	// to this executor alone, so a candidate request here and a verification
	// navigation in verifyExecutor can race for the same token slot without
	// a lock shared across both. Never nil (the constructor defaults it).
	tokenMu *sync.Mutex
}

// newExecutor builds a test-job executor. findingsMu and tokenMu, when
// non-nil, MUST be the SAME mutexes given to this scan's verifyExecutor (see
// defaultHandlers): both enqueueVerification (here) and
// correlateVerification read-then-write Finding rows keyed by a correlation
// lookup, not a store-level unique constraint, so without a shared
// findingsMu, two candidates (or a candidate and a verification) racing on
// the same site can create a duplicate Finding or lose an update; without a
// shared tokenMu, a candidate request here and a verification navigation
// there can race for the same single-use session token (see
// dynamic_params.go). nil defaults to a fresh mutex for each, which is
// correct whenever a caller (e.g. a test exercising only this executor)
// never shares a scan with a separately-constructed verifyExecutor.
func newExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, q queue.Queue, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex, tokenMu *sync.Mutex) *executor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	if tokenMu == nil {
		tokenMu = &sync.Mutex{}
	}
	return &executor{store: st, engine: eng, evidence: ev, queue: q, cfg: cfg.withDefaults(), log: log, baselines: newBaselineCache(), findingsMu: findingsMu, tokenMu: tokenMu}
}

var _ worker.Handler = (*executor)(nil)

// Handle implements worker.Handler.
//
// Return value → job state: SUCCESS and SKIPPED return nil (job succeeds);
// CANCELLED returns the context error; TIMEOUT and transport ERROR return a
// retryable error (the queue retries with backoff up to MaxAttempts); permanent
// errors (out of scope, invalid request, unresolvable job) wrap
// worker.ErrPermanent so they are not retried.
func (e *executor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	tc := &domain.TestCase{
		ID:               domain.NewID(),
		ScanID:           job.ScanID,
		JobID:            job.ID,
		Attempt:          job.Attempts,
		InjectionPointID: job.Target.InjectionPointID,
		Status:           domain.TestCaseRunning,
		URL:              job.Target.URL, // refined to the exact URL sent once built
		StartedAt:        &started,
		CreatedAt:        started,
		UpdatedAt:        started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		// Without a record we would send an unaccounted-for request. Retry later.
		return fmt.Errorf("persist test case: %w", err)
	}

	res := e.run(ctx, job, tc)

	// The job context may already be canceled (that is the CANCELLED case), so the
	// final writes use a detached context with its own bound.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e.finish(wctx, tc, res)

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
		return res.err // TIMEOUT / transport ERROR: retry with backoff
	}
}

// result is the outcome of one execution attempt.
type result struct {
	outcome   domain.TestOutcome
	skipped   bool
	permanent bool
	err       error
	note      string
	req       *httpengine.CapturedRequest
	resp      *httpengine.Response
	duration  time.Duration

	// Reflection/detection extras (nil/empty for a plain baseline).
	vulnClass      domain.VulnClass
	detail         []byte      // engine-specific result (JSON) for TestCase.Detail
	sharedEvidence []domain.ID // already-persisted evidence to reference (e.g. baseline)

	// reflection is finalized in finish(), once the evidence IDs it must reference
	// exist; it is then marshaled into TestCase.Detail.
	reflection   *detection.ReflectionReport
	baselineReq  domain.ID
	baselineResp domain.ID

	// blockSuspected/blockBaselineStatus/blockMutatedStatus: see
	// possibleBlockNote. Set on a "not reflected" result whose status code
	// looks like a WAF/rate-limit/maintenance block rather than a clean
	// negative, so run() can record the diagnostic Finding described in
	// upsertBlockFinding (finding.go) — this is the ONLY consumer; the note
	// text alone (always set regardless) stays on the TestCase either way.
	blockSuspected      bool
	blockBaselineStatus int
	blockMutatedStatus  int

	// captchaSuspected/captchaLabel: see detection.CaptchaSuspected. Set when
	// a CAPTCHA/bot-challenge page newly appears for the mutated/candidate
	// request (not present on the baseline) — detect-only, never attempted
	// to solve or bypass (AGENTS.md §2.2). run() calls recordCaptchaFinding
	// (verify.go) for this, same pattern as blockSuspected above; the two
	// are independent signals and can both be set on the same result.
	captchaSuspected bool
	captchaLabel     string
}

func (e *executor) run(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) result {
	ep, params, focus, err := e.resolve(ctx, job)
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err}
	}
	tc.Method, tc.URL = string(ep.Method), ep.URL

	cand, hasCand, err := parseCandidateJob(job)
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, vulnClass: domain.VulnReflectedXSS}
	}

	kind := "baseline"
	switch {
	case hasCand:
		kind = fmt.Sprintf("candidate %s/%s; parameter %s (%s)", cand.Source, cand.Category, focus.Name, focus.Location)
	case focus != nil:
		kind = fmt.Sprintf("reflection; parameter %s (%s)", focus.Name, focus.Location)
	}
	// State-changing safeguard applies to baseline, reflection, AND candidate jobs:
	// a candidate breakout is never sent to a state-changing endpoint unless the
	// operator opted in.
	if !e.cfg.AllowStateChanging && !isSafeMethod(ep.Method) {
		return result{skipped: true, note: fmt.Sprintf("%s skipped: %s is state-changing and AllowStateChanging is off", kind, ep.Method)}
	}

	switch {
	case hasCand:
		// A candidate job needs its injection point to resolve a focus parameter.
		if focus == nil {
			return result{outcome: domain.OutcomeError, permanent: true, err: errors.New("candidate job has no injection point"), vulnClass: domain.VulnReflectedXSS}
		}
		res := e.runCandidate(ctx, tc, ep, params, focus, cand)
		// A candidate that reflected is always correlated into a PENDING finding
		// — confirmed or rejected only by real browser verification, never by
		// this HTTP-only result. enqueueVerification itself decides whether a
		// browser-verify job can even be enqueued (browser navigation carries no
		// request body, so a POST/body-carrying candidate's finding stays
		// Pending — see docs/scan-orchestration.md).
		if res.reflection != nil && res.reflection.Reflected {
			e.enqueueVerification(ctx, job, ep, cand, focus, tc.ID)
		} else if res.blockSuspected {
			e.recordBlockFinding(ctx, job, ep, focus, res.blockBaselineStatus, res.blockMutatedStatus, tc.ID)
		}
		if res.captchaSuspected {
			e.recordCaptchaFinding(ctx, job, ep, focus, res.captchaLabel, tc.ID)
		}
		return res
	case focus != nil:
		res := e.runReflection(ctx, tc, ep, params, focus)
		// Enqueue one child test job per planned candidate, before this (parent)
		// job completes, so scan completion waits for them. Candidate jobs do not
		// re-plan, so this does not recurse.
		if res.reflection != nil && res.reflection.Plan != nil {
			e.enqueueCandidates(ctx, job, res.reflection.Plan)
		}
		if res.blockSuspected {
			e.recordBlockFinding(ctx, job, ep, focus, res.blockBaselineStatus, res.blockMutatedStatus, tc.ID)
		}
		if res.captchaSuspected {
			e.recordCaptchaFinding(ctx, job, ep, focus, res.captchaLabel, tc.ID)
		}
		return res
	default:
		return e.runBaselineOnly(ctx, tc, ep, params)
	}
}

// runBaselineOnly executes an endpoint-level job: a single baseline request with
// every parameter at its observed value (no marker, no detection).
func (e *executor) runBaselineOnly(ctx context.Context, tc *domain.TestCase, ep *domain.Endpoint, params []*domain.Parameter) result {
	req, err := buildRequest(ep, params, nil)
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: "baseline"}
	}
	tc.URL = req.URL
	resp, outcome, err, dur := e.send(ctx, req)
	return result{
		outcome:   outcome,
		permanent: outcome == domain.OutcomeError && isPermanentRequestError(err),
		err:       err,
		note:      "baseline",
		req:       capturedFrom(req, resp),
		resp:      resp,
		duration:  dur,
	}
}

// send executes one request with the per-request timeout and classifies the
// execution outcome. It never classifies reflection; that is the caller's job.
func (e *executor) send(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error, time.Duration) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err, 0 // already canceled: send nothing
	}
	// The timeout travels WITH the request (applied inside Do): the engine may
	// hold this request for a rate-limit permit first, and that wait is not
	// network time and must not be reported as a TIMEOUT.
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	t0 := time.Now()
	resp, err := e.engine.Do(ctx, &timed)
	dur := time.Since(t0)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil, resp.Duration
	case ctx.Err() != nil:
		// The JOB's context ended (scan cancel / shutdown), not our own timeout.
		return nil, domain.OutcomeCancelled, ctx.Err(), dur
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err, dur
	default:
		return nil, domain.OutcomeError, err, dur
	}
}

// resolve loads the job's endpoint, the endpoint's parameters, and (for an
// injection-point job) the focused parameter. It verifies everything belongs to
// the job's scan. Shared with the verify-job handler (verify.go).
func (e *executor) resolve(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, *domain.Parameter, error) {
	return resolveJobTarget(ctx, e.store, job)
}

// resolveJobTarget is the free-function form of resolve, shared by the test-job
// executor and the browser-verify handler so both resolve a job's target
// identically.
func resolveJobTarget(ctx context.Context, st store.Store, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, *domain.Parameter, error) {
	endpointID := job.Target.EndpointID
	var focus *domain.Parameter

	if ipID := job.Target.InjectionPointID; !ipID.Empty() {
		ip, err := st.InjectionPoints().Get(ctx, ipID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("resolve injection point %s: %w", ipID, err)
		}
		if ip.ScanID != job.ScanID {
			return nil, nil, nil, fmt.Errorf("injection point %s belongs to another scan", ipID)
		}
		if endpointID.Empty() {
			endpointID = ip.EndpointID
		} else if endpointID != ip.EndpointID {
			return nil, nil, nil, fmt.Errorf("injection point %s does not belong to endpoint %s", ipID, endpointID)
		}
		if focus, err = st.Parameters().Get(ctx, ip.ParameterID); err != nil {
			return nil, nil, nil, fmt.Errorf("resolve parameter %s: %w", ip.ParameterID, err)
		}
	}
	if endpointID.Empty() {
		return nil, nil, nil, errors.New("job has neither an endpoint nor an injection point")
	}

	ep, err := st.Endpoints().Get(ctx, endpointID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve endpoint %s: %w", endpointID, err)
	}
	if ep.ScanID != job.ScanID {
		return nil, nil, nil, fmt.Errorf("endpoint %s belongs to another scan", endpointID)
	}
	params, err := st.Parameters().ListByEndpoint(ctx, endpointID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list parameters: %w", err)
	}
	return ep, params, focus, nil
}

// finish persists the attempt's result and its request/response evidence.
func (e *executor) finish(ctx context.Context, tc *domain.TestCase, r result) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Note = r.note
	tc.DurationMS = r.duration.Milliseconds()
	if r.resp != nil {
		tc.HTTPStatus = r.resp.Status
	}

	switch {
	case r.skipped:
		tc.Status = domain.TestCaseSkipped
		tc.DurationMS = 0
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

	if r.vulnClass != "" {
		tc.VulnClass = r.vulnClass
	}
	tc.Detail = r.detail

	ids := append([]domain.ID(nil), r.sharedEvidence...) // e.g. shared baseline evidence
	var own []domain.ID                                  // this attempt's request[, response]
	if !r.skipped && e.evidence != nil && r.req != nil {
		var err error
		own, err = e.persistEvidence(ctx, tc, r)
		ids = append(ids, own...)
		if err != nil {
			// The request already happened; keep its outcome but flag the gap so
			// the record is not mistaken for complete evidence.
			tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(err.Error(), 200))
			e.log.Warn("persist evidence", "job", tc.JobID, "err", err)
		}
	}
	tc.EvidenceIDs = ids

	if r.reflection != nil {
		e.finalizeReflection(tc, r, own)
	}

	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Error("persist test case result", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

// persistEvidence stores the request (always) and response (when received) as
// evidence blobs and rows, returning their IDs.
func (e *executor) persistEvidence(ctx context.Context, tc *domain.TestCase, r result) ([]domain.ID, error) {
	var ids []domain.ID
	id, err := e.putEvidence(ctx, tc.ScanID, domain.EvidenceRequest, dumpRequest(r.req), "test_case="+string(tc.ID)+" request")
	if err != nil {
		return ids, err
	}
	ids = append(ids, id)
	if r.resp != nil {
		note := "test_case=" + string(tc.ID) + " response"
		if r.resp.Truncated {
			note += " (body truncated at the engine's size cap)"
		}
		id, err := e.putEvidence(ctx, tc.ScanID, domain.EvidenceResponse, dumpResponse(r.resp), note)
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// putEvidence writes one HTTP-message evidence blob + row and returns its ID.
func (e *executor) putEvidence(ctx context.Context, scanID domain.ID, kind domain.EvidenceKind, data []byte, note string) (domain.ID, error) {
	return putEvidenceBlob(ctx, e.store, e.evidence, scanID, kind, ".http", "message/http", data, note)
}

// putEvidenceBlob writes one evidence blob + row and returns its ID. Shared by
// the test-job executor (HTTP message evidence) and the browser-verify handler
// (screenshot/DOM/browser-log evidence), which differ only in extension/media
// type.
func putEvidenceBlob(ctx context.Context, st store.Store, ev evidence.Store, scanID domain.ID, kind domain.EvidenceKind, ext, mediaType string, data []byte, note string) (domain.ID, error) {
	ref, err := ev.Put(scanID, kind, ext, data)
	if err != nil {
		return "", err
	}
	row := &domain.Evidence{
		ID: domain.NewID(), ScanID: scanID, Kind: kind, MediaType: mediaType,
		BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256,
		Note: note, CreatedAt: time.Now(),
	}
	if err := st.Evidence().Create(ctx, row); err != nil {
		return "", err
	}
	return row.ID, nil
}

// ---------------------------------------------------------------------------
// request construction
// ---------------------------------------------------------------------------

// observedJSONContentType preserves an observed JSON media type only when it is
// valid JSON (application/json or a +json subtype); otherwise it uses the
// standard application/json fallback.
func observedJSONContentType(raw string) string {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return "application/json"
	}
	mediaType = strings.ToLower(mediaType)
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		return raw
	}
	return "application/json"
}

// buildRequest builds the baseline request for an endpoint: its URL with every
// known query parameter present at its observed value, and — for body-carrying
// methods — a form or JSON body of the known form/JSON parameters at their
// observed values. Parameters are ordered deterministically so the same job
// always produces the same bytes.
func buildRequest(ep *domain.Endpoint, params []*domain.Parameter, inj *injection) (*httpengine.Request, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, fmt.Errorf("endpoint URL %q: %w", ep.URL, err)
	}

	sorted := append([]*domain.Parameter(nil), params...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Location < sorted[j].Location
	})

	q := u.Query()
	form := url.Values{}
	jsonBody := map[string]json.RawMessage{}
	var headerOverride map[string]string
	var cookieOverride []*http.Cookie
	for _, p := range sorted {
		val := p.Example
		injectedA := inj != nil && inj.param != nil && p.ID == inj.param.ID
		injectedB := inj != nil && inj.paramB != nil && p.ID == inj.paramB.ID
		injected := injectedA || injectedB
		switch {
		case injectedA:
			val = inj.value // the marker goes ONLY into the selected injection point
		case injectedB:
			val = inj.valueB // the SECOND override, for a combined (multi-parameter) candidate
		}
		switch p.Location {
		case domain.LocationQuery:
			switch {
			case injected:
				q.Set(p.Name, val) // override the observed value with the marker
			case !q.Has(p.Name): // a value already in the URL is the observed one
				q.Set(p.Name, val)
			}
		case domain.LocationForm:
			form.Set(p.Name, val)
		case domain.LocationJSON:
			if !injected && p.Source == domain.SourceBrowserNetwork && json.Valid([]byte(p.Example)) {
				// Network discovery stores a bounded raw JSON value in Example so
				// non-focused fields keep their original JSON type/shape.
				jsonBody[p.Name] = json.RawMessage(p.Example)
			} else {
				raw, err := json.Marshal(val)
				if err != nil {
					return nil, err
				}
				jsonBody[p.Name] = raw
			}
		case domain.LocationHeader:
			// Only the mutated/candidate request overrides a header — the
			// baseline must never disturb any header the scan relies on
			// (auth headers, the session cookie header, the engine's own
			// default User-Agent), so a non-injected Header parameter is a
			// no-op here.
			if injected {
				if headerOverride == nil {
					headerOverride = make(map[string]string, 1)
				}
				headerOverride[p.Name] = val
			}
		case domain.LocationCookie:
			// Same principle as Header: the scan's own session cookies are
			// already carried by scopedEngine.WithSessionCookies on every
			// request, so only the injected cookie needs an explicit
			// override here — appended as its own Cookie, never replacing
			// or removing any other cookie the request carries.
			if injected {
				cookieOverride = append(cookieOverride, &http.Cookie{Name: p.Name, Value: val})
			}
		case domain.LocationPath:
			// The baseline path segment is already correct in ep.URL; only
			// the injected candidate rewrites that ONE segment.
			if injected {
				if idx, ok := discovery.ParsePathSegmentParamName(p.Name); ok {
					segs := discovery.PathSegments(u.Path)
					if idx >= 0 && idx < len(segs) {
						segs[idx] = val
						u.Path = discovery.JoinPathSegments(segs)
						u.RawPath = "" // let url.URL re-derive the encoded form
					}
				}
			}
		}
	}
	u.RawQuery = q.Encode()

	req := &httpengine.Request{Method: string(ep.Method), URL: u.String()}
	if len(headerOverride) > 0 {
		req.Headers = headerOverride
	}
	if len(cookieOverride) > 0 {
		req.Cookies = cookieOverride
	}
	if !hasBody(ep.Method) {
		return req, nil
	}
	switch {
	case len(form) > 0:
		req.Body = []byte(form.Encode())
		req.ContentType = "application/x-www-form-urlencoded"
	case len(jsonBody) > 0:
		b, err := json.Marshal(jsonBody) // map keys are marshaled sorted
		if err != nil {
			return nil, err
		}
		req.Body = b
		req.ContentType = observedJSONContentType(ep.ContentType)
	}
	return req, nil
}

func isSafeMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodGET, domain.MethodHEAD, domain.MethodOPTIONS, "":
		return true
	default:
		return false
	}
}

// canBrowserVerify reports whether method+location has an in-scope browser
// document replay: ordinary GET/HEAD, POST/form via a real form submission, or
// POST/JSON via a one-shot top-level navigation request override. Other
// body-carrying methods remain unsupported and their Findings stay Pending.
func canBrowserVerify(method domain.HTTPMethod, loc domain.ParamLocation) bool {
	switch method {
	case domain.MethodGET, domain.MethodHEAD, "":
		return true
	case domain.MethodPOST:
		return loc == domain.LocationForm || loc == domain.LocationJSON
	default:
		return false
	}
}

func hasBody(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH, domain.MethodDELETE:
		return true
	default:
		return false
	}
}

// possibleBlockNote flags a suspicious status-code change between the
// baseline (unmodified) request and a mutated/candidate request that did NOT
// reflect: if the baseline succeeded (2xx/3xx) but the mutated request came
// back 403/429/503 — common WAF/rate-limit/maintenance signals — "not
// reflected" could mean "blocked", not "safe". This is detection only, never
// evasion (AGENTS.md §2.2: no anti-bot/WAF bypass of any kind is added here;
// the exact same request is still sent, once): it exists so an operator does
// not mistake a blocked probe for a clean negative. Returns "" when nothing
// looks anomalous.
// The bool return additionally tells the caller whether to record a
// diagnostic Finding for this (see result.blockSuspected / upsertBlockFinding
// in finding.go) — before that was wired, this signal only ever reached a raw
// TestCase note, invisible on every report surface.
func possibleBlockNote(baselineStatus, mutatedStatus int) (string, bool) {
	baselineOK := baselineStatus >= 200 && baselineStatus < 400
	suspicious := mutatedStatus == 403 || mutatedStatus == 429 || mutatedStatus == 503
	if baselineOK && suspicious && mutatedStatus != baselineStatus {
		return fmt.Sprintf(" (possible block/filter: status changed %d -> %d from baseline; "+
			"this may not be a clean negative — Indago does not retry or evade, see AGENTS.md §2.2)",
			baselineStatus, mutatedStatus), true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

// isTimeout reports whether err is a deadline/timeout (our request timeout, the
// engine's own, or a network-level timeout).
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isPermanentRequestError reports errors that retrying cannot fix.
func isPermanentRequestError(err error) bool {
	return errors.Is(err, ErrOutOfScope) ||
		errors.Is(err, httpengine.ErrInvalidRequest) ||
		errors.Is(err, httpengine.ErrNotImplemented) ||
		errors.Is(err, httpengine.ErrTooManyRedirects)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// evidence rendering (HTTP/1.1 message text; binary-safe)
// ---------------------------------------------------------------------------

// capturedFrom returns what was sent: the engine's capture when a response was
// received, otherwise a reconstruction from the request itself.
func capturedFrom(req *httpengine.Request, resp *httpengine.Response) *httpengine.CapturedRequest {
	if resp != nil && resp.Request != nil {
		return resp.Request
	}
	h := http.Header{}
	for k, v := range req.Headers {
		h.Set(k, v)
	}
	if req.ContentType != "" && h.Get("Content-Type") == "" {
		h.Set("Content-Type", req.ContentType)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	return &httpengine.CapturedRequest{Method: method, URL: req.URL, Headers: h, Body: req.Body}
}

// dumpRequest renders the request as an HTTP/1.1 message.
func dumpRequest(c *httpengine.CapturedRequest) []byte {
	var b bytes.Buffer
	target := c.URL
	host := ""
	if u, err := url.Parse(c.URL); err == nil {
		target = u.RequestURI()
		host = u.Host
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", c.Method, target)
	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	writeHeaders(&b, c.Headers)
	b.WriteString("\r\n")
	b.Write(c.Body)
	return b.Bytes()
}

// dumpResponse renders the response as an HTTP/1.1 message.
func dumpResponse(r *httpengine.Response) []byte {
	var b bytes.Buffer
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	statusText := strings.TrimSpace(strings.TrimPrefix(r.StatusText, fmt.Sprint(r.Status)))
	fmt.Fprintf(&b, "%s %d %s\r\n", proto, r.Status, statusText)
	writeHeaders(&b, r.Headers)
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.Bytes()
}

func writeHeaders(b *bytes.Buffer, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}
