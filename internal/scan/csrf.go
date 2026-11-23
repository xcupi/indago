package scan

// Cross-Site Request Forgery (CSRF) detection engine.
//
// One CSRF job inspects ONE discovered state-changing endpoint (POST, PUT,
// PATCH, DELETE) in a scan that carries an authenticated session. Because the
// probe sends a state-changing request, the executor is strictly gated by
// ExecutorConfig.AllowStateChanging: when off, no network request is sent and
// a clean skipped TestCase is recorded.
//
// When AllowStateChanging is enabled, the engine:
//  1. Checks whether the endpoint's parameters include a known anti-CSRF token
//     name (csrf, _token, xsrf, authenticity_token, __requestverificationtoken,
//     nonce, anti_forgery).
//  2. Inspects the scan's session cookies (when StatePath is set) to see
//     whether any cookie lacks SameSite=Strict or SameSite=Lax.
//  3. Sends ONE bounded state-changing probe carrying Origin: https://evil.example
//     and Referer: https://evil.example/csrf, omitting any anti-CSRF token
//     parameters, using the scan's session cookies and NoRedirects=true.
//  4. Records HTTP acceptance as an inconclusive observation. This executor
//     cannot establish authenticated browser behavior or a user-impacting action.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	csrfEngine = "csrf"

	// maxCSRFEndpoints bounds the per-scan CSRF pass.
	maxCSRFEndpoints = 20
	// csrfPriority schedules CSRF probes alongside other bounded active checks.
	csrfPriority = 35

	csrfEvilOrigin  = "https://evil.example"
	csrfEvilReferer = "https://evil.example/csrf"
)

// csrfTokenNames lists lowercase parameter-name substrings that identify an
// anti-CSRF token parameter.
var csrfTokenNames = []string{
	"csrf",
	"_token",
	"xsrf",
	"authenticity_token",
	"__requestverificationtoken",
	"nonce",
	"anti_forgery",
}

// csrfDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type csrfDetail struct {
	Engine                  string            `json:"engine"`
	URL                     string            `json:"url"`
	Method                  string            `json:"method"`
	HTTPStatus              int               `json:"http_status,omitempty"`
	DedupKey                string            `json:"dedup_key,omitempty"`
	Occurrences             int               `json:"occurrences,omitempty"`
	Verdict                 domain.Verdict    `json:"verdict"`
	Severity                domain.Severity   `json:"severity,omitempty"`
	Confidence              domain.Confidence `json:"confidence,omitempty"`
	Reason                  string            `json:"reason,omitempty"`
	HasTokenParam           bool              `json:"has_token_param,omitempty"`
	TokenParamNames         []string          `json:"token_param_names,omitempty"`
	LacksSameSiteProtection bool              `json:"lacks_samesite_protection,omitempty"`
	WeakSameSiteCookies     []string          `json:"weak_samesite_cookies,omitempty"`
	OriginSent              string            `json:"origin_sent,omitempty"`
	RefererSent             string            `json:"referer_sent,omitempty"`
	Throttled               bool              `json:"throttled,omitempty"`
	Skipped                 bool              `json:"skipped,omitempty"`
	SkipReason              string            `json:"skip_reason,omitempty"`
	TestCaseIDs             []domain.ID       `json:"test_case_ids,omitempty"`
	EvidenceIDs             []domain.ID       `json:"evidence_ids,omitempty"`
}

type csrfExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newCSRFExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) worker.Handler {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &csrfExecutor{
		store:      st,
		engine:     eng,
		evidence:   ev,
		cfg:        cfg.withDefaults(),
		log:        log,
		findingsMu: findingsMu,
	}
}

var _ worker.Handler = (*csrfExecutor)(nil)

// Handle implements worker.Handler.
func (e *csrfExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, err := e.csrfTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	if ep == nil || strings.TrimSpace(ep.URL) == "" {
		return fmt.Errorf("%w: csrf job has no target URL", worker.ErrPermanent)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodPost
	}

	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnCSRF, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist csrf test case: %w", err)
	}

	d := &csrfDetail{
		Engine:  csrfEngine,
		URL:     ep.URL,
		Method:  method,
		Verdict: domain.VerdictRejected,
	}

	if reason, skip := e.csrfSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "csrf skipped: "+reason)
		return nil
	}

	d.DedupKey = csrfDedupKey(method, ep.URL)

	// 1. Inspect parameters for known anti-CSRF token names and omit them from
	// the probe so we test whether the server enforces token presence.
	tokenNames, nonTokenParams := splitCSRFParams(params)
	if len(tokenNames) > 0 {
		d.HasTokenParam = true
		d.TokenParamNames = tokenNames
	}

	// 2. Inspect session cookies (when StatePath is set) for SameSite posture.
	var cookies []*http.Cookie
	if sess, err := e.store.Sessions().GetByScan(ctx, job.ScanID); err == nil && sess != nil && sess.StatePath != "" {
		cookies = sessionCookies(sess.StatePath)
		for _, c := range cookies {
			if c.SameSite != http.SameSiteStrictMode && c.SameSite != http.SameSiteLaxMode {
				d.LacksSameSiteProtection = true
				d.WeakSameSiteCookies = append(d.WeakSameSiteCookies, c.Name)
			}
		}
	}

	// 3. Build and send the bounded cross-origin, tokenless probe.
	req, err := buildRequest(ep, nonTokenParams, nil)
	if err != nil {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "failed to build CSRF probe request: " + truncate(err.Error(), 200)
		e.finish(ctx, tc, d, domain.TestCaseFailed, "csrf inconclusive: "+d.Reason)
		return nil
	}
	req.NoRedirects = true
	if req.Headers == nil {
		req.Headers = make(map[string]string, 2)
	}
	req.Headers["Origin"] = csrfEvilOrigin
	req.Headers["Referer"] = csrfEvilReferer
	d.OriginSent = csrfEvilOrigin
	d.RefererSent = csrfEvilReferer

	// Attach session cookies directly if the engine is not a scopedEngine that
	// already carries them.
	if len(cookies) > 0 && len(req.Cookies) == 0 {
		if se, ok := e.engine.(*scopedEngine); !ok || se == nil || len(se.cookies) == 0 {
			req.Cookies = cookies
		}
	}

	resp, outcome, err := e.csrfDo(ctx, req)
	if resp != nil {
		tc.HTTPStatus = resp.Status
		d.HTTPStatus = resp.Status
		e.persistEvidence(ctx, tc, resp)
	}

	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the cross-origin CSRF probe request did not complete"
		if err != nil {
			d.Reason += ": " + truncate(err.Error(), 200)
		}
		e.finish(ctx, tc, d, domain.TestCaseFailed, "csrf inconclusive: "+d.Reason)
		return nil
	}

	if isThrottleStatus(resp.Status) {
		d.Throttled = true
		d.Verdict = domain.VerdictInconclusive
		d.Reason = fmt.Sprintf("the target answered HTTP %d to the CSRF probe; stopping to respect backpressure", resp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "csrf inconclusive: "+d.Reason)
		return nil
	}

	// HTTP acceptance cannot establish authenticated browser behavior or impact.
	if resp.Status >= http.StatusOK && resp.Status < http.StatusBadRequest {
		d.Verdict = domain.VerdictInconclusive
		d.Confidence = domain.ConfidenceLow
		d.Severity = domain.SeverityInfo
		d.Reason = fmt.Sprintf("the HTTP probe received %d; authenticated browser behavior and impact were not established", resp.Status)
		e.correlate(ctx, job, ep, tc, d)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "csrf inconclusive: "+d.Reason)
		return nil
	}

	d.Verdict = domain.VerdictRejected
	d.Reason = fmt.Sprintf("the target rejected the cross-origin/tokenless %s request with HTTP %d", method, resp.Status)
	e.finish(ctx, tc, d, domain.TestCaseCompleted, "csrf: "+d.Reason)
	return nil
}

func (e *csrfExecutor) csrfTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, error) {
	if job == nil {
		return nil, nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, params, _, err := resolveJobTarget(ctx, e.store, job)
		return ep, params, err
	}
	raw := strings.TrimSpace(job.Target.URL)
	if raw == "" {
		return nil, nil, fmt.Errorf("job has neither an endpoint nor a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, fmt.Errorf("job URL %q is not an absolute http(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodPOST, Source: domain.SourceUserProvided}, nil, nil
}

func (e *csrfExecutor) csrfSkip(ep *domain.Endpoint) (string, bool) {
	if !e.cfg.AllowStateChanging {
		return "AllowStateChanging is off; state-changing CSRF probes are disabled", true
	}
	if e.cfg.SkipWriteEndpoints {
		return "state-changing CSRF probes disabled by skip_write_endpoints", true
	}
	if !isCSRFStateChangingMethod(ep.Method) {
		return fmt.Sprintf("%s is not a state-changing method", ep.Method), true
	}
	if isLogoutLikeEndpoint(ep) {
		return "logout endpoint " + endpointLabel(ep.URL) + " is excluded from CSRF probing", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

func isCSRFStateChangingMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH, domain.MethodDELETE:
		return true
	default:
		return false
	}
}

func isLogoutLikeEndpoint(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return false
	}
	p := strings.ToLower(strings.Trim(u.Path, "/"))
	for _, seg := range strings.Split(p, "/") {
		if strings.Contains(seg, "logout") || strings.Contains(seg, "log-out") ||
			strings.Contains(seg, "signout") || strings.Contains(seg, "sign-out") {
			return true
		}
	}
	return false
}

func isCSRFTokenParamName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	for _, sub := range csrfTokenSubstringsOrNames() {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func csrfTokenSubstringsOrNames() []string {
	return csrfTokenNames
}

func splitCSRFParams(params []*domain.Parameter) (tokenNames []string, nonToken []*domain.Parameter) {
	for _, p := range params {
		if p == nil {
			continue
		}
		if isCSRFTokenParamName(p.Name) {
			tokenNames = append(tokenNames, p.Name)
			continue
		}
		nonToken = append(nonToken, p)
	}
	return tokenNames, nonToken
}

func (e *csrfExecutor) csrfDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err
	default:
		return nil, domain.OutcomeError, err
	}
}

func (e *csrfExecutor) persistEvidence(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " csrf cross-origin request"
		if redactRequestCookieValues(captured.Headers) {
			note += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("csrf: persist request evidence", "test_case", tc.ID, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	respNote := "test_case=" + string(tc.ID) + " csrf cross-origin response"
	if redactSetCookieValues(recorded.Headers) {
		respNote += " (cookie values redacted)"
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), respNote); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("csrf: persist response evidence", "test_case", tc.ID, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

func (e *csrfExecutor) finish(ctx context.Context, tc *domain.TestCase, d *csrfDetail, status domain.TestCaseStatus, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Status = status
	tc.Note = truncate(note, 1024)
	if status == domain.TestCaseSkipped {
		tc.Outcome = ""
	} else if d.Verdict == domain.VerdictInconclusive &&
		(status != domain.TestCaseCompleted || d.HTTPStatus < http.StatusOK || d.HTTPStatus >= http.StatusBadRequest) {
		tc.Outcome = domain.OutcomeError
	} else {
		tc.Outcome = domain.OutcomeSuccess
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	tc.Detail, _ = json.Marshal(d)
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("csrf: persist test case", "test_case", tc.ID, "err", err)
	}
}

func (e *csrfExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *csrfDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("csrf: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	if d.Occurrences == 0 {
		d.Occurrences = 1
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	title := fmt.Sprintf("Cross-Site Request Forgery (CSRF) on %s %s", d.Method, endpointHostLabel(ep.URL))
	summary := d.Reason

	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("csrf: list findings", "scan", job.ScanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnCSRF || f.Provenance.Engine != csrfEngine {
			continue
		}
		var fd csrfDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" || fd.DedupKey != d.DedupKey {
			continue
		}
		fd.Occurrences++
		fd.HTTPStatus = d.HTTPStatus
		fd.Reason, fd.Verdict = d.Reason, d.Verdict
		fd.Severity, fd.Confidence = d.Severity, d.Confidence
		fd.HasTokenParam, fd.TokenParamNames = d.HasTokenParam, d.TokenParamNames
		fd.LacksSameSiteProtection, fd.WeakSameSiteCookies = d.LacksSameSiteProtection, d.WeakSameSiteCookies
		fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, d.TestCaseIDs)
		fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, d.EvidenceIDs)
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, d.EvidenceIDs)
		f.Title, f.Summary = title, summary
		f.Verdict, f.Severity, f.Confidence = d.Verdict, d.Severity, d.Confidence
		f.Provenance.VerifiedAt = nil
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("csrf: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnCSRF,
		Verdict: d.Verdict, Severity: d.Severity, Confidence: d.Confidence,
		Title: title, Summary: summary, EndpointID: ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, d.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: csrfEngine, DiscoverySource: ep.Source, DetectedAt: now},
		Detail:      detail, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("csrf: create finding", "scan", job.ScanID, "err", err)
	}
}

func csrfDedupKey(method, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "csrf\x00" + method + "\x00" + rawURL
	}
	return "csrf\x00" + method + "\x00" + strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueCSRFProbes queues ONE JobCSRF per unique state-changing endpoint
// (POST, PUT, PATCH, DELETE) in scans that have an authenticated session,
// capped at maxCSRFEndpoints and skipping download/logout-like endpoints.
func (c *Controller) enqueueCSRFProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipCSRF {
		return
	}
	sess, err := c.store.Sessions().GetByScan(ctx, scanID)
	if err != nil || !csrfHasAuthenticatedSession(sess) {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	seen := make(map[string]struct{}, len(endpoints))
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxCSRFEndpoints {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isCSRFStateChangingMethod(ep.Method) {
			continue
		}
		if isLogoutLikeEndpoint(ep) || isDownloadLikeEndpoint(ep) {
			continue
		}
		key := csrfDedupKey(string(ep.Method), ep.URL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobCSRF,
			State:       domain.JobQueued,
			Priority:    csrfPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("csrf: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("csrf probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

func csrfHasAuthenticatedSession(sess *domain.Session) bool {
	if sess == nil {
		return false
	}
	if len(sessionCookies(sess.StatePath)) > 0 {
		return true
	}
	if sess.State == domain.SessionActive {
		return true
	}
	return sess.Mode != "" && sess.Mode != domain.AuthAnonymous
}
