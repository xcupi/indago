package scan

// Read-only Host-header inspection check.
//
// CRITICAL is CWE-644, not CWE-79. Goal: prove that the server TRUSTS a
// client-supplied Host / X-Forwarded-Host value when it builds an absolute URL,
// a redirect target or a Refresh target. A finding is corroborated the same way
// security headers are: the response itself proves the header was used, so
// there is no payload, no execution and nothing that can harm the target.
//
// One job acts on ONE origin (scheme://host[:port]), not on every URL: host
// handling is an origin/site policy, so reporting it per endpoint would
// multiply one misconfiguration into hundreds of near-duplicate findings. The
// executor sends one bounded read-only GET baseline plus at most one control
// GET per canary header (X-Forwarded-Host, then Host).
//
// Boundaries:
//   - Read-only: GET only, no body, no state change, no payload. A
//     state-changing or write-like endpoint is skipped without a request.
//   - Bounded: at most maxHostHeaderOrigins origins per scan, at most
//     len(hhControlHeaders)+1 requests per origin.
//   - Cache-safe: every request carries a unique cache-buster query parameter,
//     so a shared cache can neither answer a probe from another caller's entry
//     nor store the probe's response under a URL a user would request.
//   - Never followed: each request sets NoRedirects, so a response that
//     reflects the canary host in its Location is handed back as evidence
//     instead of being followed to the canary (which never resolves — the
//     .invalid TLD is reserved by RFC 2606).
//   - Deterministic: every signal is a pure function of the response bytes and
//     headers, so no browser and no LLM participate (AGENTS.md §2.5).
//   - Baseline-aware: a vector is only reported when the canary host appears in
//     the CONTROL response and did NOT appear in the baseline, so a page that
//     legitimately contains that string can never produce a finding.

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
	hhEngine = "host_header"

	// hhCanaryHost is the control value sent in the Host / X-Forwarded-Host
	// header. The .invalid TLD is reserved (RFC 2606) and never resolves, so
	// the value can never name a real destination and a reflection can never
	// send the scanner (or a victim) to a live attacker host.
	hhCanaryHost = "indago-host-check.invalid"

	// hhCacheBusterParam is appended to every request URL. Its value is
	// unique per request, so a shared cache keyed on the URL can never serve
	// another caller's response to a probe, and a probe response can never be
	// stored under a URL a user would request.
	hhCacheBusterParam = "indago_host_check"

	// maxHostHeaderOrigins bounds the pass: one job per origin.
	maxHostHeaderOrigins = 20
	// hostHeaderPriority places the passive host-header inspection in the
	// same origin-level family as the security-header pass, just after it.
	hostHeaderPriority = 37
)

// hhControlHeaders are the control headers tried, in order. X-Forwarded-Host
// comes first because a reverse proxy most often trusts it without validation;
// Host itself is the classic vector and needs httpengine.Request.Host (Go's
// transport ignores a "Host" entry in the header map).
var hhControlHeaders = []string{"X-Forwarded-Host", "Host"}

// Signal kinds, one per response vector where the canary host can surface.
const (
	hhKindLocation = "host_header_reflected_in_location"
	hhKindRefresh  = "host_header_reflected_in_refresh"
	hhKindBodyURL  = "host_header_reflected_in_body_url"
)

// hostHeaderProbe is one control request's outcome. It is persisted in the
// test-case and finding details, so it must stay a plain data value.
type hostHeaderProbe struct {
	Header    string   `json:"header"`
	Value     string   `json:"value"`
	URL       string   `json:"url"`
	Status    int      `json:"status,omitempty"`
	Location  string   `json:"location,omitempty"`
	Refresh   string   `json:"refresh,omitempty"`
	Reflected bool     `json:"reflected"`
	Vectors   []string `json:"vectors,omitempty"`
	Note      string   `json:"note,omitempty"`
}

// hostHeaderSignal is one observed reflection vector on an origin.
type hostHeaderSignal struct {
	Key         string            `json:"key"`
	Kind        string            `json:"kind"`
	Header      string            `json:"header"`
	Severity    domain.Severity   `json:"severity"`
	Confidence  domain.Confidence `json:"confidence"`
	Reason      string            `json:"reason"`
	Remediation string            `json:"remediation"`
	Observed    string            `json:"observed,omitempty"`
	Title       string            `json:"title"`
}

// hostHeaderDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type hostHeaderDetail struct {
	Engine           string             `json:"engine"`
	URL              string             `json:"url"`
	BaselineURL      string             `json:"baseline_url,omitempty"`
	Origin           string             `json:"origin"`
	Method           string             `json:"method"`
	Canary           string             `json:"canary,omitempty"`
	CacheBusterParam string             `json:"cache_buster_param,omitempty"`
	FinalURL         string             `json:"final_url,omitempty"`
	HTTPStatus       int                `json:"http_status,omitempty"`
	DedupKey         string             `json:"dedup_key,omitempty"`
	Occurrences      int                `json:"occurrences,omitempty"`
	Verdict          domain.Verdict     `json:"verdict"`
	Severity         domain.Severity    `json:"severity,omitempty"`
	Confidence       domain.Confidence  `json:"confidence,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	Probes           []hostHeaderProbe  `json:"probes,omitempty"`
	Signals          []hostHeaderSignal `json:"signals,omitempty"`
	Throttled        bool               `json:"throttled,omitempty"`
	Skipped          bool               `json:"skipped,omitempty"`
	SkipReason       string             `json:"skip_reason,omitempty"`
	TestCaseIDs      []domain.ID        `json:"test_case_ids,omitempty"`
	EvidenceIDs      []domain.ID        `json:"evidence_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

// hostHeaderOrigin is the scheme://host[:port] identity of rawURL — the
// correlation unit for this engine. It is the same origin identity the
// security-header pass uses.
func hostHeaderOrigin(rawURL string) string { return securityHeadersOrigin(rawURL) }

// hostHeaderDedupKey is the finding identity: one row per origin.
func hostHeaderDedupKey(origin string) string {
	return hhEngine + "\x00" + strings.ToLower(origin)
}

// hostHeaderSignalKey identifies one (origin, header, vector) observation.
func hostHeaderSignalKey(origin, header, vector string) string {
	return hostHeaderDedupKey(origin) + "\x00" + strings.ToLower(header) + "\x00" + vector
}

// hhResponse is the minimal response view the analyzer needs. Keeping it a
// plain value is what makes analyzeHostHeader testable without a network.
type hhResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func hhResponseOf(resp *httpengine.Response) hhResponse {
	if resp == nil {
		return hhResponse{}
	}
	return hhResponse{Status: resp.Status, Header: resp.Headers, Body: resp.Body}
}

// analyzeHostHeader returns the vectors where the control response carries the
// canary host but the baseline response did not. It is pure: no clock, no I/O,
// no network.
//
// The baseline subtraction is the false-positive guard: a page that already
// mentions the canary string (a fixture, a test page, a cached document)
// cannot produce a finding, because only a vector that APPEARED in response to
// the control header is attributable to that header.
func analyzeHostHeader(baseline, control hhResponse, canary string) []string {
	if canary == "" {
		return nil
	}
	seen := make(map[string]bool)
	for _, v := range hhVectors(baseline, canary) {
		seen[v] = true
	}
	var out []string
	for _, v := range hhVectors(control, canary) {
		if !seen[v] {
			out = append(out, v)
		}
	}
	return out
}

// hhVectors lists the response vectors that carry the canary host, in a fixed
// order so the same response always yields the same list.
func hhVectors(resp hhResponse, canary string) []string {
	if canary == "" {
		return nil
	}
	var out []string
	if loc := resp.Header.Get("Location"); hhContainsHost(loc, canary) {
		out = append(out, hhKindLocation)
	}
	if refresh := resp.Header.Get("Refresh"); hhContainsHost(refresh, canary) {
		out = append(out, hhKindRefresh)
	}
	if hhBodyHasAbsoluteURL(resp.Body, canary) {
		out = append(out, hhKindBodyURL)
	}
	return out
}

// hhContainsHost reports whether a header value mentions the canary host,
// case-insensitively. A header value is a single logical target, so containment
// is the right test: "http://indago-host-check.invalid/x" and
// "0; url=http://INDAGO-HOST-CHECK.INVALID" both count.
func hhContainsHost(value, canary string) bool {
	return canary != "" && strings.Contains(strings.ToLower(value), strings.ToLower(canary))
}

// hhBodyHasAbsoluteURL reports whether the body carries an ABSOLUTE URL whose
// host is the canary (http://<canary>/..., https://<canary>/...). A bare
// occurrence of the host string is not enough: it proves the bytes were echoed,
// not that the server built a link from them. The host must also end at a
// host-valid boundary, so "indago-host-check.invalid.evil.test" does not count.
func hhBodyHasAbsoluteURL(body []byte, canary string) bool {
	hay := strings.ToLower(string(body))
	needle := strings.ToLower(canary)
	if needle == "" {
		return false
	}
	for off := 0; off < len(hay); {
		i := strings.Index(hay[off:], needle)
		if i < 0 {
			return false
		}
		i += off
		end := i + len(needle)
		if hhSchemeBefore(hay, i) && hhHostEndsAt(hay, end) {
			return true
		}
		off = end
	}
	return false
}

// hhSchemeBefore reports whether an absolute http(s) scheme ends exactly at i.
func hhSchemeBefore(hay string, i int) bool {
	prefix := hay[:i]
	return strings.HasSuffix(prefix, "http://") || strings.HasSuffix(prefix, "https://")
}

// hhHostEndsAt reports whether the character at end terminates a host (or the
// string does): a path/query/fragment separator, a port, a delimiter, or
// whitespace. A letter, digit, dot or hyphen means the match is only part of a
// longer host name.
func hhHostEndsAt(hay string, end int) bool {
	if end >= len(hay) {
		return true
	}
	switch hay[end] {
	case '/', '?', '#', ':', '\\', '"', '\'', '<', '>', '&', ';', ',', ' ', '\t', '\r', '\n', ')', ']', '}':
		return true
	}
	return false
}

// hhVectorLabel renders a vector for a human-readable reason/title.
func hhVectorLabel(kind string) string {
	switch kind {
	case hhKindLocation:
		return "a Location redirect"
	case hhKindRefresh:
		return "a Refresh header"
	case hhKindBodyURL:
		return "an absolute URL in the response body"
	}
	return "the response"
}

// hostHeaderSignalFor renders one signal for a reflected vector.
func hostHeaderSignalFor(origin string, p hostHeaderProbe, vector string) hostHeaderSignal {
	s := hostHeaderSignal{
		Key:        hostHeaderSignalKey(origin, p.Header, vector),
		Kind:       vector,
		Header:     p.Header,
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceHigh,
		Reason: fmt.Sprintf("the server used the client-supplied %s value as the host of %s, so a crafted "+
			"request makes the site point at an attacker-controlled host — phishing under the real brand, "+
			"password-reset poisoning, or cache poisoning behind a shared cache", p.Header, hhVectorLabel(vector)),
		Remediation: "Never build a redirect target or an absolute URL from the request's Host or " +
			"X-Forwarded-Host header. Configure the canonical hostname server-side, validate any incoming " +
			"Host against that allow-list and reject (or ignore) anything else, and make sure a front proxy " +
			"does not pass an unvalidated X-Forwarded-Host through.",
		Title: fmt.Sprintf("Host header injection: %s used in %s", p.Header, hhVectorLabel(vector)),
	}
	switch vector {
	case hhKindLocation:
		s.Observed = "Location: " + p.Location
	case hhKindRefresh:
		s.Observed = "Refresh: " + p.Refresh
	case hhKindBodyURL:
		s.Observed = "absolute URL containing " + hhCanaryHost
	}
	return s
}

// hostHeaderSummary is the one-line test-case/finding summary.
func hostHeaderSummary(signals []hostHeaderSignal) string {
	headers := make([]string, 0, len(signals))
	seenHeader := make(map[string]bool, len(signals))
	vectors := make([]string, 0, len(signals))
	seenVector := make(map[string]bool, len(signals))
	for _, s := range signals {
		if !seenHeader[s.Header] {
			seenHeader[s.Header] = true
			headers = append(headers, s.Header)
		}
		if !seenVector[s.Kind] {
			seenVector[s.Kind] = true
			vectors = append(vectors, hhVectorLabel(s.Kind))
		}
	}
	return fmt.Sprintf("a client-supplied host was reflected via %s into %s",
		strings.Join(headers, " and "), strings.Join(vectors, ", "))
}

// hhCacheBusted appends a unique cache-buster query parameter to rawURL,
// preserving any existing query and fragment.
func hhCacheBusted(rawURL, token string) string {
	fragment := ""
	if i := strings.IndexByte(rawURL, '#'); i >= 0 {
		rawURL, fragment = rawURL[:i], rawURL[i:]
	}
	sep := "?"
	switch {
	case strings.HasSuffix(rawURL, "?") || strings.HasSuffix(rawURL, "&"):
		sep = ""
	case strings.Contains(rawURL, "?"):
		sep = "&"
	}
	return rawURL + sep + hhCacheBusterParam + "=" + token + fragment
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type hostHeaderExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newHostHeaderExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *hostHeaderExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &hostHeaderExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*hostHeaderExecutor)(nil)

// Handle implements worker.Handler: one baseline GET, then at most one control
// GET per canary header, then pure analysis.
func (e *hostHeaderExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := hostHeaderTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnHostHeader, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist host-header test case: %w", err)
	}

	origin := hostHeaderOrigin(ep.URL)
	d := &hostHeaderDetail{
		Engine: hhEngine, URL: ep.URL, Origin: origin, Method: method,
		Canary: hhCanaryHost, CacheBusterParam: hhCacheBusterParam,
		Verdict: domain.VerdictRejected,
	}
	if reason, skip := e.hhSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "host header check skipped: "+reason)
		return nil
	}
	d.DedupKey = hostHeaderDedupKey(origin)

	// Baseline: the same single hop the controls will see, with its own unique
	// cache buster so no shared cache is read or written under a real URL.
	baselineURL := hhCacheBusted(ep.URL, markerToken("hhb"))
	d.BaselineURL = baselineURL
	baseReq := httpengine.GET(baselineURL)
	baseReq.NoRedirects = true
	baseResp, outcome, reqErr := e.hhDo(ctx, baseReq)
	now := time.Now()
	tc.FinishedAt = &now
	if baseResp != nil {
		tc.HTTPStatus = baseResp.Status
	}
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the read-only baseline request to this origin did not complete"
		tc.Note = truncate("host header inconclusive: "+errorText(reqErr, outcome), 1024)
		e.finish(ctx, tc, d, domain.TestCaseFailed, tc.Note)
		return nil
	}
	tc.DurationMS = time.Since(started).Milliseconds()
	d.HTTPStatus = baseResp.Status
	d.FinalURL = baseResp.FinalURL
	e.persist(ctx, tc, "baseline", baseResp)

	if isThrottleStatus(baseResp.Status) {
		d.Throttled = true
		d.Reason = fmt.Sprintf("the target answered HTTP %d, so the response was not judged and no control request was sent", baseResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "host header check skipped: target throttled the baseline request")
		return nil
	}

	baseline := hhResponseOf(baseResp)
	completed := 0
	var signals []hostHeaderSignal
	for _, header := range hhControlHeaders {
		controlURL := hhCacheBusted(ep.URL, markerToken("hhc"))
		req := httpengine.GET(controlURL)
		// A reflection must be EVIDENCE, never a navigation: the canary host
		// would leave the scan's scope, so the 3xx itself is what we keep.
		req.NoRedirects = true
		if header == "Host" {
			req.Host = hhCanaryHost
		} else {
			req.WithHeader(header, hhCanaryHost)
		}

		resp, ctrlOutcome, ctrlErr := e.hhDo(ctx, req)
		probe := hostHeaderProbe{Header: header, Value: hhCanaryHost, URL: controlURL}
		switch {
		case ctrlOutcome != domain.OutcomeSuccess:
			probe.Note = "control request did not complete: " + errorText(ctrlErr, ctrlOutcome)
		case isThrottleStatus(resp.Status):
			// Backpressure is not a judgement on the header: record it, stop
			// sending, and never turn a throttle page into a finding.
			probe.Status = resp.Status
			probe.Note = fmt.Sprintf("the target answered HTTP %d, so this control was not judged", resp.Status)
			d.Throttled = true
			e.persist(ctx, tc, header+" control", resp)
		default:
			completed++
			probe.Status = resp.Status
			probe.Location = truncate(resp.Headers.Get("Location"), 512)
			probe.Refresh = truncate(resp.Headers.Get("Refresh"), 512)
			probe.Vectors = analyzeHostHeader(baseline, hhResponseOf(resp), hhCanaryHost)
			probe.Reflected = len(probe.Vectors) > 0
			e.persist(ctx, tc, header+" control", resp)
			for _, vector := range probe.Vectors {
				signals = append(signals, hostHeaderSignalFor(origin, probe, vector))
			}
		}
		d.Probes = append(d.Probes, probe)
		if d.Throttled {
			break
		}
	}

	d.Signals = signals
	tc.DurationMS = time.Since(started).Milliseconds()
	note := "host header: no client-supplied host was reflected into a redirect target or an absolute URL on this origin"
	switch {
	case len(signals) > 0:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = domain.SeverityMedium, domain.ConfidenceHigh
		d.Reason = hostHeaderSummary(signals)
		note = "host header: " + d.Reason
		e.correlate(ctx, job, ep, tc, d)
	case d.Throttled:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled a control request, so the origin was not judged"
		note = "host header check inconclusive: target throttled a control request"
	case completed == 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "no control request completed, so the origin was not judged"
		note = "host header check inconclusive: no control request completed"
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// hostHeaderTarget resolves the job's endpoint, tolerating an origin job that
// carries only a URL (nothing is persisted for such a detached endpoint).
func hostHeaderTarget(ctx context.Context, st store.Store, job *domain.TestJob) (*domain.Endpoint, error) {
	if job == nil {
		return nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, _, _, err := resolveJobTarget(ctx, st, job)
		if err != nil {
			return nil, err
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" {
			return nil, fmt.Errorf("endpoint %q has no URL", job.Target.EndpointID)
		}
		return ep, nil
	}
	raw := strings.TrimSpace(job.Target.URL)
	if raw == "" {
		return nil, fmt.Errorf("job has neither an endpoint nor a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("job URL %q is not an absolute http(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}, nil
}

// hhSkip applies the same read-only/write guards the other passive engines use:
// this check must never be the request that mutates a target.
func (e *hostHeaderExecutor) hhSkip(ep *domain.Endpoint) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; a host-header check only sends GET", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// hhDo sends one request with the executor's per-request timeout.
func (e *hostHeaderExecutor) hhDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
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

// persist stores one request/response pair. Cookie values are redacted before
// the blob is written, exactly like the other header-reading engines.
func (e *hostHeaderExecutor) persist(ctx context.Context, tc *domain.TestCase, label string, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " host_header " + label + " request"
		if redactRequestCookieValues(captured.Headers) {
			note += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("host header: persist request evidence", "test_case", tc.ID, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := "test_case=" + string(tc.ID) + " host_header " + label + " response"
	if redactSetCookieValues(recorded.Headers) {
		note += " (cookie values redacted)"
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), note); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("host header: persist response evidence", "test_case", tc.ID, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// finish persists the test case.
func (e *hostHeaderExecutor) finish(ctx context.Context, tc *domain.TestCase, d *hostHeaderDetail, status domain.TestCaseStatus, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Status = status
	tc.Note = truncate(note, 1024)
	if status == domain.TestCaseSkipped {
		tc.Outcome = ""
	} else if d.Verdict == domain.VerdictInconclusive {
		tc.Outcome = domain.OutcomeError
	} else {
		tc.Outcome = domain.OutcomeSuccess
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	tc.Detail, _ = json.Marshal(d)
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("host header: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate upserts ONE finding per origin. A second endpoint on the same
// origin — or a resumed execution that re-runs the pass — absorbs into the same
// row and only unions evidence and the occurrence count.
func (e *hostHeaderExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *hostHeaderDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("host header: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("host header: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	// finish() runs after correlation, so the IDs this attempt earned are
	// merged in here — a finding must never be created without its evidence
	// or without a link back to the test case that proved it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	var current *domain.Finding
	for _, f := range existing {
		if f.VulnClass != domain.VulnHostHeader {
			continue
		}
		var fd hostHeaderDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		if fd.DedupKey == d.DedupKey {
			current = f
			break
		}
	}

	title := "Host header injection: " + originHostLabel(d.Origin) + " reflects a client-supplied host"
	findingDetail := *d
	if findingDetail.Occurrences == 0 {
		findingDetail.Occurrences = 1
	}
	detail, _ := json.Marshal(&findingDetail)

	if current != nil {
		var fd hostHeaderDetail
		if err := json.Unmarshal(current.Detail, &fd); err == nil {
			if fd.Occurrences == 0 {
				fd.Occurrences = 1
			}
			fd.Occurrences++
			fd.Reason = d.Reason
			fd.Probes, fd.Signals = d.Probes, d.Signals
			fd.Severity, fd.Confidence = d.Severity, d.Confidence
			fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, []domain.ID{tc.ID})
			fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, tc.EvidenceIDs)
			if b, err := json.Marshal(fd); err == nil {
				current.Detail = b
			}
		}
		current.EvidenceIDs = appendUniqueIDs(current.EvidenceIDs, tc.EvidenceIDs)
		current.Title, current.Summary = title, d.Reason
		current.Severity, current.Confidence = d.Severity, d.Confidence
		current.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, current); err != nil {
			e.log.Warn("host header: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnHostHeader,
		Verdict: domain.VerdictConfirmed, Severity: d.Severity, Confidence: d.Confidence,
		Title: title, Summary: d.Reason, EndpointID: ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: hhEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
		Detail:      detail, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("host header: create finding", "scan", job.ScanID, "err", err)
	}
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueHostHeaderProbes queues ONE JobHostHeader per unique origin. Endpoint
// URLs are collapsed to scheme://host[:port] before deduplication, so a
// 500-page crawl yields one job per site, never one per URL.
func (c *Controller) enqueueHostHeaderProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipHostHeader {
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
		if queued >= maxHostHeaderOrigins {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isSafeMethod(ep.Method) {
			continue
		}
		// Never spend the one job for an origin on an endpoint the executor
		// would then skip for policy reasons: a different endpoint on the same
		// origin carries the same host handling.
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		origin := hostHeaderOrigin(ep.URL)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobHostHeader,
			State:       domain.JobQueued,
			Priority:    hostHeaderPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("host header: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("host header probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
