package scan

// Server-side open redirect engine (read-only).
//
// One job acts on one endpoint. The engine replaces ONE redirect-shaped
// parameter at a time with a harmless canary destination and observes what the
// server does with it:
//
//   - a 3xx Location header,
//   - a <meta http-equiv="refresh"> target,
//   - or a script assignment such as location.href = "..." / location.replace("...").
//
// Boundaries:
//   - Read-only: at most one baseline plus a hard-capped number of GET (or,
//     only with the explicit state-changing opt-in, the endpoint's own method)
//     requests. Nothing is submitted that the scan would not already send.
//   - The canary is https://canary.invalid — a reserved, non-resolvable domain
//     (RFC 2606). Indago never contacts it, and every probe sets NoRedirects so
//     the target's redirect is INSPECTED, never followed: the payload must not
//     be able to steer a scan request out of scope.
//   - A redirect is only reported when its parsed destination really lands on
//     the canary host. A Location that merely mentions the canary inside its own
//     query (e.g. /login?next=https://canary.invalid) stays on the target and is
//     NOT a finding. A redirect already present in the unmodified baseline is
//     not attributed to the parameter.
//   - Deterministic: the verdict is a pure function of the response, never an
//     LLM's opinion (AGENTS.md §2.5).

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	openRedirectEngine = "open_redirect"
	// openRedirectCanaryHost is reserved (the .invalid TLD is never delegated),
	// so a redirect naming it can never reach a real third party.
	openRedirectCanaryHost = "canary.invalid"
	openRedirectCanaryURL  = "https://" + openRedirectCanaryHost + "/"

	// maxOpenRedirectParams bounds how many redirect-shaped parameters one
	// endpoint contributes.
	maxOpenRedirectParams = 3
	// maxOpenRedirectAttempts bounds the payload-bearing requests per job, so a
	// parameter-rich endpoint cannot turn into a spray.
	maxOpenRedirectAttempts = 10
	// openRedirectBodyScanLimit caps how much of a 2xx body is scanned for a
	// client-side redirect sink.
	openRedirectBodyScanLimit = 256 << 10
)

// openRedirectPayload is one harmless canary destination and the parser bypass
// it exercises.
type openRedirectPayload struct {
	Value string
	Kind  string
}

// openRedirectPayloads builds the bounded payload set for a target. The host is
// taken from the target URL exactly as it appears (including a port) so the
// userinfo shape looks as trusted as possible to a naive prefix check while the
// REAL destination stays the canary.
func openRedirectPayloads(rawURL string) []openRedirectPayload {
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Host
	}
	out := []openRedirectPayload{
		{Value: openRedirectCanaryURL, Kind: "absolute"},
		{Value: "//" + openRedirectCanaryHost + "/", Kind: "protocol_relative"},
	}
	if host != "" {
		out = append(out, openRedirectPayload{Value: "https://" + host + "@" + openRedirectCanaryHost + "/", Kind: "userinfo"})
	}
	// A backslash is normalized to "/" by browsers in the authority position, so
	// "/\canary.invalid" navigates to //canary.invalid even though a naive
	// parser sees a same-site path.
	out = append(out, openRedirectPayload{Value: `/\` + openRedirectCanaryHost + `/`, Kind: "backslash"})
	return out
}

// openRedirectLocationSupported reports whether a parameter location can carry a
// redirect destination through the HTTP request the scanner sends. Header,
// cookie and path-segment values do not select a redirect target.
func openRedirectLocationSupported(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationRawQuery:
		return true
	default:
		return false
	}
}

// openRedirectParamTokens are the words that mark a parameter as a redirect
// destination. Matching is per token, so "next_page", "returnUrl" and
// "callback_url" all match while "curl" does not.
var openRedirectParamTokens = map[string]bool{
	"next": true, "nexturl": true,
	"url": true, "uri": true,
	"redirect": true, "redirects": true, "redirecturl": true, "redirecturi": true,
	"redir":  true,
	"return": true, "returnto": true, "returnpath": true, "returnurl": true,
	"goto": true,
	"dest": true, "desturl": true, "destination": true, "destinationurl": true,
	"callback": true, "callbackurl": true, "callbackuri": true,
	"continue": true, "continueurl": true,
	"target": true, "targeturl": true,
	"forward": true, "forwardurl": true,
	"link": true, "ref": true,
}

// paramNameTokens splits a parameter name into lowercased word tokens on
// separators and camelCase boundaries.
func paramNameTokens(name string) []string {
	var tokens []string
	var cur strings.Builder
	prevLower := false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range name {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ' || r == '[' || r == ']' || r == '/' || r == ':':
			flush()
			prevLower = false
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			cur.WriteRune(unicode.ToLower(r))
			prevLower = false
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			cur.WriteRune(r)
			prevLower = r >= 'a' && r <= 'z'
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	return tokens
}

// isRedirectParamName reports whether a parameter name looks like a redirect
// destination.
func isRedirectParamName(name string) bool {
	for _, tok := range paramNameTokens(name) {
		if openRedirectParamTokens[tok] {
			return true
		}
	}
	return false
}

// openRedirectParams returns the endpoint's redirect-shaped parameters, in a
// deterministic order, capped at maxOpenRedirectParams.
func openRedirectParams(params []*domain.Parameter) []*domain.Parameter {
	out := make([]*domain.Parameter, 0, len(params))
	for _, p := range params {
		if p == nil || !openRedirectLocationSupported(p.Location) || !isRedirectParamName(p.Name) {
			continue
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Location < out[j].Location
	})
	if len(out) > maxOpenRedirectParams {
		out = out[:maxOpenRedirectParams]
	}
	return out
}

// openRedirectSignal is a redirect sink whose destination resolved to the
// canary, as observed in one response.
type openRedirectSignal struct {
	Kind   string `json:"kind"`   // location_header | meta_refresh | script_redirect
	Raw    string `json:"raw"`    // the destination exactly as the response wrote it
	Target string `json:"target"` // the absolute URL a browser would navigate to
}

var (
	// metaRefreshTagRe matches a <meta http-equiv="refresh" ...> tag.
	metaRefreshTagRe = regexp.MustCompile(`(?is)<meta\s[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
	// metaRefreshURLRe extracts the URL of a refresh tag's content attribute.
	metaRefreshURLRe = regexp.MustCompile(`(?is)\burl\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;"'>]+))`)
	// scriptRedirectRe matches the literal assignment shapes that navigate:
	// location = "..." / location.href = "..." / location.replace("...") /
	// location.assign("...") / window.location.href = "...".
	scriptRedirectRe = regexp.MustCompile(`(?is)(?:window\s*\.\s*)?location\s*(?:\.\s*(?:href|replace|assign)\s*(?:=|\()|=)\s*(?:"([^"]*)"|'([^']*)')`)
)

// detectOpenRedirect reports whether this response redirects the caller to the
// canary. It never contacts the canary and never follows the redirect.
func detectOpenRedirect(resp *httpengine.Response, requestURL string) (openRedirectSignal, bool) {
	if resp == nil || resp.Status == 0 {
		return openRedirectSignal{}, false
	}
	if isRedirectStatus(resp.Status) {
		loc := strings.TrimSpace(resp.Headers.Get("Location"))
		if target, ok := openRedirectCanaryTarget(requestURL, loc); ok {
			return openRedirectSignal{Kind: "location_header", Raw: loc, Target: target}, true
		}
		return openRedirectSignal{}, false
	}
	if resp.Status < 200 || resp.Status >= 300 || len(resp.Body) == 0 {
		return openRedirectSignal{}, false
	}
	body := resp.Body
	if len(body) > openRedirectBodyScanLimit {
		body = body[:openRedirectBodyScanLimit]
	}
	for _, tag := range metaRefreshTagRe.FindAllString(string(body), -1) {
		for _, m := range metaRefreshURLRe.FindAllStringSubmatch(tag, -1) {
			raw := firstNonEmptyGroup(m)
			if target, ok := openRedirectCanaryTarget(requestURL, raw); ok {
				return openRedirectSignal{Kind: "meta_refresh", Raw: raw, Target: target}, true
			}
		}
	}
	for _, m := range scriptRedirectRe.FindAllStringSubmatch(string(body), -1) {
		raw := firstNonEmptyGroup(m)
		if target, ok := openRedirectCanaryTarget(requestURL, raw); ok {
			return openRedirectSignal{Kind: "script_redirect", Raw: raw, Target: target}, true
		}
	}
	return openRedirectSignal{}, false
}

// firstNonEmptyGroup returns the first non-empty capture group of a submatch.
func firstNonEmptyGroup(m []string) string {
	for _, g := range m[1:] {
		if v := strings.TrimSpace(g); v != "" {
			return v
		}
	}
	return ""
}

// openRedirectCanaryTarget resolves a redirect destination the way a browser
// would and reports whether it lands on the canary host. Backslashes are
// normalized only when the value carries no scheme, which is exactly where a
// browser treats them as path separators.
func openRedirectCanaryTarget(requestURL, destination string) (string, bool) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", false
	}
	if !strings.Contains(destination, "://") {
		destination = strings.ReplaceAll(destination, `\`, "/")
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(destination)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	if !openRedirectIsCanaryHost(resolved.Hostname()) {
		return "", false
	}
	return resolved.String(), true
}

// openRedirectIsCanaryHost reports whether host is the canary domain or a
// subdomain of it.
func openRedirectIsCanaryHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return host == openRedirectCanaryHost || strings.HasSuffix(host, "."+openRedirectCanaryHost)
}

// openRedirectAttempt is one parameter/payload pair and what it produced.
type openRedirectAttempt struct {
	Parameter   string               `json:"parameter"`
	Location    domain.ParamLocation `json:"location"`
	Payload     string               `json:"payload"`
	PayloadKind string               `json:"payload_kind"`
	URL         string               `json:"url,omitempty"`
	Status      int                  `json:"status,omitempty"`
	RedirectTo  string               `json:"location_header,omitempty"`
	Signal      string               `json:"signal,omitempty"`
	Target      string               `json:"target,omitempty"`
	Confirmed   bool                 `json:"confirmed,omitempty"`
	Note        string               `json:"note,omitempty"`
	EvidenceIDs []domain.ID          `json:"evidence_ids,omitempty"`
}

// openRedirectConfirmation is one confirmed (endpoint, parameter) redirect,
// which is what a finding is created for.
type openRedirectConfirmation struct {
	Parameter   string               `json:"parameter"`
	Location    domain.ParamLocation `json:"location"`
	Payload     string               `json:"payload"`
	PayloadKind string               `json:"payload_kind"`
	Signal      string               `json:"signal"`
	Target      string               `json:"target"`
	DedupKey    string               `json:"dedup_key"`
	TestURL     string               `json:"test_url,omitempty"`
}

// openRedirectDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type openRedirectDetail struct {
	Engine      string                     `json:"engine"`
	URL         string                     `json:"url"`
	Method      string                     `json:"method"`
	DedupKey    string                     `json:"dedup_key,omitempty"`
	Occurrences int                        `json:"occurrences,omitempty"`
	Baseline    *openRedirectAttempt       `json:"baseline,omitempty"`
	Attempts    []openRedirectAttempt      `json:"attempts,omitempty"`
	Confirmed   []openRedirectConfirmation `json:"confirmed,omitempty"`
	Verdict     domain.Verdict             `json:"verdict"`
	Severity    domain.Severity            `json:"severity,omitempty"`
	Confidence  domain.Confidence          `json:"confidence,omitempty"`
	Reason      string                     `json:"reason,omitempty"`
	Throttled   bool                       `json:"throttled,omitempty"`
	BudgetOut   bool                       `json:"attempt_budget_exhausted,omitempty"`
	Skipped     bool                       `json:"skipped,omitempty"`
	SkipReason  string                     `json:"skip_reason,omitempty"`
	TestCaseIDs []domain.ID                `json:"test_case_ids,omitempty"`
	EvidenceIDs []domain.ID                `json:"evidence_ids,omitempty"`
}

// openRedirectExecutor runs open-redirect jobs.
type openRedirectExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newOpenRedirectExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *openRedirectExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &openRedirectExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*openRedirectExecutor)(nil)

// Handle implements worker.Handler.
func (e *openRedirectExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, err := e.openRedirectTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	if ep == nil || strings.TrimSpace(ep.URL) == "" {
		return fmt.Errorf("%w: open redirect job has no target URL", worker.ErrPermanent)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnOpenRedirect, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist open redirect test case: %w", err)
	}

	d := &openRedirectDetail{Engine: openRedirectEngine, URL: ep.URL, Method: method, Verdict: domain.VerdictRejected}
	if reason, skip := e.openRedirectSkip(ep, params); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "open redirect skipped: "+reason)
		return nil
	}
	candidates := openRedirectParams(params)
	if len(candidates) == 0 {
		d.Skipped = true
		d.SkipReason = "the endpoint exposes no redirect-shaped parameter (next/url/return/goto/dest/redir/callback...)"
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "open redirect skipped: "+d.SkipReason)
		return nil
	}

	// The baseline keeps every parameter at its observed value, so a redirect
	// that was already there is never attributed to the injected payload.
	baseReq, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	baseReq.NoRedirects = true
	baseSignal, baseFound := openRedirectSignal{}, false
	baseProbe := &openRedirectAttempt{Parameter: "(baseline)", Payload: "", PayloadKind: "baseline", URL: baseReq.URL}
	baseResp, outcome, _ := e.do(ctx, baseReq)
	baseProbe.Status, baseProbe.EvidenceIDs = e.record(ctx, tc, baseResp, baseProbe.EvidenceIDs, "baseline")
	if baseResp != nil {
		tc.HTTPStatus = baseResp.Status
		baseProbe.RedirectTo = strings.TrimSpace(baseResp.Headers.Get("Location"))
		baseSignal, baseFound = detectOpenRedirect(baseResp, baseReq.URL)
		if baseFound {
			baseProbe.Signal, baseProbe.Target = baseSignal.Kind, baseSignal.Target
			baseProbe.Note = "the unmodified request already redirects here; a matching probe result is not attributed to the parameter"
		}
	}
	d.Baseline = baseProbe
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the baseline request to the endpoint did not complete"
		e.finish(ctx, tc, d, domain.TestCaseFailed, "open redirect inconclusive: baseline request failed")
		return nil
	}
	if isThrottleStatus(baseResp.Status) {
		d.Throttled = true
		d.Reason = fmt.Sprintf("the target answered HTTP %d to the baseline; no redirect payload was sent", baseResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "open redirect skipped: target throttled the baseline request")
		return nil
	}

	payloads := openRedirectPayloads(ep.URL)
	attempts, failed := 0, 0
	for _, p := range candidates {
		if d.Throttled || attempts >= maxOpenRedirectAttempts {
			d.BudgetOut = attempts >= maxOpenRedirectAttempts
			break
		}
		for _, payload := range payloads {
			if attempts >= maxOpenRedirectAttempts {
				d.BudgetOut = true
				break
			}
			req, err := buildRequest(ep, params, &injection{param: p, value: payload.Value})
			if err != nil {
				continue
			}
			// Inspect the redirect instead of following it: the payload must never
			// steer a scan request off the target.
			req.NoRedirects = true
			a := openRedirectAttempt{Parameter: p.Name, Location: p.Location, Payload: payload.Value, PayloadKind: payload.Kind, URL: req.URL}
			resp, outcome, _ := e.do(ctx, req)
			attempts++
			a.Status, a.EvidenceIDs = e.record(ctx, tc, resp, a.EvidenceIDs, "payload")
			if resp != nil {
				a.RedirectTo = strings.TrimSpace(resp.Headers.Get("Location"))
			}
			if outcome != domain.OutcomeSuccess {
				failed++
				a.Note = "the request did not complete"
				d.Attempts = append(d.Attempts, a)
				continue
			}
			if isThrottleStatus(resp.Status) {
				d.Throttled = true
				a.Note = fmt.Sprintf("the target answered HTTP %d; stopping to respect backpressure", resp.Status)
				d.Attempts = append(d.Attempts, a)
				break
			}
			sig, found := detectOpenRedirect(resp, req.URL)
			if !found {
				a.Note = "the response did not redirect to the canary"
				d.Attempts = append(d.Attempts, a)
				continue
			}
			a.Signal, a.Target = sig.Kind, sig.Target
			if baseFound && baseSignal.Kind == sig.Kind && baseSignal.Target == sig.Target {
				a.Note = "the unmodified baseline already redirects to this destination"
				d.Attempts = append(d.Attempts, a)
				continue
			}
			a.Confirmed = true
			d.Attempts = append(d.Attempts, a)
			d.Confirmed = append(d.Confirmed, openRedirectConfirmation{
				Parameter: p.Name, Location: p.Location, Payload: payload.Value, PayloadKind: payload.Kind,
				Signal: sig.Kind, Target: sig.Target, TestURL: req.URL,
				DedupKey: openRedirectDedupKey(ep.URL, p.Name, p.Location),
			})
			// One confirmed payload per parameter is enough: the parameter is
			// already proved to steer the destination.
			break
		}
	}

	switch {
	case len(d.Confirmed) > 0:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = domain.SeverityMedium, domain.ConfidenceHigh
		d.Reason = openRedirectReason(d.Confirmed[0])
		e.correlate(ctx, job, ep, tc, d)
	case attempts > 0 && failed == attempts:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "none of the payload requests completed, so the parameter could not be exercised"
	default:
		d.Verdict = domain.VerdictRejected
		d.Reason = "no redirect-shaped parameter sent the response to the attacker-controlled destination"
		if d.Throttled {
			d.Reason = "probing stopped early because the target asked for less traffic"
		}
	}

	note := "open redirect: " + d.Reason
	if d.Verdict == domain.VerdictInconclusive {
		note = "open redirect inconclusive: " + d.Reason
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// openRedirectReason renders the human summary for a confirmation.
func openRedirectReason(c openRedirectConfirmation) string {
	mechanism := "an HTTP redirect"
	switch c.Signal {
	case "meta_refresh":
		mechanism = "a meta refresh"
	case "script_redirect":
		mechanism = "a script redirect"
	}
	return fmt.Sprintf("setting parameter %q to %q made the server answer with %s to %s, so a link on this origin can send a user to an arbitrary site",
		c.Parameter, c.Payload, mechanism, c.Target)
}

// openRedirectTarget resolves the job's endpoint and its parameters. A job
// carrying only a URL is still actionable: its own query string supplies the
// candidate parameters, and nothing is persisted on the discovery side.
func (e *openRedirectExecutor) openRedirectTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, error) {
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
	ep := &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}
	names := make([]string, 0, len(u.Query()))
	for name := range u.Query() {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]*domain.Parameter, 0, len(names))
	for _, name := range names {
		params = append(params, &domain.Parameter{
			// A distinct ID per synthesized parameter: buildRequest decides which
			// parameter to override by ID, and empty IDs would all compare equal.
			ID: domain.NewID(), Name: name, Location: domain.LocationQuery, Example: u.Query().Get(name),
			EndpointID: ep.ID, ScanID: job.ScanID, Source: domain.SourceUserProvided,
		})
	}
	return ep, params, nil
}

// openRedirectSkip mirrors the test executor's guards: a payload-bearing job is
// only sent to a safe method unless the operator explicitly opted into
// state-changing traffic, and write-like/export endpoints stay untouched.
func (e *openRedirectExecutor) openRedirectSkip(ep *domain.Endpoint, params []*domain.Parameter) (string, bool) {
	if !isSafeMethod(ep.Method) && !e.cfg.AllowStateChanging {
		return fmt.Sprintf("%s is state-changing and AllowStateChanging is off", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, params) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// do sends one request with the executor's per-request timeout.
func (e *openRedirectExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
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

// record persists one request/response pair and returns the attempt's status and
// the evidence IDs (existing plus new).
func (e *openRedirectExecutor) record(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, ids []domain.ID, role string) (int, []domain.ID) {
	if resp == nil {
		return 0, ids
	}
	newIDs, err := e.persist(ctx, tc, resp, role)
	if err != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(err.Error(), 200))
		e.log.Warn("open redirect: persist evidence", "test_case", tc.ID, "err", err)
	}
	ids = appendUniqueIDs(ids, newIDs)
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, newIDs)
	return resp.Status, ids
}

// persist stores the request/response pair for one attempt.
func (e *openRedirectExecutor) persist(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, role string) ([]domain.ID, error) {
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return nil, nil
	}
	prefix := ""
	if role == "baseline" {
		// Evidence.Role classifies by note prefix; this request is the unmodified
		// baseline every payload is compared against.
		prefix = domain.EvidenceNoteBaselinePrefix
	}
	var ids []domain.ID
	captured := *resp.Request
	captured.Headers = resp.Request.Headers.Clone()
	note := prefix + "test_case=" + string(tc.ID) + " open redirect " + role + " request"
	if redactRequestCookieValues(captured.Headers) {
		note += " (cookie values redacted)"
	}
	reqID, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
		dumpRequest(&captured), note)
	if err != nil {
		return ids, err
	}
	ids = append(ids, reqID)
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	respNote := prefix + "test_case=" + string(tc.ID) + " open redirect " + role + " response"
	if redactSetCookieValues(recorded.Headers) {
		respNote += " (cookie values redacted)"
	}
	respID, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), respNote)
	if err != nil {
		return ids, err
	}
	return append(ids, respID), nil
}

// openRedirectDedupKey identifies one (endpoint, parameter, location) redirect,
// so repeated attempts at the same site absorb into one finding.
func openRedirectDedupKey(rawURL, param string, loc domain.ParamLocation) string {
	return "open_redirect\x00" + rawURL + "\x00" + param + "\x00" + string(loc)
}

// finish persists the job's test case and correlates any confirmed parameters.
func (e *openRedirectExecutor) finish(ctx context.Context, tc *domain.TestCase, d *openRedirectDetail, status domain.TestCaseStatus, note string) {
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
		e.log.Warn("open redirect: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate upserts one finding per confirmed (endpoint, parameter) redirect.
func (e *openRedirectExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *openRedirectDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("open redirect: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("open redirect: list findings", "scan", job.ScanID, "err", err)
		return
	}
	// finish() runs after correlation, so this attempt's IDs are merged here:
	// a finding must never be created without the evidence that proves it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	now := time.Now()
	for _, c := range d.Confirmed {
		title := fmt.Sprintf("Open redirect via parameter %q on %s", c.Parameter, endpointHostLabel(ep.URL))
		summary := openRedirectReason(c)
		fd := *d
		fd.DedupKey = c.DedupKey
		fd.Confirmed = []openRedirectConfirmation{c}

		var match *domain.Finding
		for _, f := range existing {
			if f.VulnClass != domain.VulnOpenRedirect {
				continue
			}
			var prev openRedirectDetail
			if err := json.Unmarshal(f.Detail, &prev); err != nil || prev.DedupKey == "" || prev.DedupKey != c.DedupKey {
				continue
			}
			match = f
			fd.Occurrences = prev.Occurrences + 1
			fd.TestCaseIDs = appendUniqueIDs(prev.TestCaseIDs, fd.TestCaseIDs)
			fd.EvidenceIDs = appendUniqueIDs(prev.EvidenceIDs, fd.EvidenceIDs)
			break
		}
		if fd.Occurrences == 0 {
			fd.Occurrences = 1
		}
		detail, _ := json.Marshal(fd)

		if match != nil {
			match.Title, match.Summary = title, summary
			match.EvidenceIDs = appendUniqueIDs(match.EvidenceIDs, fd.EvidenceIDs)
			match.Detail = detail
			match.UpdatedAt = now
			if err := e.store.Findings().Update(ctx, match); err != nil {
				e.log.Warn("open redirect: update finding", "scan", job.ScanID, "err", err)
			}
			continue
		}
		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnOpenRedirect,
			Verdict: domain.VerdictConfirmed, Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh,
			Title: title, Summary: summary, EndpointID: ep.ID, Location: c.Location,
			EvidenceIDs: appendUniqueIDs(nil, fd.EvidenceIDs),
			Provenance:  domain.Provenance{Engine: openRedirectEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
			Detail:      detail, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.log.Warn("open redirect: create finding", "scan", job.ScanID, "err", err)
		}
	}
}
