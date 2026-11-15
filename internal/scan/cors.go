package scan

// CORS misconfiguration engine (read-only).
//
// One CORS job acts on one endpoint. The engine sends a baseline GET without an
// Origin header, then a BOUNDED set of read-only GET/OPTIONS probes, each
// carrying exactly one attacker-shaped Origin value, and decides from the
// response headers ALONE: Access-Control-Allow-Origin (ACAO) and
// Access-Control-Allow-Credentials (ACAC).
//
// Boundaries:
//   - Read-only: GET and OPTIONS only, no request body, no state change.
//   - Bounded: one baseline + at most four origin probes + at most one
//     preflight, per endpoint. The origin set is derived from the target's own
//     host, never sprayed.
//   - No stray traffic: redirects are NOT followed (a probe must measure THIS
//     endpoint's policy, not whatever it redirects to), the canary origins
//     (evil-canary.invalid / a canary subdomain) are never resolved, and the
//     engine the controller passes is the scan's scope-enforcing one.
//   - Deterministic: the verdict is a pure function of the response headers, so
//     no browser and no LLM participate (AGENTS.md §2.5).
//
// A CORS misconfiguration is reported because the response PROVES it: the
// server itself named an attacker-shaped origin, or combined a wildcard with
// credentials. Nothing here is inferred, guessed, or scored by a model.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
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
	corsEngine = "cors"

	// corsCanaryOrigin is a reserved, non-resolvable origin (the .invalid TLD is
	// never delegated). Indago never contacts it: only the target's own
	// response headers are read.
	corsCanaryOrigin = "https://evil-canary.invalid"
	// corsCanaryLabel is the label used to build a probe origin that is
	// attacker-registerable while still containing the target host verbatim
	// (https://<target-host>.evil-canary.invalid) — the shape a prefix/substring
	// allowlist wrongly trusts.
	corsCanaryLabel = "evil-canary"
	// corsSubdomainLabel builds https://<label>.<target-host>, the shape a
	// "trust every subdomain of ours" policy wrongly trusts.
	corsSubdomainLabel = "indago-canary"
	// corsNullValue is the serialized origin of a sandboxed/opaque document.
	corsNullValue = "null"
)

// vulnClassCORS labels CORS findings. domain.VulnClass has no CORS member yet;
// adding one is the QA/QC wiring change that also introduces JobCORS, so the
// value is declared here for now. An unknown class degrades gracefully
// everywhere it is consumed (internal/report falls back to a generic class
// entry, internal/web simply has no per-class coverage counter for it).
const vulnClassCORS domain.VulnClass = domain.VulnCORS

// corsVariant says which attacker-shaped origin a probe carries, so the verdict
// can explain WHY a reflection matters.
type corsVariant string

const (
	// corsVariantCanary: a fully arbitrary origin the attacker owns.
	corsVariantCanary corsVariant = "arbitrary_origin"
	// corsVariantNull: the opaque "null" origin of a sandboxed iframe/data URL.
	corsVariantNull corsVariant = "null_origin"
	// corsVariantPrefix: https://<target-host>.evil-canary.invalid — a
	// registrable origin that a naive prefix/substring allowlist accepts.
	corsVariantPrefix corsVariant = "prefix_match_bypass"
	// corsVariantSubdomain: https://indago-canary.<target-host> — an origin in
	// the target's own namespace, trusted only by a "any subdomain" policy (and
	// therefore reachable only with a foothold/subdomain takeover).
	corsVariantSubdomain corsVariant = "subdomain_trust"
)

// corsProbeSpec is one Origin value the engine sends.
type corsProbeSpec struct {
	Origin  string
	Variant corsVariant
}

// corsProbeOrigins derives the bounded origin set from the target URL. It is
// deterministic: the same URL always yields the same, ordered list.
func corsProbeOrigins(rawURL string) []corsProbeSpec {
	out := []corsProbeSpec{
		{Origin: corsCanaryOrigin, Variant: corsVariantCanary},
		{Origin: corsNullValue, Variant: corsVariantNull},
	}
	host := corsTargetHostname(rawURL)
	if !corsHasRegistrableHost(host) {
		// An IP literal (or a single-label host) has no subdomain/prefix space
		// worth probing: https://evil.<ip> is not an origin anyone can hold.
		return out
	}
	out = append(out,
		corsProbeSpec{Origin: "https://" + host + "." + corsCanaryLabel + ".invalid", Variant: corsVariantPrefix},
		corsProbeSpec{Origin: "https://" + corsSubdomainLabel + "." + host, Variant: corsVariantSubdomain},
	)
	return out
}

// corsTargetHostname returns the lowercased hostname of rawURL without a port.
func corsTargetHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// corsHasRegistrableHost reports whether host is a DNS name with at least two
// labels (so a subdomain/prefix variation is meaningful and syntactically
// valid). IP literals and single-label hosts are excluded.
func corsHasRegistrableHost(host string) bool {
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	if !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
	}
	return len(host) <= 200
}

// corsProbe is the recorded result of one request. Its classification fields are
// filled by classifyCORSProbe, which is a PURE function of the response.
type corsProbe struct {
	Origin           string            `json:"origin,omitempty"`
	Variant          corsVariant       `json:"variant,omitempty"`
	Method           string            `json:"method"`
	Status           int               `json:"status,omitempty"`
	FinalURL         string            `json:"final_url,omitempty"`
	AllowOrigin      string            `json:"access_control_allow_origin,omitempty"`
	AllowCredentials string            `json:"access_control_allow_credentials,omitempty"`
	Misconfigured    bool              `json:"misconfigured,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Severity         domain.Severity   `json:"severity,omitempty"`
	Confidence       domain.Confidence `json:"confidence,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	EvidenceIDs      []domain.ID       `json:"evidence_ids,omitempty"`
}

// Signal kinds. They are stable strings so a report/UI can group them.
const (
	corsKindArbitraryOrigin     = "arbitrary_origin_reflection"
	corsKindNullOrigin          = "null_origin_allowed"
	corsKindPrefixBypass        = "prefix_match_bypass"
	corsKindSubdomainTrust      = "subdomain_trust"
	corsKindWildcardCredentials = "wildcard_with_credentials"
	corsKindWildcardPublic      = "wildcard_public"
	corsKindUnrelatedOrigin     = "unrelated_origin"
	corsKindSubdomainNoCreds    = "subdomain_trust_without_credentials"
	corsKindNoCORS              = "no_cors_headers"
	corsKindUnavailable         = "probe_unavailable"
)

// classifyCORSProbe decides what ONE response proves. It is a pure function of
// the probe's headers (no I/O, no clock, no LLM), which is what makes a CORS
// verdict reproducible from the stored evidence.
//
// A wildcard ACAO WITHOUT credentials is deliberately not a finding: that is a
// normal, intentional policy for public resources. A wildcard WITH credentials
// is a spec violation and a broken policy, so it is reported as a medium
// misconfiguration. An echoed origin is reported by variant: an origin the
// attacker can hold (arbitrary/prefix) is high with credentials and medium
// without; the target's own subdomain is reported only with credentials,
// because without them no authenticated read is possible.
func classifyCORSProbe(p *corsProbe) {
	if p == nil {
		return
	}
	acao := strings.TrimSpace(p.AllowOrigin)
	credentials := strings.EqualFold(strings.TrimSpace(p.AllowCredentials), "true")
	p.Misconfigured, p.Kind, p.Severity, p.Confidence, p.Reason = false, "", "", "", ""

	switch {
	case acao == "":
		p.Kind = corsKindNoCORS
		p.Reason = "the response carried no Access-Control-Allow-Origin header"
		return
	case acao == "*":
		if !credentials {
			p.Kind = corsKindWildcardPublic
			p.Reason = "Access-Control-Allow-Origin: * without credentials is an intentional policy for public data and is not reported"
			return
		}
		p.Misconfigured = true
		p.Kind = corsKindWildcardCredentials
		p.Severity = domain.SeverityMedium
		p.Confidence = domain.ConfidenceMedium
		p.Reason = "Access-Control-Allow-Origin: * was sent together with Access-Control-Allow-Credentials: true; " +
			"browsers reject that combination, so the policy is broken and whatever proxy or framework adds one of the two headers later will expose the response to every origin"
		return
	}

	// "null" is reported whether or not it is what this probe sent: a server
	// that always answers null still lets a sandboxed (opaque-origin) document
	// read the response.
	if strings.EqualFold(acao, corsNullValue) {
		p.Misconfigured = true
		p.Kind = corsKindNullOrigin
		p.Reason = "the server allowed the opaque origin \"null\"; any sandboxed iframe or data: document has that origin, so it can read the response"
		p.Confidence = domain.ConfidenceHigh
		if credentials {
			p.Severity = domain.SeverityHigh
			p.Reason += " and was allowed to send credentials"
		} else {
			p.Severity = domain.SeverityMedium
			p.Reason += " (without credentials)"
		}
		return
	}

	if !strings.EqualFold(acao, strings.TrimSpace(p.Origin)) {
		p.Kind = corsKindUnrelatedOrigin
		p.Reason = fmt.Sprintf("the response allowed %q, which is not the origin this probe sent", acao)
		return
	}

	switch p.Variant {
	case corsVariantPrefix:
		p.Misconfigured = true
		p.Kind = corsKindPrefixBypass
		p.Confidence = domain.ConfidenceHigh
		p.Reason = "the server echoed an origin whose host starts with the target host but ends in .evil-canary.invalid, " +
			"an origin anyone can register; an allowlist that matches a prefix or substring of the origin is bypassable"
	case corsVariantSubdomain:
		p.Kind = corsKindSubdomainTrust
		p.Confidence = domain.ConfidenceMedium
		if !credentials {
			p.Kind = corsKindSubdomainNoCreds
			p.Reason = "the server allowed its own canary subdomain without credentials; that needs a foothold on a sibling subdomain and exposes no authenticated data, so it is recorded but not reported"
			return
		}
		p.Misconfigured = true
		p.Reason = "the server allowed ANY subdomain of the target (canary subdomain) together with credentials, " +
			"so a compromised or taken-over sibling subdomain can read authenticated responses"
	default:
		p.Misconfigured = true
		p.Kind = corsKindArbitraryOrigin
		p.Confidence = domain.ConfidenceHigh
		p.Reason = "the server echoed an arbitrary attacker-controlled origin"
	}
	if !credentials {
		p.Severity = domain.SeverityMedium
		p.Reason += " without credentials, so only unauthenticated responses are readable"
		return
	}
	if p.Variant == corsVariantSubdomain {
		p.Severity = domain.SeverityMedium
		p.Reason += " (a foothold on a sibling subdomain is required)"
		return
	}
	p.Severity = domain.SeverityHigh
	p.Reason += " with Access-Control-Allow-Credentials: true, so any site can read this endpoint's authenticated responses"
}

// corsDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type corsDetail struct {
	Engine      string            `json:"engine"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	DedupKey    string            `json:"dedup_key,omitempty"`
	Occurrences int               `json:"occurrences,omitempty"`
	Baseline    *corsProbe        `json:"baseline,omitempty"`
	Probes      []corsProbe       `json:"probes,omitempty"`
	Verdict     domain.Verdict    `json:"verdict"`
	Severity    domain.Severity   `json:"severity,omitempty"`
	Confidence  domain.Confidence `json:"confidence,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Throttled   bool              `json:"throttled,omitempty"`
	Skipped     bool              `json:"skipped,omitempty"`
	SkipReason  string            `json:"skip_reason,omitempty"`
	TestCaseIDs []domain.ID       `json:"test_case_ids,omitempty"`
	EvidenceIDs []domain.ID       `json:"evidence_ids,omitempty"`
}

// corsExecutor runs CORS jobs.
type corsExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newCORSExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *corsExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &corsExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*corsExecutor)(nil)

// Handle implements worker.Handler.
func (e *corsExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, err := e.corsTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	if ep == nil || strings.TrimSpace(ep.URL) == "" {
		return fmt.Errorf("%w: cors job has no target URL", worker.ErrPermanent)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: vulnClassCORS, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist cors test case: %w", err)
	}

	d := &corsDetail{Engine: corsEngine, URL: ep.URL, Method: method, Verdict: domain.VerdictRejected}
	if reason, skip := e.corsSkip(ep, params); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "cors skipped: "+reason)
		return nil
	}
	d.DedupKey = corsDedupKey(ep.URL)

	// The baseline is the same request WITHOUT an Origin header: it tells the
	// operator what the endpoint answers normally, and it is the evidence that
	// an ACAO seen later was triggered by the probe rather than being static.
	baseline := &corsProbe{Method: http.MethodGet}
	baseReq := httpengine.GET(ep.URL)
	baseReq.NoRedirects = true
	resp, outcome, err := e.corsDo(ctx, baseReq)
	e.corsRecord(ctx, baseline, tc, resp, err)
	d.Baseline = baseline
	if resp != nil {
		tc.HTTPStatus = resp.Status
	}
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the baseline request to the endpoint did not complete"
		e.finish(ctx, tc, d, domain.TestCaseFailed, "cors inconclusive: baseline request failed")
		return nil
	}
	if isThrottleStatus(resp.Status) {
		d.Throttled = true
		d.Reason = fmt.Sprintf("the target answered HTTP %d to the baseline; the target asked for less traffic, so no origin probe was sent", resp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "cors skipped: target throttled the baseline request")
		return nil
	}

	probes := 0
	failed := 0
	for _, spec := range corsProbeOrigins(ep.URL) {
		p := corsProbe{Origin: spec.Origin, Variant: spec.Variant, Method: http.MethodGet}
		req := httpengine.GET(ep.URL)
		req.NoRedirects = true // measure THIS endpoint, never a redirect target
		req.Headers = map[string]string{"Origin": spec.Origin}
		resp, outcome, err := e.corsDo(ctx, req)
		e.corsRecord(ctx, &p, tc, resp, err)
		probes++
		if outcome != domain.OutcomeSuccess {
			failed++
			p.Kind = corsKindUnavailable
			p.Reason = "the probe request did not complete"
			d.Probes = append(d.Probes, p)
			continue
		}
		if isThrottleStatus(resp.Status) {
			d.Throttled = true
			d.Probes = append(d.Probes, p)
			d.Reason = fmt.Sprintf("the target answered HTTP %d to an origin probe; stopping to respect the target's backpressure", resp.Status)
			break
		}
		classifyCORSProbe(&p)
		d.Probes = append(d.Probes, p)
	}

	// A preflight is what a server that only wires CORS into its OPTIONS handler
	// answers; it is one extra read-only request, sent only when the simple
	// probes have not already proved the misconfiguration.
	if !d.Throttled && corsBestSignal(d.Probes) == nil {
		p := corsProbe{Origin: corsCanaryOrigin, Variant: corsVariantCanary, Method: http.MethodOptions}
		req := httpengine.NewRequest(http.MethodOptions, ep.URL)
		req.NoRedirects = true // a preflight must not be bounced to another route
		req.Headers = map[string]string{
			"Origin":                        corsCanaryOrigin,
			"Access-Control-Request-Method": http.MethodGet,
		}
		resp, outcome, err := e.corsDo(ctx, req)
		e.corsRecord(ctx, &p, tc, resp, err)
		probes++
		if outcome == domain.OutcomeSuccess && isThrottleStatus(resp.Status) {
			d.Throttled = true
		} else if outcome == domain.OutcomeSuccess {
			classifyCORSProbe(&p)
		} else {
			failed++
			p.Kind = corsKindUnavailable
			p.Reason = "the preflight request did not complete"
		}
		d.Probes = append(d.Probes, p)
	}

	best := corsBestSignal(d.Probes)
	switch {
	case best != nil:
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = best.Severity, best.Confidence
		d.Reason = fmt.Sprintf("%s (%s): %s", corsKindTitle(best.Kind), best.Origin, best.Reason)
	case probes > 0 && failed == probes:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "none of the origin probes completed, so the endpoint's CORS policy could not be observed"
	default:
		d.Verdict = domain.VerdictRejected
		d.Reason = "no origin probe was reflected and no wildcard-with-credentials policy was observed"
		if d.Throttled {
			d.Reason = "probing stopped early because the target asked for less traffic"
		}
	}

	note := "cors: " + d.Reason
	switch d.Verdict {
	case domain.VerdictConfirmed:
		e.correlate(ctx, job, ep, tc, d)
	case domain.VerdictInconclusive:
		note = "cors inconclusive: " + d.Reason
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// corsTarget resolves the job's endpoint. A CORS job normally carries an
// EndpointID; a job carrying only a URL (an origin-level job) is still
// actionable, so a detached in-memory endpoint is built for it — nothing is
// persisted on the discovery side.
func (e *corsExecutor) corsTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, error) {
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
	return &domain.Endpoint{URL: raw, Method: domain.MethodGET, Source: domain.SourceUserProvided}, nil, nil
}

// corsSkip applies the same read-only/write guards the test executor uses, so a
// CORS probe can never become the one request that mutates a target.
func (e *corsExecutor) corsSkip(ep *domain.Endpoint, params []*domain.Parameter) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; a CORS probe only sends GET/OPTIONS", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, params) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// corsDo sends one request with the executor's per-request timeout and
// classifies the outcome.
func (e *corsExecutor) corsDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
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

// corsRecord copies a response's CORS headers into the probe, persists the
// request/response evidence, and appends its IDs to the test case.
func (e *corsExecutor) corsRecord(ctx context.Context, p *corsProbe, tc *domain.TestCase, resp *httpengine.Response, err error) {
	if resp == nil {
		if err != nil {
			p.Kind = corsKindUnavailable
			p.Reason = truncate(err.Error(), 300)
		}
		return
	}
	p.Status = resp.Status
	p.FinalURL = resp.FinalURL
	p.AllowOrigin = resp.Headers.Get("Access-Control-Allow-Origin")
	p.AllowCredentials = resp.Headers.Get("Access-Control-Allow-Credentials")
	ids, evErr := e.corsPersist(ctx, tc, resp, p)
	if evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
		e.log.Warn("cors: persist evidence", "test_case", tc.ID, "err", evErr)
	}
	p.EvidenceIDs = appendUniqueIDs(p.EvidenceIDs, ids)
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// corsPersist stores the request/response pair for one probe.
func (e *corsExecutor) corsPersist(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, p *corsProbe) ([]domain.ID, error) {
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return nil, nil
	}
	role := "cors " + p.Method
	if p.Origin != "" {
		role += " origin=" + p.Origin
	} else {
		role += " baseline (no Origin)"
	}
	baselinePrefix := ""
	if p.Origin == "" {
		// Evidence.Role classifies by note prefix; the un-Oriented request IS the
		// baseline this endpoint is compared against.
		baselinePrefix = domain.EvidenceNoteBaselinePrefix
	}
	var ids []domain.ID
	captured := *resp.Request
	captured.Headers = resp.Request.Headers.Clone()
	note := baselinePrefix + "test_case=" + string(tc.ID) + " " + role + " request"
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
	respNote := baselinePrefix + "test_case=" + string(tc.ID) + " " + role + " response"
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

// corsBestSignal returns the strongest misconfiguration among the probes, or nil
// when none was observed. Ties break deterministically (severity, then the
// probe order, which is itself deterministic).
func corsBestSignal(probes []corsProbe) *corsProbe {
	var best *corsProbe
	for i := range probes {
		p := &probes[i]
		if !p.Misconfigured {
			continue
		}
		if best == nil || corsSeverityRank(p.Severity) > corsSeverityRank(best.Severity) {
			best = p
		}
	}
	return best
}

func corsSeverityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}

// corsDedupKey identifies one endpoint's CORS policy: every origin shape that
// proves the same policy collapse into one finding.
func corsDedupKey(rawURL string) string {
	return "cors\x00" + rawURL
}

// corsKindTitle turns a signal kind into a human title fragment.
func corsKindTitle(kind string) string {
	switch kind {
	case corsKindArbitraryOrigin:
		return "arbitrary origin reflected"
	case corsKindNullOrigin:
		return "null origin allowed"
	case corsKindPrefixBypass:
		return "origin allowlist bypassed with a lookalike domain"
	case corsKindSubdomainTrust:
		return "any subdomain trusted with credentials"
	case corsKindWildcardCredentials:
		return "wildcard allow-origin combined with credentials"
	}
	return "permissive cross-origin policy"
}

// finish persists the test case and, when confirmed, correlates the finding.
func (e *corsExecutor) finish(ctx context.Context, tc *domain.TestCase, d *corsDetail, status domain.TestCaseStatus, note string) {
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
		e.log.Warn("cors: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate creates or updates the finding for an endpoint's CORS policy. The
// shared findingsMu is the same mutex every other engine's correlation takes:
// the read-then-write below is not a store-level unique constraint.
func (e *corsExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *corsDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("cors: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	// finish() runs after correlation, so the IDs this attempt earned are merged
	// in here — a finding must never be created without its evidence.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	if d.Occurrences == 0 {
		d.Occurrences = 1
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	title := "CORS misconfiguration: " + corsKindTitle(detailKind(d)) + " on " + endpointHostLabel(ep.URL)
	summary := d.Reason

	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("cors: list findings", "scan", job.ScanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != vulnClassCORS {
			continue
		}
		var fd corsDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" || fd.DedupKey != d.DedupKey {
			continue
		}
		fd.Occurrences++
		fd.Probes, fd.Baseline = d.Probes, d.Baseline
		fd.Reason, fd.Verdict = d.Reason, d.Verdict
		if corsSeverityRank(d.Severity) >= corsSeverityRank(fd.Severity) {
			fd.Severity, fd.Confidence = d.Severity, d.Confidence
			f.Severity, f.Confidence = d.Severity, d.Confidence
		}
		fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, d.TestCaseIDs)
		fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, d.EvidenceIDs)
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, d.EvidenceIDs)
		f.Title, f.Summary = title, summary
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("cors: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: vulnClassCORS,
		Verdict: domain.VerdictConfirmed, Severity: d.Severity, Confidence: d.Confidence,
		Title: title, Summary: summary, EndpointID: ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, d.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: corsEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
		Detail:      detail, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("cors: create finding", "scan", job.ScanID, "err", err)
	}
}

// detailKind returns the strongest kind recorded in the detail.
func detailKind(d *corsDetail) string {
	if best := corsBestSignal(d.Probes); best != nil {
		return best.Kind
	}
	return ""
}

// endpointHostLabel is endpointLabel qualified by the target host, so a finding
// title names the site as well as the path.
func endpointHostLabel(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return endpointLabel(rawURL)
	}
	return u.Host + endpointLabel(rawURL)
}
