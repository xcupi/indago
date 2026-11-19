package scan

// Read-only HTTP response security-headers and cookie-policy check.
//
// One job acts on ONE origin (scheme://host[:port]), not on every URL: response
// security headers and cookie flags are an origin/site policy, so reporting
// them per endpoint would multiply one misconfiguration into hundreds of
// near-duplicate findings. The executor sends exactly ONE GET — the scan's
// baseline inspection — and decides from the response headers and Set-Cookie
// attributes alone.
//
// Boundaries:
//   - Read-only: one GET per origin, no body, no state change, no payload.
//   - Bounded: at most maxSecurityHeadersOrigins origins per scan.
//   - Deterministic: every signal is a pure function of the response headers,
//     so no browser and no LLM participate (AGENTS.md §2.5).
//   - No secret retention: cookie VALUES are never recorded in the detail,
//     the finding, or the evidence (the stored response has Set-Cookie values
//     redacted by redactSetCookieValues).
//   - Final response only: the engine inspects the response that ends the
//     redirect chain (scheme-gated HSTS applies to THAT scheme). Cookies set
//     on an intermediate 3xx hop are not visible here; the scope-enforcing
//     engine follows the chain, and re-requesting every hop would multiply
//     traffic for a policy observation the final page already carries.
//
// A finding here is an observation of an absent/weak header, not an exploit:
// the response itself PROVES the header was missing or the cookie attribute was
// absent. Severity reflects the defence that header or attribute would have
// provided.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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
	shEngine = "security_headers"

	// shCategoryHeader / shCategoryCookie separate the two finding families
	// this one engine reports, so a report/UI can group them.
	shCategoryHeader = "header"
	shCategoryCookie = "cookie"

	// maxSecurityHeadersOrigins bounds the pass: one job per origin.
	maxSecurityHeadersOrigins = 20
	// securityHeadersPriority runs the passive header inspection before the
	// payload-bearing engines: it is the cheapest request in the scan.
	securityHeadersPriority = 36
)

// Signal kinds. Stable strings so a report/UI can group them.
const (
	shKindMissingHSTS         = "missing_strict_transport_security"
	shKindHSTSDisabled        = "strict_transport_security_disabled"
	shKindMissingXCTO         = "missing_x_content_type_options"
	shKindWeakXCTO            = "weak_x_content_type_options"
	shKindMissingCSPAndFrames = "missing_csp_and_frame_options"
	shKindWeakFrames          = "weak_x_frame_options"
	shKindServerVersion       = "server_version_disclosure"
	shKindPoweredByVersion    = "x_powered_by_version_disclosure"
	shKindCookieSecurityAttrs = "cookie_missing_security_attributes"
)

// securityHeadersSignal is one observed weakness on an origin. Its DedupKey
// identifies the (origin, category, subject) triple, so a second endpoint on
// the same origin absorbs into the same finding instead of adding a row.
type securityHeadersSignal struct {
	Key         string            `json:"key"`
	Category    string            `json:"category"`
	Kind        string            `json:"kind"`
	Subject     string            `json:"subject"`
	Severity    domain.Severity   `json:"severity"`
	Confidence  domain.Confidence `json:"confidence"`
	Reason      string            `json:"reason"`
	Remediation string            `json:"remediation"`
	// Observed is the header value or cookie attribute summary that was
	// actually seen. It never contains a cookie value.
	Observed string   `json:"observed,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	Title    string   `json:"title"`
}

// securityHeadersCookie is the flag state of one Set-Cookie header. The cookie
// VALUE is deliberately not a field: this struct is persisted.
type securityHeadersCookie struct {
	Name        string   `json:"name"`
	Secure      bool     `json:"secure"`
	HTTPOnly    bool     `json:"http_only"`
	SameSite    string   `json:"same_site,omitempty"`
	SessionLike bool     `json:"session_like,omitempty"`
	Missing     []string `json:"missing,omitempty"`
}

// securityHeadersDetail is the engine-specific JSON recorded in
// TestCase.Detail and Finding.Detail.
type securityHeadersDetail struct {
	Engine          string                  `json:"engine"`
	URL             string                  `json:"url"`
	FinalURL        string                  `json:"final_url,omitempty"`
	Origin          string                  `json:"origin"`
	Method          string                  `json:"method"`
	HTTPStatus      int                     `json:"http_status,omitempty"`
	DedupKey        string                  `json:"dedup_key,omitempty"`
	Occurrences     int                     `json:"occurrences,omitempty"`
	Verdict         domain.Verdict          `json:"verdict"`
	Severity        domain.Severity         `json:"severity,omitempty"`
	Confidence      domain.Confidence       `json:"confidence,omitempty"`
	Reason          string                  `json:"reason,omitempty"`
	ObservedHeaders map[string]string       `json:"observed_headers,omitempty"`
	Cookies         []securityHeadersCookie `json:"cookies,omitempty"`
	Signals         []securityHeadersSignal `json:"signals,omitempty"`
	Throttled       bool                    `json:"throttled,omitempty"`
	Skipped         bool                    `json:"skipped,omitempty"`
	SkipReason      string                  `json:"skip_reason,omitempty"`
	TestCaseIDs     []domain.ID             `json:"test_case_ids,omitempty"`
	EvidenceIDs     []domain.ID             `json:"evidence_ids,omitempty"`
}

// shObservedHeaders is the bounded set of headers copied into the detail so a
// finding can be read without opening the raw evidence blob.
var shObservedHeaders = []string{
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"Content-Security-Policy",
	"X-Frame-Options",
	"Server",
	"X-Powered-By",
	"Referrer-Policy",
	"Content-Type",
}

// ---------------------------------------------------------------------------
// pure analysis
// ---------------------------------------------------------------------------

// securityHeadersOrigin returns the scheme://host[:port] identity of rawURL,
// lowercased, or "" when rawURL is not an absolute http(s) URL. It is the
// correlation unit for this engine: headers and cookie flags are an origin
// policy.
func securityHeadersOrigin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

// securityHeadersDedupKey is the finding identity: one row per origin, per
// category (header/cookie) and per subject (header name/cookie name).
func securityHeadersDedupKey(origin, category, subject string) string {
	return shEngine + "\x00" + strings.ToLower(origin) + "\x00" + category + "\x00" + strings.ToLower(subject)
}

// securityHeadersOriginKey identifies the origin-level inspection recorded in a
// TestCase.Detail (the finding-level keys are the per-subject ones below).
func securityHeadersOriginKey(origin string) string {
	return shEngine + "\x00" + strings.ToLower(origin)
}

// analyzeSecurityHeaders inspects ONE response. It is pure: no clock, no I/O,
// no network. origin is the correlation identity, finalURL decides whether the
// HTTPS-only checks apply.
//
// Order is fixed (HSTS, nosniff, framing, version disclosure, then cookies by
// name) so the same response always yields the same signal list.
func analyzeSecurityHeaders(origin, finalURL string, h http.Header) ([]securityHeadersSignal, []securityHeadersCookie) {
	https := false
	if u, err := url.Parse(finalURL); err == nil {
		https = strings.EqualFold(u.Scheme, "https")
	}

	var signals []securityHeadersSignal
	add := func(s securityHeadersSignal) {
		s.Key = securityHeadersDedupKey(origin, s.Category, s.Subject)
		s.Confidence = domain.ConfidenceHigh
		if len(s.Missing) > 0 {
			s.Observed = "missing: " + strings.Join(s.Missing, ", ")
		}
		signals = append(signals, s)
	}

	// 1. HSTS — only meaningful over HTTPS: a browser ignores the header on a
	// plain-HTTP response, so reporting it there would be wrong.
	hsts := strings.TrimSpace(h.Get("Strict-Transport-Security"))
	switch {
	case https && hsts == "":
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindMissingHSTS, Subject: "Strict-Transport-Security",
			Severity: domain.SeverityMedium,
			Reason: "the HTTPS response carried no Strict-Transport-Security header, so a browser is free to " +
				"downgrade a later visit to plain HTTP and a network attacker can strip TLS",
			Remediation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS " +
				"response (and only after the whole site is HTTPS-ready), so browsers refuse a plain-HTTP downgrade.",
			Title: "Missing Strict-Transport-Security header",
		})
	case https && hsts != "":
		if age, ok := hstsMaxAge(hsts); !ok || age <= 0 {
			add(securityHeadersSignal{
				Category: shCategoryHeader, Kind: shKindHSTSDisabled, Subject: "Strict-Transport-Security",
				Severity: domain.SeverityLow, Observed: hsts,
				Reason: "the Strict-Transport-Security header does not enable protection (missing or zero max-age), " +
					"so browsers treat the origin as if HSTS were not configured",
				Remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains with a non-zero max-age.",
				Title:       "Strict-Transport-Security header does not enable protection",
			})
		}
	}

	// 2. X-Content-Type-Options — stops MIME sniffing.
	xcto := strings.TrimSpace(h.Get("X-Content-Type-Options"))
	switch {
	case xcto == "":
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindMissingXCTO, Subject: "X-Content-Type-Options",
			Severity: domain.SeverityLow,
			Reason: "the response carried no X-Content-Type-Options header, so a browser may sniff a different " +
				"content type than the one declared and execute an uploaded or reflected file as HTML/script",
			Remediation: "Send X-Content-Type-Options: nosniff on every response.",
			Title:       "Missing X-Content-Type-Options: nosniff header",
		})
	case !strings.EqualFold(xcto, "nosniff"):
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindWeakXCTO, Subject: "X-Content-Type-Options",
			Severity: domain.SeverityLow, Observed: xcto,
			Reason:      "the X-Content-Type-Options header does not disable MIME sniffing (only nosniff does)",
			Remediation: "Send X-Content-Type-Options: nosniff on every response.",
			Title:       "X-Content-Type-Options does not disable MIME sniffing",
		})
	}

	// 3. Framing / CSP. X-Frame-Options OR a CSP with frame-ancestors is
	// enough; only the complete absence of both is reported.
	csp := strings.TrimSpace(h.Get("Content-Security-Policy"))
	xfo := strings.TrimSpace(h.Get("X-Frame-Options"))
	cspFrames := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	switch {
	case csp == "" && xfo == "":
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindMissingCSPAndFrames, Subject: "Content-Security-Policy",
			Severity: domain.SeverityMedium,
			Reason: "the response carried neither Content-Security-Policy nor X-Frame-Options, so nothing restricts " +
				"which origin may frame the page (clickjacking) and no policy constrains injected script",
			Remediation: "Send Content-Security-Policy (including frame-ancestors 'self') on HTML responses; " +
				"X-Frame-Options: SAMEORIGIN remains a useful fallback for older browsers.",
			Title: "Missing Content-Security-Policy and X-Frame-Options headers",
		})
	case xfo != "" && !cspFrames && !validXFrameOptions(xfo):
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindWeakFrames, Subject: "X-Frame-Options",
			Severity: domain.SeverityLow, Observed: xfo,
			Reason: "the X-Frame-Options value is not a policy a current browser enforces (DENY or SAMEORIGIN), " +
				"so framing protection is absent or browser-dependent",
			Remediation: "Use X-Frame-Options: DENY or SAMEORIGIN, or Content-Security-Policy: frame-ancestors 'self'.",
			Title:       "X-Frame-Options policy is not enforced",
		})
	}

	// 4. Version disclosure. Only a value that actually carries a version is
	// reported: "Server: nginx" discloses software, not a patch level.
	if v := strings.TrimSpace(h.Get("Server")); v != "" && containsVersion(v) {
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindServerVersion, Subject: "Server",
			Severity: domain.SeverityLow, Observed: v,
			Reason: "the Server header names the exact product and version, which tells an attacker which known " +
				"vulnerabilities apply without any active probing",
			Remediation: "Suppress the version (for example nginx server_tokens off, Apache ServerTokens Prod); " +
				"prefer removing the header entirely at the edge.",
			Title: "Server header discloses the software version",
		})
	}
	if v := strings.TrimSpace(h.Get("X-Powered-By")); v != "" && containsVersion(v) {
		add(securityHeadersSignal{
			Category: shCategoryHeader, Kind: shKindPoweredByVersion, Subject: "X-Powered-By",
			Severity: domain.SeverityLow, Observed: v,
			Reason: "the X-Powered-By header names the exact runtime and version, which tells an attacker which " +
				"known vulnerabilities apply without any active probing",
			Remediation: "Remove the X-Powered-By header (for example expose_php = Off in PHP, or strip it at the " +
				"reverse proxy).",
			Title: "X-Powered-By header discloses the runtime version",
		})
	}

	// 5. Cookie attributes, one observation per cookie name.
	cookies := analyzeSetCookies(https, h)
	for _, c := range cookies {
		if len(c.Missing) == 0 {
			continue
		}
		// Severity is the strongest single issue: a JavaScript-readable
		// session cookie and a cookie sent over plain HTTP are both medium;
		// a missing SameSite alone is low.
		severity := domain.SeverityLow
		reason := "the cookie is set without " + strings.Join(c.Missing, ", ")
		if c.SessionLike && !c.HTTPOnly {
			severity = domain.SeverityMedium
			reason = "the session-like cookie is readable by JavaScript (no HttpOnly), so any script running on the " +
				"origin — including one injected through a separate XSS — can read the session"
		} else if !c.Secure && https {
			severity = domain.SeverityMedium
			reason = "the cookie is set over HTTPS without the Secure attribute, so a browser will also send it over " +
				"plain HTTP where a network attacker can read it"
		}
		add(securityHeadersSignal{
			Category: shCategoryCookie, Kind: shKindCookieSecurityAttrs, Subject: c.Name,
			Severity: severity, Observed: cookieFlagsLabel(c), Missing: c.Missing,
			Reason:      reason,
			Remediation: cookieRemediation(c),
			Title:       fmt.Sprintf("Cookie %q is missing security attributes", c.Name),
		})
	}
	return signals, cookies
}

// analyzeSetCookies parses every Set-Cookie header and reports the enforced
// flags. The cookie VALUE is discarded here, before anything is persisted.
func analyzeSetCookies(https bool, h http.Header) []securityHeadersCookie {
	parsed := (&http.Response{Header: h}).Cookies()
	if len(parsed) == 0 {
		return nil
	}
	out := make([]securityHeadersCookie, 0, len(parsed))
	seen := make(map[string]bool, len(parsed))
	for _, c := range parsed {
		name := strings.TrimSpace(c.Name)
		if name == "" || seen[name] {
			// The same cookie set twice in one response: one finding per name.
			continue
		}
		seen[name] = true
		obs := securityHeadersCookie{
			Name:        name,
			Secure:      c.Secure,
			HTTPOnly:    c.HttpOnly,
			SameSite:    sameSiteLabel(c.SameSite),
			SessionLike: isSessionLikeCookieName(name),
		}
		if obs.SessionLike && !c.HttpOnly {
			obs.Missing = append(obs.Missing, "HttpOnly")
		}
		if https && !c.Secure {
			obs.Missing = append(obs.Missing, "Secure")
		}
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			obs.Missing = append(obs.Missing, "SameSite")
		}
		out = append(out, obs)
	}
	return out
}

// isSessionLikeCookieName reports whether a cookie name looks like it carries a
// session/authentication credential. It is a heuristic over name TOKENS (split
// on anything that is not a letter/digit), so "connect.sid" and "JSESSIONID"
// match while a word that merely contains the letters (e.g. "consider") does
// not. A cookie that does not match is still reported for Secure/SameSite; only
// the HttpOnly finding depends on this heuristic.
func isSessionLikeCookieName(name string) bool {
	for _, tok := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		switch tok {
		case "sid", "sess", "session", "sessionid", "auth", "token", "jwt", "remember", "jsessionid", "phpsessid":
			return true
		}
		if strings.Contains(tok, "session") {
			return true
		}
	}
	return false
}

// sameSiteLabel renders the parsed SameSite mode for the detail.
func sameSiteLabel(mode http.SameSite) string {
	switch mode {
	case http.SameSiteDefaultMode:
		return ""
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return ""
}

// cookieFlagsLabel is a value-free summary of the flags actually present.
func cookieFlagsLabel(c securityHeadersCookie) string {
	set := make([]string, 0, 3)
	if c.HTTPOnly {
		set = append(set, "HttpOnly")
	}
	if c.Secure {
		set = append(set, "Secure")
	}
	if c.SameSite != "" {
		set = append(set, "SameSite="+c.SameSite)
	}
	if len(set) == 0 {
		return "no security attributes"
	}
	return strings.Join(set, ", ")
}

// cookieRemediation names exactly the attributes that are absent.
func cookieRemediation(c securityHeadersCookie) string {
	parts := make([]string, 0, len(c.Missing))
	for _, m := range c.Missing {
		switch m {
		case "HttpOnly":
			parts = append(parts, "add HttpOnly so JavaScript cannot read the cookie")
		case "Secure":
			parts = append(parts, "add Secure so the cookie is never sent over plain HTTP")
		case "SameSite":
			parts = append(parts, "add SameSite=Lax or SameSite=Strict (None requires Secure) to limit cross-site sending")
		}
	}
	if len(parts) == 0 {
		return "Set the cookie with HttpOnly, Secure and SameSite."
	}
	return "Set-Cookie " + c.Name + ": " + strings.Join(parts, "; ") + "."
}

// hstsMaxAge extracts the max-age directive. ok is false when the directive is
// absent or unparseable, which browsers treat the same as max-age=0.
func hstsMaxAge(v string) (int64, bool) {
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "max-age") {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// validXFrameOptions reports whether the value is a policy current browsers
// enforce. ALLOW-FROM is obsolete and ignored by every current engine.
func validXFrameOptions(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DENY", "SAMEORIGIN":
		return true
	}
	return false
}

// containsVersion reports whether a header value carries a version-like token:
// a digit plus either a dot or a product/version separator. Bare product names
// ("nginx", "AmazonS3", "ASP.NET") are not reported.
func containsVersion(v string) bool {
	digit, marker := false, false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r == '.' || r == '/':
			marker = true
		}
	}
	return digit && marker
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

type securityHeadersExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newSecurityHeadersExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *securityHeadersExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &securityHeadersExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*securityHeadersExecutor)(nil)

// Handle implements worker.Handler: one baseline GET, then pure analysis.
func (e *securityHeadersExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := e.shTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodGet
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSecurityHeaders, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist security-headers test case: %w", err)
	}

	origin := securityHeadersOrigin(ep.URL)
	d := &securityHeadersDetail{Engine: shEngine, URL: ep.URL, Origin: origin, Method: method, Verdict: domain.VerdictRejected}
	if reason, skip := e.shSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "security headers skipped: "+reason)
		return nil
	}
	d.DedupKey = securityHeadersOriginKey(origin)

	req := httpengine.GET(ep.URL)
	resp, outcome, err := e.shDo(ctx, req)
	now := time.Now()
	tc.FinishedAt = &now
	if resp != nil {
		tc.HTTPStatus = resp.Status
	}
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the read-only baseline request to this origin did not complete"
		tc.Note = truncate("security headers inconclusive: "+errorText(err, outcome), 1024)
		e.finish(ctx, tc, d, domain.TestCaseFailed, tc.Note)
		return nil
	}
	tc.DurationMS = time.Since(started).Milliseconds()
	d.HTTPStatus = resp.Status
	d.FinalURL = resp.FinalURL
	d.ObservedHeaders = observedHeaders(resp.Headers)
	e.persist(ctx, tc, resp)

	if isThrottleStatus(resp.Status) {
		d.Throttled = true
		d.Reason = fmt.Sprintf("the target answered HTTP %d, so the response headers were not judged", resp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "security headers skipped: target throttled the baseline request")
		return nil
	}

	finalURL := strings.TrimSpace(resp.FinalURL)
	if finalURL == "" {
		finalURL = ep.URL
	}
	signals, cookies := analyzeSecurityHeaders(origin, finalURL, resp.Headers)
	d.Cookies, d.Signals = cookies, signals
	note := "security headers: no missing or weak header and no weak cookie attribute on this origin"
	// d.Verdict stays Rejected when nothing was observed: there is no finding
	// to report, and an empty signal list is a negative result, not a gap.
	if len(signals) > 0 {
		d.Verdict = domain.VerdictConfirmed
		d.Severity, d.Confidence = securityHeadersTopSeverity(signals), domain.ConfidenceHigh
		d.Reason = securityHeadersSummary(signals)
		note = "security headers: " + d.Reason
		e.correlate(ctx, job, ep, tc, d)
	}
	e.finish(ctx, tc, d, domain.TestCaseCompleted, note)
	return nil
}

// shTarget resolves the job's endpoint, tolerating an origin job that carries
// only a URL (nothing is persisted for such a detached endpoint).
func (e *securityHeadersExecutor) shTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, error) {
	if job == nil {
		return nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, _, _, err := resolveJobTarget(ctx, e.store, job)
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

// shSkip applies the same read-only/write guards the other passive engines use:
// this check must never be the request that mutates a target.
func (e *securityHeadersExecutor) shSkip(ep *domain.Endpoint) (string, bool) {
	if !isSafeMethod(ep.Method) {
		return fmt.Sprintf("%s is state-changing; a security-header check only sends GET", ep.Method), true
	}
	if e.cfg.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
		return "write-like endpoint " + endpointLabel(ep.URL) + " is disabled by skip_write_endpoints", true
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return "export/download endpoint " + endpointLabel(ep.URL) + " is disabled by skip_download_endpoints", true
	}
	return "", false
}

// shDo sends one request with the executor's per-request timeout.
func (e *securityHeadersExecutor) shDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
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

// errorText renders the failure reason for the note.
func errorText(err error, outcome domain.TestOutcome) string {
	if err != nil {
		return truncate(err.Error(), 300)
	}
	return "outcome " + string(outcome)
}

// observedHeaders copies the bounded header set into the detail. Set-Cookie is
// deliberately excluded (the cookie observations carry the names/flags only).
func observedHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(shObservedHeaders))
	for _, name := range shObservedHeaders {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			out[name] = truncate(v, 512)
		}
	}
	return out
}

// persist stores the request/response pair. Cookie values are redacted before
// the blob is written, exactly like the other header-reading engines.
func (e *securityHeadersExecutor) persist(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := "test_case=" + string(tc.ID) + " security_headers baseline request"
		if redactRequestCookieValues(captured.Headers) {
			note += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("security headers: persist request evidence", "test_case", tc.ID, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := "test_case=" + string(tc.ID) + " security_headers baseline response"
	if redactSetCookieValues(recorded.Headers) {
		note += " (cookie values redacted)"
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), note); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("security headers: persist response evidence", "test_case", tc.ID, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

// finish persists the test case.
func (e *securityHeadersExecutor) finish(ctx context.Context, tc *domain.TestCase, d *securityHeadersDetail, status domain.TestCaseStatus, note string) {
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
		e.log.Warn("security headers: persist test case", "test_case", tc.ID, "err", err)
	}
}

// correlate upserts one Finding per signal. The dedup key is
// (origin, category, subject), so a second endpoint on the same origin — or a
// resumed execution that re-runs the pass — absorbs into the same row and only
// unions evidence and the occurrence count.
func (e *securityHeadersExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *securityHeadersDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("security headers: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("security headers: list findings", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	// finish() runs after correlation, so the IDs this attempt earned are
	// merged in here — a finding must never be created without its evidence
	// or without a link back to the test case that proved it.
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	byKey := make(map[string]*domain.Finding, len(existing))
	for _, f := range existing {
		if f.VulnClass != domain.VulnSecurityHeaders && f.VulnClass != domain.VulnCookiePolicy {
			continue
		}
		var fd securityHeadersDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" {
			continue
		}
		byKey[fd.DedupKey] = f
	}

	for _, s := range d.Signals {
		class := domain.VulnSecurityHeaders
		if s.Category == shCategoryCookie {
			class = domain.VulnCookiePolicy
		}
		title := s.Title + ": " + originHostLabel(d.Origin)
		findingDetail := *d
		findingDetail.DedupKey = s.Key
		findingDetail.Severity, findingDetail.Confidence = s.Severity, s.Confidence
		findingDetail.Reason = s.Reason
		findingDetail.Signals = []securityHeadersSignal{s}
		if findingDetail.Occurrences == 0 {
			findingDetail.Occurrences = 1
		}
		detail, _ := json.Marshal(&findingDetail)

		if f := byKey[s.Key]; f != nil {
			var fd securityHeadersDetail
			if err := json.Unmarshal(f.Detail, &fd); err == nil {
				if fd.Occurrences == 0 {
					fd.Occurrences = 1
				}
				fd.Occurrences++
				if securityHeadersSeverityRank(s.Severity) > securityHeadersSeverityRank(fd.Severity) {
					fd.Severity, fd.Confidence = s.Severity, s.Confidence
					f.Severity, f.Confidence = s.Severity, s.Confidence
				}
				fd.Reason, fd.Signals = s.Reason, []securityHeadersSignal{s}
				fd.ObservedHeaders, fd.Cookies = findingDetail.ObservedHeaders, findingDetail.Cookies
				fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, []domain.ID{tc.ID})
				fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, tc.EvidenceIDs)
				if b, err := json.Marshal(fd); err == nil {
					f.Detail = b
				}
			}
			f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, tc.EvidenceIDs)
			f.Title, f.Summary = title, s.Reason
			f.UpdatedAt = now
			if err := e.store.Findings().Update(ctx, f); err != nil {
				e.log.Warn("security headers: update finding", "scan", job.ScanID, "err", err)
			}
			continue
		}

		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: class,
			Verdict: domain.VerdictConfirmed, Severity: s.Severity, Confidence: s.Confidence,
			Title: title, Summary: s.Reason, EndpointID: ep.ID,
			EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
			Provenance:  domain.Provenance{Engine: shEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
			Detail:      detail, CreatedAt: now, UpdatedAt: now,
		}
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.log.Warn("security headers: create finding", "scan", job.ScanID, "err", err)
			continue
		}
		byKey[s.Key] = f
	}
}

// originHostLabel renders the host[:port] of an origin for a finding title.
func originHostLabel(origin string) string {
	if u, err := url.Parse(origin); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
}

// securityHeadersTopSeverity returns the strongest severity among the signals.
func securityHeadersTopSeverity(signals []securityHeadersSignal) domain.Severity {
	best := domain.SeverityInfo
	for _, s := range signals {
		if securityHeadersSeverityRank(s.Severity) > securityHeadersSeverityRank(best) {
			best = s.Severity
		}
	}
	return best
}

// securityHeadersSeverityRank orders severities for comparison.
func securityHeadersSeverityRank(s domain.Severity) int {
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

// securityHeadersSummary is the one-line test-case/finding summary.
func securityHeadersSummary(signals []securityHeadersSignal) string {
	subjects := make([]string, 0, len(signals))
	for _, s := range signals {
		subjects = append(subjects, s.Subject)
	}
	return fmt.Sprintf("%d missing/weak response header or cookie attribute(s) on this origin: %s",
		len(signals), strings.Join(subjects, ", "))
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueSecurityHeadersProbes queues ONE JobSecurityHeaders per unique origin.
// Endpoint URLs are collapsed to scheme://host[:port] before deduplication, so
// a 500-page crawl yields one job per site, never one per URL.
func (c *Controller) enqueueSecurityHeadersProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipSecurityHeaders {
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
		if queued >= maxSecurityHeadersOrigins {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isSafeMethod(ep.Method) {
			continue
		}
		// Never spend the one job for an origin on an endpoint the executor
		// would then skip for policy reasons: a different endpoint on the same
		// origin carries the same header policy.
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		if sc.Config.SkipWriteEndpoints && isWriteLikeEndpoint(ep, nil) {
			continue
		}
		origin := securityHeadersOrigin(ep.URL)
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
			Type:        domain.JobSecurityHeaders,
			State:       domain.JobQueued,
			Priority:    securityHeadersPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("security headers: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("security header probes: enqueued", "scan", scanID, "jobs", queued)
	}
}
