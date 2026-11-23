package scan

// Stored XSS engine.
//
// One JobStoredXSS is enqueued per eligible state-changing endpoint (POST/PUT/
// PATCH with a text-like form or JSON parameter). The probe sends exactly ONE
// benign marker into that one parameter, then checks whether it executed:
//
//   - In band: a real Chromium context visits the GET pages that could render
//     the stored value, and the marker's own signal (window.__indago_sxss) has
//     to be observed there. Unchanged.
//   - Blind, only when an OAST collaborator is configured: the same marker also
//     asks the rendering client to request one URL on that collaborator,
//     carrying nothing but the correlation token. A callback proves the stored
//     value reached a renderer this scan cannot itself visit (an admin panel,
//     a moderation queue, a digest) — the case in-band verification cannot
//     cover at all.
//
// Boundaries this file keeps:
//
//   - Zero server-side destructive mutation. The blind arm adds NO request to
//     the target: the existing single submission carries both signals, and the
//     existing endpoint/lifetime gates (state-changing opt-in, login/logout/
//     delete/download exclusion, maxStoredXSSEndpoints, maxStoredXSSVerifyPages)
//     are untouched. The only extra traffic goes to the operator's own
//     collaborator, and only when the operator configured one.
//   - The marker stays a benign marker. It is a bare token, never alert/cookie/
//     storage/network exfiltration: the beacon URL carries the token as its
//     path and nothing else.
//   - A callback is evidence, never a verdict on its own: confirmation still
//     requires the exact token this probe planted, attributed to this probe,
//     under the same deterministic rules the in-band signal uses (AGENTS.md
//     §2.5). No LLM is involved anywhere.
//   - Scope is never widened. The browser context's AllowRequest gate keeps its
//     normal rule and gains exactly one exemption: the single beacon URL this
//     probe planted (scheme+host+path), so the verifying renderer can carry out
//     the callback. Nothing else is reachable (see storedXSSAllowWithBeacon).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	maxStoredXSSEndpoints   = 10
	maxStoredXSSVerifyPages = 8
	storedXSSEngine         = "stored_xss"
	storedXSSSettleWait     = 50 * time.Millisecond

	// storedXSSConfirmBrowser / storedXSSConfirmOAST are the two ways this
	// engine can observe execution. Both are deterministic browser-side
	// events naming the probe's own token.
	storedXSSConfirmBrowser = "browser-js-eval"
	storedXSSConfirmOAST    = "oast"

	// Blind OAST bounds. Polling only ever reads the operator's collaborator;
	// it sends nothing and touches no target.
	storedXSSOASTPollAttempts = 6
	storedXSSOASTPollInterval = 2 * time.Second
	storedXSSOASTPollTimeout  = 5 * time.Second
	storedXSSOASTPollBodyMax  = 1 << 20
	storedXSSOASTHitMax       = 512
)

type storedXSSJob struct {
	EndpointID domain.ID `json:"endpoint_id"`
	// CallbackURL and PollURL are the OAST collaborator pair this probe may
	// arm its blind arm with, resolved once at enqueue time from the
	// controller's collaborator (see enqueueStoredXSSProbes). Both empty means
	// "no collaborator configured": the probe then behaves exactly as it did
	// before the blind arm existed.
	//
	// The poll URL carries the collaborator's per-process read secret. It is
	// persisted with the job because a job may be retried after a restart, and
	// a probe that planted a beacon must still be able to read its own hit
	// then. The store is this operator's local database and the poll API is
	// loopback-only; it is never written into evidence or a report.
	CallbackURL string `json:"callback_url,omitempty"`
	PollURL     string `json:"poll_url,omitempty"`
}

func parseStoredXSSJob(job *domain.TestJob) (storedXSSJob, error) {
	if job == nil {
		return storedXSSJob{}, errors.New("stored_xss job is nil")
	}
	var sj storedXSSJob
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &sj); err != nil {
			return sj, fmt.Errorf("decode stored_xss job payload: %w", err)
		}
	}
	if sj.EndpointID.Empty() {
		sj.EndpointID = job.Target.EndpointID
	}
	if sj.EndpointID.Empty() {
		return sj, errors.New("stored_xss job payload missing endpoint_id")
	}
	return sj, nil
}

func isStoredXSSEligibleMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH:
		return true
	default:
		return false
	}
}

func isLoginLikeEndpoint(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return false
	}
	p := strings.ToLower(strings.Trim(u.Path, "/"))
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "login", "log-in", "signin", "sign-in", "authenticate":
			return true
		}
		if strings.Contains(seg, "login") || strings.Contains(seg, "signin") {
			return true
		}
	}
	return false
}

func isDeleteLikeEndpoint(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	if ep.Method == domain.MethodDELETE {
		return true
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return false
	}
	p := strings.ToLower(strings.Trim(u.Path, "/"))
	for _, seg := range strings.Split(p, "/") {
		if strings.Contains(seg, "delete") || strings.Contains(seg, "remove") ||
			strings.Contains(seg, "destroy") || strings.Contains(seg, "purge") {
			return true
		}
	}
	return false
}

func isStoredXSSExcludedEndpoint(ep *domain.Endpoint) bool {
	return isLoginLikeEndpoint(ep) || isLogoutLikeEndpoint(ep) || isDeleteLikeEndpoint(ep) || isDownloadLikeEndpoint(ep)
}

func isStoredXSSNonTextParam(p *domain.Parameter) bool {
	if isDynamicTokenName(p.Name) || isCSRFTokenParamName(p.Name) {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(p.Name))
	for _, blocked := range []string{"password", "passwd", "pwd", "pass", "pin", "otp", "totp", "mfa", "captcha"} {
		if lower == blocked || strings.Contains(lower, blocked) {
			return true
		}
	}
	if p.Location == domain.LocationJSON {
		ex := strings.TrimSpace(p.Example)
		if ex == "true" || ex == "false" || ex == "null" {
			return true
		}
		if ex != "" && !strings.HasPrefix(ex, "\"") && !strings.HasPrefix(ex, "{") && !strings.HasPrefix(ex, "[") {
			return true
		}
	}
	return false
}

var storedXSSPreferredParamNames = map[string]bool{
	"comment":     true,
	"message":     true,
	"body":        true,
	"content":     true,
	"text":        true,
	"title":       true,
	"name":        true,
	"description": true,
	"bio":         true,
	"note":        true,
	"feedback":    true,
	"review":      true,
	"post":        true,
	"subject":     true,
	"summary":     true,
}

// selectStoredXSSParameter returns the first eligible text-like LocationForm
// or LocationJSON parameter for an endpoint, preferring common text fields.
func selectStoredXSSParameter(params []*domain.Parameter) *domain.Parameter {
	sorted := append([]*domain.Parameter(nil), params...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Location != sorted[j].Location {
			return sorted[i].Location < sorted[j].Location
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})

	var fallback *domain.Parameter
	for _, p := range sorted {
		if p == nil {
			continue
		}
		if p.Location != domain.LocationForm && p.Location != domain.LocationJSON {
			continue
		}
		if isStoredXSSNonTextParam(p) {
			continue
		}
		if storedXSSPreferredParamNames[strings.ToLower(strings.TrimSpace(p.Name))] {
			return p
		}
		if fallback == nil {
			fallback = p
		}
	}
	return fallback
}

// enqueueStoredXSSProbes enqueues one JobStoredXSS per eligible state-changing
// endpoint (POST/PUT/PATCH with LocationForm or LocationJSON, skipping
// login/logout/delete/download endpoints), capped at maxStoredXSSEndpoints.
//
// When the server runs an OAST collaborator (`indago serve -oast-addr`, see
// oast_wiring.go) its callback/poll pair travels with each job, which is what
// arms the engine's blind arm. No per-scan stored-XSS callback exists, so the
// built-in collaborator is used as-is; with no collaborator (the default) the
// pair is empty and every probe keeps its previous in-band-only behavior.
func (c *Controller) enqueueStoredXSSProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("stored_xss probes: load scan", "scan", scanID, "err", err)
		return
	}
	if !sc.Config.EnableStoredXSS {
		return
	}
	callbackURL, pollURL := c.storedXSSOASTPair()
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("stored_xss probes: list endpoints", "scan", scanID, "err", err)
		return
	}

	seen := make(map[string]bool, len(endpoints))
	now := time.Now()
	enqueued := 0
	for _, ep := range endpoints {
		if ep == nil || !isStoredXSSEligibleMethod(ep.Method) || isStoredXSSExcludedEndpoint(ep) {
			continue
		}
		dedup := string(ep.Method) + " " + ep.URL
		if seen[dedup] {
			continue
		}
		params, err := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if err != nil {
			c.log.Warn("stored_xss probes: list parameters", "scan", scanID, "endpoint", ep.ID, "err", err)
			continue
		}
		if selectStoredXSSParameter(params) == nil {
			continue
		}
		seen[dedup] = true

		payload, err := json.Marshal(storedXSSJob{EndpointID: ep.ID, CallbackURL: callbackURL, PollURL: pollURL})
		if err != nil {
			c.log.Warn("stored_xss probes: marshal job", "scan", scanID, "err", err)
			continue
		}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobStoredXSS,
			State:       domain.JobQueued,
			Priority:    50,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload:     payload,
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("stored_xss probes: enqueue job", "scan", scanID, "err", err)
			continue
		}
		enqueued++
		if enqueued >= maxStoredXSSEndpoints {
			break
		}
	}
	if enqueued > 0 {
		c.log.Info("stored_xss probes: enqueued", "scan", scanID, "jobs", enqueued, "blind_oast", callbackURL != "" && pollURL != "")
	}
}

// storedXSSOASTPair returns the built-in collaborator's callback/poll pair for
// stored-XSS probes, or empty strings when the server started none. The pair is
// only ever the server's own listener: there is no per-scan callback field for
// this engine, and fabricating a fallback URL would point a rendering client at
// something the operator never configured.
func (c *Controller) storedXSSOASTPair() (string, string) {
	w := c.oastCollaborator()
	if w == nil {
		return "", ""
	}
	return w.callbackPair("", "")
}

type storedXSSExecutor struct {
	store      store.Store
	http       httpengine.Engine
	browser    *browser.Manager
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex

	// pollAttempts/pollInterval bound how long one job waits for a blind OAST
	// callback. Fields rather than constants so a test can shorten the wait
	// without changing behavior.
	pollAttempts int
	pollInterval time.Duration
}

// newStoredXSSExecutor creates the worker.Handler for JobStoredXSS.
func newStoredXSSExecutor(st store.Store, eng httpengine.Engine, bm *browser.Manager, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) worker.Handler {
	if log == nil {
		log = slog.Default()
	}
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &storedXSSExecutor{
		store:        st,
		http:         eng,
		browser:      bm,
		evidence:     ev,
		cfg:          cfg,
		log:          log,
		findingsMu:   findingsMu,
		pollAttempts: storedXSSOASTPollAttempts,
		pollInterval: storedXSSOASTPollInterval,
	}
}

// ---------------------------------------------------------------------------
// blind OAST callback
// ---------------------------------------------------------------------------

// storedXSSOASTConfig is the validated collaborator pair one probe may use.
// BeaconURL is empty whenever the pair is absent or refused, and Note then
// explains why (recorded on the test case, never substituted).
type storedXSSOASTConfig struct {
	// BeaconURL is the exact absolute URL the marker asks a renderer to
	// request. It carries the probe's token as its path and nothing else.
	BeaconURL string
	// PollURL is the collaborator's read API the scanner polls for that URL.
	PollURL string
	// Note explains why the beacon is not armed.
	Note string
}

func (c storedXSSOASTConfig) armed() bool { return c.BeaconURL != "" && c.PollURL != "" }

// storedXSSOASTFor validates the collaborator pair a job carries and derives
// the beacon URL for token. It never substitutes a refused URL: a misconfigured
// collaborator leaves the probe on its in-band path with the reason recorded.
//
// The beacon is fetched by a BROWSER, so loopback and private hosts are allowed
// (the verifying Chromium may well run on this host, and a lab collaborator
// lives on the operator's LAN) — but the rules that keep a rendering client
// away from cloud metadata and link-local space are the ones already applied to
// a collaborator poll URL, so they are reused rather than restated
// (ssrfForbiddenPollHost: metadata host names, unspecified, link-local,
// multicast).
func storedXSSOASTFor(callbackRaw, pollRaw, token string) storedXSSOASTConfig {
	callbackRaw, pollRaw = strings.TrimSpace(callbackRaw), strings.TrimSpace(pollRaw)
	if callbackRaw == "" && pollRaw == "" {
		return storedXSSOASTConfig{}
	}
	if callbackRaw == "" || pollRaw == "" {
		return storedXSSOASTConfig{Note: "the OAST callback pair is incomplete (a callback URL and a poll URL are both required)"}
	}
	u, err := url.Parse(callbackRaw)
	if err != nil {
		return storedXSSOASTConfig{Note: "the OAST callback URL is not parsable: " + truncate(err.Error(), 160)}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return storedXSSOASTConfig{Note: "the OAST callback URL is not absolute http(s)"}
	}
	host := u.Hostname()
	if host == "" {
		return storedXSSOASTConfig{Note: "the OAST callback URL has no host"}
	}
	if reason, refused := ssrfForbiddenPollHost(host); refused {
		return storedXSSOASTConfig{Note: "the OAST callback host is " + reason + "; refusing to make a rendering client request it"}
	}
	if strings.TrimSpace(token) == "" {
		return storedXSSOASTConfig{Note: "the probe has no correlation token for the blind arm"}
	}
	u.User = nil // never leak operator credentials into a value a renderer sees
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	u.Path = strings.TrimRight(u.Path, "/") + "/" + token
	beacon := u.String()
	// The beacon is embedded in an HTML attribute holding JavaScript: a quote,
	// bracket, backslash or whitespace would break out of it, so such a URL is
	// refused rather than escaped (a collaborator never needs one).
	if bad := storedXSSUnsafeBeaconChar(beacon); bad != "" {
		return storedXSSOASTConfig{Note: fmt.Sprintf("the OAST callback URL contains %q, which cannot be embedded safely in the marker", bad)}
	}
	poll, err := ssrfPollURL(pollRaw)
	if err != nil {
		return storedXSSOASTConfig{Note: "the OAST poll URL is unusable: " + truncate(err.Error(), 160)}
	}
	return storedXSSOASTConfig{BeaconURL: beacon, PollURL: poll}
}

// storedXSSUnsafeBeaconChar returns the first byte that cannot appear inside
// the marker's single-quoted JavaScript string, or "".
func storedXSSUnsafeBeaconChar(s string) string {
	for _, r := range s {
		switch {
		case r < 0x21, r == 0x7f:
			return string(r)
		case r == '"', r == '\'', r == '<', r == '>', r == '\\', r == '`':
			return string(r)
		}
	}
	return ""
}

// storedXSSMarkerPayload returns the ONE benign marker this engine submits.
// It is a bare token used as a JavaScript expression, plus — only when a
// collaborator is armed — a request for the beacon URL. Deterministic, no
// alert/cookie/storage access, and byte-identical to the pre-OAST marker when
// beaconURL is empty.
func storedXSSMarkerPayload(token, beaconURL string) string {
	marker := "window.__indago_sxss=window.__indago_sxss||{};window.__indago_sxss['" + token + "']=1"
	if beaconURL == "" {
		return `<img src=x onerror="` + marker + `">`
	}
	return `<img src=x onerror="` + marker + `;(new Image()).src='` + beaconURL + `'">`
}

// awaitStoredXSSCallback polls the collaborator, bounded by pollAttempts, for a
// request carrying token. It returns the matching poll line (bounded) and
// whether one arrived. Only the collaborator is read: this sends nothing.
func (e *storedXSSExecutor) awaitStoredXSSCallback(ctx context.Context, cfg storedXSSOASTConfig, token string) (string, bool) {
	if !cfg.armed() || strings.TrimSpace(token) == "" {
		return "", false
	}
	attempts := e.pollAttempts
	if attempts <= 0 {
		attempts = storedXSSOASTPollAttempts
	}
	interval := e.pollInterval
	if interval <= 0 {
		interval = storedXSSOASTPollInterval
	}
	client := &http.Client{Timeout: storedXSSOASTPollTimeout}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return "", false
			case <-time.After(interval):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.PollURL, nil)
		if err != nil {
			return "", false
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, storedXSSOASTPollBodyMax))
		_ = resp.Body.Close()
		if line, ok := storedXSSPollLineContaining(string(body), token); ok {
			return line, true
		}
	}
	return "", false
}

// storedXSSPollLineContaining finds the poll line naming token. The
// collaborator's read API lists one interaction per line (see internal/oast's
// poll.go), so the line itself is the evidence: method, host, path, remote
// address and source, with no poll secret in it.
func storedXSSPollLineContaining(body, token string) (string, bool) {
	needle := strings.ToLower(strings.TrimSpace(token))
	if needle == "" {
		return "", false
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(strings.ToLower(line), needle) {
			return truncate(strings.TrimSpace(line), storedXSSOASTHitMax), true
		}
	}
	return "", false
}

func (e *storedXSSExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	sj, err := parseStoredXSSJob(job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	ep, err := e.store.Endpoints().Get(ctx, sj.EndpointID)
	if err != nil {
		return fmt.Errorf("%w: resolve endpoint: %w", worker.ErrPermanent, err)
	}
	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return fmt.Errorf("%w: load scan: %w", worker.ErrPermanent, err)
	}
	if !sc.Config.EnableStoredXSS {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: EnableStoredXSS is off")
		return nil
	}
	if !e.cfg.AllowStateChanging {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: AllowStateChanging is off (state-changing probes disabled)")
		return nil
	}
	if e.cfg.SkipWriteEndpoints || sc.Config.SkipWriteEndpoints {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: state-changing probes disabled by skip_write_endpoints")
		return nil
	}

	token := "sxss_" + strings.ReplaceAll(domain.NewID().String(), "-", "")
	// The blind arm is armed only by a validated collaborator pair; a refused
	// or absent one leaves oastCfg.BeaconURL empty and the probe identical to
	// its pre-OAST shape.
	oastCfg := storedXSSOASTFor(sj.CallbackURL, sj.PollURL, token)
	if oastCfg.Note != "" {
		e.log.Warn("stored_xss: blind OAST callback not armed", "scan", job.ScanID, "reason", oastCfg.Note)
	}

	if e.browser == nil && !oastCfg.armed() {
		e.skipTestCase(ctx, job, ep, storedXSSNoBrowserNote(oastCfg))
		return nil
	}
	if e.http == nil {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: no HTTP engine configured")
		return nil
	}
	if !isStoredXSSEligibleMethod(ep.Method) || isStoredXSSExcludedEndpoint(ep) {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: endpoint is not eligible")
		return nil
	}

	params, err := e.store.Parameters().ListByEndpoint(ctx, ep.ID)
	if err != nil {
		return fmt.Errorf("stored_xss: list parameters: %w", err)
	}
	focus := selectStoredXSSParameter(params)
	if focus == nil {
		e.skipTestCase(ctx, job, ep, "stored_xss skipped: no eligible form/json text parameter")
		return nil
	}

	var allow func(string) bool
	var allowAuthority func(string) bool
	if scope, err := e.store.Scopes().GetByProject(ctx, sc.ProjectID); err == nil && scope != nil {
		if len(scope.IncludeHosts) > 0 || len(scope.SubdomainOnlyHosts) > 0 {
			allow = func(u string) bool { return scope.Permits(u).Allowed }
			allowAuthority = scope.PermitsHost
			if !allow(ep.URL) {
				return fmt.Errorf("%w: endpoint is out of scope", worker.ErrPermanent)
			}
		}
	}

	markerPayload := storedXSSMarkerPayload(token, oastCfg.BeaconURL)
	evalExpr := fmt.Sprintf(`Boolean(window.__indago_sxss && window.__indago_sxss['%s'])`, token)

	// Exactly ONE state-changing request per job, whatever the arms: the same
	// submission carries the in-band marker and, when armed, the blind beacon.
	req, err := buildRequest(ep, params, &injection{param: focus, value: markerPayload})
	if err != nil {
		return fmt.Errorf("%w: build submit request: %w", worker.ErrPermanent, err)
	}

	tc := e.newTestCase(ctx, job, ep.Method, ep.URL)
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.http.Do(ctx, &timed)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return err
	}

	// No local renderer: a blind callback is the only observation channel this
	// probe has, so it runs instead of the browser pass (never in addition to
	// it, and still after the single submission above).
	if e.browser == nil {
		line, hit := e.awaitStoredXSSCallback(ctx, oastCfg, token)
		if !hit {
			e.finishTestCase(ctx, tc, nil, fmt.Sprintf("stored_xss: marker %s did not reach the OAST collaborator within %d poll(s)", token, e.storedXSSPollAttempts()))
			return nil
		}
		e.recordOASTEvidence(ctx, tc, job.ScanID, req, resp, focus.Name, oastCfg, token, line)
		e.finishTestCase(ctx, tc, nil, fmt.Sprintf("stored_xss confirmed blind: token=%s was requested from the OAST collaborator", token))
		e.correlateFinding(ctx, sc, job, ep, tc, focus.Name, storedXSSTrigger{
			ConfirmMethod: storedXSSConfirmOAST,
			Token:         token,
			Blind:         true,
		})
		return nil
	}

	endpoints, err := e.store.Endpoints().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return fmt.Errorf("stored_xss: list endpoints: %w", err)
	}
	verifyPages := selectStoredXSSVerifyPages(ep, sc, endpoints, allow, maxStoredXSSVerifyPages)
	if len(verifyPages) == 0 {
		// The blind arm does not need a local page to visit: the renderer it
		// waits for is whatever consumes the stored value.
		if oastCfg.armed() {
			if line, hit := e.awaitStoredXSSCallback(ctx, oastCfg, token); hit {
				e.recordOASTEvidence(ctx, tc, job.ScanID, req, resp, focus.Name, oastCfg, token, line)
				e.finishTestCase(ctx, tc, nil, fmt.Sprintf("stored_xss confirmed blind: token=%s was requested from the OAST collaborator", token))
				e.correlateFinding(ctx, sc, job, ep, tc, focus.Name, storedXSSTrigger{
					ConfirmMethod: storedXSSConfirmOAST,
					Token:         token,
					Blind:         true,
				})
				return nil
			}
			e.finishTestCase(ctx, tc, nil, "stored_xss: no eligible GET HTML pages to verify and no OAST callback arrived")
			return nil
		}
		e.finishTestCase(ctx, tc, nil, storedXSSNoPagesNote(oastCfg))
		return nil
	}

	bctx, err := e.browser.NewContext(ctx, browser.ContextOptions{
		AllowRequest:      allow,
		AllowAuthority:    allowAuthority,
		StorageStatePath:  e.sessionStatePathFor(ctx, job.ScanID),
		IgnoreHTTPSErrors: sc.Config.AllowInsecureTLS,
	})
	if err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return fmt.Errorf("stored_xss: create browser context: %w", err)
	}
	defer bctx.Close()

	visited := 0
	for _, pageURL := range verifyPages {
		if ctx.Err() != nil {
			e.finishTestCase(ctx, tc, ctx.Err(), "")
			return ctx.Err()
		}
		visited++
		executed, evalErr := e.visitAndEval(ctx, bctx, pageURL, evalExpr)
		if evalErr != nil {
			if isBrowserScopeBlocked(evalErr) {
				continue
			}
			e.log.Debug("stored_xss: visit page failed", "scan", job.ScanID, "url", pageURL, "err", evalErr)
			continue
		}
		if !executed {
			continue
		}

		e.recordEvidence(ctx, tc, job.ScanID, req, resp, focus.Name, pageURL, token, evalExpr)
		e.finishTestCase(ctx, tc, nil, fmt.Sprintf("stored_xss confirmed: token=%s executed on %s", token, pageURL))
		e.correlateFinding(ctx, sc, job, ep, tc, focus.Name, storedXSSTrigger{
			ConfirmMethod: storedXSSConfirmBrowser,
			SinkPageURL:   pageURL,
			Token:         token,
		})
		return nil
	}

	// The in-band pass saw nothing. A renderer this scan cannot visit may still
	// have executed the stored value, so read the collaborator once (bounded)
	// before recording a negative.
	note := fmt.Sprintf("stored_xss: marker %s did not execute on %d visited page(s)", token, visited)
	if oastCfg.armed() {
		if line, hit := e.awaitStoredXSSCallback(ctx, oastCfg, token); hit {
			e.recordOASTEvidence(ctx, tc, job.ScanID, req, resp, focus.Name, oastCfg, token, line)
			e.finishTestCase(ctx, tc, nil, fmt.Sprintf("stored_xss confirmed blind: token=%s was requested from the OAST collaborator", token))
			e.correlateFinding(ctx, sc, job, ep, tc, focus.Name, storedXSSTrigger{
				ConfirmMethod: storedXSSConfirmOAST,
				Token:         token,
				Blind:         true,
			})
			return nil
		}
		note += " and no OAST callback carrying it arrived"
	} else if oastCfg.Note != "" {
		note += " (blind callback not armed: " + truncate(oastCfg.Note, 200) + ")"
	}
	e.finishTestCase(ctx, tc, nil, note)
	return nil
}

// storedXSSNoBrowserNote explains a skip when no browser is configured: the
// in-band pass cannot run, and unless a collaborator is armed there is no
// observation channel left at all.
func storedXSSNoBrowserNote(cfg storedXSSOASTConfig) string {
	note := "stored_xss skipped: no browser configured"
	if cfg.Note != "" {
		note += " and the blind OAST callback is not armed: " + cfg.Note
	}
	return note
}

// storedXSSNoPagesNote records the case where the in-band pass has no page to
// visit. The blind arm already had its poll, so the note reports its outcome.
func storedXSSNoPagesNote(cfg storedXSSOASTConfig) string {
	note := "stored_xss: no eligible GET HTML pages to verify"
	if cfg.Note != "" {
		note += " (blind callback not armed: " + truncate(cfg.Note, 200) + ")"
	}
	return note
}

// storedXSSPollAttempts is the poll bound this executor uses, defaulted when a
// test constructed it without the constructor's values.
func (e *storedXSSExecutor) storedXSSPollAttempts() int {
	if e.pollAttempts > 0 {
		return e.pollAttempts
	}
	return storedXSSOASTPollAttempts
}

func (e *storedXSSExecutor) visitAndEval(ctx context.Context, bctx *browser.Context, pageURL, evalExpr string) (bool, error) {
	page, err := bctx.NewPage(ctx)
	if err != nil {
		return false, err
	}
	defer page.Close()

	if _, err := page.Navigate(ctx, pageURL, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		return false, err
	}
	rawRes, err := page.Evaluate(ctx, evalExpr)
	if err != nil {
		return false, err
	}
	if executed, _ := rawRes.(bool); executed {
		return true, nil
	}
	// Give async <img onerror=...> handlers a brief settle window if they have
	// not fired by WaitLoad yet.
	if _, err := settleDOMXSSObservation(ctx, page, storedXSSSettleWait); err != nil {
		return false, err
	}
	rawRes, err = page.Evaluate(ctx, evalExpr)
	if err != nil {
		return false, err
	}
	executed, _ := rawRes.(bool)
	return executed, nil
}

func selectStoredXSSVerifyPages(submitEP *domain.Endpoint, sc *domain.Scan, endpoints []*domain.Endpoint, allow func(string) bool, limit int) []string {
	type scoredURL struct {
		url   string
		tier  int
		order int
	}

	submitURL, _ := url.Parse(submitEP.URL)
	var submitOrigin, submitDir, submitBase string
	if submitURL != nil {
		submitOrigin = strings.ToLower(submitURL.Scheme + "://" + submitURL.Host)
		p := strings.TrimSuffix(submitURL.Path, "/")
		submitBase = strings.ToLower(p)
		if idx := strings.LastIndex(p, "/"); idx > 0 {
			submitDir = strings.ToLower(p[:idx])
		} else {
			submitDir = "/"
		}
	}

	seedSet := make(map[string]bool)
	if sc != nil {
		for _, s := range sc.SeedURLs {
			seedSet[s] = true
		}
	}

	seen := make(map[string]bool)
	var candidates []scoredURL
	add := func(rawURL string, tier int) {
		if rawURL == "" || seen[rawURL] {
			return
		}
		if allow != nil && !allow(rawURL) {
			return
		}
		if isDownloadLikeEndpoint(&domain.Endpoint{URL: rawURL}) || isPrototypePollutionStaticAsset(rawURL) {
			return
		}
		seen[rawURL] = true
		candidates = append(candidates, scoredURL{url: rawURL, tier: tier, order: len(candidates)})
	}

	classifyTier := func(rawURL string) int {
		if rawURL == submitEP.URL {
			return 0
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return 4
		}
		origin := strings.ToLower(u.Scheme + "://" + u.Host)
		if submitOrigin != "" && origin != submitOrigin {
			return 4
		}
		p := strings.ToLower(strings.TrimSuffix(u.Path, "/"))
		if submitBase != "" && (p == submitBase || strings.HasPrefix(p, submitBase) || strings.HasPrefix(submitBase, p)) && p != "" {
			return 1
		}
		if submitDir != "" && submitDir != "/" && strings.HasPrefix(p, submitDir) {
			return 1
		}
		if seedSet[rawURL] || u.Path == "" || u.Path == "/" {
			return 2
		}
		return 3
	}

	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		if ep.Method != domain.MethodGET && ep.Method != "" {
			continue
		}
		if !domXSSContentTypeAllowsDOM(ep.ContentType) {
			continue
		}
		add(ep.URL, classifyTier(ep.URL))
	}
	if sc != nil {
		for _, s := range sc.SeedURLs {
			add(s, 2)
		}
	}
	if submitOrigin != "" {
		add(submitOrigin+"/", 2)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].tier != candidates[j].tier {
			return candidates[i].tier < candidates[j].tier
		}
		return candidates[i].order < candidates[j].order
	})

	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]string, len(candidates))
	for i, c := range candidates {
		out[i] = c.url
	}
	return out
}

func (e *storedXSSExecutor) sessionStatePathFor(ctx context.Context, scanID domain.ID) string {
	sess, err := e.store.Sessions().GetByScan(ctx, scanID)
	if err != nil || sess == nil {
		return ""
	}
	return sess.StatePath
}

type storedXSSSubmitEvidence struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Param       string `json:"param"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
}

type storedXSSVerifyEvidence struct {
	SubmitURL      string `json:"submit_url"`
	SinkPageURL    string `json:"sink_page_url"`
	Param          string `json:"param"`
	Token          string `json:"token"`
	EvalExpression string `json:"eval_expression"`
	JSEvalResult   bool   `json:"js_eval_result"`
}

// storedXSSOASTEvidence is the blind arm's evidence: the beacon this probe
// planted and the collaborator's own record of the callback. It deliberately
// carries no poll URL — that URL is the collaborator's read secret and evidence
// is written to disk and shipped in reports.
type storedXSSOASTEvidence struct {
	SubmitURL   string `json:"submit_url"`
	Param       string `json:"param"`
	BeaconURL   string `json:"beacon_url"`
	Token       string `json:"token"`
	Hit         bool   `json:"hit"`
	CallbackLog string `json:"callback_log,omitempty"`
}

// recordSubmitEvidence stores the one submission a probe made. Every
// confirmation path references it, so a blind confirmation is as reproducible
// as an in-band one.
func (e *storedXSSExecutor) recordSubmitEvidence(ctx context.Context, tc *domain.TestCase, scanID domain.ID, req *httpengine.Request, resp *httpengine.Response, paramName string) {
	if e.evidence == nil || req == nil {
		return
	}
	statusCode := 0
	if resp != nil {
		statusCode = resp.Status
	}
	reqData, err := json.Marshal(storedXSSSubmitEvidence{
		Method:      req.Method,
		URL:         req.URL,
		Param:       paramName,
		ContentType: req.ContentType,
		Body:        string(req.Body),
		StatusCode:  statusCode,
	})
	if err != nil {
		return
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceRequest, ".json", "application/json", reqData, fmt.Sprintf("stored_xss submit param=%s", paramName)); err == nil {
		tc.EvidenceIDs = appendUniqueID(tc.EvidenceIDs, id)
	}
}

func (e *storedXSSExecutor) recordEvidence(ctx context.Context, tc *domain.TestCase, scanID domain.ID, req *httpengine.Request, resp *httpengine.Response, paramName, sinkPageURL, token, evalExpr string) {
	if e.evidence == nil {
		return
	}
	e.recordSubmitEvidence(ctx, tc, scanID, req, resp, paramName)
	if verifyData, err := json.Marshal(storedXSSVerifyEvidence{
		SubmitURL:      req.URL,
		SinkPageURL:    sinkPageURL,
		Param:          paramName,
		Token:          token,
		EvalExpression: evalExpr,
		JSEvalResult:   true,
	}); err == nil {
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceBrowserLog, ".json", "application/json", verifyData, fmt.Sprintf("stored_xss verified sink=%s", sinkPageURL)); err == nil {
			tc.EvidenceIDs = appendUniqueID(tc.EvidenceIDs, id)
		}
	}
}

// recordOASTEvidence stores what the blind arm observed: the submission, the
// beacon it planted, and the collaborator's matching interaction line.
func (e *storedXSSExecutor) recordOASTEvidence(ctx context.Context, tc *domain.TestCase, scanID domain.ID, req *httpengine.Request, resp *httpengine.Response, paramName string, cfg storedXSSOASTConfig, token, callbackLog string) {
	if e.evidence == nil {
		return
	}
	e.recordSubmitEvidence(ctx, tc, scanID, req, resp, paramName)
	data, err := json.Marshal(storedXSSOASTEvidence{
		SubmitURL:   req.URL,
		Param:       paramName,
		BeaconURL:   cfg.BeaconURL,
		Token:       token,
		Hit:         callbackLog != "",
		CallbackLog: callbackLog,
	})
	if err != nil {
		return
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceBrowserLog, ".json", "application/json", data, "stored_xss blind OAST callback"); err == nil {
		tc.EvidenceIDs = appendUniqueID(tc.EvidenceIDs, id)
	}
}

// storedXSSTrigger is how one probe's execution was observed. Both methods are
// deterministic browser-side events naming this probe's own token: never a
// payload heuristic, never an LLM.
type storedXSSTrigger struct {
	// ConfirmMethod is storedXSSConfirmBrowser or storedXSSConfirmOAST.
	ConfirmMethod string
	// SinkPageURL is the page that executed the marker (browser confirmation).
	SinkPageURL string
	Token       string
	// Blind records that the collaborator, not a local page, was the observer.
	Blind bool
}

type storedXSSDetail struct {
	Engine       string `json:"engine"`
	DedupKey     string `json:"dedup_key"`
	SubmitMethod string `json:"submit_method"`
	SubmitURL    string `json:"submit_url"`
	Param        string `json:"param"`
	SinkPageURL  string `json:"sink_page_url,omitempty"`
	Token        string `json:"token"`
	JSEvalResult bool   `json:"js_eval_result"`
	// ConfirmMethod / Blind distinguish the two observation channels: in-band
	// Chromium execution at a known sink page, versus a blind OAST callback
	// from a renderer this scan cannot visit.
	ConfirmMethod string `json:"confirm_method,omitempty"`
	Blind         bool   `json:"blind,omitempty"`
	Occurrences   int    `json:"occurrences"`
}

func storedXSSDedupKey(method domain.HTTPMethod, submitURL, paramName, sinkPageURL string) string {
	return storedXSSEngine + "\x00" + string(method) + "\x00" + submitURL + "\x00" + paramName + "\x00" + sinkPageURL
}

func (e *storedXSSExecutor) correlateFinding(ctx context.Context, sc *domain.Scan, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, paramName string, trig storedXSSTrigger) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	key := storedXSSDedupKey(ep.Method, ep.URL, paramName, trig.SinkPageURL)
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("stored_xss: list findings for correlation", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	for _, f := range existing {
		if f.VulnClass != domain.VulnStoredXSS {
			continue
		}
		var fd storedXSSDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey != key {
			continue
		}
		fd.Occurrences++
		fd.Token = trig.Token
		// A repeat observation never downgrades what the row already proves,
		// but it does record a second channel when one appears later.
		if fd.ConfirmMethod == "" {
			fd.ConfirmMethod = trig.ConfirmMethod
			fd.Blind = trig.Blind
		}
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, tc.EvidenceIDs)
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("stored_xss: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	src := ep.Source
	if !src.IsValid() {
		src = domain.SourceBrowserNetwork
	}
	detail, _ := json.Marshal(storedXSSDetail{
		Engine:        storedXSSEngine,
		DedupKey:      key,
		SubmitMethod:  string(ep.Method),
		SubmitURL:     ep.URL,
		Param:         paramName,
		SinkPageURL:   trig.SinkPageURL,
		Token:         trig.Token,
		JSEvalResult:  trig.ConfirmMethod == storedXSSConfirmBrowser,
		ConfirmMethod: trig.ConfirmMethod,
		Blind:         trig.Blind,
		Occurrences:   1,
	})
	summary := fmt.Sprintf("Submitting a marker payload to %s %s parameter %q executed in Chromium when visiting %s.", ep.Method, ep.URL, paramName, trig.SinkPageURL)
	if trig.Blind {
		summary = fmt.Sprintf("Submitting a marker payload to %s %s parameter %q caused a rendering client to request the operator's OAST collaborator carrying this probe's token: the stored markup executed in a renderer this scan cannot visit directly.", ep.Method, ep.URL, paramName)
	}
	f := &domain.Finding{
		ID:               domain.NewID(),
		ScanID:           job.ScanID,
		ProjectID:        sc.ProjectID,
		VulnClass:        domain.VulnStoredXSS,
		Verdict:          domain.VerdictConfirmed,
		Severity:         domain.SeverityHigh,
		Confidence:       domain.ConfidenceHigh,
		Title:            fmt.Sprintf("Stored XSS via %s %s (%s)", ep.Method, endpointLabel(ep.URL), paramName),
		Summary:          summary,
		EndpointID:       ep.ID,
		InjectionPointID: job.Target.InjectionPointID,
		EvidenceIDs:      appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance: domain.Provenance{
			Engine:          storedXSSEngine,
			DiscoverySource: src,
			DetectedAt:      now,
			VerifiedAt:      &now,
		},
		Detail:    detail,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("stored_xss: create finding", "scan", job.ScanID, "err", err)
	}
}

func (e *storedXSSExecutor) skipTestCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, note string) {
	tc := e.newTestCase(ctx, job, ep.Method, ep.URL)
	tc.Status = domain.TestCaseSkipped
	e.finishTestCase(ctx, tc, nil, note)
}

func (e *storedXSSExecutor) newTestCase(ctx context.Context, job *domain.TestJob, method domain.HTTPMethod, rawURL string) *domain.TestCase {
	now := time.Now()
	tc := &domain.TestCase{
		ID:        domain.NewID(),
		ScanID:    job.ScanID,
		JobID:     job.ID,
		Attempt:   job.Attempts,
		VulnClass: domain.VulnStoredXSS,
		Status:    domain.TestCaseRunning,
		Method:    string(method),
		URL:       rawURL,
		StartedAt: &now,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("stored_xss: persist test case", "job", job.ID, "err", err)
	}
	return tc
}

func (e *storedXSSExecutor) finishTestCase(ctx context.Context, tc *domain.TestCase, probeErr error, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	if note != "" {
		tc.Note = note
	}
	switch {
	case tc.Status == domain.TestCaseSkipped:
	case probeErr == nil:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = domain.OutcomeSuccess
	case ctx.Err() != nil:
		tc.Status = domain.TestCaseCancelled
		tc.Outcome = domain.OutcomeCancelled
	case browser.IsTimeout(probeErr):
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeTimeout
		tc.Error = truncate(probeErr.Error(), 1024)
	default:
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeError
		tc.Error = truncate(probeErr.Error(), 1024)
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := e.store.TestCases().Update(wctx, tc); err != nil {
		e.log.Error("stored_xss: persist test case result", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}
