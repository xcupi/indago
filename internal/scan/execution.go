package scan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
	"github.com/indago/indago/internal/ratelimit"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// execution is the live machinery for one running scan: a worker pool draining
// the queue, a discovery run feeding it, and a monitor that completes the scan.
type execution struct {
	scanID domain.ID
	pool   *worker.Pool
	disc   *discovery.Manager // nil when discovery had already completed

	// limiter is the scan's ONE request-rate limiter. The same instance paces
	// every target-facing path of the scan — raw HTTP (discovery, candidate and
	// reflection tests, redirect hops, via scopedEngine), browser discovery
	// navigations, and browser verification — so SetRate on it (runtime
	// reconfigure) takes effect on all of them at once.
	limiter *ratelimit.Limiter

	cancel   context.CancelFunc
	discDone chan struct{} // closed when the discovery goroutine has exited
	monDone  chan struct{} // closed when the monitor goroutine has exited

	// closeHTTP releases a scan-dedicated proxied HTTP client's idle
	// connections (see scanHTTPEngine). Never nil; a no-op for the common
	// case where the scan shares the controller's own engine.
	closeHTTP func()

	// discFinished is set once discovery completed normally (or was skipped
	// because it had already completed before a restart).
	discFinished atomic.Bool

	// stopped is set as soon as the execution starts being torn down. It stays
	// in Controller.running while the completion write is in flight (see
	// finish), so the controller paths that would act on a LIVE pool — Resume,
	// Reconfigure — must be able to tell that this execution is only finalizing
	// and that resuming/resizing it would revive a pool that no longer exists.
	stopped atomic.Bool

	// evasionPassDone marks that this execution's one-time, bounded automatic
	// filter-bypass escalation (see evasion_escalation.go) has already been
	// evaluated at a quiet queue. It runs BEFORE combinedPassDone: evidence
	// from the canonical candidates is complete by then, and any bypass jobs
	// it enqueues must drain before the unrelated combined fallback runs.
	evasionPassDone atomic.Bool

	// combinedPassDone marks that this execution's one-time, bounded
	// combined (multi-parameter) candidate pass (see combined.go) has
	// already been enqueued — never run twice in the same execution.
	// Checked in evaluate() the first time the ordinary job queue goes
	// quiet, before the scan is allowed to actually complete.
	combinedPassDone atomic.Bool

	// domXSSPassDone marks that this execution's one-time DOM-XSS probe
	// pass (see domxss.go's enqueueDOMXSSProbes) has already been
	// enqueued — the SAME "run once when the queue goes quiet" shape
	// combinedPassDone uses, checked right after it in evaluate().
	domXSSPassDone atomic.Bool

	// idorPassDone marks that this execution's one-time IDOR probe pass (see
	// idor.go's enqueueIDORProbes) has already been enqueued. It runs after
	// the DOM-XSS pass, for scans that explicitly enabled the engine.
	idorPassDone atomic.Bool

	// accessControlPassDone marks that this execution's one-time access-control
	// probe pass (see accesscontrol.go's enqueueAccessControlProbes) has
	// already been enqueued. It runs on the same quiet tick as the other
	// protected passes and never gates on browser work.
	accessControlPassDone atomic.Bool

	// accessDisclosurePassDone marks that this execution's one-time
	// page-disclosure pass (case 19's script-disclosed path) has been
	// enqueued.
	accessDisclosurePassDone atomic.Bool

	// roleFlagPassDone marks the one-time client-controlled-flag differential
	// pass (case 20) for scans that opted into it.
	roleFlagPassDone atomic.Bool

	// roleFieldPassDone marks the one-time role-field write pass (case 21) for
	// scans that opted into it.
	roleFieldPassDone atomic.Bool
	// disclosurePassDone marks the one-time information-disclosure pass
	// (cases 38/39) for this execution.
	disclosurePassDone atomic.Bool
	// commandInjectionPassDone marks the one-time OS command injection pass.
	commandInjectionPassDone atomic.Bool
	// sstiPassDone marks the one-time server-side template injection pass.
	sstiPassDone atomic.Bool
	// sqliPassDone marks the one-time SQL injection pass.
	sqliPassDone atomic.Bool
	// xxePassDone marks the one-time XML external entity pass.
	xxePassDone atomic.Bool
	// ssrfPassDone marks the one-time non-destructive SSRF pass.
	ssrfPassDone atomic.Bool
	// pathTraversalPassDone marks the one-time read-only path traversal /
	// local file inclusion pass.
	pathTraversalPassDone atomic.Bool
	// corsPassDone marks the one-time read-only CORS misconfiguration pass.
	corsPassDone atomic.Bool
	// securityHeadersPassDone marks the one-time read-only HTTP response
	// security-headers / cookie-policy pass (one GET per origin).
	securityHeadersPassDone atomic.Bool
	// hostHeaderPassDone marks the one-time read-only host-header inspection
	// pass (one bounded GET baseline plus control requests per origin).
	hostHeaderPassDone atomic.Bool
	// openRedirectPassDone marks the one-time server-side open redirect pass.
	openRedirectPassDone atomic.Bool
	// graphQLPassDone marks the one-time safe GraphQL exposure pass.
	graphQLPassDone atomic.Bool
}

// pause routes a scan pause to both the worker pool and discovery.
func (e *execution) pause() {
	e.pool.Pause()
	if e.disc != nil {
		e.disc.Pause()
	}
}

// resume routes a scan resume to both the worker pool and discovery.
func (e *execution) resume() {
	e.pool.Resume()
	if e.disc != nil {
		e.disc.Resume()
	}
}

// launch builds and starts an execution for a RUNNING scan: the worker pool and
// (unless it already completed) discovery, plus the monitor. The caller holds
// c.mu and records the returned execution in c.running.
func (c *Controller) launch(ctx context.Context, sc *domain.Scan, scope domain.Scope, target *domain.Target) (*execution, error) {
	runCtx, cancel := context.WithCancel(c.baseCtx)

	// ONE scope-enforcing engine per scan, shared by discovery and the executor:
	// every request either of them makes is scope-checked, redirect hops included.
	// If the scan's session saved a browser storage state (the same one browser
	// verification uses), its cookies are carried here too — otherwise a
	// cookie-gated endpoint would never reflect for the HTTP-level executor, and
	// nothing downstream would ever reach verification.
	//
	// httpEng is the controller's shared engine UNLESS this scan configured its
	// own ProxyPool, in which case it's a fresh client dedicated to this scan
	// (see scanHTTPEngine) — closeHTTP releases it once the scan stops.
	httpEng, closeHTTP, err := c.scanHTTPEngine(sc)
	if err != nil {
		// Fail closed BEFORE anything is sent: the scan asked for a proxy, a TLS
		// override and/or a hunting User-Agent and the client that carries it
		// could not be built. Falling back to the shared engine here would send
		// target traffic without them — unproxied, unspoofed or unidentified —
		// so the launch is aborted and the caller records the failure/pause.
		cancel()
		closeHTTP()
		return nil, err
	}
	limiter := newScanLimiter(sc.Config.RequestsPerSecond)
	eng := newScopedEngine(httpEng, scope).WithRateLimiter(limiter)
	cookies := c.sessionCookiesFor(ctx, sc)
	if len(cookies) > 0 {
		eng = eng.WithSessionCookies(cookies)
	}
	if headers := c.sessionAuthHeadersFor(ctx, sc); len(headers) > 0 {
		eng = eng.WithSessionAuthHeaders(headers)
	}
	if c.opts.Preflight {
		if err := c.preflightTarget(runCtx, eng, target, seedsFor(sc, target)); err != nil {
			cancel()
			closeHTTP()
			return nil, err
		}
	}

	handlers := c.opts.Handlers
	if handlers == nil {
		handlers = c.defaultHandlers(sc, eng, scope, sc.Config.ProxyPool, limiter, sc.Config.IDORCandidates,
			idor.EnumerationOptions{Enabled: sc.Config.EnableIDOREnumeration, Neighbours: sc.Config.IDOREnumerationNeighbours})
	}
	pool := worker.New(c.queue, handlers, c.poolConfig(sc), c.log)
	if err := pool.Start(runCtx); err != nil {
		cancel()
		closeHTTP()
		return nil, err
	}

	ex := &execution{
		scanID:    sc.ID,
		pool:      pool,
		limiter:   limiter,
		cancel:    cancel,
		discDone:  make(chan struct{}),
		monDone:   make(chan struct{}),
		closeHTTP: closeHTTP,
	}

	if sc.Discovery == domain.DiscoveryComplete {
		// Already discovered before a restart: don't crawl again.
		ex.discFinished.Store(true)
		close(ex.discDone)
	} else {
		cfg := c.discoveryConfig(sc)
		// The scan's own session cookies (if any) — see
		// discovery.Config.SessionCookies — so discovery can register Cookie
		// injection points for cookies actually present in the scan's
		// session context, excluding whatever looks like the auth cookie.
		cfg.SessionCookies = cookies
		cfg.Limiter = limiter
		reg := discovery.NewRealRegistry(eng, c.discoveryBrowser(sc), cfg)
		ex.disc = discovery.NewManager(c.store, c.queue, reg, cfg, c.log)
		seeds := seedsFor(sc, target)
		go c.runDiscovery(runCtx, ex, sc, scope, seeds)
	}

	go c.monitor(runCtx, ex)
	return ex, nil
}

// newScanLimiter builds the scan's ONE request-rate limiter. It deliberately
// uses the evenly spaced limiter rather than the ±jitter variant:
// requests_per_second is a MINIMUM spacing floor (defensive load protection for
// the target), and a randomized early permit would let two consecutive requests
// land closer together than 1/rps — as much as 35% early at the jitter fraction
// this wiring previously passed. Every target-facing path of the scan shares the
// returned instance, so a runtime SetRate reconfigures them all at once.
func newScanLimiter(rps float64) *ratelimit.Limiter {
	return ratelimit.New(rps)
}

// ErrScanHTTPClient is returned when a scan asked for a scoped HTTP client — a
// proxy pool, a randomized-TLS override, or a hunting User-Agent — and that
// client could not be built. The scan must not start or resume: the shared
// engine would send target traffic without the operator's proxy, fingerprint or
// identifier. Start records the scan as failed and Resume returns it to paused,
// so no worker pool is left running and nothing is queued.
var ErrScanHTTPClient = errors.New("scan: refusing to send target traffic without the scan's required HTTP client")

// newHTTPEngine builds a scan-scoped client. It is a variable so tests can
// exercise an internal construction failure that is NOT a config-validation
// failure; the fail-closed path must hold for both.
var newHTTPEngine = httpengine.New

// scanHTTPEngine returns the HTTP engine this scan's discovery and raw
// candidate/reflection testing should use, plus a closer to release any
// dedicated resources it holds. Every scan shares the controller's single
// c.opts.HTTP client by default — closing it would affect every other
// running scan, so the returned closer is a no-op in that case. A scan that
// configures its own domain.ScanConfig.ProxyPool instead gets a fresh,
// scan-scoped *httpengine.Client built from the controller's base
// HTTPConfig with that pool substituted in. Browser verification already
// picks up ProxyPool on its own (verifyExecutor.nextProxy, wired in
// defaultHandlers) — this is the raw-HTTP-side half of the same "every
// outbound request this scan makes" contract (domain.ScanConfig.ProxyPool).
//
// FAIL CLOSED: when the scan asked for a proxy, a randomized TLS fingerprint
// and/or a hunting User-Agent, the only honest engine is the one carrying it.
// If that client cannot be built, this returns ErrScanHTTPClient instead of the
// shared engine — a fallback would silently send unproxied (or unidentified)
// target traffic, which is exactly what the operator configured the scan to
// avoid. A hunting User-Agent that cannot be applied is reported the same way
// rather than dropped: the identifier is often a program requirement.
func (c *Controller) scanHTTPEngine(sc *domain.Scan) (httpengine.Engine, func(), error) {
	wantsProxy := len(sc.Config.ProxyPool) > 0
	wantsTLS := sc.Config.RandomizeTLSFingerprint
	wantsUA := sc.Config.HuntingUserAgent != ""
	if !wantsProxy && !wantsTLS && !wantsUA {
		return c.opts.HTTP, func() {}, nil
	}
	cfg := c.opts.HTTPConfig
	cfg.ProxyPool = sc.Config.ProxyPool
	cfg.RandomizeTLSFingerprint = sc.Config.RandomizeTLSFingerprint
	if wantsUA {
		if sc.Config.HuntingUserAgentReplace {
			cfg.UserAgent = sc.Config.HuntingUserAgent
		} else {
			cfg.UserAgent = strings.TrimSpace(httpengine.DefaultUserAgent + " " + sc.Config.HuntingUserAgent)
		}
	}
	eng, err := newHTTPEngine(cfg)
	if err != nil {
		reason := "its hunting User-Agent could not be applied"
		if wantsProxy || wantsTLS {
			reason = "its proxy/TLS-override HTTP client could not be built"
		}
		// httpengine.New quotes the offending entry verbatim; this error is
		// persisted on the scan (status/UI), so strip any proxy credentials
		// before it travels.
		msg := redactProxyCredentials(err.Error(), sc.Config.ProxyPool)
		c.log.Error("scan HTTP client unavailable; refusing to run without it",
			"scan", sc.ID, "reason", reason, "err", msg)
		return nil, func() {}, fmt.Errorf("%w: %s: %s", ErrScanHTTPClient, reason, msg)
	}
	return eng, eng.Close, nil
}

// redactProxyCredentials removes the userinfo of every proxy URL in pool from
// msg, so a credential embedded in an operator proxy URL cannot end up in a
// persisted scan error or a log line.
func redactProxyCredentials(msg string, pool []string) string {
	for _, p := range pool {
		userinfo := proxyUserinfo(p)
		if userinfo == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, userinfo+"@", "***@")
	}
	return msg
}

// proxyUserinfo returns the raw userinfo of a proxy URL, or "" when it has none.
// It falls back to the literal "scheme://userinfo@host" shape for a URL that
// net/url rejects — exactly the malformed entries whose error message quotes
// them back.
func proxyUserinfo(proxy string) string {
	if u, err := url.Parse(proxy); err == nil {
		if u.User == nil {
			return ""
		}
		return u.User.String()
	}
	i := strings.Index(proxy, "://")
	if i < 0 {
		return ""
	}
	rest := proxy[i+3:]
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return ""
	}
	return rest[:at]
}

// discoveryConfig derives the per-scan discovery config from the controller
// defaults and the scan's own concurrency and crawl-extent controls. The crawl
// controls are read here (at discovery start); a value of 0 means "keep the
// server/profile default", except QuickScan which forces seeds-only.
// huntingUserAgent returns the User-Agent every request and browser context
// of this scan should use. Empty means "leave the engine/browser default".
func (c *Controller) huntingUserAgent(sc *domain.Scan) string {
	ua := strings.TrimSpace(sc.Config.HuntingUserAgent)
	if ua == "" {
		return ""
	}
	if sc.Config.HuntingUserAgentReplace {
		return ua
	}
	return strings.TrimSpace(httpengine.DefaultUserAgent + " " + ua)
}

func (c *Controller) discoveryConfig(sc *domain.Scan) discovery.Config {
	cfg := discovery.DefaultConfig()
	if c.opts.Discovery != nil {
		cfg = *c.opts.Discovery
	}
	if sc.Config.DiscoveryConcurrency > 0 {
		cfg.Concurrency = sc.Config.DiscoveryConcurrency
	}
	if sc.Config.MaxDepth > 0 {
		cfg.MaxDepth = sc.Config.MaxDepth
	}
	cfg.SkipGlobalInjection = sc.Config.SkipGlobalInjection
	cfg.SkipStaticAssets = sc.Config.SkipStaticAssets
	cfg.SkipReflectedXSS = sc.Config.SkipReflectedXSS
	if sc.Config.MaxPages > 0 {
		cfg.MaxPages = sc.Config.MaxPages
	}
	if sc.Config.MaxEndpoints > 0 {
		cfg.MaxEndpoints = sc.Config.MaxEndpoints
	}
	if sc.Config.QuickScan {
		cfg.MaxDepth = 0 // seeds only: do not follow links
	}
	// Recon level is per scan (set at creation). An unparseable/absent value
	// means off: the safe default.
	if level, err := discovery.ParseReconLevel(sc.Config.ReconLevel); err == nil {
		cfg.ReconLevel = level
	}
	// Raw query-string injection is per scan and off unless explicitly set. An
	// unparseable/absent stored value means off, exactly like recon.
	if mode, err := discovery.ParseRawQueryMode(sc.Config.RawQueryInjection); err == nil {
		cfg.RawQueryInjection = mode
	}
	// A scan that omits the GraphQL engine must not spend a discovery request
	// looking for a GraphQL endpoint nothing would test. The probe is ON for
	// every scan that keeps the engine, at every recon level — see
	// discovery.NewWellKnownSource.
	cfg.SkipGraphQLProbe = sc.Config.SkipGraphQL
	cfg.HuntingUserAgent = c.huntingUserAgent(sc)
	return cfg
}

// seedsFor returns the scan's discovery seeds: the operator-provided seeds, or
// the target base URL when none were given.
func seedsFor(sc *domain.Scan, target *domain.Target) []string {
	if len(sc.SeedURLs) > 0 {
		return append([]string(nil), sc.SeedURLs...)
	}
	return []string{target.BaseURL}
}

// runDiscovery runs discovery for the scan and persists its state transitions.
//
// Cancellation vs shutdown: when ctx is canceled the goroutine returns WITHOUT
// touching the persisted discovery state. Cancel records "canceled" itself; a
// process shutdown must leave it "running" so a restart knows discovery still
// has to run.
func (c *Controller) runDiscovery(ctx context.Context, ex *execution, sc *domain.Scan, scope domain.Scope, seeds []string) {
	defer close(ex.discDone)

	if _, err := c.mutate(ctx, sc.ID, func(s *domain.Scan) error {
		s.Discovery = domain.DiscoveryRunning
		return nil
	}); err != nil {
		if ctx.Err() == nil {
			c.log.Warn("persist discovery start", "scan", sc.ID, "err", err)
		}
		return
	}

	var statePath string
	if sess, err := c.store.Sessions().Get(ctx, sc.SessionID); err == nil {
		statePath = sess.StatePath
	}
	res, err := ex.disc.Run(ctx, discovery.RunParams{
		ScanID:           sc.ID,
		Scope:            scope,
		SeedURLs:         seeds,
		SessionID:        sc.SessionID,
		SessionStatePath: statePath,
		// The operator-supplied OpenAPI/Swagger document (or its URL). Empty
		// for every scan that supplied none, which is the default.
		OpenAPISpecJSON: sc.Config.OpenAPISpecJSON,
		OpenAPISpecURL:  sc.Config.OpenAPISpecURL,
	})
	if err != nil {
		if ctx.Err() != nil {
			return // canceled or shutting down: leave persisted state alone
		}
		c.failScan(sc.ID, "discovery: "+err.Error())
		return
	}
	// Individual sources can fail (e.g. a missing sitemap) without invalidating
	// the run; surface them in the log and carry on.
	for _, e := range res.Errors {
		c.log.Warn("discovery source error", "scan", sc.ID, "err", e)
	}

	stats := c.snapshotStats(ctx, sc.ID)
	if _, err := c.mutate(ctx, sc.ID, func(s *domain.Scan) error {
		s.Discovery = domain.DiscoveryComplete
		// AskedAtConfirmed is bookkeeping, not a live-computed snapshot value
		// (see its doc comment and refreshStats); carry it over rather than
		// resetting it to zero.
		stats.AskedAtConfirmed = s.Stats.AskedAtConfirmed
		s.Stats = stats
		return nil
	}); err != nil {
		if ctx.Err() == nil {
			c.log.Warn("persist discovery completion", "scan", sc.ID, "err", err)
		}
		return
	}
	ex.discFinished.Store(true)
	c.log.Info("discovery complete", "scan", sc.ID,
		"endpoints", res.Endpoints, "parameters", res.Parameters, "jobs", res.Jobs,
		"recon", res.Recon)
}

// stopExecution tears an execution down and waits for its goroutines. The caller
// must NOT hold c.mu. waitMonitor must be false when called from the monitor
// goroutine itself.
func (c *Controller) stopExecution(ex *execution, waitMonitor bool) {
	ex.stopped.Store(true) // no live pool from here on (see execution.stopped)
	ex.cancel()
	ex.pool.Stop()
	<-ex.discDone
	if waitMonitor {
		<-ex.monDone
	}
	ex.closeHTTP()
}

// monitor periodically evaluates a running scan: it refreshes persisted stats,
// applies the stop policy, and completes the scan once discovery has finished
// and no job remains queued, leased, or running.
func (c *Controller) monitor(ctx context.Context, ex *execution) {
	defer close(ex.monDone)
	t := time.NewTicker(c.opts.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.evaluate(ctx, ex) {
				return
			}
		}
	}
}

// evaluate runs one monitor pass and reports whether the monitor should exit
// (the scan finished or is no longer ours).
func (c *Controller) evaluate(ctx context.Context, ex *execution) (done bool) {
	sc, err := c.store.Scans().Get(ctx, ex.scanID)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Warn("monitor: load scan", "scan", ex.scanID, "err", err)
		}
		return false
	}
	if sc.State.IsTerminal() {
		return true
	}

	c.refreshStats(ctx, ex.scanID)

	// Only a RUNNING scan can stop or complete; paused/awaiting_auth scans wait.
	if sc.State != domain.ScanRunning {
		return false
	}

	// Session expiration: the scanner never silently re-authenticates (see
	// domain.Session's doc comment). An expired session pauses the scan into
	// AwaitingAuth so no further target-facing work runs against it; Resume
	// re-establishes the session before work continues.
	if expired, err := c.sessionExpired(ctx, sc); err != nil {
		if ctx.Err() == nil {
			c.log.Warn("monitor: check session expiry", "scan", ex.scanID, "err", err)
		}
	} else if expired {
		c.log.Info("session expired", "scan", ex.scanID)
		if err := c.pauseForExpiredSession(ctx, ex.scanID); err != nil {
			c.log.Warn("pause for expired session", "scan", ex.scanID, "err", err)
		}
		return false
	}

	// Stop policy (confirmed findings). Phase 0 produces none, but the wiring is
	// real so detection can drive it later.
	confirmed := c.countConfirmed(ctx, ex.scanID)
	switch d := EvaluateStop(sc.Stop, confirmed); {
	case d.Stop:
		c.log.Info("stop policy reached", "scan", ex.scanID, "reason", d.Reason)
		return c.finish(ctx, ex, true)
	case d.Pause && confirmed > sc.Stats.AskedAtConfirmed:
		c.log.Info("stop policy: pausing for operator", "scan", ex.scanID, "reason", d.Reason)
		// Persisted, not just kept on the execution object: a restart must not
		// forget this and immediately re-pause for findings the operator
		// already saw before the crash.
		if _, err := c.mutate(ctx, ex.scanID, func(s *domain.Scan) error {
			s.Stats.AskedAtConfirmed = confirmed
			return nil
		}); err != nil {
			c.log.Warn("persist asked-at-confirmed", "scan", ex.scanID, "err", err)
		}
		if err := c.Pause(ctx, ex.scanID); err != nil {
			c.log.Warn("stop policy pause", "scan", ex.scanID, "err", err)
		}
		return false
	}

	// Completion policy: discovery done AND nothing queued/leased/running.
	// Children are enqueued before their parent job completes, so Pending()==0
	// after discovery finished means the scan is quiescent.
	if !ex.discFinished.Load() {
		return false
	}
	q, err := c.queue.Stats(ctx, ex.scanID)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Warn("monitor: queue stats", "scan", ex.scanID, "err", err)
		}
		return false
	}
	if q.Pending() > 0 {
		// Work is outstanding. Normally that just means "wait". But a queue
		// holding jobs of a type this execution can never run — no handler, no
		// worker group that names it — will never drain, no matter how long the
		// monitor waits. Fail the scan with a reason instead of leaving it
		// running forever.
		if stuck, reason := c.noRunnableJob(ctx, ex); stuck {
			c.log.Warn("scan cannot make progress; reaching a terminal state instead of running forever",
				"scan", ex.scanID, "reason", reason)
			return c.failExecution(ctx, ex, reason)
		}
		return false
	}
	// Bounded, one-time automatic filter-bypass escalation (see
	// evasion_escalation.go): at the FIRST quiet tick, after every canonical
	// candidate (and its browser verification) has drained, try the
	// documented benign-marker bypass shapes for those reflected-XSS
	// injection points whose canonical candidates all completed without a
	// confirmed execution signal. It runs BEFORE the combined fallback so
	// that evidence from the ordinary plan is complete, and so any bypass
	// jobs it enqueues drain before the unrelated multi-parameter pass.
	// Like combinedPassDone, the flag makes this exactly once per execution
	// and the return value lets the monitor loop again rather than finish
	// with the new jobs still queued.
	if !ex.evasionPassDone.Load() {
		ex.evasionPassDone.Store(true)
		if !sc.Config.SkipReflectedXSS {
			c.enqueueEvasionEscalationCandidates(ctx, ex.scanID)
			return false
		}
	}
	// Bounded, one-time combined (multi-parameter) candidate fallback pass
	// (see combined.go): the FIRST time the ordinary job queue goes quiet,
	// run it instead of completing — any jobs it enqueues (there may be
	// none) must themselves drain before the scan is allowed to finish, so
	// this returns false (not done) to let the monitor loop again. The
	// flag ensures this runs exactly once per execution, even though this
	// branch is reached on every subsequent quiet tick too.
	if !ex.combinedPassDone.Load() {
		ex.combinedPassDone.Store(true)
		if !sc.Config.SkipReflectedXSS {
			c.enqueueCombinedCandidates(ctx, ex.scanID)
			return false
		}
	}
	// Bounded, one-time probe passes. They are enqueued on the SAME quiet
	// tick and are independent of each other: DOM-XSS probing is
	// browser-group work (slow, and able to stall when no usable browser
	// worker is available), while IDOR probing is raw HTTP on the ordinary
	// HTTP group. Letting the IDOR pass wait for DOM jobs to drain is how a
	// single stuck DOM job starved object-authorization testing entirely
	// (observed with browser_concurrency=0), so neither pass gates the
	// other. The one-time flags keep both to one pass per execution.
	passes := false
	// DOM-XSS: only one source/sink category is implemented (see
	// docs/dom-xss.md) — genuinely cheap (bounded by discovered endpoints,
	// not candidates), so it never gates behind "single-parameter testing
	// failed" the way combined does; it runs for every GET/HEAD-navigable
	// endpoint regardless.
	if !ex.domXSSPassDone.Load() {
		ex.domXSSPassDone.Store(true)
		if !sc.Config.SkipDOMXSS {
			c.enqueueDOMXSSProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// IDOR: only for a scan that opted into the engine (see idor.go).
	if !ex.idorPassDone.Load() {
		ex.idorPassDone.Store(true)
		if !sc.Config.SkipIDOR {
			c.enqueueIDORProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Access control: bounded by robots.txt/sitemap provenance and a fixed
	// admin-path vocabulary (see accesscontrol.go). No opt-in flag: every
	// request is a single in-scope GET of a path discovery already disclosed,
	// and the pass never sends a state-changing method.
	if !ex.accessControlPassDone.Load() {
		ex.accessControlPassDone.Store(true)
		if !sc.Config.SkipAccessControl {
			c.enqueueAccessControlProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Case 19's second source: administrative paths a discovered page's OWN
	// scripts disclose. Same anonymous GET probe, same bounds.
	if !ex.accessDisclosurePassDone.Load() {
		ex.accessDisclosurePassDone.Store(true)
		if !sc.Config.SkipAccessControl {
			c.enqueueAccessControlDisclosureProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Case 20: client-controlled flag differential. Opt-in (it may propose the
	// conventional /admin path when discovery found no privileged endpoint).
	if !ex.roleFlagPassDone.Load() {
		ex.roleFlagPassDone.Store(true)
		if !sc.Config.SkipAccessControl {
			c.enqueueRoleFlagProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Case 21: role-field write on the caller's own profile. Opt-in AND
	// state-changing opt-in; scan creation already refuses any other
	// combination, and the executor re-checks before sending.
	// Cases 38/39: information disclosure. Passive — one GET per candidate
	// endpoint, no mutation, no opt-in (see disclosure.go).
	if !ex.disclosurePassDone.Load() {
		ex.disclosurePassDone.Store(true)
		if !sc.Config.SkipInfoDisclosure {
			c.enqueueDisclosureProbes(ctx, ex.scanID)
			// Case 37 rides the same pass: one wrong-typed GET per numeric query
			// parameter, bounded.
			c.enqueueDisclosureErrorProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.commandInjectionPassDone.Load() {
		ex.commandInjectionPassDone.Store(true)
		if sc.Config.EnableCommandInjection {
			c.enqueueCommandInjectionProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.sstiPassDone.Load() {
		ex.sstiPassDone.Store(true)
		if sc.Config.EnableSSTI {
			c.enqueueSSTIProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.sqliPassDone.Load() {
		ex.sqliPassDone.Store(true)
		if sc.Config.EnableSQLi {
			c.enqueueSQLiProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.xxePassDone.Load() {
		ex.xxePassDone.Store(true)
		if sc.Config.EnableXXE {
			c.enqueueXXEProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.roleFieldPassDone.Load() {
		ex.roleFieldPassDone.Store(true)
		if !sc.Config.SkipAccessControl {
			c.enqueueRoleFieldProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.ssrfPassDone.Load() {
		ex.ssrfPassDone.Store(true)
		if !sc.Config.SkipSSRF {
			c.enqueueSSRFProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.pathTraversalPassDone.Load() {
		ex.pathTraversalPassDone.Store(true)
		if !sc.Config.SkipPathTraversal {
			c.enqueuePathTraversalProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.corsPassDone.Load() {
		ex.corsPassDone.Store(true)
		if !sc.Config.SkipCORS {
			c.enqueueCORSProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Read-only response security headers and cookie policy: ONE GET per
	// origin, no mutation, no opt-in (see securityheaders.go).
	if !ex.securityHeadersPassDone.Load() {
		ex.securityHeadersPassDone.Store(true)
		if !sc.Config.SkipSecurityHeaders {
			c.enqueueSecurityHeadersProbes(ctx, ex.scanID)
			passes = true
		}
	}
	// Read-only host-header inspection: one bounded baseline plus control
	// requests per origin, no mutation, no opt-in (see hostheader.go).
	if !ex.hostHeaderPassDone.Load() {
		ex.hostHeaderPassDone.Store(true)
		if !sc.Config.SkipHostHeader {
			c.enqueueHostHeaderProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.openRedirectPassDone.Load() {
		ex.openRedirectPassDone.Store(true)
		if !sc.Config.SkipOpenRedirect {
			c.enqueueOpenRedirectProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if !ex.graphQLPassDone.Load() {
		ex.graphQLPassDone.Store(true)
		if !sc.Config.SkipGraphQL {
			c.enqueueGraphQLProbes(ctx, ex.scanID)
			passes = true
		}
	}
	if passes {
		return false
	}
	return c.finish(ctx, ex, false)
}

// noRunnableJob reports whether every outstanding job of the scan is one that
// this execution can never run: no registered handler, no worker group that
// names its type. It only answers true when nothing is active — a job a worker
// is currently running is governed by the pool's per-job deadline, and a queued
// job whose type the pool serves will run either now, once its retry backoff
// elapses, or once an operator reconfigures a zero-sized group. None of those
// is a permanent stall.
func (c *Controller) noRunnableJob(ctx context.Context, ex *execution) (bool, string) {
	jobs, err := c.queue.Jobs(ctx, ex.scanID)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Warn("monitor: list jobs", "scan", ex.scanID, "err", err)
		}
		return false, ""
	}
	pending := 0
	for _, j := range jobs {
		if j.State.IsTerminal() {
			continue
		}
		if j.State.IsActive() {
			return false, "" // a worker holds it; the pool deadline bounds it
		}
		pending++
	}
	if pending == 0 {
		return false, ""
	}
	for _, j := range jobs {
		if j.State.IsTerminal() {
			continue
		}
		if ex.pool.Serves(j.Type) {
			return false, ""
		}
	}
	return true, fmt.Sprintf("%d queued job(s) remain but no worker group serves their type", pending)
}

// failExecution records a terminal failure for a scan whose queue can never
// drain. It takes ownership of the execution under mu (so a concurrent
// pause/cancel wins cleanly), tears it down, cancels the jobs that can never
// run, and only then persists the terminal state. Called from the monitor
// goroutine, hence waitMonitor=false.
func (c *Controller) failExecution(ctx context.Context, ex *execution, reason string) bool {
	c.mu.Lock()
	if c.running[ex.scanID] != ex {
		c.mu.Unlock()
		return true // Cancel/Shutdown took ownership
	}
	sc, err := c.store.Scans().Get(ctx, ex.scanID)
	if err != nil || sc.State != domain.ScanRunning {
		c.mu.Unlock()
		return false // paused/awaiting auth (or unreadable): keep the execution
	}
	delete(c.running, ex.scanID)
	c.mu.Unlock()

	c.stopExecution(ex, false) // we ARE the monitor goroutine

	bg := context.Background()
	if _, err := c.queue.CancelScan(bg, ex.scanID); err != nil {
		c.log.Warn("fail scan: cancel remaining jobs", "scan", ex.scanID, "err", err)
	}
	c.failScan(ex.scanID, "scan stalled: "+reason)
	return true
}

// completionOutcome is what finish managed to do with the scan's terminal state.
type completionOutcome int

const (
	// completionPersisted: the row now reads COMPLETED in the store.
	completionPersisted completionOutcome = iota
	// completionSuperseded: another actor (cancel, shutdown, pause) took the
	// scan over while the completion write was in flight. finish wrote nothing
	// and that actor records the terminal state itself.
	completionSuperseded
	// completionFailed: the write could not be persisted within the bounded
	// retries. The scan is NOT reported as completed.
	completionFailed
)

// Completion persistence is bounded and observable. A transient store error (a
// locked database file, a momentarily unwritable disk) must never silently
// strand a finished scan in `running` with no execution left to drive it — and
// completion must never be reported unless the row actually says COMPLETED.
const (
	// completionAttempts is the total number of tries, not the retry count.
	completionAttempts = 4
	// completionRetryBase is the delay before the second attempt; it doubles
	// per attempt. Total added latency stays well under 200ms, which bounds how
	// long a Cancel/Shutdown waiting on this monitor can be held up.
	completionRetryBase = 20 * time.Millisecond
)

// finish completes the scan from the monitor. When cancelJobs is set (stop
// policy) the scan's remaining jobs are canceled too. It returns true when the
// execution was finished (so the monitor exits) and false when the scan is not
// in a completable state and keeps running.
//
// Ordering:
//
//  1. Confirm under mu that the scan is still RUNNING and that this execution
//     still owns it. Pause/Resume/Cancel/Shutdown also take mu, so the state
//     cannot change between that check and the completion write.
//  2. Tear the execution down (discovery can no longer enqueue; interrupted
//     workers finish re-queueing their retries), THEN cancel remaining jobs.
//  3. Only now record COMPLETED — and only if the write actually lands — so a
//     status reader can never observe a completed scan that still has pending
//     jobs, and an unwritable store can never produce a lie.
//
// Ownership is deliberately kept (the execution stays in c.running) across 2
// and 3, and re-verified under mu in the same critical section as each write
// attempt. Releasing it first — as this used to do — created a window where a
// failed write left the scan `running` with nothing driving it, while every
// error (transient storage included) was reported as "a cancel won the race".
func (c *Controller) finish(ctx context.Context, ex *execution, cancelJobs bool) bool {
	c.mu.Lock()
	if c.running[ex.scanID] != ex {
		c.mu.Unlock()
		return true // Cancel/Shutdown took ownership; nothing left to do here
	}
	sc, err := c.store.Scans().Get(ctx, ex.scanID)
	if err != nil || sc.State != domain.ScanRunning {
		c.mu.Unlock()
		return false // paused/awaiting auth (or unreadable): keep the execution
	}
	c.mu.Unlock() // never wait for goroutines while holding mu

	c.stopExecution(ex, false) // we ARE the monitor goroutine

	// The run context is canceled now; finish the bookkeeping with a fresh one.
	bg := context.Background()
	if cancelJobs {
		if _, err := c.queue.CancelScan(bg, ex.scanID); err != nil {
			c.log.Warn("finish: cancel jobs", "scan", ex.scanID, "err", err)
		}
	}
	ended := time.Now()
	stats := c.snapshotStats(bg, ex.scanID)

	outcome, attempts, err := c.persistCompletion(bg, ex, ended, stats)
	switch outcome {
	case completionPersisted:
		c.log.Info("scan completed", "scan", ex.scanID, "stopped_early", cancelJobs, "attempts", attempts)
	case completionSuperseded:
		c.log.Info("finish: completion superseded by a concurrent scan state change",
			"scan", ex.scanID, "attempts", attempts, "err", err)
	case completionFailed:
		// Never claim COMPLETED for a row that does not say so. Record a
		// terminal failure the operator can see instead of leaving the scan
		// looking alive with no execution behind it (best effort: the store
		// may still be failing, and the failure record says so too).
		reason := "completion could not be persisted"
		if err != nil {
			reason += ": " + err.Error()
		}
		c.log.Error("finish: could not persist completion",
			"scan", ex.scanID, "attempts", attempts, "err", err)
		c.recordUnpersistedCompletion(ex.scanID, reason)
	}
	return true
}

// recordUnpersistedCompletion marks a scan failed after its completion could
// not be written. It only touches a scan that is still RUNNING: a concurrent
// Cancel (or a restart's recovery) owns the terminal state from that point on,
// and rewriting a canceled scan as failed would be the same class of lie this
// whole path exists to avoid.
func (c *Controller) recordUnpersistedCompletion(id domain.ID, reason string) {
	ended := time.Now()
	sc, err := c.mutate(context.Background(), id, func(s *domain.Scan) error {
		if s.State != domain.ScanRunning {
			return errSkipWrite // someone else owns the terminal state
		}
		if err := transition(s, domain.ScanFailed); err != nil {
			return err
		}
		s.Error = reason
		s.EndedAt = &ended
		return nil
	})
	if err != nil {
		c.log.Warn("could not record unpersisted completion", "scan", id, "err", err)
		return
	}
	if sc.State != domain.ScanFailed {
		c.log.Info("unpersisted completion: scan state is owned elsewhere",
			"scan", id, "state", sc.State)
		return
	}
	c.log.Error("scan failed", "scan", id, "reason", reason)
}

// persistCompletion writes the COMPLETED state, retrying a bounded number of
// times, and drops this execution's ownership of the scan in the same critical
// section as whichever outcome it reaches. Every attempt re-checks ownership,
// shutdown and the persisted state under mu, so a Cancel/Shutdown that won the
// race is never overwritten with a completion it did not ask for.
func (c *Controller) persistCompletion(ctx context.Context, ex *execution, ended time.Time, stats domain.ScanStats) (completionOutcome, int, error) {
	var lastErr error
	for attempt := 1; attempt <= completionAttempts; attempt++ {
		if attempt > 1 {
			delay := completionRetryBase << (attempt - 2)
			c.log.Warn("finish: retrying completion write", "scan", ex.scanID,
				"attempt", attempt, "attempts", completionAttempts, "delay", delay, "err", lastErr)
			time.Sleep(delay)
		}

		c.mu.Lock()
		if c.running[ex.scanID] != ex {
			// Cancel or Shutdown took the execution over. There is nothing to
			// write: either it records the terminal state, or the shutdown
			// leaves the row `running` on purpose so a restart can recover it.
			c.mu.Unlock()
			return completionSuperseded, attempt,
				fmt.Errorf("%w: execution was taken over", ErrBadState)
		}
		sc, err := c.store.Scans().Get(ctx, ex.scanID)
		if err != nil {
			c.mu.Unlock()
			lastErr = err
			if !isTransientStoreErr(err) {
				c.release(ex)
				return completionFailed, attempt, err
			}
			continue
		}
		if sc.State != domain.ScanRunning {
			// Paused / awaiting auth / already terminal: whoever moved it owns
			// the next step. Drop our now-stale execution so a later Resume
			// rebuilds one instead of resuming a torn-down pool.
			delete(c.running, ex.scanID)
			c.mu.Unlock()
			return completionSuperseded, attempt, fmt.Errorf("%w: %s -> completed", ErrBadState, sc.State)
		}
		_, err = c.mutate(ctx, ex.scanID, func(s *domain.Scan) error {
			if err := transition(s, domain.ScanCompleted); err != nil {
				return err
			}
			s.EndedAt = &ended
			s.Stats = stats
			return nil
		})
		if err == nil {
			// Same critical section as the write: a status reader holding mu
			// can never see a completed scan still listed as running.
			delete(c.running, ex.scanID)
			c.mu.Unlock()
			return completionPersisted, attempt, nil
		}
		c.mu.Unlock()
		lastErr = err
		if errors.Is(err, ErrBadState) {
			c.release(ex)
			return completionSuperseded, attempt, err
		}
		if !isTransientStoreErr(err) {
			c.release(ex)
			return completionFailed, attempt, err
		}
	}
	c.release(ex)
	return completionFailed, completionAttempts, lastErr
}

// release drops this execution's ownership of its scan, but only if the map
// still holds THIS execution: a Cancel/Shutdown that already removed it, or a
// Resume that installed a replacement, must never be undone here.
func (c *Controller) release(ex *execution) {
	c.mu.Lock()
	if c.running[ex.scanID] == ex {
		delete(c.running, ex.scanID)
	}
	c.mu.Unlock()
}

// isTransientStoreErr reports whether a failed scan write is worth retrying:
// anything that is not a definitive answer about the data. A canceled context,
// a missing row, or a rejected state transition will not improve with another
// identical attempt; a locked/unavailable store may.
func isTransientStoreErr(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, store.ErrNotFound),
		errors.Is(err, ErrBadState):
		return false
	default:
		return true
	}
}

// countConfirmed returns the number of confirmed findings for a scan.
func (c *Controller) countConfirmed(ctx context.Context, scanID domain.ID) int {
	findings, err := c.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		return 0
	}
	n := 0
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			n++
		}
	}
	return n
}

// snapshotStats computes the persisted rollup for a scan from the store and
// queue. Errors degrade to zero values; this is best-effort reporting.
func (c *Controller) snapshotStats(ctx context.Context, scanID domain.ID) domain.ScanStats {
	var st domain.ScanStats
	if eps, err := c.store.Endpoints().ListByScan(ctx, scanID); err == nil {
		st.EndpointsDiscovered = len(eps)
	}
	if ps, err := c.store.Parameters().ListByScan(ctx, scanID); err == nil {
		st.ParametersDiscovered = len(ps)
	}
	if q, err := c.queue.Stats(ctx, scanID); err == nil {
		st.JobsQueued = q.Queued
		st.JobsCompleted = q.Succeeded
		st.JobsFailed = q.Failed
		st.JobsCanceled = q.Canceled
		st.JobsTotal = q.Total()
	}
	if fs, err := c.store.Findings().ListByScan(ctx, scanID); err == nil {
		for _, f := range fs {
			switch f.Verdict {
			case domain.VerdictConfirmed:
				st.FindingsConfirmed++
			case domain.VerdictRejected:
				st.FindingsRejected++
			case domain.VerdictInconclusive:
				st.FindingsInconclusive++
			}
		}
	}
	return st
}

// refreshStats persists the stats rollup when it changed. AskedAtConfirmed is
// bookkeeping (see its doc comment), not a live-computed snapshot value, so it
// is carried over rather than reset to zero on every refresh.
func (c *Controller) refreshStats(ctx context.Context, scanID domain.ID) {
	stats := c.snapshotStats(ctx, scanID)
	_, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
		stats.AskedAtConfirmed = s.Stats.AskedAtConfirmed
		if s.Stats == stats {
			return errSkipWrite
		}
		s.Stats = stats
		return nil
	})
	if err != nil && ctx.Err() == nil && !isNotFound(err) {
		c.log.Warn("refresh stats", "scan", scanID, "err", err)
	}
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
