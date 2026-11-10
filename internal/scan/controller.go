// Package scan orchestrates scan lifecycle: it enforces scope, establishes the
// reused authentication session, runs discovery and the worker pool for a scan
// concurrently, and exposes start/pause/resume/cancel, runtime reconfiguration,
// status, and restart recovery.
//
// How a scan runs (see docs/scan-orchestration.md):
//
//   - Start moves a scan to RUNNING and launches an execution: a worker pool
//     (draining the persistent queue) plus a discovery run, in parallel.
//     Discovery persists every in-scope endpoint/parameter and enqueues a test
//     job for it immediately, so testing never waits for discovery.
//   - Pause/Resume/Cancel are routed to BOTH the worker pool and discovery.
//   - A monitor completes the scan once discovery has finished and no job is
//     queued, leased, or running (and applies the stop policy).
//   - After a process restart, interrupted scans are restored as PAUSED; Resume
//     rebuilds their execution. Nothing sends traffic until the operator resumes.
//
// Job handlers are supplied through Options.Handlers; by default they are the
// Phase 0 no-ops (handlers.go), so no XSS detection or payload generation
// happens here. Scope enforcement is real and fails closed, at creation, at
// start, in the discovery collector, and — for every outbound HTTP request and
// redirect hop — in scopedEngine.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/verification"
	"github.com/indago/indago/internal/worker"
)

// Sentinel errors.
var (
	ErrScopeRequired = errors.New("scan: explicit scope required before scanning")
	ErrScopeEmpty    = errors.New("scan: scope is empty (fails closed)")
	ErrOutOfScope    = errors.New("scan: target is out of scope")
	ErrNotRunning    = errors.New("scan: not running")
	ErrBadState      = errors.New("scan: illegal state transition")
	ErrShutdown      = errors.New("scan: controller is shut down")
	ErrInvalidSeed   = errors.New("scan: invalid seed URL")
	// ErrBadConfig reports an out-of-range scan configuration value (e.g. a
	// crawl depth/limit beyond its cap). Operator-fixable input.
	ErrBadConfig = errors.New("scan: invalid configuration")
	// ErrAuth reports an unusable authentication configuration: an
	// unimplemented mode, a state path given for a mode that takes none, or
	// session material AuthExisting cannot use (at creation, or when Start/
	// Resume re-establishes the session and finds it gone or changed). It is
	// operator-fixable input, never an internal failure.
	ErrAuth = errors.New("scan: authentication")
	// ErrWAFPreflight reports that the preflight request was blocked by
	// backpressure, a CAPTCHA/challenge, or a WAF-identified 403/406. The scan
	// is paused before discovery or payload work; retry after the target's
	// cooldown window.
	ErrWAFPreflight = errors.New("scan: WAF preflight")
)

// errSkipWrite lets a mutate callback signal "nothing changed; do not persist".
var errSkipWrite = errors.New("scan: skip write")

// Options configures a Controller. Zero values get sane defaults.
type Options struct {
	// Worker pool timing.
	LeaseDuration time.Duration
	Heartbeat     time.Duration
	IdlePoll      time.Duration

	// PollInterval is how often the completion monitor evaluates a running scan
	// (default 200ms).
	PollInterval time.Duration

	// ReapInterval is how often expired job leases are reclaimed for a worker
	// that stopped heartbeating without the job ever reaching a terminal state
	// (a hung or crashed handler goroutine, for example) — see
	// queue.Queue.ReapExpired. Reaping more often than a lease's own duration
	// cannot find anything new, so the default is LeaseDuration.
	ReapInterval time.Duration

	// HTTP is the engine discovery uses. It is wrapped in a scope-enforcing
	// engine per scan, which follows redirects itself — so HTTP MUST be built with
	// FollowRedirects=false. Nil means "no network discovery" (httpengine.Stub):
	// seeds are still registered, nothing is fetched.
	HTTP httpengine.Engine

	// HTTPConfig is the Config HTTP was built from. It is otherwise unused —
	// every scan shares HTTP directly — EXCEPT when a scan sets its own
	// domain.ScanConfig.ProxyPool: scanHTTPEngine then clones HTTPConfig with
	// that pool substituted in and builds a fresh, scan-scoped client from it,
	// so a per-scan proxy pool actually changes where that scan's raw
	// discovery/candidate requests go instead of only affecting browser
	// verification. Left zero-value when HTTP is a Stub/fake (tests): a scan
	// configuring ProxyPool without a real HTTPConfig still gets SOME client
	// (built from the zero Config), just not one tuned the way the real one
	// would be.
	HTTPConfig httpengine.Config

	// Browser, when non-nil, enables browser network-observation discovery AND
	// (when it is the concrete *browser.Manager) browser verification of
	// reflected candidates. Scope IS enforced for verification (and for
	// discovery's own browser source) via the AllowRequest gate built from the
	// scan's scope.
	Browser browser.Browser

	// Verification overrides the Verifier JobVerify jobs use (nil → derived from
	// Browser, else the Phase 0 Stub). Tests inject a fake Verifier here to
	// exercise verifyExecutor without a real browser.
	Verification verification.Verifier
	// VerifyConfig tunes a Browser-derived BrowserVerifier (navigation timeout,
	// DOM excerpt window). Ignored when Verification is set.
	VerifyConfig verification.BrowserVerifierConfig

	// Discovery tunes discovery limits and depth (nil → discovery.DefaultConfig).
	Discovery *discovery.Config

	// Handlers overrides the job handlers (nil → the defaults: the test-job
	// executor for JobTest, no-ops for the other types). This is the seam where
	// detection/verification attach in later phases.
	Handlers map[domain.JobType]worker.Handler

	// Evidence stores request/response blobs for executed tests. Nil records
	// outcomes without evidence blobs.
	Evidence evidence.Store

	// Executor tunes the default test-job executor (timeout, state-changing
	// methods). Ignored when Handlers overrides JobTest.
	Executor ExecutorConfig

	// SessionsDir is where Controller.resolveAuth writes a captured login's
	// session state file for AuthMode Interactive/MFA/Password — the same
	// directory web.LoginFunc's standalone /api/auth/login handler already
	// writes into (config.Config.SessionsDir()), so a session captured
	// either way lives in one place. Empty falls back to os.TempDir() (a
	// test building a Controller without a real data dir still works,
	// just not with the server's actual layout).
	SessionsDir string

	// Preflight performs one benign request to the target before discovery
	// starts. A 429/503, a CAPTCHA/challenge page, or a WAF-identified 403/406
	// pauses the scan instead of sending the whole crawl/payload plan into a
	// block. Off by default for embedded/test controllers; the server enables it.
	Preflight bool
	// AutoPauseOnBlock pauses a running scan when a live request reports
	// backpressure (429/503) or a newly appearing CAPTCHA. A 403 filter
	// rejection does NOT auto-pause: that is the evidence that can justify the
	// separately bounded evasion pass. Off by default for tests.
	AutoPauseOnBlock bool
}

func (o Options) withDefaults() Options {
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 60 * time.Second
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = o.LeaseDuration / 3
	}
	if o.IdlePoll <= 0 {
		o.IdlePoll = 200 * time.Millisecond
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 200 * time.Millisecond
	}
	if o.ReapInterval <= 0 {
		o.ReapInterval = o.LeaseDuration
	}
	if o.HTTP == nil {
		o.HTTP = httpengine.Stub{}
	}
	return o
}

// Controller coordinates scans.
type Controller struct {
	store   store.Store
	queue   queue.Queue
	log     *slog.Logger
	version string
	opts    Options

	baseCtx    context.Context
	baseCancel context.CancelFunc

	// mu guards running and closed. It is NEVER held while waiting for a
	// goroutine to exit (Cancel/Shutdown release it first), which is what keeps
	// the completion monitor from deadlocking against them.
	mu      sync.Mutex
	running map[domain.ID]*execution
	closed  bool

	// scanMu serializes read-modify-write of scan rows so the monitor's stats
	// refresh can never overwrite a concurrent state change with stale data.
	// Lock order: mu → scanMu (never the reverse).
	scanMu sync.Mutex
}

// NewController builds a controller. A nil logger uses slog.Default.
func NewController(st store.Store, q queue.Queue, log *slog.Logger, version string, opts Options) *Controller {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{
		store:      st,
		queue:      q,
		log:        log,
		version:    version,
		opts:       opts.withDefaults(),
		baseCtx:    ctx,
		baseCancel: cancel,
		running:    make(map[domain.ID]*execution),
	}
	go c.reapExpiredLeases(ctx)
	return c
}

// reapExpiredLeases periodically reclaims jobs whose lease expired without
// ever reaching a terminal state — the queue-level safety net for a worker
// that stops heartbeating but never fails or completes the job (a hung
// handler, a goroutine that panicked past its recover, ...). Without this,
// such a job stays stuck until the whole process restarts (Recover only runs
// once, at startup). Runs for the Controller's lifetime; stops at Shutdown.
func (c *Controller) reapExpiredLeases(ctx context.Context) {
	t := time.NewTicker(c.opts.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := c.queue.ReapExpired(ctx, time.Now())
			if err != nil {
				if ctx.Err() == nil {
					c.log.Warn("reap expired leases", "err", err)
				}
				continue
			}
			if n > 0 {
				c.log.Warn("reclaimed jobs with expired leases (worker stopped heartbeating without failing/completing them)", "count", n)
			}
		}
	}
}

// CreateScanParams are the inputs to CreateScan.
type CreateScanParams struct {
	ProjectID domain.ID
	TargetID  domain.ID
	Name      string
	Profile   domain.ProfileName
	Config    *domain.ScanConfig // override, used when Profile == Custom
	Stop      domain.StopPolicy
	AuthMode  domain.AuthMode
	// AuthProfileID optionally selects a reusable target/project session.
	// When AuthMode is empty, the profile supplies auth_mode "existing";
	// explicit AuthMode anonymous still means anonymous.
	AuthProfileID domain.ID
	// AuthStatePath is the saved session material (cookies/storage state) to
	// import when AuthMode is AuthExisting — e.g. the file an interactive login
	// run earlier saved. Ignored for every other mode.
	AuthStatePath string
	// LoginURL is the page CreateScan opens to drive the login itself, for
	// AuthMode Interactive, MFA, or Password. Ignored for Anonymous/Existing
	// (which never drive a login of their own — see resolveAuth).
	LoginURL string
	// SuccessURL is a glob the browser must navigate to before the login is
	// considered done — REQUIRED for Interactive/MFA/Password (there is no
	// human in CreateScan's own flow to otherwise judge success, and for
	// Password there is no human anywhere in the loop at all). See
	// browser.LoginOptions.SuccessURLGlob / AutoLoginOptions.SuccessURLGlob.
	SuccessURL string
	// LoginUsernameSelector/LoginPasswordSelector/LoginSubmitSelector are
	// CSS-selector overrides for AuthMode Password only, for a login form
	// browser.AutoLogin's built-in heuristic can't locate correctly. Empty
	// uses the heuristic. Ignored for every other mode.
	LoginUsernameSelector string
	LoginPasswordSelector string
	LoginSubmitSelector   string
	// SeedURLs are discovery seeds. Empty means the target's base URL. Every seed
	// must be in scope; an out-of-scope seed is rejected rather than silently
	// dropped.
	SeedURLs []string

	// Crawl-extent controls, applied on top of the resolved profile/config so
	// they work with any profile. QuickScan limits discovery to the seeds
	// (depth 0). MaxDepth/MaxPages/MaxEndpoints override the server defaults
	// when > 0. See domain.ScanConfig.
	QuickScan    bool
	MaxDepth     int
	MaxPages     int
	MaxEndpoints int

	// ReconLevel selects the opt-in wordlist content/parameter discovery:
	// "off" (default), "safe", "standard", or "aggressive". See
	// discovery.Config.ReconLevel and docs/recon-wordlists.md. Empty means off,
	// so existing scans and clients are unaffected.
	ReconLevel string

	// CandidateProfile ("minimal" | "standard" | "thorough"; empty = standard)
	// and MaxCandidates (> 0 overrides the profile's per-injection-point cap)
	// bound the candidates sent per injection point. See domain.ScanConfig.
	CandidateProfile string
	MaxCandidates    int
	// EnableEvasion — see domain.ScanConfig.EnableEvasion. Off by default.
	EnableEvasion bool
	// RawQueryInjection — see domain.ScanConfig.RawQueryInjection and
	// discovery.ParseRawQueryMode. Empty / "off" (the default) adds nothing;
	// "auto" probes GET endpoints with no named query parameters; "always"
	// also probes endpoints that have them.
	RawQueryInjection string
	// ProxyPool — see domain.ScanConfig.ProxyPool. Empty (the default) means a
	// direct connection for both raw HTTP traffic and browser verification.
	ProxyPool []string
	// RandomizeTLSFingerprint — see domain.ScanConfig.RandomizeTLSFingerprint.
	// Off by default; mutually exclusive with ProxyPool (validated below).
	RandomizeTLSFingerprint bool
	// IDORCandidates are operator-supplied foreign object identifiers — see
	// domain.ScanConfig.IDORCandidates. Bounded and validated at creation.
	//
	// There is no separate "enable the IDOR engine" switch: the engine runs
	// automatically for any scan that carries a real caller identity, exactly
	// like the other engines' automatic passes.
	IDORCandidates []string
	// EnableIDOREnumeration / IDOREnumerationNeighbours — see
	// domain.ScanConfig.EnableIDOREnumeration. Enumeration is a second,
	// explicit opt-in ON TOP of the automatic engine because it deliberately
	// sends foreign identifiers the caller did not disclose; it requires an
	// authenticated session like the engine itself.
	EnableIDOREnumeration     bool
	IDOREnumerationNeighbours int
	// EnableRoleParam opts into the access-control engine's client-controlled
	// flag differential (case 20). Off by default; GET only and bounded.
	EnableRoleParam bool
	// EnableAccessControlPages opts into the page-disclosure pass (case 19's
	// script-disclosed path source). Off by default; bounded and GET only.
	EnableAccessControlPages bool
	// EnableRoleWrite opts into the access-control engine's role-field slice
	// (case 21). Off by default; requires an authenticated session AND the
	// server's AllowStateChanging opt-in because it writes the caller's own
	// profile.
	EnableRoleWrite bool
	// EnableAdminStepProbe opts into the cases 35/36 admin-action probes.
	EnableAdminStepProbe bool
	// EnableObjectFamilyProbe opts into the case 34 object-family slice.
	EnableObjectFamilyProbe bool
	// EnableXSSLibrary opts into the cheat-sheet library families.
	EnableXSSLibrary bool
	// SkipGlobalInjection omits header/cookie injection points.
	SkipGlobalInjection bool
	// SkipStaticAssets drops crawler/browser-discovered static resources.
	SkipStaticAssets bool
	// Capability switches; see domain.ScanConfig.
	SkipReflectedXSS      bool
	SkipDOMXSS            bool
	SkipAccessControl     bool
	SkipIDOR              bool
	SkipInfoDisclosure    bool
	SkipWriteEndpoints    bool
	SkipDownloadEndpoints bool
	MaxDOMXSSEndpoints    int
}

// Crawl-extent upper bounds, so an operator typo cannot ask the crawler to go
// effectively unbounded.
const (
	maxCrawlDepth     = 20
	maxCrawlPages     = 100000
	maxCrawlEndpoints = 100000
)

// CreateScan validates scope and inputs, then persists a scan in the Created
// state together with a pending session. It performs no testing.
func (c *Controller) CreateScan(ctx context.Context, p CreateScanParams) (*domain.Scan, error) {
	project, err := c.store.Projects().Get(ctx, p.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("scan: project: %w", err)
	}
	target, err := c.store.Targets().Get(ctx, p.TargetID)
	if err != nil {
		return nil, fmt.Errorf("scan: target: %w", err)
	}
	if target.ProjectID != p.ProjectID {
		return nil, errors.New("scan: target does not belong to project")
	}
	profileID := p.AuthProfileID
	if profileID == "" {
		profileID = target.AuthProfileID
	}
	if profileID != "" {
		authProfile, err := c.store.AuthProfiles().Get(ctx, profileID)
		if err != nil {
			return nil, fmt.Errorf("scan: auth profile: %w", err)
		}
		if authProfile.ProjectID != p.ProjectID {
			return nil, errors.New("scan: auth profile does not belong to project")
		}
		if authProfile.StatePath == "" {
			return nil, fmt.Errorf("%w: auth profile %q has no saved session", ErrAuth, authProfile.Name)
		}
		if p.AuthMode == "" || (p.AuthMode == domain.AuthExisting && p.AuthStatePath == "") {
			p.AuthMode = domain.AuthExisting
			p.AuthStatePath = authProfile.StatePath
		}
	}

	// Scope is mandatory and must permit the target base URL. Fail closed.
	scope, err := c.loadScope(ctx, p.ProjectID)
	if err != nil {
		return nil, err
	}
	if d := scope.Permits(target.BaseURL); !d.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}

	// Seeds must parse and be in scope. Stored canonical so restarts see the same
	// values the collector will deduplicate against.
	var seeds []string
	for _, raw := range p.SeedURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		info, err := discovery.Normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %v", ErrInvalidSeed, raw, err)
		}
		if d := scope.Permits(info.Canonical); !d.Allowed {
			return nil, fmt.Errorf("%w: seed %s: %s", ErrOutOfScope, info.Canonical, d.Reason)
		}
		seeds = append(seeds, info.Canonical)
	}

	profile := p.Profile
	if !profile.IsValid() {
		profile = domain.ProfileBalanced
	}
	cfg := ProfileConfig(profile)
	if profile == domain.ProfileCustom && p.Config != nil {
		cfg = *p.Config
	}
	// Crawl-extent controls sit alongside the concurrency preset: they apply
	// whatever the profile. 0 keeps the server/profile default.
	cfg.QuickScan = p.QuickScan
	if p.MaxDepth > 0 {
		cfg.MaxDepth = p.MaxDepth
	}
	if p.MaxPages > 0 {
		cfg.MaxPages = p.MaxPages
	}
	if p.MaxEndpoints > 0 {
		cfg.MaxEndpoints = p.MaxEndpoints
	}
	// Wordlist recon is opt-in per scan; an explicit but invalid level is a
	// creation error (fail fast) rather than silently running off.
	if p.ReconLevel != "" {
		level, err := discovery.ParseReconLevel(p.ReconLevel)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadConfig, err)
		}
		cfg.ReconLevel = string(level)
	}
	if err := validateCrawlExtent(cfg); err != nil {
		return nil, err
	}
	// Candidate selection (like the crawl extent) applies whatever the profile
	// preset. Validated now so a typo fails at creation, not mid-scan.
	if p.CandidateProfile != "" {
		cfg.CandidateProfile = p.CandidateProfile
	}
	if p.MaxCandidates != 0 { // negative is passed through so ResolveProfile rejects it
		cfg.MaxCandidates = p.MaxCandidates
	}
	if _, err := detection.ResolveProfile(cfg.CandidateProfile, cfg.MaxCandidates); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadConfig, err)
	}
	cfg.HuntingUserAgent = project.HuntingUserAgent
	cfg.HuntingUserAgentReplace = project.HuntingUserAgentReplace
	cfg.AuthProfileID = profileID
	if strings.ContainsAny(cfg.HuntingUserAgent, "\r\n") {
		return nil, fmt.Errorf("%w: hunting user agent must be a single header value", ErrBadConfig)
	}
	cfg.EnableEvasion = p.EnableEvasion
	// Raw query-string injection is a separate, opt-in capability. Parse the
	// explicit value (empty means off) so a typo fails at creation rather than
	// silently enabling or disabling probes mid-scan.
	if p.RawQueryInjection != "" {
		mode, err := discovery.ParseRawQueryMode(p.RawQueryInjection)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadConfig, err)
		}
		cfg.RawQueryInjection = string(mode)
	}
	cfg.ProxyPool = p.ProxyPool
	if err := validateProxyPool(cfg.ProxyPool); err != nil {
		return nil, err
	}
	cfg.RandomizeTLSFingerprint = p.RandomizeTLSFingerprint
	if cfg.RandomizeTLSFingerprint && len(cfg.ProxyPool) > 0 {
		return nil, fmt.Errorf("%w: randomize_tls_fingerprint and proxy_pool cannot both be set — "+
			"Go's HTTP transport performs TLS internally after any proxy tunnel, never through a "+
			"custom TLS dialer, so the fingerprint override would silently have no effect through a proxy", ErrBadConfig)
	}
	// The session mode decides several validations below (IDOR enumeration,
	// the role-field slice), so resolve it once, up front.
	mode := p.AuthMode
	if !mode.IsValid() {
		mode = domain.AuthAnonymous
	}
	// IDOR engine: automatic, so there is nothing to opt into here. Only the
	// operator-supplied candidate identifiers are carried over.
	cfg.IDORCandidates = cleanIDORCandidates(p.IDORCandidates)
	if err := validateIDORCandidates(cfg.IDORCandidates); err != nil {
		return nil, err
	}
	// Bounded enumeration stays a second, explicit opt-in ON TOP of the
	// automatic engine: it deliberately sends foreign identifiers the caller
	// never disclosed. It still needs an authenticated session, so refuse the
	// combination at creation instead of running a pass that can only skip.
	cfg.EnableIDOREnumeration = p.EnableIDOREnumeration
	cfg.IDOREnumerationNeighbours = p.IDOREnumerationNeighbours
	if err := validateIDOREnumeration(mode, cfg.EnableIDOREnumeration, cfg.IDOREnumerationNeighbours); err != nil {
		return nil, err
	}
	// Access-control differentials. The flag differential is read-only; the
	// role-field slice writes the caller's own profile and needs both the
	// server's state-changing opt-in and a session to write from.
	cfg.EnableRoleParam = p.EnableRoleParam
	cfg.EnableAccessControlPages = p.EnableAccessControlPages
	cfg.EnableRoleWrite = p.EnableRoleWrite
	cfg.EnableAdminStepProbe = p.EnableAdminStepProbe
	cfg.EnableObjectFamilyProbe = p.EnableObjectFamilyProbe
	cfg.EnableXSSLibrary = p.EnableXSSLibrary
	cfg.SkipGlobalInjection = p.SkipGlobalInjection
	cfg.SkipStaticAssets = p.SkipStaticAssets
	cfg.SkipReflectedXSS = p.SkipReflectedXSS
	cfg.SkipDOMXSS = p.SkipDOMXSS
	cfg.SkipAccessControl = p.SkipAccessControl
	cfg.SkipIDOR = p.SkipIDOR
	cfg.SkipInfoDisclosure = p.SkipInfoDisclosure
	cfg.SkipWriteEndpoints = p.SkipWriteEndpoints
	cfg.SkipDownloadEndpoints = p.SkipDownloadEndpoints
	cfg.MaxDOMXSSEndpoints = p.MaxDOMXSSEndpoints

	statePath, err := c.resolveAuth(ctx, mode, p, scope, c.huntingUserAgent(&domain.Scan{Config: domain.ScanConfig{HuntingUserAgent: project.HuntingUserAgent, HuntingUserAgentReplace: project.HuntingUserAgentReplace}}))
	if err != nil {
		return nil, err
	}
	// The role-field slice writes the caller's own profile and decides from
	// that caller's privileged access. Without a session there is nobody to
	// escalate, and without the server's state-changing opt-in the write would
	// only ever be skipped — both are refused at creation instead.
	if cfg.EnableObjectFamilyProbe && mode == domain.AuthAnonymous {
		return nil, fmt.Errorf("%w: enable_object_family_probe requires an authenticated session (the probe authors an object as the caller); use -auth existing/-auth interactive/-auth mfa/-auth password", ErrBadConfig)
	}
	if cfg.EnableAdminStepProbe && mode == domain.AuthAnonymous {
		return nil, fmt.Errorf("%w: enable_admin_step_probe requires an authenticated session (there is no caller to authorize); use -auth existing/-auth interactive/-auth mfa/-auth password", ErrBadConfig)
	}
	if cfg.EnableRoleWrite {
		if mode == domain.AuthAnonymous {
			return nil, fmt.Errorf("%w: enable_role_write requires an authenticated session (auth_mode %q has no caller profile); use -auth existing/-auth interactive/-auth mfa/-auth password", ErrBadConfig, mode)
		}
		if !c.opts.Executor.AllowStateChanging {
			return nil, fmt.Errorf("%w: enable_role_write requires the server's explicit -allow-state-changing opt-in; the engine writes the caller's own profile and is never enabled implicitly", ErrBadConfig)
		}
	}
	stop := p.Stop
	if !stop.Mode.IsValid() {
		stop.Mode = domain.StopContinueAll
	}

	now := time.Now()
	sess := &domain.Session{
		ID: domain.NewID(), ScanID: domain.NewID(), // ScanID set below once scan ID is known
		Mode: mode, State: domain.SessionNone, StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}
	sc := &domain.Scan{
		ID:        domain.NewID(),
		ProjectID: p.ProjectID,
		TargetID:  p.TargetID,
		Name:      p.Name,
		State:     domain.ScanCreated,
		Profile:   profile,
		Config:    cfg,
		Stop:      stop,
		SessionID: sess.ID,
		SeedURLs:  seeds,
		Discovery: domain.DiscoveryPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	sess.ScanID = sc.ID

	if err := c.store.Sessions().Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("scan: create session: %w", err)
	}
	if err := c.store.Scans().Create(ctx, sc); err != nil {
		return nil, fmt.Errorf("scan: create scan: %w", err)
	}
	c.log.Info("scan created", "scan", sc.ID, "profile", profile, "auth", mode, "seeds", len(seeds))
	return sc, nil
}

// Start establishes the session and begins a Created scan: the worker pool and
// discovery start together.
func (c *Controller) Start(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrShutdown
	}

	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if sc.State != domain.ScanCreated {
		return fmt.Errorf("%w: can only start a created scan (state=%s)", ErrBadState, sc.State)
	}
	// A project may be edited after its scan was queued (the bounty import
	// creates a scan immediately). Pick up the latest hunting identity at
	// start so the operator does not have to recreate the scan.
	if project, err := c.store.Projects().Get(ctx, sc.ProjectID); err == nil {
		sc.Config.HuntingUserAgent = project.HuntingUserAgent
		sc.Config.HuntingUserAgentReplace = project.HuntingUserAgentReplace
	}

	// Defense in depth: re-check scope at start (scope may have changed).
	scope, err := c.loadScope(ctx, sc.ProjectID)
	if err != nil {
		return err
	}
	target, err := c.store.Targets().Get(ctx, sc.TargetID)
	if err != nil {
		return err
	}
	if d := scope.Permits(target.BaseURL); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}
	// A target's auth profile can be assigned after its scan was created (the
	// bounty import creates scans before the operator logs in). Pick it up at
	// start so an imported draft does not silently run anonymously.
	if err := c.inheritTargetAuthProfile(ctx, sc, target); err != nil {
		return err
	}

	if err := c.establishSession(ctx, sc); err != nil {
		return err
	}

	started := time.Now()
	sc, err = c.mutate(ctx, scanID, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanRunning); err != nil {
			return err
		}
		s.StartedAt = &started
		s.Error = ""
		return nil
	})
	if err != nil {
		return err
	}

	ex, err := c.launch(ctx, sc, scope, target)
	if err != nil {
		if errors.Is(err, ErrWAFPreflight) {
			_, _ = c.mutate(ctx, scanID, func(s *domain.Scan) error {
				s.Error = err.Error()
				return transition(s, domain.ScanPaused)
			})
			return err
		}
		c.failScan(scanID, fmt.Sprintf("start: %v", err))
		return err
	}
	c.running[scanID] = ex
	c.log.Info("scan started", "scan", scanID, "discovery", sc.Discovery)
	return nil
}

// Pause stops new work for a running scan: workers stop leasing and discovery
// stops starting network work. In-flight work finishes. Idempotent.
func (c *Controller) Pause(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ex, ok := c.running[scanID]
	if !ok {
		// A scan restored after a restart is already paused with no execution.
		sc, err := c.store.Scans().Get(ctx, scanID)
		if err == nil && sc.State == domain.ScanPaused {
			return nil
		}
		return ErrNotRunning
	}
	if _, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
		return transition(s, domain.ScanPaused)
	}); err != nil {
		return err
	}
	ex.pause()
	c.log.Info("scan paused", "scan", scanID)
	return nil
}

// pauseForBlock is the asynchronous callback used by live executors when the
// target answers 429/503 or presents a CAPTCHA. The request itself is not a
// vulnerability verdict; continuing would only spend more traffic against a
// target that has explicitly asked for a pause.
func (c *Controller) pauseForBlock(scanID domain.ID, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ex, ok := c.running[scanID]
	if !ok {
		return
	}
	if _, err := c.mutate(context.Background(), scanID, func(s *domain.Scan) error {
		s.Error = reason
		return transition(s, domain.ScanPaused)
	}); err != nil {
		c.log.Warn("hold scan after block signal", "scan", scanID, "err", err)
		return
	}
	ex.pause()
	c.log.Info("scan paused after target block signal", "scan", scanID, "reason", reason)
}

// Resume continues a paused scan. If the scan was restored after a restart (no
// live execution), Resume rebuilds the worker pool and discovery first.
func (c *Controller) Resume(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrShutdown
	}

	if ex, ok := c.running[scanID]; ok {
		sc, err := c.store.Scans().Get(ctx, scanID)
		if err != nil {
			return err
		}
		if err := c.reauthenticateIfAwaitingAuth(ctx, sc); err != nil {
			return err
		}
		if _, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
			return transition(s, domain.ScanRunning)
		}); err != nil {
			return err
		}
		ex.resume()
		c.log.Info("scan resumed", "scan", scanID)
		return nil
	}

	// No live execution: only a persisted paused/awaiting_auth scan can be
	// restored. Anything else is not resumable.
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if sc.State != domain.ScanPaused && sc.State != domain.ScanAwaitingAuth {
		return ErrNotRunning
	}
	scope, err := c.loadScope(ctx, sc.ProjectID)
	if err != nil {
		return err
	}
	target, err := c.store.Targets().Get(ctx, sc.TargetID)
	if err != nil {
		return err
	}
	if d := scope.Permits(target.BaseURL); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}
	if err := c.reauthenticateIfAwaitingAuth(ctx, sc); err != nil {
		return err
	}

	sc, err = c.mutate(ctx, scanID, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanRunning); err != nil {
			return err
		}
		s.Error = ""
		return nil
	})
	if err != nil {
		return err
	}
	ex, err := c.launch(ctx, sc, scope, target)
	if err != nil {
		// Put the scan back so the operator can retry.
		_, _ = c.mutate(context.Background(), scanID, func(s *domain.Scan) error {
			s.Error = err.Error()
			return transition(s, domain.ScanPaused)
		})
		return err
	}
	c.running[scanID] = ex
	c.log.Info("scan restored and resumed", "scan", scanID, "discovery", sc.Discovery)
	return nil
}

// Cancel cancels a scan: stops its workers and discovery, cancels its queued and
// in-flight jobs, and records the terminal state. It works on scans with no live
// execution (e.g. paused after a restart). Idempotent for terminal scans.
func (c *Controller) Cancel(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if sc.State.IsTerminal() {
		c.mu.Unlock()
		return nil
	}
	// created scans go straight to canceled; everything else passes through
	// canceling while the execution is torn down.
	first := domain.ScanCanceling
	if sc.State == domain.ScanCreated {
		first = domain.ScanCanceled
	}
	if _, err := c.mutate(ctx, scanID, func(s *domain.Scan) error { return transition(s, first) }); err != nil {
		c.mu.Unlock()
		return err
	}
	ex := c.running[scanID]
	delete(c.running, scanID)
	c.mu.Unlock() // release BEFORE waiting: the monitor may be blocked on mu

	if ex != nil {
		c.stopExecution(ex, true)
	}
	return c.finalizeCancel(ctx, scanID)
}

// finalizeCancel cancels the scan's jobs and records the terminal canceled state.
func (c *Controller) finalizeCancel(ctx context.Context, scanID domain.ID) error {
	if _, err := c.queue.CancelScan(ctx, scanID); err != nil {
		return err
	}
	ended := time.Now()
	stats := c.snapshotStats(ctx, scanID)
	_, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanCanceled); err != nil {
			return err
		}
		s.EndedAt = &ended
		if s.Discovery != domain.DiscoveryComplete {
			s.Discovery = domain.DiscoveryCanceled
		}
		s.Stats = stats
		return nil
	})
	if err == nil {
		c.log.Info("scan canceled", "scan", scanID)
	}
	return err
}

// Reconfigure changes a scan's concurrency/rate at runtime. The new config is
// persisted and, if the scan is running, applied to the live worker pool.
//
// Discovery concurrency is read when discovery starts, so a change to it takes
// effect the next time discovery (re)starts rather than mid-crawl.
func (c *Controller) Reconfigure(ctx context.Context, scanID domain.ID, cfg domain.ScanConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
		s.Config = cfg
		s.Profile = domain.ProfileCustom
		return nil
	}); err != nil {
		return err
	}
	if ex, ok := c.running[scanID]; ok {
		_ = ex.pool.Resize(GroupDiscovery, cfg.DiscoveryConcurrency)
		_ = ex.pool.Resize(GroupHTTP, cfg.HTTPConcurrency)
		_ = ex.pool.Resize(GroupBrowser, minBrowserWorkers(cfg.BrowserConcurrency))
		// The scan's one limiter: reaches discovery fetches, redirect hops,
		// browser discovery and verification, and raw test requests at once.
		ex.limiter.SetRate(cfg.RequestsPerSecond)
		// GroupDiscovery above is queue-pool bookkeeping only: discovery itself
		// never runs as a queued job (see handlers.go), so resizing it changes
		// nothing on its own. Discovery has its own concurrency fan-out
		// (discovery.Manager), reached here so DiscoveryConcurrency is actually
		// adjustable at runtime, not just accepted and ignored.
		if ex.disc != nil {
			ex.disc.SetConcurrency(cfg.DiscoveryConcurrency)
		}
	}
	c.log.Info("scan reconfigured", "scan", scanID, "config", cfg)
	return nil
}

// Stats returns live queue statistics for a scan.
func (c *Controller) Stats(ctx context.Context, scanID domain.ID) (queue.Stats, error) {
	return c.queue.Stats(ctx, scanID)
}

// IsRunning reports whether the controller currently manages an execution for
// scanID.
func (c *Controller) IsRunning(scanID domain.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.running[scanID]
	return ok
}

// Shutdown stops every execution and waits for its goroutines to exit, without
// changing any scan's persisted state — so a restart sees them as interrupted
// and RecoverScans restores them. After Shutdown the controller rejects Start
// and Resume.
func (c *Controller) Shutdown() {
	c.mu.Lock()
	c.closed = true
	exs := make([]*execution, 0, len(c.running))
	for id, ex := range c.running {
		exs = append(exs, ex)
		delete(c.running, id)
	}
	c.mu.Unlock() // release BEFORE waiting (see mu)

	// In parallel, not sequentially: each stopExecution can take up to its
	// pool's ShutdownTimeout if a handler is wedged (see worker.Pool.Stop), and
	// with several scans running at once a sequential wait would multiply that
	// by the scan count instead of bounding total shutdown time by the worst
	// single one.
	var wg sync.WaitGroup
	for _, ex := range exs {
		wg.Add(1)
		go func(ex *execution) {
			defer wg.Done()
			c.stopExecution(ex, true)
		}(ex)
	}
	wg.Wait()
	c.baseCancel()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// resolveAuth checks a scan's authentication configuration at creation, so an
// unusable one is rejected up front (ErrAuth) instead of failing at Start,
// and — for Interactive, MFA, and Password — actually DRIVES the login
// (blocking CreateScan until it finishes, times out, or the context is
// canceled, the same contract web.LoginFunc's standalone /api/auth/login
// endpoint already has). Returns the state path to persist on the Session.
func (c *Controller) resolveAuth(ctx context.Context, mode domain.AuthMode, p CreateScanParams, scope domain.Scope, userAgent string) (string, error) {
	statePath := strings.TrimSpace(p.AuthStatePath)
	loginURL := strings.TrimSpace(p.LoginURL)
	successURL := strings.TrimSpace(p.SuccessURL)
	allow := func(raw string) bool { return scope.Permits(raw).Allowed }
	if mode == domain.AuthPassword || mode == domain.AuthInteractive || mode == domain.AuthMFA {
		if loginURL != "" && !allow(loginURL) {
			return "", fmt.Errorf("%w: login_url must be permitted by project scope; explicitly include authorized SSO hosts and paths in Projects → Scope", ErrOutOfScope)
		}
	}

	switch mode {
	case domain.AuthAnonymous:
		if statePath != "" || loginURL != "" {
			return "", fmt.Errorf("%w: auth_state_path/login_url are only valid with auth mode %q, %q, %q, or %q",
				ErrAuth, domain.AuthExisting, domain.AuthInteractive, domain.AuthMFA, domain.AuthPassword)
		}
		return "", nil

	case domain.AuthExisting:
		if loginURL != "" {
			return "", fmt.Errorf("%w: login_url is only valid with auth mode %q, %q, or %q — %q imports a session you already captured",
				ErrAuth, domain.AuthInteractive, domain.AuthMFA, domain.AuthPassword, domain.AuthExisting)
		}
		if statePath != "" && filepath.IsAbs(statePath) {
			statePath = filepath.Clean(statePath)
		}
		if err := auth.ValidateStateFile(statePath); err != nil {
			return "", fmt.Errorf("%w: %w", ErrAuth, err)
		}
		return statePath, nil

	case domain.AuthInteractive, domain.AuthMFA:
		if statePath != "" {
			return "", fmt.Errorf("%w: auth_state_path is not valid with auth mode %q — Indago captures the session itself; use %q to import one you already have",
				ErrAuth, mode, domain.AuthExisting)
		}
		if loginURL == "" {
			return "", fmt.Errorf("%w: auth mode %q requires login_url", ErrAuth, mode)
		}
		if successURL == "" {
			return "", fmt.Errorf("%w: auth mode %q requires success_url — CreateScan has no UI to show a waiting state, so it needs an objective signal that the operator's login (and any MFA step) finished before it saves a session", ErrAuth, mode)
		}
		mgr, ok := c.opts.Browser.(*browser.Manager)
		if !ok || mgr == nil {
			return "", fmt.Errorf("%w: auth mode %q requires a browser (start the server with `indago serve -browser`)", ErrAuth, mode)
		}
		path, err := c.newSessionStatePath()
		if err != nil {
			return "", fmt.Errorf("%w: build session state path: %w", ErrAuth, err)
		}
		res, err := mgr.InteractiveLogin(ctx, browser.LoginOptions{AllowRequest: allow, LoginURL: loginURL, SuccessURLGlob: successURL, StorageStatePath: path, UserAgent: userAgent})
		if err != nil {
			return "", fmt.Errorf("%w: interactive login: %w", ErrAuth, err)
		}
		return res.StorageStatePath, nil

	case domain.AuthPassword:
		if statePath != "" {
			return "", fmt.Errorf("%w: auth_state_path is not valid with auth mode %q — Indago captures the session itself; use %q to import one you already have",
				ErrAuth, mode, domain.AuthExisting)
		}
		if loginURL == "" {
			return "", fmt.Errorf("%w: auth mode %q requires login_url", ErrAuth, mode)
		}
		if successURL == "" {
			return "", fmt.Errorf("%w: auth mode %q requires success_url — with no human in the loop at all, Indago needs an objective signal that the submitted form actually logged in", ErrAuth, mode)
		}
		// Credentials come ONLY from the server process's own environment —
		// never from the request body, never from a CLI flag that would sit
		// in shell history or `ps`. Read fresh on every login (not cached at
		// server startup), matching the operator's own chosen contract.
		user := strings.TrimSpace(os.Getenv("INDAGO_AUTH_USER"))
		pass := os.Getenv("INDAGO_AUTH_PASS")
		if user == "" || pass == "" {
			return "", fmt.Errorf("%w: auth mode %q requires INDAGO_AUTH_USER and INDAGO_AUTH_PASS set in the SERVER's own environment before this scan is created — never sent over the API/CLI, never persisted", ErrAuth, mode)
		}
		mgr, ok := c.opts.Browser.(*browser.Manager)
		if !ok || mgr == nil {
			return "", fmt.Errorf("%w: auth mode %q requires a browser (start the server with `indago serve -browser`)", ErrAuth, mode)
		}
		path, err := c.newSessionStatePath()
		if err != nil {
			return "", fmt.Errorf("%w: build session state path: %w", ErrAuth, err)
		}
		res, err := mgr.AutoLogin(ctx, browser.AutoLoginOptions{
			AllowRequest: allow,
			LoginURL:     loginURL, Username: user, Password: pass, SuccessURLGlob: successURL, StorageStatePath: path,
			UsernameSelector: p.LoginUsernameSelector, PasswordSelector: p.LoginPasswordSelector, SubmitSelector: p.LoginSubmitSelector,
		})
		if err != nil {
			return "", fmt.Errorf("%w: password login: %w", ErrAuth, err)
		}
		return res.StorageStatePath, nil

	default:
		// Unreachable: CreateScan already coerces an invalid mode to
		// Anonymous before calling resolveAuth. Fails closed regardless, in
		// case a future AuthMode value is added to the enum before its case
		// is added here.
		return "", fmt.Errorf("%w: auth mode %q is not implemented", ErrAuth, mode)
	}
}

// sessionsDir is where resolveAuth saves a captured login's session state.
// See Options.SessionsDir.
func (c *Controller) sessionsDir() string {
	if c.opts.SessionsDir != "" {
		return c.opts.SessionsDir
	}
	return os.TempDir()
}

// newSessionStatePath returns a fresh, ABSOLUTE path under sessionsDir for a
// captured login to save its session material to. Absolute matters:
// auth.ValidateStateFile (which capturedSession.Establish/Validate run
// against on every scan start/resume, not just once at capture time) rejects
// a relative path outright — and Options.SessionsDir/config.Config.DataDir
// default to a relative "data", so joining them naively produces a path
// that is only valid while the server's current working directory happens
// to be the same as when it was captured.
func (c *Controller) newSessionStatePath() (string, error) {
	path := filepath.Join(c.sessionsDir(), "login-"+string(domain.NewID())+".json")
	return filepath.Abs(path)
}

// validateCrawlExtent bounds the crawl-extent controls so a typo cannot ask the
// crawler to run effectively unbounded.
func validateCrawlExtent(cfg domain.ScanConfig) error {
	switch {
	case cfg.MaxDepth < 0 || cfg.MaxDepth > maxCrawlDepth:
		return fmt.Errorf("%w: max_depth must be between 0 and %d", ErrBadConfig, maxCrawlDepth)
	case cfg.MaxPages < 0 || cfg.MaxPages > maxCrawlPages:
		return fmt.Errorf("%w: max_pages must be between 0 and %d", ErrBadConfig, maxCrawlPages)
	case cfg.MaxEndpoints < 0 || cfg.MaxEndpoints > maxCrawlEndpoints:
		return fmt.Errorf("%w: max_endpoints must be between 0 and %d", ErrBadConfig, maxCrawlEndpoints)
	}
	return nil
}

// validateProxyPool rejects an implausible proxy entry up front (not a URL,
// or a scheme Indago's HTTP transport can't dial) rather than letting a typo
// surface later as every request in the scan silently failing to connect.
func validateProxyPool(pool []string) error {
	for _, p := range pool {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return fmt.Errorf("%w: proxy_pool entry %q is not a valid proxy URL (want http://host:port, https://host:port, or socks5://host:port)", ErrBadConfig, p)
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return fmt.Errorf("%w: proxy_pool entry %q has unsupported scheme %q (want http, https, socks5, or socks5h)", ErrBadConfig, p, u.Scheme)
		}
	}
	return nil
}

// IDOR candidate-identifier bounds: a typo must never turn the differential
// into an enumeration run.
const (
	maxIDORCandidates   = 10
	maxIDORCandidateLen = 120
)

// cleanIDORCandidates trims, drops empties and collapses duplicates while
// preserving the operator's order.
func cleanIDORCandidates(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// validateIDORCandidates rejects an implausible identifier up front: this
// list is the ONLY unbounded-by-derivation input to the differential, so it is
// hard-capped and restricted to identifier-shaped values.
func validateIDORCandidates(cands []string) error {
	if len(cands) > maxIDORCandidates {
		return fmt.Errorf("%w: at most %d idor_candidates are allowed, got %d", ErrBadConfig, maxIDORCandidates, len(cands))
	}
	for _, v := range cands {
		if len(v) > maxIDORCandidateLen {
			return fmt.Errorf("%w: idor_candidates entry is longer than %d characters", ErrBadConfig, maxIDORCandidateLen)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f || r == '<' || r == '>' || r == '"' || r == '\'' || r == '\\' || r == ' ' || r == '\t' {
				return fmt.Errorf("%w: idor_candidates entry %q contains whitespace, control or markup characters", ErrBadConfig, v)
			}
		}
	}
	return nil
}

// validateIDOREnumeration rejects a configuration that cannot do what the
// operator asked: enumeration without the engine, or N outside the engine's
// stated range. Bounded means bounded — a typo must not become a wordlist.
func validateIDOREnumeration(authMode domain.AuthMode, enableEnum bool, neighbours int) error {
	if enableEnum && authMode == domain.AuthAnonymous {
		return fmt.Errorf("%w: idor_enumerate requires an authenticated session (auth_mode %q has no caller identity to compare against); use -auth existing/-auth interactive/-auth mfa/-auth password", ErrBadConfig, authMode)
	}
	if neighbours != 0 && !enableEnum {
		return fmt.Errorf("%w: idor_enumerate_n requires idor_enumerate", ErrBadConfig)
	}
	if neighbours < 0 || neighbours > idor.MaxEnumerationNeighbours {
		return fmt.Errorf("%w: idor_enumerate_n must be between 1 and %d (0 = default %d), got %d",
			ErrBadConfig, idor.MaxEnumerationNeighbours, idor.DefaultEnumerationNeighbours, neighbours)
	}
	return nil
}

// loadScope loads the project's scope, failing closed when absent or empty.
func (c *Controller) loadScope(ctx context.Context, projectID domain.ID) (domain.Scope, error) {
	scope, err := c.store.Scopes().GetByProject(ctx, projectID)
	if errors.Is(err, store.ErrNotFound) {
		return domain.Scope{}, ErrScopeRequired
	}
	if err != nil {
		return domain.Scope{}, fmt.Errorf("scan: scope: %w", err)
	}
	if len(scope.IncludeHosts) == 0 {
		return domain.Scope{}, ErrScopeEmpty
	}
	return *scope, nil
}

// inheritTargetAuthProfile upgrades a draft scan to the target's reusable
// session when the operator assigned one after the scan was created. The
// target profile is authoritative: a scan without its own profile must not
// silently keep testing anonymously.
func (c *Controller) inheritTargetAuthProfile(ctx context.Context, sc *domain.Scan, target *domain.Target) error {
	profileID := sc.Config.AuthProfileID
	if profileID == "" {
		profileID = target.AuthProfileID
	}
	if profileID == "" {
		return nil
	}
	profile, err := c.store.AuthProfiles().Get(ctx, profileID)
	if err != nil {
		return fmt.Errorf("%w: load auth profile: %v", ErrAuth, err)
	}
	if profile.ProjectID != sc.ProjectID {
		return fmt.Errorf("%w: auth profile does not belong to the scan project", ErrAuth)
	}
	if profile.StatePath == "" {
		return fmt.Errorf("%w: auth profile %q has no saved session; log in on the target first", ErrAuth, profile.Name)
	}
	if sc.SessionID.Empty() {
		return fmt.Errorf("%w: scan has no session row", ErrAuth)
	}
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil {
		return fmt.Errorf("%w: load session: %v", ErrAuth, err)
	}
	if sess.Mode == domain.AuthExisting && sess.StatePath == profile.StatePath {
		sc.Config.AuthProfileID = profile.ID
		return nil
	}
	sess.Mode = domain.AuthExisting
	sess.StatePath = profile.StatePath
	sess.State = domain.SessionAuthenticating
	sess.ExpiresAt = nil
	sess.LastError = ""
	sess.UpdatedAt = time.Now()
	if err := c.store.Sessions().Update(ctx, sess); err != nil {
		return fmt.Errorf("%w: update session: %v", ErrAuth, err)
	}
	sc.Config.AuthProfileID = profile.ID
	return nil
}

func (c *Controller) establishSession(ctx context.Context, sc *domain.Scan) error {
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil {
		return fmt.Errorf("scan: load session: %w", err)
	}
	a, err := auth.For(sess.Mode)
	if err != nil {
		return err
	}
	established, err := a.Establish(ctx, auth.Input{ScanID: sc.ID, StatePath: sess.StatePath})
	if err != nil {
		return fmt.Errorf("%w: establish session: %w", ErrAuth, err)
	}
	// Preserve the existing session row ID; copy over established fields.
	sess.State = established.State
	sess.StatePath = established.StatePath
	sess.ExpiresAt = established.ExpiresAt
	sess.UpdatedAt = time.Now()
	if err := c.store.Sessions().Update(ctx, sess); err != nil {
		return fmt.Errorf("scan: update session: %w", err)
	}
	return nil
}

// sessionCookiesFor returns every valid cookie in the scan's saved browser
// storage state (if any). scopedEngine applies each cookie's host/domain,
// path, scheme, and expiry rules independently at every request and redirect
// hop. Best-effort: a missing session, no saved state, or a read/parse failure
// yields nil; HTTP-level testing then proceeds unauthenticated.
func (c *Controller) sessionCookiesFor(ctx context.Context, sc *domain.Scan) []*http.Cookie {
	if sc.SessionID.Empty() {
		return nil
	}
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil || sess.StatePath == "" {
		return nil
	}
	return sessionCookies(sess.StatePath)
}

// reauthenticateIfAwaitingAuth re-establishes the scan's session before it
// resumes from AwaitingAuth. The scanner never silently re-authenticates
// outside of this path (see domain.Session's doc comment) — a plain Paused
// resume does nothing here.
func (c *Controller) reauthenticateIfAwaitingAuth(ctx context.Context, sc *domain.Scan) error {
	if sc.State != domain.ScanAwaitingAuth {
		return nil
	}
	if err := c.establishSession(ctx, sc); err != nil {
		return fmt.Errorf("scan: re-authenticate: %w", err)
	}
	return nil
}

// sessionExpired reports whether the scan's established session is no longer
// usable: its ExpiresAt is in the past, or its mode's Authenticator.Validate
// reports it inactive (e.g. AuthExisting's session material was removed —
// continuing would silently test the target unauthenticated). A session with
// no expiry that still validates (e.g. the anonymous mode) never expires.
func (c *Controller) sessionExpired(ctx context.Context, sc *domain.Scan) (bool, error) {
	if sc.SessionID.Empty() {
		return false, nil
	}
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil {
		return false, err
	}
	if sess.State != domain.SessionActive {
		return false, nil
	}
	if sess.ExpiresAt != nil && sess.ExpiresAt.Before(time.Now()) {
		return true, nil
	}
	a, err := auth.For(sess.Mode)
	if err != nil {
		return false, err
	}
	ok, err := a.Validate(ctx, sess)
	if err != nil {
		return false, err
	}
	return !ok, nil
}

// pauseForExpiredSession marks the session Expired and moves the scan to
// AwaitingAuth, pausing its execution exactly like an operator Pause (no
// further target-facing work proceeds) until Resume re-establishes the
// session. Mirrors Pause's own lock discipline (c.mu held for the whole
// operation; mutate's scanMu nests inside it).
func (c *Controller) pauseForExpiredSession(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ex, ok := c.running[scanID]
	if !ok {
		return nil // execution already gone; nothing to pause
	}
	sc, err := c.mutate(ctx, scanID, func(s *domain.Scan) error {
		return transition(s, domain.ScanAwaitingAuth)
	})
	if err != nil {
		return err
	}
	if !sc.SessionID.Empty() {
		if sess, err := c.store.Sessions().Get(ctx, sc.SessionID); err == nil && sess.State != domain.SessionExpired {
			sess.State = domain.SessionExpired
			sess.UpdatedAt = time.Now()
			if err := c.store.Sessions().Update(ctx, sess); err != nil {
				c.log.Warn("mark session expired", "scan", scanID, "err", err)
			}
		}
	}
	ex.pause()
	c.log.Info("scan paused: session expired, awaiting re-authentication", "scan", scanID)
	return nil
}

func (c *Controller) poolConfig(sc *domain.Scan) worker.Config {
	return worker.Config{
		ScanID: sc.ID,
		Groups: []worker.GroupSpec{
			{Name: GroupDiscovery, Types: []domain.JobType{domain.JobDiscovery}, Size: sc.Config.DiscoveryConcurrency},
			{Name: GroupHTTP, Types: []domain.JobType{domain.JobTest, domain.JobIDOR, domain.JobAccessControl, domain.JobDisclosure}, Size: sc.Config.HTTPConcurrency},
			{Name: GroupBrowser, Types: []domain.JobType{domain.JobVerify, domain.JobDOMXSS}, Size: minBrowserWorkers(sc.Config.BrowserConcurrency)},
		},
		LeaseDuration: c.opts.LeaseDuration,
		Heartbeat:     c.opts.Heartbeat,
		IdlePoll:      c.opts.IdlePoll,
	}
}

// minBrowserWorkers clamps the browser group to at least one worker. Unlike
// HTTP/discovery concurrency, 0 here is a legitimate, deliberately-supported
// configuration — "no browser available for this scan" (Options.Browser nil,
// or the operator just set it to 0) — and verifyExecutor already handles that
// by skipping JobVerify jobs gracefully (verification.Stub → skipped, not
// failed; see verify_test.go's TestVerifyHandleNoBrowserConfiguredSkips). That
// guarantee requires at least one worker to actually LEASE those jobs so the
// handler gets a chance to skip them — a zero-sized group never leases
// anything, so a reflected GET candidate's JobVerify would sit queued forever
// and the scan would never complete.
func minBrowserWorkers(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

// mutate is the single path for read-modify-write of a scan row. It serializes
// writers (scanMu), loads the current row, applies fn, stamps UpdatedAt, and
// persists. fn may return errSkipWrite to leave the row untouched.
func (c *Controller) mutate(ctx context.Context, id domain.ID, fn func(*domain.Scan) error) (*domain.Scan, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()

	sc, err := c.store.Scans().Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := fn(sc); err != nil {
		if errors.Is(err, errSkipWrite) {
			return sc, nil
		}
		return nil, err
	}
	sc.UpdatedAt = time.Now()
	if err := c.store.Scans().Update(ctx, sc); err != nil {
		return nil, err
	}
	return sc, nil
}

// transition validates and applies a scan state change. A no-op when already in
// the target state.
func transition(sc *domain.Scan, next domain.ScanState) error {
	if sc.State == next {
		return nil
	}
	if !sc.State.CanTransitionTo(next) {
		return fmt.Errorf("%w: %s -> %s", ErrBadState, sc.State, next)
	}
	sc.State = next
	return nil
}

// failScan records a terminal failure for a scan (best effort).
func (c *Controller) failScan(id domain.ID, reason string) {
	ended := time.Now()
	_, err := c.mutate(context.Background(), id, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanFailed); err != nil {
			return err
		}
		s.Error = reason
		s.EndedAt = &ended
		return nil
	})
	if err != nil {
		c.log.Warn("could not record scan failure", "scan", id, "err", err)
	} else {
		c.log.Error("scan failed", "scan", id, "reason", reason)
	}
}
