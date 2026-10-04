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
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
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

	// HTTP is the engine discovery uses. It is wrapped in a scope-enforcing
	// engine per scan, which follows redirects itself — so HTTP MUST be built with
	// FollowRedirects=false. Nil means "no network discovery" (httpengine.Stub):
	// seeds are still registered, nothing is fetched.
	HTTP httpengine.Engine

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
	return &Controller{
		store:      st,
		queue:      q,
		log:        log,
		version:    version,
		opts:       opts.withDefaults(),
		baseCtx:    ctx,
		baseCancel: cancel,
		running:    make(map[domain.ID]*execution),
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
	// SeedURLs are discovery seeds. Empty means the target's base URL. Every seed
	// must be in scope; an out-of-scope seed is rejected rather than silently
	// dropped.
	SeedURLs []string
}

// CreateScan validates scope and inputs, then persists a scan in the Created
// state together with a pending session. It performs no testing.
func (c *Controller) CreateScan(ctx context.Context, p CreateScanParams) (*domain.Scan, error) {
	if _, err := c.store.Projects().Get(ctx, p.ProjectID); err != nil {
		return nil, fmt.Errorf("scan: project: %w", err)
	}
	target, err := c.store.Targets().Get(ctx, p.TargetID)
	if err != nil {
		return nil, fmt.Errorf("scan: target: %w", err)
	}
	if target.ProjectID != p.ProjectID {
		return nil, errors.New("scan: target does not belong to project")
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

	mode := p.AuthMode
	if !mode.IsValid() {
		mode = domain.AuthAnonymous
	}
	stop := p.Stop
	if !stop.Mode.IsValid() {
		stop.Mode = domain.StopContinueAll
	}

	now := time.Now()
	sess := &domain.Session{
		ID: domain.NewID(), ScanID: domain.NewID(), // ScanID set below once scan ID is known
		Mode: mode, State: domain.SessionNone, CreatedAt: now, UpdatedAt: now,
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

	if err := c.establishSession(ctx, sc); err != nil {
		return err
	}

	started := time.Now()
	sc, err = c.mutate(ctx, scanID, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanRunning); err != nil {
			return err
		}
		s.StartedAt = &started
		return nil
	})
	if err != nil {
		return err
	}

	ex, err := c.launch(ctx, sc, scope, target)
	if err != nil {
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

// Resume continues a paused scan. If the scan was restored after a restart (no
// live execution), Resume rebuilds the worker pool and discovery first.
func (c *Controller) Resume(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrShutdown
	}

	if ex, ok := c.running[scanID]; ok {
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

	sc, err = c.mutate(ctx, scanID, func(s *domain.Scan) error {
		return transition(s, domain.ScanRunning)
	})
	if err != nil {
		return err
	}
	ex, err := c.launch(ctx, sc, scope, target)
	if err != nil {
		// Put the scan back so the operator can retry.
		_, _ = c.mutate(context.Background(), scanID, func(s *domain.Scan) error {
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
		_ = ex.pool.Resize(GroupBrowser, cfg.BrowserConcurrency)
		ex.pool.SetRate(cfg.RequestsPerSecond)
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

	for _, ex := range exs {
		c.stopExecution(ex, true)
	}
	c.baseCancel()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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

func (c *Controller) establishSession(ctx context.Context, sc *domain.Scan) error {
	sess, err := c.store.Sessions().Get(ctx, sc.SessionID)
	if err != nil {
		return fmt.Errorf("scan: load session: %w", err)
	}
	a, err := auth.For(sess.Mode)
	if err != nil {
		return err
	}
	established, err := a.Establish(ctx, auth.Input{ScanID: sc.ID})
	if err != nil {
		return fmt.Errorf("scan: establish session: %w", err)
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

func (c *Controller) poolConfig(sc *domain.Scan) worker.Config {
	return worker.Config{
		ScanID: sc.ID,
		Groups: []worker.GroupSpec{
			{Name: GroupDiscovery, Types: []domain.JobType{domain.JobDiscovery}, Size: sc.Config.DiscoveryConcurrency},
			{Name: GroupHTTP, Types: []domain.JobType{domain.JobTest}, Size: sc.Config.HTTPConcurrency},
			{Name: GroupBrowser, Types: []domain.JobType{domain.JobVerify}, Size: sc.Config.BrowserConcurrency},
		},
		LeaseDuration:     c.opts.LeaseDuration,
		Heartbeat:         c.opts.Heartbeat,
		IdlePoll:          c.opts.IdlePoll,
		RequestsPerSecond: sc.Config.RequestsPerSecond,
	}
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
