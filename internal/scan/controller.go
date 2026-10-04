// Package scan orchestrates scan lifecycle: it enforces scope, establishes the
// reused authentication session, wires the worker pool to the persistent queue,
// and exposes pause/resume/cancel plus runtime reconfiguration.
//
// Phase 0 note: the controller wires no-op job handlers (see handlers.go), so a
// running scan exercises the full queue/worker pipeline without performing any
// target testing. Scope enforcement is real and fails closed.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// Sentinel errors.
var (
	ErrScopeRequired = errors.New("scan: explicit scope required before scanning")
	ErrScopeEmpty    = errors.New("scan: scope is empty (fails closed)")
	ErrOutOfScope    = errors.New("scan: target is out of scope")
	ErrNotRunning    = errors.New("scan: not running")
	ErrBadState      = errors.New("scan: illegal state transition")
)

// Options tunes worker-pool timing. Zero values get sane defaults.
type Options struct {
	LeaseDuration time.Duration
	Heartbeat     time.Duration
	IdlePoll      time.Duration
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
	return o
}

// Controller coordinates scans.
type Controller struct {
	store   store.Store
	queue   queue.Queue
	log     *slog.Logger
	version string
	opts    Options

	mu      sync.Mutex
	running map[domain.ID]*execution
	baseCtx context.Context
}

type execution struct {
	pool *worker.Pool
}

// NewController builds a controller. A nil logger uses slog.Default.
func NewController(st store.Store, q queue.Queue, log *slog.Logger, version string, opts Options) *Controller {
	if log == nil {
		log = slog.Default()
	}
	return &Controller{
		store:   st,
		queue:   q,
		log:     log,
		version: version,
		opts:    opts.withDefaults(),
		running: make(map[domain.ID]*execution),
		baseCtx: context.Background(),
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
	scope, err := c.store.Scopes().GetByProject(ctx, p.ProjectID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrScopeRequired
	}
	if err != nil {
		return nil, fmt.Errorf("scan: scope: %w", err)
	}
	if len(scope.IncludeHosts) == 0 {
		return nil, ErrScopeEmpty
	}
	if d := scope.Permits(target.BaseURL); !d.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
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
	c.log.Info("scan created", "scan", sc.ID, "profile", profile, "auth", mode)
	return sc, nil
}

// Start establishes the session and begins processing a Created scan.
func (c *Controller) Start(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if sc.State != domain.ScanCreated {
		return fmt.Errorf("%w: can only start a created scan (state=%s)", ErrBadState, sc.State)
	}

	// Defense in depth: re-check scope at start.
	scope, err := c.store.Scopes().GetByProject(ctx, sc.ProjectID)
	if err != nil {
		return fmt.Errorf("scan: scope: %w", err)
	}
	target, err := c.store.Targets().Get(ctx, sc.TargetID)
	if err != nil {
		return err
	}
	if d := scope.Permits(target.BaseURL); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}

	// Establish the reused session.
	if err := c.establishSession(ctx, sc); err != nil {
		return err
	}

	// Transition to running.
	if err := c.setState(ctx, sc, domain.ScanRunning); err != nil {
		return err
	}
	started := time.Now()
	sc.StartedAt = &started
	sc.UpdatedAt = started
	if err := c.store.Scans().Update(ctx, sc); err != nil {
		return err
	}

	// Build and start the per-scan worker pool.
	pool := worker.New(c.queue, phase0Handlers(c.log), c.poolConfig(sc), c.log)
	if err := pool.Start(c.baseCtx); err != nil {
		return err
	}
	c.running[sc.ID] = &execution{pool: pool}
	c.log.Info("scan started", "scan", sc.ID)
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

// Pause stops leasing for a running scan; in-flight jobs continue.
func (c *Controller) Pause(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ex, ok := c.running[scanID]
	if !ok {
		return ErrNotRunning
	}
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if err := c.setState(ctx, sc, domain.ScanPaused); err != nil {
		return err
	}
	ex.pool.Pause()
	return nil
}

// Resume continues a paused scan.
func (c *Controller) Resume(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ex, ok := c.running[scanID]
	if !ok {
		return ErrNotRunning
	}
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if err := c.setState(ctx, sc, domain.ScanRunning); err != nil {
		return err
	}
	ex.pool.Resume()
	return nil
}

// Cancel cancels a scan: stops its pool and cancels its queued/active jobs.
func (c *Controller) Cancel(ctx context.Context, scanID domain.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	if sc.State.IsTerminal() {
		return nil
	}
	if err := c.setState(ctx, sc, domain.ScanCanceling); err != nil {
		return err
	}
	if ex, ok := c.running[scanID]; ok {
		ex.pool.Stop()
		delete(c.running, scanID)
	}
	if _, err := c.queue.CancelScan(ctx, scanID); err != nil {
		return err
	}
	if err := c.setState(ctx, sc, domain.ScanCanceled); err != nil {
		return err
	}
	ended := time.Now()
	sc.EndedAt = &ended
	sc.UpdatedAt = ended
	return c.store.Scans().Update(ctx, sc)
}

// Reconfigure changes a scan's concurrency/rate at runtime. The new config is
// persisted and, if the scan is running, applied to the live worker pool.
func (c *Controller) Reconfigure(ctx context.Context, scanID domain.ID, cfg domain.ScanConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return err
	}
	sc.Config = cfg
	sc.Profile = domain.ProfileCustom
	sc.UpdatedAt = time.Now()
	if err := c.store.Scans().Update(ctx, sc); err != nil {
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

// IsRunning reports whether the controller currently manages a pool for scanID.
func (c *Controller) IsRunning(scanID domain.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.running[scanID]
	return ok
}

// Recover requeues orphaned active jobs after a restart. Call once on startup
// before starting scans.
func (c *Controller) Recover(ctx context.Context) (int, error) {
	return c.queue.Recover(ctx)
}

// Shutdown stops all running pools (without changing scan state), for graceful
// process shutdown.
func (c *Controller) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ex := range c.running {
		ex.pool.Stop()
		delete(c.running, id)
	}
}

// setState validates and persists a scan state transition (caller holds c.mu or
// is otherwise synchronized for the scan).
func (c *Controller) setState(ctx context.Context, sc *domain.Scan, next domain.ScanState) error {
	if sc.State == next {
		return nil
	}
	if !sc.State.CanTransitionTo(next) {
		return fmt.Errorf("%w: %s -> %s", ErrBadState, sc.State, next)
	}
	sc.State = next
	sc.UpdatedAt = time.Now()
	return c.store.Scans().Update(ctx, sc)
}
