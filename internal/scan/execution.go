package scan

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

// execution is the live machinery for one running scan: a worker pool draining
// the queue, a discovery run feeding it, and a monitor that completes the scan.
type execution struct {
	scanID domain.ID
	pool   *worker.Pool
	disc   *discovery.Manager // nil when discovery had already completed

	cancel   context.CancelFunc
	discDone chan struct{} // closed when the discovery goroutine has exited
	monDone  chan struct{} // closed when the monitor goroutine has exited

	// discFinished is set once discovery completed normally (or was skipped
	// because it had already completed before a restart).
	discFinished atomic.Bool
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
	eng := newScopedEngine(c.opts.HTTP, scope)
	if cookies := c.sessionCookiesFor(ctx, sc, target); len(cookies) > 0 {
		eng = eng.WithSessionCookies(cookies)
	}

	handlers := c.opts.Handlers
	if handlers == nil {
		handlers = c.defaultHandlers(eng, scope)
	}
	pool := worker.New(c.queue, handlers, c.poolConfig(sc), c.log)
	if err := pool.Start(runCtx); err != nil {
		cancel()
		return nil, err
	}

	ex := &execution{
		scanID:   sc.ID,
		pool:     pool,
		cancel:   cancel,
		discDone: make(chan struct{}),
		monDone:  make(chan struct{}),
	}

	if sc.Discovery == domain.DiscoveryComplete {
		// Already discovered before a restart: don't crawl again.
		ex.discFinished.Store(true)
		close(ex.discDone)
	} else {
		cfg := c.discoveryConfig(sc)
		reg := discovery.NewRealRegistry(eng, c.opts.Browser, cfg)
		ex.disc = discovery.NewManager(c.store, c.queue, reg, cfg, c.log)
		seeds := seedsFor(sc, target)
		go c.runDiscovery(runCtx, ex, sc, scope, seeds)
	}

	go c.monitor(runCtx, ex)
	return ex, nil
}

// discoveryConfig derives the per-scan discovery config from the controller
// defaults and the scan's own concurrency and crawl-extent controls. The crawl
// controls are read here (at discovery start); a value of 0 means "keep the
// server/profile default", except QuickScan which forces seeds-only.
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
	if sc.Config.MaxPages > 0 {
		cfg.MaxPages = sc.Config.MaxPages
	}
	if sc.Config.MaxEndpoints > 0 {
		cfg.MaxEndpoints = sc.Config.MaxEndpoints
	}
	if sc.Config.QuickScan {
		cfg.MaxDepth = 0 // seeds only: do not follow links
	}
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
		"endpoints", res.Endpoints, "parameters", res.Parameters, "jobs", res.Jobs)
}

// stopExecution tears an execution down and waits for its goroutines. The caller
// must NOT hold c.mu. waitMonitor must be false when called from the monitor
// goroutine itself.
func (c *Controller) stopExecution(ex *execution, waitMonitor bool) {
	ex.cancel()
	ex.pool.Stop()
	<-ex.discDone
	if waitMonitor {
		<-ex.monDone
	}
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
		return false
	}
	return c.finish(ctx, ex, false)
}

// finish completes the scan from the monitor. When cancelJobs is set (stop
// policy) the scan's remaining jobs are canceled too. It returns true when the
// execution was finished (so the monitor exits) and false when the scan is not
// in a completable state and keeps running.
//
// Ordering:
//
//  1. Take ownership under mu: confirm the scan is still RUNNING and remove the
//     execution from the map in one critical section. Pause/Resume/Cancel also
//     take mu, so the state cannot change between the check and the removal.
//  2. Tear the execution down (discovery can no longer enqueue; interrupted
//     workers finish re-queueing their retries), THEN cancel remaining jobs.
//  3. Only now record COMPLETED, so a status reader can never observe a
//     completed scan that still has pending jobs.
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
	delete(c.running, ex.scanID)
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
	if _, err := c.mutate(bg, ex.scanID, func(s *domain.Scan) error {
		if err := transition(s, domain.ScanCompleted); err != nil {
			return err
		}
		s.EndedAt = &ended
		s.Stats = stats
		return nil
	}); err != nil {
		// A concurrent Cancel won the race after we took ownership; it records the
		// terminal state itself.
		c.log.Info("finish: scan state changed during completion", "scan", ex.scanID, "err", err)
		return true
	}
	c.log.Info("scan completed", "scan", ex.scanID, "stopped_early", cancelJobs)
	return true
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
