// Package worker implements Indago's concurrent worker pool. Workers lease jobs
// from a queue.Queue and execute registered handlers.
//
// The pool is organized into named groups (e.g. "discovery", "http", "browser"),
// each serving a set of job types with its own worker count. Group sizes and the
// request rate can be changed at runtime, and the whole pool can be paused and
// resumed — satisfying the spec's independently-configurable, runtime-tunable
// concurrency controls.
//
// Phase 0 note: handlers are supplied by the caller. The scan controller wires
// no-op handlers in Phase 0, so starting a pool performs no target traffic.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// ErrPermanent marks a handler failure that must not be retried. Any other
// error is treated as transient and retried subject to the job's MaxAttempts.
var ErrPermanent = errors.New("worker: permanent failure")

// ErrJobTimeout marks an attempt the pool abandoned because it outlived the
// configured per-job deadline. It is retryable (a fresh worker gets the next
// attempt); only an exhausted MaxAttempts makes the job terminal.
var ErrJobTimeout = errors.New("worker: job deadline exceeded")

// Handler executes a single job. Handlers must honor ctx cancellation.
type Handler interface {
	Handle(ctx context.Context, job *domain.TestJob) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, job *domain.TestJob) error

// Handle implements Handler.
func (f HandlerFunc) Handle(ctx context.Context, job *domain.TestJob) error { return f(ctx, job) }

// GroupSpec declares a worker group: a name, the job types it serves, and its
// initial worker count.
type GroupSpec struct {
	Name  string
	Types []domain.JobType
	Size  int
}

// Config tunes pool behavior.
type Config struct {
	// ScanID restricts this pool to one scan's jobs (empty = any scan). A
	// per-scan pool lets pause/cancel affect only that scan.
	ScanID        domain.ID
	Groups        []GroupSpec
	LeaseDuration time.Duration // lease validity per job
	Heartbeat     time.Duration // lease-extension interval while running
	IdlePoll      time.Duration // sleep between empty lease attempts
	// ShutdownTimeout bounds how long Stop waits for in-flight handlers to
	// return. A handler that ignores context cancellation (a hung network or
	// browser call, say) would otherwise block Stop — and so the whole
	// process's graceful shutdown — forever; past this timeout Stop logs a
	// warning and returns anyway, abandoning that handler's goroutine rather
	// than waiting on it indefinitely.
	ShutdownTimeout time.Duration
	// JobTimeout bounds one handler attempt. When a handler outlives it the
	// pool stops the attempt (cancels its context, which also stops lease
	// heartbeating), records a retryable failure, and abandons the handler
	// goroutine so the worker slot is freed: a wedged browser/driver call must
	// not hold a whole worker group hostage until the process exits. The job
	// is retried on a fresh worker, up to its MaxAttempts, then becomes dead.
	// Zero uses the default (15 minutes).
	JobTimeout time.Duration
	// RecordTimeout bounds the write that records a job's outcome. It is
	// deliberately independent of the worker's own context: that context is
	// already canceled when a stopping worker records "this attempt did not
	// finish", and a canceled context makes a SQLite write fail, leaving the
	// job active and invisible until lease expiry.
	RecordTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 60 * time.Second
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = c.LeaseDuration / 3
	}
	if c.IdlePoll <= 0 {
		c.IdlePoll = 200 * time.Millisecond
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.JobTimeout <= 0 {
		c.JobTimeout = 15 * time.Minute
	}
	if c.RecordTimeout <= 0 {
		c.RecordTimeout = 15 * time.Second
	}
	return c
}

// Pool is a dynamic, group-based worker pool.
type Pool struct {
	q        queue.Queue
	handlers map[domain.JobType]Handler
	log      *slog.Logger
	cfg      Config

	mu      sync.Mutex
	groups  map[string]*groupState
	paused  atomic.Bool
	started bool

	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type groupState struct {
	spec    GroupSpec
	workers []context.CancelFunc // one per live worker
	nextID  int
}

// New creates a pool over q with the given handlers and config. A nil logger
// uses slog.Default.
func New(q queue.Queue, handlers map[domain.JobType]Handler, cfg Config, log *slog.Logger) *Pool {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	p := &Pool{
		q:        q,
		handlers: handlers,
		log:      log,
		cfg:      cfg,
		groups:   make(map[string]*groupState),
	}
	return p
}

// Start launches all configured groups. It is safe to call once; subsequent
// calls return an error. Workers run until Stop or ctx cancellation.
func (p *Pool) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return errors.New("worker: pool already started")
	}
	p.baseCtx, p.cancel = context.WithCancel(ctx)
	p.started = true

	for _, spec := range p.cfg.Groups {
		g := &groupState{spec: spec}
		p.groups[spec.Name] = g
		p.scaleLocked(g, spec.Size)
	}
	p.log.Info("worker pool started", "groups", len(p.groups))
	return nil
}

// Pause stops workers from leasing new jobs. In-flight jobs continue. Idempotent.
func (p *Pool) Pause() {
	if p.paused.CompareAndSwap(false, true) {
		p.log.Info("worker pool paused")
	}
}

// Resume allows workers to lease again. Idempotent.
func (p *Pool) Resume() {
	if p.paused.CompareAndSwap(true, false) {
		p.log.Info("worker pool resumed")
	}
}

// Paused reports whether the pool is currently paused.
func (p *Pool) Paused() bool { return p.paused.Load() }

// Resize changes the worker count of a named group at runtime.
func (p *Pool) Resize(group string, n int) error {
	if n < 0 {
		return fmt.Errorf("worker: negative size %d", n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.groups[group]
	if !ok {
		return fmt.Errorf("worker: unknown group %q", group)
	}
	p.scaleLocked(g, n)
	p.log.Info("worker group resized", "group", group, "size", n)
	return nil
}

// Sizes returns a snapshot of each group's current worker count.
func (p *Pool) Sizes() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.groups))
	for name, g := range p.groups {
		out[name] = len(g.workers)
	}
	return out
}

// Serves reports whether this pool is configured to run type t at all: a
// registered handler and a worker group that names it. The group's current size
// is deliberately ignored — a zero-sized group is an operator-reconfigurable
// state (the scan can be given workers later), not proof that the job can never
// run. A type with no handler and no group, by contrast, can never be leased by
// anything, which is what a caller uses to detect a queue that cannot drain.
func (p *Pool) Serves(t domain.JobType) bool {
	if _, ok := p.handlers[t]; !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, g := range p.groups {
		for _, gt := range g.spec.Types {
			if gt == t {
				return true
			}
		}
	}
	return false
}

// Stop cancels all workers and waits for them to exit.
func (p *Pool) Stop() {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.started = false
	p.mu.Unlock()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		p.log.Info("worker pool stopped")
	case <-time.After(p.cfg.ShutdownTimeout):
		p.log.Warn("worker pool stop timed out; abandoning still-running handler(s) that did not honor context cancellation",
			"timeout", p.cfg.ShutdownTimeout)
	}
}

// scaleLocked grows or shrinks a group to n workers. Caller holds p.mu.
func (p *Pool) scaleLocked(g *groupState, n int) {
	cur := len(g.workers)
	switch {
	case n > cur:
		for i := cur; i < n; i++ {
			wctx, wcancel := context.WithCancel(p.baseCtx)
			g.workers = append(g.workers, wcancel)
			id := fmt.Sprintf("%s-%d", g.spec.Name, g.nextID)
			g.nextID++
			p.wg.Add(1)
			go p.runWorker(wctx, g.spec, id)
		}
	case n < cur:
		for i := n; i < cur; i++ {
			g.workers[i]() // cancel excess worker
		}
		g.workers = g.workers[:n]
	}
}

// runWorker is the main loop of a single worker.
func (p *Pool) runWorker(ctx context.Context, spec GroupSpec, workerID string) {
	defer p.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		if p.paused.Load() {
			if sleepCtx(ctx, p.cfg.IdlePoll) != nil {
				return
			}
			continue
		}

		job, err := p.q.Lease(ctx, workerID, p.cfg.ScanID, spec.Types, p.cfg.LeaseDuration)
		if errors.Is(err, queue.ErrNoJobs) {
			if sleepCtx(ctx, p.cfg.IdlePoll) != nil {
				return
			}
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("lease error", "worker", workerID, "err", err)
			if sleepCtx(ctx, p.cfg.IdlePoll) != nil {
				return
			}
			continue
		}
		p.process(ctx, spec, job)
	}
}

// process runs a job's handler with lease heartbeating, a hard per-attempt
// deadline, and records the outcome. The deadline matters as much as the
// heartbeat: a handler wedged in a browser/driver call that never returns
// would otherwise keep its lease alive forever and monopolize its worker group,
// starving every job queued behind it.
func (p *Pool) process(ctx context.Context, spec GroupSpec, job *domain.TestJob) {
	handler, ok := p.handlers[job.Type]
	if !ok {
		p.log.Error("no handler for job type", "type", job.Type, "job", job.ID)
		p.recordCtx(ctx, func(rctx context.Context) {
			_ = p.q.Fail(rctx, job.ID, "no handler registered for type "+string(job.Type), false)
		})
		return
	}

	hctx, hcancel := context.WithCancel(ctx)
	defer hcancel()
	go p.heartbeat(hctx, job.ID)

	err, finished := p.runHandler(hctx, job, handler)
	if !finished {
		// Stop the heartbeat BEFORE recording anything: this attempt is over,
		// and the record write itself releases the lease. The handler
		// goroutine is abandoned deliberately — waiting for it is what let one
		// wedged browser call stall an entire scan.
		hcancel()
		p.recordFail(ctx, job, fmt.Errorf("%w after %s", ErrJobTimeout, p.cfg.JobTimeout))
		return
	}

	if err != nil {
		if ctx.Err() != nil {
			// The worker itself is stopping, not the job failing. Leave the
			// lease exactly as it is: restart recovery (Queue.Recover) and the
			// controller's lease reaper are the documented paths for that, and
			// writing here with a canceled context would either silently abort
			// (SQLite) or consume an attempt for a non-failure (in-memory).
			p.logRecordErr(ctx, "leave job for recovery", job.ID, err)
			return
		}
		p.recordFail(ctx, job, err)
		return
	}
	if ctx.Err() != nil {
		// The handler returned success, but the worker was stopped mid-attempt:
		// any side effect it had not finished (child jobs still being enqueued,
		// evidence still being written) may be incomplete, so "succeeded" is
		// not trustworthy. Leave it active and let recovery replay the whole
		// attempt — the same contract as a failed attempt during shutdown.
		p.logRecordErr(ctx, "leave job for recovery", job.ID, ctx.Err())
		return
	}
	p.recordComplete(ctx, job)
}

// runHandler executes one attempt and reports whether it finished within the
// per-job deadline. A handler that outlives its deadline is left running in its
// own goroutine (it may be blocked in a driver call that ignores context); the
// buffered result channel means it can still return later without leaking.
func (p *Pool) runHandler(ctx context.Context, job *domain.TestJob, handler Handler) (error, bool) {
	done := make(chan error, 1)
	go func() { done <- handler.Handle(ctx, job) }()

	t := time.NewTimer(p.cfg.JobTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err, true
	case <-t.C:
		// The handler may have finished at the same instant the deadline
		// fired; prefer its real result over a spurious timeout.
		select {
		case err := <-done:
			return err, true
		default:
			return nil, false
		}
	}
}

// recordFail marks the job failed using a context that can still write. It is
// used for authoritative failures (a handler error, or the per-job deadline),
// and the write must not be lost just because the worker's own context was
// canceled at the same moment: a canceled context makes a SQLite write abort
// silently, leaving the job active with a lease nothing will extend or release.
func (p *Pool) recordFail(ctx context.Context, job *domain.TestJob, cause error) {
	retry := !errors.Is(cause, ErrPermanent)
	p.recordCtx(ctx, func(rctx context.Context) {
		if ferr := p.q.Fail(rctx, job.ID, cause.Error(), retry); ferr != nil {
			p.logRecordErr(ctx, "mark job failed", job.ID, ferr)
		}
	})
}

// recordComplete marks the job succeeded, under the same write-safe context.
func (p *Pool) recordComplete(ctx context.Context, job *domain.TestJob) {
	p.recordCtx(ctx, func(rctx context.Context) {
		if cerr := p.q.Complete(rctx, job.ID); cerr != nil {
			p.logRecordErr(ctx, "mark job complete", job.ID, cerr)
		}
	})
}

// recordCtx runs one outcome write with a fresh bounded context derived from
// ctx (values preserved, cancellation/deadline dropped).
func (p *Pool) recordCtx(ctx context.Context, write func(context.Context)) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.cfg.RecordTimeout)
	defer cancel()
	write(rctx)
}

// logRecordErr logs a failure to record a job's outcome. ErrNotLeasable is
// expected when the job already reached a terminal state (cancel won the race,
// or another worker reclaimed an expired lease) — it must not be retried or
// resurrected, but it must still be visible. The worker's own cancellation is
// also expected during shutdown.
func (p *Pool) logRecordErr(ctx context.Context, msg string, jobID domain.ID, err error) {
	switch {
	case errors.Is(err, queue.ErrNotLeasable):
		p.log.Info(msg+": job is no longer active (completed, cancelled, or reclaimed)", "job", jobID, "err", err)
	case ctx.Err() != nil:
		p.log.Info(msg+": execution stopping", "job", jobID, "err", err)
	default:
		p.log.Warn(msg, "job", jobID, "err", err)
	}
}

// heartbeat periodically extends the job's lease until ctx is canceled. A
// failed extension is logged and retried on the next tick rather than ending
// the loop — a transient store error (a momentary SQLITE_BUSY, for example)
// must not permanently stop heartbeating while the handler keeps running:
// that would let the lease expire out from under a job that is still
// healthy, with nothing left to extend it for the rest of the job's run.
func (p *Pool) heartbeat(ctx context.Context, jobID domain.ID) {
	t := time.NewTicker(p.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.q.Heartbeat(ctx, jobID, p.cfg.LeaseDuration); err != nil {
				if ctx.Err() == nil {
					p.log.Warn("heartbeat failed; will retry next tick", "job", jobID, "err", err)
				}
			}
		}
	}
}

// sleepCtx sleeps for d or until ctx is done, returning ctx.Err() if canceled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
