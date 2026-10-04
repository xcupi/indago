package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
)

// Manager orchestrates discovery for a scan: it runs every registered source
// concurrently against a shared Collector, so endpoints and parameters are
// persisted and turned into test jobs as they are found. It honors pause/resume
// (via a shared Gate) and cancellation (via context).
type Manager struct {
	store    store.Store
	queue    queue.Queue
	registry *Registry
	cfg      Config
	log      *slog.Logger
	gate     *Gate
}

// NewManager builds a discovery manager. A nil logger uses slog.Default.
func NewManager(st store.Store, q queue.Queue, registry *Registry, cfg Config, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		store:    st,
		queue:    q,
		registry: registry,
		cfg:      cfg.withDefaults(),
		log:      log,
		gate:     NewGate(),
	}
}

// Pause halts discovery network work (in-flight work finishes; no new work
// starts) until Resume. It maps to a scan's pause.
func (m *Manager) Pause() { m.gate.Pause() }

// Resume continues after Pause.
func (m *Manager) Resume() { m.gate.Resume() }

// Paused reports whether discovery is paused.
func (m *Manager) Paused() bool { return m.gate.Paused() }

// RunParams are the inputs to a discovery run.
type RunParams struct {
	ScanID    domain.ID
	Scope     domain.Scope
	SeedURLs  []string
	SessionID domain.ID
	Wordlist  string
}

// RunResult summarizes a completed discovery run.
type RunResult struct {
	Endpoints  int
	Parameters int
	Jobs       int
	Errors     []error
}

// Run executes all registered sources concurrently and returns when they finish
// or the context is canceled. The caller typically runs this in a goroutine so
// testing proceeds in parallel; the Collector enqueues test jobs as discovery
// progresses, so testing never waits for discovery to finish.
func (m *Manager) Run(ctx context.Context, p RunParams) (*RunResult, error) {
	collector := NewCollector(m.store, m.queue, p.ScanID, p.Scope, m.cfg, m.log)
	in := Input{
		ScanID:    p.ScanID,
		Scope:     p.Scope,
		SeedURLs:  p.SeedURLs,
		SessionID: p.SessionID,
		Wordlist:  p.Wordlist,
		Gate:      m.gate,
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, s := range m.registry.Sources() {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			err := s.Run(ctx, in, collector)
			if err == nil {
				return
			}
			// Cancellation and limit-reached are normal stops, not failures.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLimitReached) {
				return
			}
			mu.Lock()
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			mu.Unlock()
		}(s)
	}
	wg.Wait()

	eps, params, jobs := collector.Counts()
	res := &RunResult{Endpoints: eps, Parameters: params, Jobs: jobs, Errors: errs}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, nil
}
