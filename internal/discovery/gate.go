package discovery

import (
	"context"
	"sync"
)

// Gate is a cooperative pause/resume primitive. Sources call Wait before each
// unit of network work; when the gate is paused, Wait blocks until Resume is
// called or the context is canceled. A Gate starts in the resumed state.
//
// It lets discovery honor a scan's pause/resume without aborting in-flight work,
// while still respecting cancellation.
type Gate struct {
	mu     sync.Mutex
	paused bool
	ch     chan struct{} // closed while resumed; open (fresh) while paused
}

// NewGate returns a Gate in the resumed state.
func NewGate() *Gate {
	ch := make(chan struct{})
	close(ch) // resumed = closed channel (Wait proceeds immediately)
	return &Gate{ch: ch}
}

// Pause blocks subsequent Wait calls until Resume. Idempotent.
func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		g.paused = true
		g.ch = make(chan struct{}) // open channel blocks waiters
	}
}

// Resume unblocks waiters. Idempotent.
func (g *Gate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		g.paused = false
		close(g.ch)
	}
}

// Paused reports whether the gate is currently paused.
func (g *Gate) Paused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// Wait returns nil once the gate is resumed, or the context's error if it is
// canceled first. It returns immediately when the gate is not paused.
func (g *Gate) Wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		ch := g.ch
		paused := g.paused
		g.mu.Unlock()
		if !paused {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			// Resumed (or re-paused); loop to re-check state.
		}
	}
}
