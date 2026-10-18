// Package ratelimit provides the per-scan request-rate limiter. One Limiter is
// created per scan execution and shared by every target-facing path of that
// scan (raw HTTP including redirect hops, browser discovery navigations, and
// browser verification navigations), so a scan's requests_per_second is one
// budget, not one per subsystem. Its rate can be changed in place (SetRate),
// which is how a runtime reconfigure reaches paths that are already running.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter spaces permits evenly (one per 1/rps). A nil *Limiter, or one with a
// rate <= 0, is unlimited. It is safe for concurrent use. No lock is held while
// a caller sleeps or does I/O: a caller reserves its slot under the lock and
// then waits outside it.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration // 0 = unlimited
	next     time.Time     // earliest time the next permit may be used
	changed  chan struct{} // closed (and replaced) by every SetRate
}

// New returns a limiter allowing rps permits per second; rps <= 0 is unlimited.
func New(rps float64) *Limiter {
	l := &Limiter{changed: make(chan struct{})}
	l.interval = intervalFor(rps)
	return l
}

func intervalFor(rps float64) time.Duration {
	if rps <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / rps)
}

// SetRate changes the rate (requests/second; <= 0 is unlimited). Permits
// reserved after the call use the new rate. Callers already queued wake up
// immediately if the new rate is unlimited; otherwise they keep the slot they
// reserved (so a lowered rate is honoured from the next reservation on).
func (l *Limiter) SetRate(rps float64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.interval = intervalFor(rps)
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
}

// Wait blocks until the caller's permit is due, or ctx is done. Unlimited
// limiters return immediately.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.interval <= 0 {
		l.mu.Unlock()
		return nil
	}
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	changed := l.changed
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
			l.mu.Lock()
			unlimited := l.interval <= 0
			changed = l.changed
			l.mu.Unlock()
			if unlimited {
				return nil
			}
		}
	}
}
