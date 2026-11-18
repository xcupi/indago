// Package ratelimit provides the per-scan request-rate limiter. One Limiter is
// created per scan execution and shared by every target-facing path of that
// scan (raw HTTP including redirect hops, browser discovery navigations, and
// browser verification navigations), so a scan's requests_per_second is one
// budget, not one per subsystem. Its rate can be changed in place (SetRate),
// which is how a runtime reconfigure reaches paths that are already running.
package ratelimit

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

// Limiter spaces permits evenly (one per 1/rps), or with randomized ±jitter
// when configured for human-like pacing. A nil *Limiter, or one with a
// rate <= 0, is unlimited. It is safe for concurrent use. No lock is held while
// a caller sleeps or does I/O: a caller reserves its slot under the lock and
// then waits outside it.
//
// Spacing is measured between actual grants, not between reserved slots: a
// reservation only names the earliest time a permit may be used, and a grant
// that lands late (scheduler pressure, -race overhead) pushes the ones behind
// it back by the same amount instead of letting them burst to catch up.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration // 0 = unlimited
	jitter   float64       // [0, 0.9] fraction of interval for ±randomization
	next     time.Time     // earliest time the next reserved permit is due
	floor    time.Time     // earliest time the next actual grant may happen
	changed  chan struct{} // closed (and replaced) by every SetRate
}

// New returns a limiter allowing rps permits per second; rps <= 0 is unlimited.
func New(rps float64) *Limiter {
	l := &Limiter{changed: make(chan struct{})}
	l.interval = intervalFor(rps)
	return l
}

// NewWithJitter returns a limiter allowing rps permits per second with ±jitter
// (clamped to [0, 0.9]) randomized spacing around 1/rps for human-like pacing.
func NewWithJitter(rps, jitter float64) *Limiter {
	l := New(rps)
	l.SetJitter(jitter)
	return l
}

// SetJitter sets the randomized pacing fraction in [0, 0.9].
func (l *Limiter) SetJitter(jitter float64) {
	if l == nil {
		return
	}
	if jitter < 0 {
		jitter = 0
	} else if jitter > 0.9 {
		jitter = 0.9
	}
	l.mu.Lock()
	l.jitter = jitter
	l.mu.Unlock()
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

// stepLocked returns the spacing this permit opens once it is granted,
// randomized by ±jitter when configured. l.mu must be held.
func (l *Limiter) stepLocked() time.Duration {
	if l.jitter <= 0 {
		return l.interval
	}
	delta := (rand.Float64()*2 - 1) * l.jitter
	step := time.Duration(float64(l.interval) * (1 + delta))
	if step < time.Millisecond {
		step = time.Millisecond
	}
	return step
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
	// A permit is never due before now, nor before the spacing floor left by
	// the last actual grant: an idle gap must not be repaid as a burst, and a
	// late grant must not be caught up by the permits queued behind it.
	earliest := now
	if l.floor.After(earliest) {
		earliest = l.floor
	}
	if l.next.Before(earliest) {
		l.next = earliest
	}
	due := l.next
	step := l.stepLocked()
	l.next = due.Add(step)
	changed := l.changed
	l.mu.Unlock()

	for {
		timer := time.NewTimer(time.Until(due))
	wait:
		for {
			select {
			case <-timer.C:
				break wait
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-changed:
				l.mu.Lock()
				unlimited := l.interval <= 0
				changed = l.changed
				l.mu.Unlock()
				if unlimited {
					timer.Stop()
					return nil
				}
			}
		}

		l.mu.Lock()
		if l.interval <= 0 {
			l.mu.Unlock()
			return nil
		}
		now = time.Now()
		// The reserved slot is due, but a grant may only happen a full step
		// after the previous ACTUAL grant. Waking late therefore delays this
		// permit (and everything queued behind it) rather than shortening the
		// gap that follows it.
		if l.floor.After(now) {
			due = l.floor
			changed = l.changed
			l.mu.Unlock()
			continue
		}
		l.floor = now.Add(step)
		l.mu.Unlock()
		return nil
	}
}
