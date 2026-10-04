package worker

import (
	"context"
	"sync"
	"time"
)

// rateLimiter is a minimal, dependency-free request-rate limiter. It spaces
// permits evenly (1 / rps) so scanning stays conservative and predictable. A
// nil *rateLimiter means "no limit".
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newRateLimiter returns a limiter allowing rps permits per second, or nil when
// rps <= 0 (unlimited).
func newRateLimiter(rps float64) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / rps)}
}

// Wait blocks until the next permit is available or ctx is done. A nil limiter
// returns immediately.
func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
