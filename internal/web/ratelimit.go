package web

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/indago/indago/internal/config"
)

// Per-client-IP rate limiting for the control API and /metrics.
//
// Clients are keyed by the host part of r.RemoteAddr only. X-Forwarded-For and
// X-Real-IP are deliberately ignored: any client can set them, so trusting them
// would let a caller pick a fresh bucket per request. Behind a reverse proxy
// every client therefore shares the proxy's address and bucket. Per-client
// limiting in that setup belongs in the proxy (see docs/deployment.md §1).
//
// /healthz and the static UI are not limited. The Host/CSRF guard runs before
// this limiter; the bearer-token check runs after it, so unauthenticated floods
// are limited too.

const (
	// rateIdleFloor is the minimum idle time before a bucket may be evicted.
	rateIdleFloor = 10 * time.Minute
	// rateSweepEvery bounds how often the bucket table is swept.
	rateSweepEvery = time.Minute
	// rateMaxKeys caps the number of tracked clients. At the cap, unknown
	// clients are refused (fail closed) rather than growing memory.
	rateMaxKeys = 10000
	// rateCapRetrySec is the Retry-After given to clients refused at the cap.
	rateCapRetrySec = 60
)

// metricsPath is the Prometheus scrape endpoint.
const metricsPath = "/metrics"

// isGuardedPath reports whether p is subject to rate limiting and bearer-token
// checks: the control API and the metrics endpoint. Health and the static UI
// are not.
func isGuardedPath(p string) bool {
	return isAPIPath(p) || p == metricsPath
}

type rateBucket struct {
	tokens    float64
	last      time.Time
	rejecting bool // a refusal was already logged for the current burst
}

type rateLimiter struct {
	mu        sync.Mutex
	rate      float64 // tokens added per second
	burst     float64 // bucket capacity
	now       func() time.Time
	buckets   map[string]*rateBucket
	maxKeys   int
	lastSweep time.Time
	sweeps    int
	capLogged time.Time
}

// rateDecision is the outcome of one allow call. It carries no locks or I/O so
// the caller can write the response after the limiter has released its mutex.
type rateDecision struct {
	Allowed       bool
	RetryAfterSec int  // whole seconds, >= 1, when refused
	StartOfBurst  bool // first refusal of a burst: log at Info, not Debug
}

// newRateLimiter builds a limiter with sustained rate tokens/second and a
// bucket of burst tokens. A nil now uses time.Now. Callers must only construct
// one for rate > 0; config.ServerConfig.Validate enforces that.
func newRateLimiter(rate float64, burst int, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		now:     now,
		buckets: make(map[string]*rateBucket),
		maxKeys: rateMaxKeys,
	}
}

// allow spends one token for key if one is available.
func (l *rateLimiter) allow(key string) rateDecision {
	if l.rate <= 0 {
		return rateDecision{Allowed: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.maybeSweep(now)

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			start := l.capLogged.IsZero() || now.Sub(l.capLogged) >= rateSweepEvery
			if start {
				l.capLogged = now
			}
			return rateDecision{RetryAfterSec: rateCapRetrySec, StartOfBurst: start}
		}
		b = &rateBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		b.rejecting = false
		return rateDecision{Allowed: true}
	}
	retry := int(math.Ceil((1 - b.tokens) / l.rate))
	if retry < 1 {
		retry = 1
	}
	start := !b.rejecting
	b.rejecting = true
	return rateDecision{RetryAfterSec: retry, StartOfBurst: start}
}

// evictAfter is how long a bucket must be idle before dropping it is
// invisible: at least rateIdleFloor, and at least the time it takes to refill
// from empty to full. A bucket idle that long would be full anyway, so
// eviction never hands a client more than its limit.
func (l *rateLimiter) evictAfter() time.Duration {
	after := rateIdleFloor
	if fill := time.Duration(l.burst / l.rate * float64(time.Second)); fill > after {
		after = fill
	}
	return after
}

// maybeSweep drops idle buckets, at most once per rateSweepEvery. Caller holds mu.
func (l *rateLimiter) maybeSweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < rateSweepEvery {
		return
	}
	l.lastSweep = now
	l.sweeps++
	after := l.evictAfter()
	for k, b := range l.buckets {
		if now.Sub(b.last) >= after {
			delete(l.buckets, k)
		}
	}
}

// size reports how many clients are currently tracked.
func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// clientKey is the bucket key: the host part of RemoteAddr, without the port.
func clientKey(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// SetRateLimit configures per-client-IP limiting of /api/ and /metrics. A rate
// of 0 disables the limiter; a negative or non-finite rate, or a burst below 1
// with a positive rate, is an error. NewServer installs the config defaults.
func (s *Server) SetRateLimit(rate float64, burst int) error {
	if err := (config.ServerConfig{APIRate: rate, APIBurst: burst}).Validate(); err != nil {
		return err
	}
	if rate == 0 {
		s.limiter = nil
		return nil
	}
	s.limiter = newRateLimiter(rate, burst, time.Now)
	return nil
}

// rateLimit refuses guarded requests over a client's budget with 429 and a
// Retry-After header. The refusal is written after the limiter lock is released.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil || !isGuardedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		d := s.limiter.allow(clientKey(r.RemoteAddr))
		if d.Allowed {
			next.ServeHTTP(w, r)
			return
		}
		s.metrics.incRateLimited()
		// The client address is logged only at Debug: Info lines are kept by
		// default, and the address is not needed to see that a burst happened.
		if d.StartOfBurst {
			s.log.Info("api request rate limited", "method", r.Method, "path", r.URL.Path, "retry_after_s", d.RetryAfterSec)
		} else {
			s.log.Debug("api request rate limited", "method", r.Method, "path", r.URL.Path,
				"client", clientKey(r.RemoteAddr), "retry_after_s", d.RetryAfterSec)
		}
		w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSec))
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
	})
}
