package ratelimit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/ratelimit"
)

func TestLimiterSpacesPermits(t *testing.T) {
	l := ratelimit.New(2) // one permit per 500ms
	var at []time.Time
	for i := 0; i < 3; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		at = append(at, time.Now())
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < 450*time.Millisecond {
			t.Fatalf("gap %d = %v, want >= 450ms at 2 rps", i, gap)
		}
	}
}

func TestLimiterZeroIsUnlimited(t *testing.T) {
	l := ratelimit.New(0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("100 waits at rps=0 took %v; unlimited must not pace", d)
	}
}

func TestNilLimiterIsUnlimited(t *testing.T) {
	var l *ratelimit.Limiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSetRateAppliesInPlace(t *testing.T) {
	l := ratelimit.New(0)
	l.SetRate(10) // 100ms interval
	start := time.Now()
	for i := 0; i < 4; i++ { // 3 gaps of 100ms
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 280*time.Millisecond {
		t.Fatalf("after SetRate(10), 4 waits took %v, want >= 280ms", d)
	}
	l.SetRate(0)
	start = time.Now()
	for i := 0; i < 50; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("after SetRate(0), 50 waits took %v; want unpaced", d)
	}
}

// Lowering the rate to unlimited must release callers already queued behind
// the old rate, not leave them sleeping out their reserved slots.
func TestSetRateUnlimitedReleasesQueuedWaiters(t *testing.T) {
	l := ratelimit.New(0.5) // 2s interval: waiters reserve slots 0, 2, 4, 6s
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Wait(context.Background())
		}()
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	l.SetRate(0)
	wg.Wait()
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("queued waiters released after %v; want prompt release on SetRate(0)", d)
	}
}

func TestWaitHonoursContextCancel(t *testing.T) {
	l := ratelimit.New(0.5) // 2s interval
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := l.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 1*time.Second {
		t.Fatalf("cancel took %v to surface", d)
	}
}

func TestLimiterWithJitterVariesIntervals(t *testing.T) {
	l := ratelimit.NewWithJitter(20, 0.5) // 50ms ± 25ms
	var prev time.Time
	var deltas []time.Duration
	for i := 0; i < 6; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		if i > 0 {
			deltas = append(deltas, now.Sub(prev))
		}
		prev = now
	}
	if len(deltas) != 5 {
		t.Fatalf("got %d deltas, want 5", len(deltas))
	}
	var minD, maxD time.Duration
	for i, d := range deltas {
		if i == 0 || d < minD {
			minD = d
		}
		if i == 0 || d > maxD {
			maxD = d
		}
	}
	if maxD-minD < 2*time.Millisecond {
		t.Fatalf("expected varied intervals with jitter, got min=%v max=%v (%v)", minD, maxD, deltas)
	}
}

// The configured rate is a spacing floor between ACTUAL grants: a permit whose
// timer woke late must delay the ones behind it, never let them catch up in a
// burst. Run enough permits at a short interval that a contended scheduler is
// bound to wake at least one of them late.
func TestLimiterSpacesActualGrants(t *testing.T) {
	const (
		rps     = 100.0 // 10ms interval
		permits = 80
	)
	interval := time.Duration(float64(time.Second) / rps)
	// Timer/scheduler and measurement slack only; a compressed gap after a late
	// wake was observed to be roughly half the interval, well below this floor.
	slack := 2 * time.Millisecond
	l := ratelimit.New(rps)
	ctx := context.Background()
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	prev := time.Now()
	for i := 0; i < permits; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		if gap := now.Sub(prev); gap < interval-slack {
			t.Fatalf("permit %d came %v after the previous one, want >= %v", i+1, gap, interval)
		}
		prev = now
	}
}
