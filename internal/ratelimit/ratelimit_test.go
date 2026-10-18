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
