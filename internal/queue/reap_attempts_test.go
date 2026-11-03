package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// TestReapExpiredDeadLettersAfterMaxAttempts proves an expired lease is
// retried at most MaxAttempts times and then becomes terminal. Before the fix
// ReapExpired requeued an expired job unconditionally: a job that always hung
// its worker was re-leased, timed out and requeued again forever, never
// reaching `dead` and never letting the scan finish.
func TestReapExpiredDeadLettersAfterMaxAttempts(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		clk := &fakeClock{t: time.Now()}
		q.SetClock(clk.now)
		scan := domain.NewID()

		j := &domain.TestJob{ScanID: scan, Type: domain.JobTest, MaxAttempts: 2}
		if err := q.Enqueue(ctx, j); err != nil {
			t.Fatal(err)
		}

		// Attempt 1: leased, then the worker dies without heartbeating.
		l, err := q.Lease(ctx, "w", "", nil, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if l.Attempts != 1 {
			t.Fatalf("attempts = %d, want 1", l.Attempts)
		}
		clk.advance(time.Minute)
		if n, err := q.ReapExpired(ctx, clk.now()); err != nil || n != 1 {
			t.Fatalf("reap attempt 1 = (%d, %v), want (1, nil)", n, err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Queued != 1 || st.Dead != 0 {
			t.Fatalf("after first expiry: %+v, want the job retried once", st)
		}

		// Attempt 2 exhausts MaxAttempts: the next expiry must be terminal.
		l, err = q.Lease(ctx, "w", "", nil, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if l.Attempts != 2 {
			t.Fatalf("attempts = %d, want 2", l.Attempts)
		}
		clk.advance(time.Minute)
		if n, err := q.ReapExpired(ctx, clk.now()); err != nil || n != 1 {
			t.Fatalf("reap attempt 2 = (%d, %v), want (1, nil)", n, err)
		}
		st, _ = q.Stats(ctx, scan)
		if st.Dead != 1 || st.Queued != 0 {
			t.Fatalf("after exhausting MaxAttempts: %+v, want exactly one dead job", st)
		}

		// Idempotent: reaping again finds nothing and cannot resurrect the job.
		if n, err := q.ReapExpired(ctx, clk.now()); err != nil || n != 0 {
			t.Fatalf("second reap = (%d, %v), want (0, nil)", n, err)
		}
		st, _ = q.Stats(ctx, scan)
		if st.Dead != 1 || st.Queued != 0 {
			t.Fatalf("repeated reap resurrected a terminal job: %+v", st)
		}
	})
}

// TestLiveLeaseIsNotReaped is the other half of the recovery contract: only
// leases that actually expired are reclaimable. A lease that is still valid
// (its holder is alive, even if the reaper just happened to run) must keep its
// job and its attempt count untouched, so recovery can never double-run a job
// that is genuinely still alive.
func TestLiveLeaseIsNotReaped(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		clk := &fakeClock{t: time.Now()}
		q.SetClock(clk.now)
		scan := domain.NewID()

		j := &domain.TestJob{ScanID: scan, Type: domain.JobTest, MaxAttempts: 3}
		if err := q.Enqueue(ctx, j); err != nil {
			t.Fatal(err)
		}
		l, err := q.Lease(ctx, "w", "", nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if l.Attempts != 1 {
			t.Fatalf("attempts = %d, want 1", l.Attempts)
		}
		clk.advance(30 * time.Second) // still well inside the lease

		if n, err := q.ReapExpired(ctx, clk.now()); err != nil || n != 0 {
			t.Fatalf("reaped a live lease: n=%d err=%v", n, err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Running != 1 {
			t.Fatalf("live lease lost its job: %+v", st)
		}
		if l2, err := q.Lease(ctx, "w", "", nil, time.Minute); !errors.Is(err, queue.ErrNoJobs) {
			t.Fatalf("live job was re-leased (double-run): %v job=%v", err, l2)
		}
	})
}

// TestFailCannotResurrectNonActiveJob guards cancellation semantics: a late
// writer (an abandoned handler finally returning after the pool stopped) must
// not turn a cancelled or completed job back into queued work. Both queue
// implementations used to update by ID only, so a stale Fail resurrected a
// terminal job — which is exactly how a cancelled scan could sprout queued
// jobs that no worker would ever run again.
func TestFailCannotResurrectNonActiveJob(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()

		canceled := &domain.TestJob{ScanID: scan, Type: domain.JobTest, MaxAttempts: 3}
		if err := q.Enqueue(ctx, canceled); err != nil {
			t.Fatal(err)
		}
		if err := q.Cancel(ctx, canceled.ID); err != nil {
			t.Fatal(err)
		}
		if err := q.Fail(ctx, canceled.ID, "late failure from an abandoned handler", true); !errors.Is(err, queue.ErrNotLeasable) {
			t.Fatalf("Fail on a cancelled job = %v, want ErrNotLeasable", err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Canceled != 1 || st.Queued != 0 {
			t.Fatalf("cancelled job was resurrected: %+v", st)
		}

		done := &domain.TestJob{ScanID: scan, Type: domain.JobTest, MaxAttempts: 3}
		if err := q.Enqueue(ctx, done); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Lease(ctx, "w", "", nil, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := q.Complete(ctx, done.ID); err != nil {
			t.Fatal(err)
		}
		if err := q.Fail(ctx, done.ID, "late failure", true); !errors.Is(err, queue.ErrNotLeasable) {
			t.Fatalf("Fail on a completed job = %v, want ErrNotLeasable", err)
		}
		st, _ = q.Stats(ctx, scan)
		if st.Succeeded != 1 || st.Queued != 0 {
			t.Fatalf("completed job was resurrected: %+v", st)
		}
	})
}
