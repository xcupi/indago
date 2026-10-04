package queue_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/sqlite"
)

// clockQueue is a Queue whose clock can be controlled for deterministic tests.
type clockQueue interface {
	queue.Queue
	SetClock(func() time.Time)
}

type factory func(t *testing.T) (clockQueue, func())

func memFactory(t *testing.T) (clockQueue, func()) {
	return queue.NewMemory(), func() {}
}

func sqliteFactory(t *testing.T) (clockQueue, func()) {
	path := filepath.Join(t.TempDir(), "queue.db")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return queue.NewSQLite(db.SQL()), func() { _ = db.Close() }
}

func factories() map[string]factory {
	return map[string]factory{"memory": memFactory, "sqlite": sqliteFactory}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func job(scanID domain.ID, priority int) *domain.TestJob {
	return &domain.TestJob{
		ScanID: scanID, Type: domain.JobTest, Priority: priority,
		Target: domain.JobTarget{URL: "https://x/a"}, MaxAttempts: 3,
	}
}

func runEach(t *testing.T, fn func(t *testing.T, q clockQueue)) {
	for name, f := range factories() {
		t.Run(name, func(t *testing.T) {
			q, done := f(t)
			defer done()
			fn(t, q)
		})
	}
}

func TestEnqueueLeaseComplete(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()
		if err := q.Enqueue(ctx, job(scan, 0)); err != nil {
			t.Fatal(err)
		}

		leased, err := q.Lease(ctx, "w1", "", nil, time.Minute)
		if err != nil {
			t.Fatalf("lease: %v", err)
		}
		if leased.State != domain.JobRunning || leased.Attempts != 1 {
			t.Fatalf("leased state=%s attempts=%d", leased.State, leased.Attempts)
		}

		// Nothing else to lease.
		if _, err := q.Lease(ctx, "w1", "", nil, time.Minute); err != queue.ErrNoJobs {
			t.Fatalf("expected ErrNoJobs, got %v", err)
		}

		if err := q.Complete(ctx, leased.ID); err != nil {
			t.Fatalf("complete: %v", err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Succeeded != 1 || st.Pending() != 0 {
			t.Fatalf("stats after complete: %+v", st)
		}
	})
}

func TestPriorityOrder(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()
		_ = q.Enqueue(ctx, job(scan, 1))
		hi := job(scan, 10)
		_ = q.Enqueue(ctx, hi)
		_ = q.Enqueue(ctx, job(scan, 5))

		leased, err := q.Lease(ctx, "w", "", nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if leased.Priority != 10 {
			t.Fatalf("expected highest priority (10) first, got %d", leased.Priority)
		}
	})
}

func TestRetryBackoffThenDead(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		clk := &fakeClock{t: time.Now()}
		q.SetClock(clk.now)
		scan := domain.NewID()
		_ = q.Enqueue(ctx, job(scan, 0)) // MaxAttempts 3

		// Attempt 1
		l, err := q.Lease(ctx, "w", "", nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Fail(ctx, l.ID, "boom", true); err != nil {
			t.Fatal(err)
		}
		// Immediately not available (backoff in the future).
		if _, err := q.Lease(ctx, "w", "", nil, time.Minute); err != queue.ErrNoJobs {
			t.Fatalf("expected backoff to hide job, got %v", err)
		}
		// After backoff, available again.
		clk.advance(10 * time.Second)
		l, err = q.Lease(ctx, "w", "", nil, time.Minute)
		if err != nil {
			t.Fatalf("expected job after backoff: %v", err)
		}
		if l.Attempts != 2 {
			t.Fatalf("expected attempts=2, got %d", l.Attempts)
		}
		// Fail again (attempt 2 -> requeue), advance, attempt 3 -> dead.
		_ = q.Fail(ctx, l.ID, "boom", true)
		clk.advance(time.Minute)
		l, _ = q.Lease(ctx, "w", "", nil, time.Minute)
		if l.Attempts != 3 {
			t.Fatalf("expected attempts=3, got %d", l.Attempts)
		}
		if err := q.Fail(ctx, l.ID, "boom", true); err != nil {
			t.Fatal(err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Dead != 1 {
			t.Fatalf("expected 1 dead job after retries exhausted, got %+v", st)
		}
	})
}

func TestFailNoRetryIsDead(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()
		_ = q.Enqueue(ctx, job(scan, 0))
		l, _ := q.Lease(ctx, "w", "", nil, time.Minute)
		if err := q.Fail(ctx, l.ID, "fatal", false); err != nil {
			t.Fatal(err)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Dead != 1 {
			t.Fatalf("expected dead job, got %+v", st)
		}
	})
}

func TestCancelAndCancelScan(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()
		j1 := job(scan, 0)
		_ = q.Enqueue(ctx, j1)
		_ = q.Enqueue(ctx, job(scan, 0))
		_ = q.Enqueue(ctx, job(scan, 0))

		if err := q.Cancel(ctx, j1.ID); err != nil {
			t.Fatal(err)
		}
		n, err := q.CancelScan(ctx, scan)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 { // the other two still-cancelable jobs
			t.Fatalf("expected 2 canceled by CancelScan, got %d", n)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Canceled != 3 || st.Pending() != 0 {
			t.Fatalf("stats: %+v", st)
		}
	})
}

func TestRecoverRequeuesActive(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scan := domain.NewID()
		_ = q.Enqueue(ctx, job(scan, 0))
		_ = q.Enqueue(ctx, job(scan, 0))
		_, _ = q.Lease(ctx, "w", "", nil, time.Minute)
		_, _ = q.Lease(ctx, "w", "", nil, time.Minute)

		st, _ := q.Stats(ctx, scan)
		if st.Running != 2 {
			t.Fatalf("expected 2 running before recover, got %+v", st)
		}
		n, err := q.Recover(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("expected 2 recovered, got %d", n)
		}
		st, _ = q.Stats(ctx, scan)
		if st.Queued != 2 || st.Running != 0 {
			t.Fatalf("expected all requeued, got %+v", st)
		}
	})
}

func TestReapExpiredLeases(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		clk := &fakeClock{t: time.Now()}
		q.SetClock(clk.now)
		scan := domain.NewID()
		_ = q.Enqueue(ctx, job(scan, 0))
		_, _ = q.Lease(ctx, "w", "", nil, 30*time.Second)

		// Not yet expired.
		n, _ := q.ReapExpired(ctx, clk.now())
		if n != 0 {
			t.Fatalf("expected 0 reaped before expiry, got %d", n)
		}
		// After lease expiry.
		clk.advance(time.Minute)
		n, _ = q.ReapExpired(ctx, clk.now())
		if n != 1 {
			t.Fatalf("expected 1 reaped after expiry, got %d", n)
		}
		st, _ := q.Stats(ctx, scan)
		if st.Queued != 1 {
			t.Fatalf("expected job requeued, got %+v", st)
		}
	})
}

// TestSQLiteNoDoubleLease hammers the SQLite queue concurrently and asserts that
// each job is leased exactly once.
func TestSQLiteNoDoubleLease(t *testing.T) {
	q, done := sqliteFactory(t)
	defer done()
	ctx := context.Background()
	scan := domain.NewID()

	const n = 200
	for i := 0; i < n; i++ {
		if err := q.Enqueue(ctx, job(scan, 0)); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	seen := make(map[domain.ID]int)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, err := q.Lease(ctx, "w", "", nil, time.Minute)
				if err == queue.ErrNoJobs {
					return
				}
				if err != nil {
					t.Errorf("lease: %v", err)
					return
				}
				mu.Lock()
				seen[j.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != n {
		t.Fatalf("expected %d distinct jobs leased, got %d", n, len(seen))
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("job %s leased %d times (double-lease)", id, c)
		}
	}
}

func TestLeaseScanFilterIsolatesScans(t *testing.T) {
	runEach(t, func(t *testing.T, q clockQueue) {
		ctx := context.Background()
		scanA, scanB := domain.NewID(), domain.NewID()
		_ = q.Enqueue(ctx, job(scanA, 0))
		_ = q.Enqueue(ctx, job(scanB, 0))

		// Leasing with scanA's filter must only ever return scanA jobs.
		got, err := q.Lease(ctx, "w", scanA, nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if got.ScanID != scanA {
			t.Fatalf("leased job from wrong scan: %s", got.ScanID)
		}
		// No more scanA jobs available.
		if _, err := q.Lease(ctx, "w", scanA, nil, time.Minute); err != queue.ErrNoJobs {
			t.Fatalf("expected ErrNoJobs for scanA, got %v", err)
		}
		// scanB job still leasable.
		if _, err := q.Lease(ctx, "w", scanB, nil, time.Minute); err != nil {
			t.Fatalf("scanB job should still be available: %v", err)
		}
	})
}
