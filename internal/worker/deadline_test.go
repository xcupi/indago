package worker_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/sqlite"
	"github.com/indago/indago/internal/worker"
)

// sqliteQueue opens a real SQLite-backed queue. Unlike queue.Memory, a write
// issued with an already-canceled context fails without touching the row — the
// exact behavior behind "mark job failed: worker stopping; job left for
// recovery err=context canceled" in the field.
func sqliteQueue(t *testing.T) *queue.SQLite {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return queue.NewSQLite(db.SQL())
}

// TestStoppingWorkerLeavesAbandonedJobRecoverable is fixture (a): a job
// abandoned by a stopping worker keeps its lease (the documented shutdown
// contract — restart recovery, not a guessed failure, owns it) but nothing is
// left heartbeating it. Recovery must then be able to finish the job: once the
// lease expires it is reclaimed, and because this job has no attempts left it
// becomes terminal instead of being requeued forever. Before the fix the reaper
// requeued an exhausted job unconditionally, so the queue could keep a
// permanently stuck job alive indefinitely.
func TestStoppingWorkerLeavesAbandonedJobRecoverable(t *testing.T) {
	q := sqliteQueue(t)
	scanID := domain.NewID()

	job := &domain.TestJob{ScanID: scanID, Type: domain.JobTest, MaxAttempts: 1}
	if err := q.Enqueue(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, _ *domain.TestJob) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}),
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	p := worker.New(q, handlers, worker.Config{
		Groups:          []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:        5 * time.Millisecond,
		LeaseDuration:   100 * time.Millisecond,
		Heartbeat:       20 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
	}, quietLogger())
	if err := p.Start(runCtx); err != nil {
		t.Fatalf("start: %v", err)
	}
	<-started

	// Simulate the worker being told to stop (shutdown / scan cancel). The
	// handler honors ctx and returns an error; the job must be left with its
	// lease intact for the restart/reaper paths, not half-recorded.
	cancelRun()
	p.Stop()

	st, err := q.Stats(context.Background(), scanID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Running != 1 || st.Queued != 0 || st.Dead != 0 {
		t.Fatalf("stopping worker did not leave the job for recovery: %+v", st)
	}

	// Outlive the (now unrefreshed) lease: the reaper must be able to claim it,
	// and with MaxAttempts exhausted the job must go terminal rather than wait
	// in the queue forever.
	time.Sleep(150 * time.Millisecond)
	n, err := q.ReapExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 1 {
		t.Fatalf("reaped %d jobs, want 1 (the abandoned lease must be recoverable)", n)
	}
	st, err = q.Stats(context.Background(), scanID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Dead != 1 || st.Running != 0 || st.Queued != 0 {
		t.Fatalf("abandoned job with no attempts left was not made terminal: %+v", st)
	}
}

// TestStoppingWorkerDoesNotCompleteHalfFinishedAttempt pins the other half of
// the shutdown contract: a handler that returns nil *after* its worker context
// was canceled may have been interrupted mid-side-effect (child jobs still being
// enqueued, evidence still being written), so it must not be recorded as a
// success. Marking it succeeded here is how a crash could silently drop planned
// candidate work; leaving it active lets recovery replay the whole attempt.
func TestStoppingWorkerDoesNotCompleteHalfFinishedAttempt(t *testing.T) {
	q := sqliteQueue(t)
	scanID := domain.NewID()

	job := &domain.TestJob{ScanID: scanID, Type: domain.JobTest, MaxAttempts: 2}
	if err := q.Enqueue(context.Background(), job); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, _ *domain.TestJob) error {
			close(started)
			<-ctx.Done()
			return nil // "finished" only because cancellation unblocked it
		}),
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	p := worker.New(q, handlers, worker.Config{
		Groups:          []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:        5 * time.Millisecond,
		LeaseDuration:   10 * time.Second,
		Heartbeat:       time.Second,
		ShutdownTimeout: 2 * time.Second,
	}, quietLogger())
	if err := p.Start(runCtx); err != nil {
		t.Fatalf("start: %v", err)
	}
	<-started
	cancelRun()
	p.Stop()

	st, err := q.Stats(context.Background(), scanID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Succeeded != 0 {
		t.Fatalf("half-finished attempt recorded as succeeded: %+v", st)
	}
	if st.Running != 1 {
		t.Fatalf("interrupted attempt was not left for recovery: %+v", st)
	}
}

// TestJobDeadlineFreesWorkerAndDeadLettersAfterMaxAttempts is fixture (b): one
// handler hangs forever, ignoring context cancellation (a stalled browser call,
// a wedged renderer, a dialog nobody dismissed). Without a per-job deadline it
// holds the group's only worker and its own lease heartbeat forever — the
// 59-queued/1-running field shape. With one, the attempt is abandoned at the
// deadline, the job is retried up to MaxAttempts, then goes dead, and the
// queued work behind it still runs.
func TestJobDeadlineFreesWorkerAndDeadLettersAfterMaxAttempts(t *testing.T) {
	q := queue.NewMemory()
	scanID := domain.NewID()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var hungRuns, otherRuns atomic.Int64

	hung := &domain.TestJob{ScanID: scanID, Type: domain.JobTest, Priority: 10, MaxAttempts: 2}
	other := &domain.TestJob{ScanID: scanID, Type: domain.JobTest, Priority: 1, MaxAttempts: 2}
	ctx := context.Background()
	if err := q.Enqueue(ctx, hung); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, other); err != nil {
		t.Fatal(err)
	}

	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			if j.ID == hung.ID {
				hungRuns.Add(1)
				<-release // deliberately ignores ctx: the deadline must free the slot anyway
				return nil
			}
			otherRuns.Add(1)
			return nil
		}),
	}

	p := worker.New(q, handlers, worker.Config{
		Groups:          []worker.GroupSpec{{Name: "browser", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:        5 * time.Millisecond,
		LeaseDuration:   10 * time.Second,
		Heartbeat:       time.Second,
		ShutdownTimeout: 2 * time.Second,
		JobTimeout:      60 * time.Millisecond,
	}, quietLogger())
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	// The hung job exhausts its two attempts (2s retry backoff) and goes dead;
	// the job queued behind it must still be picked up by the freed worker.
	waitFor(t, 5*time.Second, "hung job dead and queued job succeeded", func() bool {
		st, _ := q.Stats(ctx, scanID)
		return st.Dead == 1 && st.Succeeded == 1
	})

	if got := hungRuns.Load(); got != 2 {
		t.Fatalf("hung handler ran %d times, want exactly 2 (one per MaxAttempts)", got)
	}
	if got := otherRuns.Load(); got != 1 {
		t.Fatalf("queued handler ran %d times, want exactly 1 (the group must be freed)", got)
	}
	st, _ := q.Stats(ctx, scanID)
	if st.Running != 0 || st.Leased != 0 {
		t.Fatalf("deadline did not release the worker: %+v", st)
	}
}
