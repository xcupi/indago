package worker_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/worker"
)

// flakyHeartbeatQueue fails the first N Heartbeat calls, then behaves
// normally — simulating a transient store error (a momentary SQLITE_BUSY,
// for example) rather than a permanent one.
type flakyHeartbeatQueue struct {
	*queue.Memory
	failures atomic.Int64
}

func (q *flakyHeartbeatQueue) Heartbeat(ctx context.Context, jobID domain.ID, leaseFor time.Duration) error {
	if q.failures.Add(-1) >= 0 {
		return context.DeadlineExceeded // stand-in transient error
	}
	return q.Memory.Heartbeat(ctx, jobID, leaseFor)
}

// TestHeartbeatSurvivesTransientError proves a single failed lease extension
// does not permanently stop heartbeating. Before the fix, pool.heartbeat
// returned (and stopped ticking forever) on the very first error — here the
// handler needs several heartbeat ticks to finish, so the job would be
// reclaimed by ReapExpired and attempted a second time if heartbeating had
// actually stopped after the injected failure.
func TestHeartbeatSurvivesTransientError(t *testing.T) {
	q := &flakyHeartbeatQueue{Memory: queue.NewMemory()}
	q.failures.Store(1) // exactly one Heartbeat call fails

	scanID := domain.NewID()
	enqueueN(t, q, scanID, domain.JobTest, 1)

	var attempts atomic.Int64
	release := make(chan struct{})
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			attempts.Add(1)
			<-release // held open across several heartbeat ticks
			return nil
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:        []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:      5 * time.Millisecond,
		LeaseDuration: 150 * time.Millisecond,
		Heartbeat:     20 * time.Millisecond,
	}, quietLogger())

	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// Outlive several heartbeat ticks (including the injected failure) and the
	// lease duration itself, while the single handler attempt is still held
	// open — proving the lease kept getting extended despite the one error.
	time.Sleep(300 * time.Millisecond)
	if n, err := q.ReapExpired(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("job was reclaimed despite a healthy (if briefly flaky) heartbeat: %d reaped", n)
	}
	close(release)

	waitFor(t, 2*time.Second, "job succeeded", func() bool {
		st, _ := q.Stats(context.Background(), scanID)
		return st.Succeeded == 1
	})
	if got := attempts.Load(); got != 1 {
		t.Fatalf("handler ran %d times, want exactly 1 (no spurious reclaim/retry)", got)
	}
}

// TestExpiredLeaseIsReclaimedAndRetried simulates the scenario ReapExpired
// exists for: a handler that outlives its own job's context (a hung
// goroutine, not a clean cancellation) stops being heartbeat-extended once
// that context is canceled, so its lease eventually expires. A periodic
// reaper (what Controller now runs — see scan.Controller.reapExpiredLeases)
// must reclaim it so a fresh attempt, by a different worker/process, can
// still complete the job instead of it being stuck forever.
func TestExpiredLeaseIsReclaimedAndRetried(t *testing.T) {
	q := queue.NewMemory()
	scanID := domain.NewID()
	enqueueN(t, q, scanID, domain.JobTest, 1)

	var attempts atomic.Int64
	hang := make(chan struct{}) // never closed: the first attempt blocks forever, ignoring ctx
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			if attempts.Add(1) == 1 {
				<-hang
			}
			return nil
		}),
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	p1 := worker.New(q, handlers, worker.Config{
		Groups:        []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:      5 * time.Millisecond,
		LeaseDuration: 80 * time.Millisecond,
		Heartbeat:     20 * time.Millisecond,
	}, quietLogger())
	if err := p1.Start(ctx1); err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, "first attempt leased", func() bool { return attempts.Load() == 1 })

	// Simulate the pool/scan being torn down (pause/cancel/restart) while the
	// handler goroutine is still wedged: canceling ctx1 stops heartbeating
	// (pool.process derives the heartbeat's context from the same ctx), but
	// the handler itself ignores ctx and stays blocked on hang forever — an
	// orphaned, leaked goroutine, same as a real hung driver call would leave
	// behind. Deliberately do NOT call p1.Stop() here: it waits on the very
	// goroutine that will never return (that gap is covered separately by
	// TestStopReturnsPromptlyDespiteAHungHandler) — this test is only about
	// what ReapExpired does once heartbeating has stopped.
	cancel1()
	time.Sleep(120 * time.Millisecond) // outlive LeaseDuration with no more heartbeats

	n, err := q.ReapExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ReapExpired reclaimed %d jobs, want 1", n)
	}

	// A fresh pool (as Resume() builds after a restart) picks the reclaimed
	// job up and completes it on the second attempt.
	p2 := worker.New(q, handlers, worker.Config{
		Groups:        []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:      5 * time.Millisecond,
		LeaseDuration: 80 * time.Millisecond,
		Heartbeat:     20 * time.Millisecond,
	}, quietLogger())
	if err := p2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p2.Stop()

	waitFor(t, 2*time.Second, "job succeeded on retry", func() bool {
		st, _ := q.Stats(context.Background(), scanID)
		return st.Succeeded == 1
	})
	if got := attempts.Load(); got != 2 {
		t.Fatalf("handler ran %d times, want exactly 2 (one hung, one that completed)", got)
	}
}

// TestStopReturnsPromptlyDespiteAHungHandler proves Stop no longer blocks
// forever when a handler ignores context cancellation entirely (ShutdownTimeout
// bounds the wait) — before the fix, Pool.Stop called wg.Wait with no timeout,
// so a single wedged handler (e.g. a hung browser/driver call) could prevent
// the whole process from ever shutting down gracefully.
func TestStopReturnsPromptlyDespiteAHungHandler(t *testing.T) {
	q := queue.NewMemory()
	enqueueN(t, q, domain.NewID(), domain.JobTest, 1)

	started := make(chan struct{})
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			close(started)
			select {} // ignores ctx entirely: never returns
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:          []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll:        5 * time.Millisecond,
		ShutdownTimeout: 100 * time.Millisecond,
	}, quietLogger())
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started

	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within ShutdownTimeout + slack; it is waiting on the hung handler forever")
	}
}
