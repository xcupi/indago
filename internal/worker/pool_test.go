package worker_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/worker"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitFor(t *testing.T, d time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", desc, d)
}

func enqueueN(t *testing.T, q queue.Queue, scan domain.ID, typ domain.JobType, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		j := &domain.TestJob{ScanID: scan, Type: typ, MaxAttempts: 2}
		if err := q.Enqueue(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPoolProcessesJobs(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	var count atomic.Int64

	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			count.Add(1)
			return nil
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 4}},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	enqueueN(t, q, scan, domain.JobTest, 50)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	waitFor(t, 3*time.Second, "all jobs succeeded", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Succeeded == 50
	})
	if count.Load() != 50 {
		t.Fatalf("handler ran %d times, want 50", count.Load())
	}
}

func TestPoolPauseResume(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error { return nil }),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 2}},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	p.Pause()
	enqueueN(t, q, scan, domain.JobTest, 10)

	// While paused, nothing should be processed.
	time.Sleep(150 * time.Millisecond)
	st, _ := q.Stats(context.Background(), scan)
	if st.Succeeded != 0 {
		t.Fatalf("processed %d jobs while paused", st.Succeeded)
	}

	p.Resume()
	waitFor(t, 3*time.Second, "jobs drained after resume", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Succeeded == 10
	})
}

func TestPoolPermanentFailureBecomesDead(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			return errors.Join(worker.ErrPermanent, errors.New("nope"))
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 2}},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	enqueueN(t, q, scan, domain.JobTest, 3)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	waitFor(t, 3*time.Second, "permanent failures become dead", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Dead == 3
	})
}

func TestPoolMissingHandlerFailsJob(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	// No handler registered for JobTest.
	p := worker.New(q, map[domain.JobType]worker.Handler{}, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	enqueueN(t, q, scan, domain.JobTest, 1)
	_ = p.Start(context.Background())
	defer p.Stop()

	waitFor(t, 2*time.Second, "job with no handler is dead", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Dead == 1
	})
}

func TestPoolResize(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			time.Sleep(10 * time.Millisecond)
			return nil
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 1}},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	if got := p.Sizes()["http"]; got != 1 {
		t.Fatalf("initial size = %d, want 1", got)
	}
	if err := p.Resize("http", 8); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, "resize up reflected", func() bool { return p.Sizes()["http"] == 8 })

	enqueueN(t, q, scan, domain.JobTest, 80)
	waitFor(t, 5*time.Second, "jobs complete after resize", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Succeeded == 80
	})

	if err := p.Resize("http", 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, "resize down reflected", func() bool { return p.Sizes()["http"] == 2 })

	if err := p.Resize("nope", 1); err == nil {
		t.Fatal("expected error resizing unknown group")
	}
}

func TestPoolTypedGroups(t *testing.T) {
	q := queue.NewMemory()
	scan := domain.NewID()
	var testCount, discCount atomic.Int64

	handlers := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			testCount.Add(1)
			return nil
		}),
		domain.JobDiscovery: worker.HandlerFunc(func(ctx context.Context, j *domain.TestJob) error {
			discCount.Add(1)
			return nil
		}),
	}
	p := worker.New(q, handlers, worker.Config{
		Groups: []worker.GroupSpec{
			{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: 2},
			{Name: "discovery", Types: []domain.JobType{domain.JobDiscovery}, Size: 2},
		},
		IdlePoll: 10 * time.Millisecond,
	}, quietLogger())

	enqueueN(t, q, scan, domain.JobTest, 20)
	enqueueN(t, q, scan, domain.JobDiscovery, 15)
	_ = p.Start(context.Background())
	defer p.Stop()

	waitFor(t, 3*time.Second, "both groups drain", func() bool {
		st, _ := q.Stats(context.Background(), scan)
		return st.Succeeded == 35
	})
	if testCount.Load() != 20 || discCount.Load() != 15 {
		t.Fatalf("test=%d disc=%d, want 20/15", testCount.Load(), discCount.Load())
	}
}
