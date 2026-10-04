package queue

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
)

// Memory is an in-memory Queue implementation. It is fully functional (including
// recovery semantics) and is used for tests and for runs where persistence is
// not required. State is lost on exit.
type Memory struct {
	mu   sync.Mutex
	jobs map[domain.ID]*domain.TestJob
	now  func() time.Time
}

// NewMemory returns an empty in-memory queue.
func NewMemory() *Memory {
	return &Memory{jobs: make(map[domain.ID]*domain.TestJob), now: time.Now}
}

// SetClock overrides the time source. It exists for deterministic tests and
// should not be used in production code.
func (q *Memory) SetClock(fn func() time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.now = fn
}

var _ Queue = (*Memory)(nil)

// typeMatches reports whether t is in types, treating empty/nil types as "any".
func typeMatches(types []domain.JobType, t domain.JobType) bool {
	if len(types) == 0 {
		return true
	}
	for _, want := range types {
		if want == t {
			return true
		}
	}
	return false
}

func (q *Memory) clone(j *domain.TestJob) *domain.TestJob {
	c := *j
	if j.Payload != nil {
		c.Payload = append([]byte(nil), j.Payload...)
	}
	if j.LeasedUntil != nil {
		t := *j.LeasedUntil
		c.LeasedUntil = &t
	}
	return &c
}

func (q *Memory) Enqueue(_ context.Context, job *domain.TestJob) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	if job.ID.Empty() {
		job.ID = domain.NewID()
	}
	if job.State == "" {
		job.State = domain.JobQueued
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	job.AvailableAt = defaultIfZero(job.AvailableAt, now)
	q.jobs[job.ID] = q.clone(job)
	return nil
}

func (q *Memory) Lease(_ context.Context, workerID string, scanID domain.ID, types []domain.JobType, leaseFor time.Duration) (*domain.TestJob, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()

	// Gather available queued jobs matching the optional scan and type filters.
	var avail []*domain.TestJob
	for _, j := range q.jobs {
		if j.State != domain.JobQueued || j.AvailableAt.After(now) {
			continue
		}
		if !scanID.Empty() && j.ScanID != scanID {
			continue
		}
		if !typeMatches(types, j.Type) {
			continue
		}
		avail = append(avail, j)
	}
	if len(avail) == 0 {
		return nil, ErrNoJobs
	}
	// Highest priority first, then oldest available.
	sort.Slice(avail, func(i, k int) bool {
		if avail[i].Priority != avail[k].Priority {
			return avail[i].Priority > avail[k].Priority
		}
		return avail[i].AvailableAt.Before(avail[k].AvailableAt)
	})

	j := avail[0]
	until := now.Add(leaseFor)
	j.State = domain.JobRunning
	j.LeaseID = workerID
	j.LeasedUntil = &until
	j.Attempts++
	j.UpdatedAt = now
	return q.clone(j), nil
}

func (q *Memory) Heartbeat(_ context.Context, jobID domain.ID, leaseFor time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[jobID]
	if !ok {
		return ErrNotLeasable
	}
	if !j.State.IsActive() {
		return ErrNotLeasable
	}
	until := q.now().Add(leaseFor)
	j.LeasedUntil = &until
	j.UpdatedAt = q.now()
	return nil
}

func (q *Memory) Complete(_ context.Context, jobID domain.ID) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[jobID]
	if !ok {
		return ErrNotLeasable
	}
	if !j.State.IsActive() {
		return ErrNotLeasable
	}
	j.State = domain.JobSucceeded
	j.LeaseID = ""
	j.LeasedUntil = nil
	j.UpdatedAt = q.now()
	return nil
}

func (q *Memory) Fail(_ context.Context, jobID domain.ID, cause string, retry bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[jobID]
	if !ok {
		return ErrNotLeasable
	}
	now := q.now()
	j.LastError = cause
	j.LeaseID = ""
	j.LeasedUntil = nil
	j.UpdatedAt = now

	if retry && j.Attempts < j.MaxAttempts {
		j.State = domain.JobQueued
		j.AvailableAt = now.Add(backoff(j.Attempts))
		return nil
	}
	j.State = domain.JobDead
	return nil
}

func (q *Memory) Cancel(_ context.Context, jobID domain.ID) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[jobID]
	if !ok {
		return ErrNotLeasable
	}
	if j.State.IsTerminal() {
		return nil
	}
	j.State = domain.JobCanceled
	j.LeaseID = ""
	j.LeasedUntil = nil
	j.UpdatedAt = q.now()
	return nil
}

func (q *Memory) CancelScan(_ context.Context, scanID domain.ID) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	now := q.now()
	for _, j := range q.jobs {
		if j.ScanID == scanID && !j.State.IsTerminal() {
			j.State = domain.JobCanceled
			j.LeaseID = ""
			j.LeasedUntil = nil
			j.UpdatedAt = now
			n++
		}
	}
	return n, nil
}

func (q *Memory) Recover(_ context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	now := q.now()
	for _, j := range q.jobs {
		if j.State.IsActive() {
			q.requeue(j, now)
			n++
		}
	}
	return n, nil
}

func (q *Memory) ReapExpired(_ context.Context, now time.Time) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, j := range q.jobs {
		if j.State.IsActive() && j.LeasedUntil != nil && !j.LeasedUntil.After(now) {
			q.requeue(j, now)
			n++
		}
	}
	return n, nil
}

// requeue returns an active job to the queued state (caller holds the lock).
func (q *Memory) requeue(j *domain.TestJob, now time.Time) {
	j.State = domain.JobQueued
	j.LeaseID = ""
	j.LeasedUntil = nil
	j.AvailableAt = now
	j.UpdatedAt = now
}

func (q *Memory) Stats(_ context.Context, scanID domain.ID) (Stats, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var s Stats
	for _, j := range q.jobs {
		if j.ScanID != scanID {
			continue
		}
		switch j.State {
		case domain.JobQueued:
			s.Queued++
		case domain.JobLeased:
			s.Leased++
		case domain.JobRunning:
			s.Running++
		case domain.JobSucceeded:
			s.Succeeded++
		case domain.JobFailed:
			s.Failed++
		case domain.JobCanceled:
			s.Canceled++
		case domain.JobDead:
			s.Dead++
		}
	}
	return s, nil
}
