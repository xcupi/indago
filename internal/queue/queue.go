// Package queue defines Indago's persistent job queue and two implementations
// (in-memory and SQLite-backed). The queue is the backbone of concurrent
// scanning: discovery and testing both enqueue work, and a pool of workers
// leases and executes it.
//
// Design requirements (from the product spec):
//
//   - Persistent: survives process restarts (SQLite implementation).
//   - Pause / resume / cancel: supported at the scan level (pause/resume are
//     coordinated by the worker pool, which stops/starts leasing; cancel is a
//     queue operation on jobs).
//   - Restart recovery: active (leased/running) jobs are requeued on startup,
//     and jobs whose worker died (expired lease) are reaped at runtime.
//
// The queue is generic over JobType; it never interprets a job's payload.
package queue

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/indago/indago/internal/domain"
)

// ErrNoJobs is returned by Lease when no job is currently available.
var ErrNoJobs = errors.New("queue: no jobs available")

// ErrNotLeasable is returned when an operation requires a job to be in an
// active (leased/running) state but it is not.
var ErrNotLeasable = errors.New("queue: job is not in a leasable state")

// Stats is a per-scan rollup of job counts by state.
type Stats struct {
	Queued    int `json:"queued"`
	Leased    int `json:"leased"`
	Running   int `json:"running"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Canceled  int `json:"canceled"`
	Dead      int `json:"dead"`
}

// Total returns the sum of all job counts.
func (s Stats) Total() int {
	return s.Queued + s.Leased + s.Running + s.Succeeded + s.Failed + s.Canceled + s.Dead
}

// Pending returns the number of jobs that still represent outstanding work
// (queued, leased, or running).
func (s Stats) Pending() int { return s.Queued + s.Leased + s.Running }

// Queue is the persistent job queue contract. Implementations must be safe for
// concurrent use by many workers.
type Queue interface {
	// Enqueue persists a new job in the queued state. If the job's ID is empty
	// one is assigned. CreatedAt/UpdatedAt/AvailableAt default to now.
	Enqueue(ctx context.Context, job *domain.TestJob) error

	// Lease atomically claims the highest-priority available job (state queued,
	// available_at <= now), transitions it to running, records the lease
	// (workerID, expiry = now+leaseFor), and returns it.
	//
	// A non-empty scanID restricts leasing to that scan (so each scan's pool
	// draws only its own work, enabling per-scan pause/cancel). A non-empty
	// types restricts to those job types (so independently-sized worker groups —
	// discovery/HTTP/browser — draw their own work). Returns ErrNoJobs when
	// nothing matching is available.
	Lease(ctx context.Context, workerID string, scanID domain.ID, types []domain.JobType, leaseFor time.Duration) (*domain.TestJob, error)

	// Heartbeat extends the lease on a running job. Returns ErrNotLeasable if
	// the job is no longer active.
	Heartbeat(ctx context.Context, jobID domain.ID, leaseFor time.Duration) error

	// Complete marks a running job succeeded.
	Complete(ctx context.Context, jobID domain.ID) error

	// Fail records a failure. If retry is true and attempts remain, the job is
	// requeued with backoff; otherwise it becomes dead.
	Fail(ctx context.Context, jobID domain.ID, cause string, retry bool) error

	// Cancel cancels a single non-terminal job.
	Cancel(ctx context.Context, jobID domain.ID) error

	// CancelScan cancels every non-terminal job of a scan. Returns the count.
	CancelScan(ctx context.Context, scanID domain.ID) (int, error)

	// Recover requeues ALL active (leased/running) jobs to queued. Intended for
	// process startup, when no worker legitimately holds a lease. Returns count.
	Recover(ctx context.Context) (int, error)

	// ReapExpired requeues active jobs whose lease expired at or before now
	// (dead-worker detection during normal running). Returns count.
	ReapExpired(ctx context.Context, now time.Time) (int, error)

	// Stats returns job counts by state for a scan.
	Stats(ctx context.Context, scanID domain.ID) (Stats, error)
}

// Tuning constants for retry backoff.
const (
	backoffBase = 2 * time.Second
	backoffCap  = 5 * time.Minute
)

// backoff computes the retry delay for the given (1-based) attempt number using
// capped exponential backoff.
func backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := float64(backoffBase) * math.Pow(2, float64(attempt-1))
	if d > float64(backoffCap) {
		return backoffCap
	}
	return time.Duration(d)
}

// defaultIfZero returns v, or def when v is the zero Time.
func defaultIfZero(v, def time.Time) time.Time {
	if v.IsZero() {
		return def
	}
	return v
}
