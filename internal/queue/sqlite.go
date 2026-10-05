package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/indago/indago/internal/domain"
)

// SQLite is a persistent Queue backed by the shared `jobs` table. It operates
// directly on a *sql.DB (obtained from the sqlite store via SQL()), which keeps
// the queue decoupled from the store package while reusing the same schema.
//
// Leasing is atomic: a candidate is selected and claimed with a state-guarded
// UPDATE inside a transaction, so concurrent workers never double-lease a job.
type SQLite struct {
	db  *sql.DB
	now func() time.Time
}

// NewSQLite returns a persistent queue over the given database. The caller is
// responsible for having created the schema (store/sqlite Migrate).
func NewSQLite(db *sql.DB) *SQLite {
	return &SQLite{db: db, now: time.Now}
}

// SetClock overrides the time source. It exists for deterministic tests and
// should not be used in production code.
func (q *SQLite) SetClock(fn func() time.Time) { q.now = fn }

var _ Queue = (*SQLite)(nil)

const qTimeLayout = time.RFC3339Nano

func qts(t time.Time) string { return t.UTC().Format(qTimeLayout) }

func qtsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(qTimeLayout)
}

func qparse(s string) time.Time {
	t, _ := time.Parse(qTimeLayout, s)
	return t
}

func qparsePtr(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, _ := time.Parse(qTimeLayout, ns.String)
	return &t
}

// placeholders returns "?,?,..." with n placeholders for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

const sqJobCols = `id, scan_id, type, state, priority, target, payload, attempts, max_attempts, lease_id, leased_until, last_error, available_at, created_at, updated_at`

func scanSQJob(sc interface{ Scan(...any) error }) (*domain.TestJob, error) {
	var j domain.TestJob
	var tgt, available, created, updated string
	var leased sql.NullString
	if err := sc.Scan(&j.ID, &j.ScanID, &j.Type, &j.State, &j.Priority, &tgt, &j.Payload,
		&j.Attempts, &j.MaxAttempts, &j.LeaseID, &leased, &j.LastError, &available, &created, &updated); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(tgt), &j.Target)
	j.LeasedUntil = qparsePtr(leased)
	j.AvailableAt = qparse(available)
	j.CreatedAt = qparse(created)
	j.UpdatedAt = qparse(updated)
	return &j, nil
}

func (q *SQLite) Enqueue(ctx context.Context, job *domain.TestJob) error {
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

	tgt, err := json.Marshal(job.Target)
	if err != nil {
		return err
	}
	_, err = q.db.ExecContext(ctx,
		`INSERT INTO jobs (`+sqJobCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.ScanID, job.Type, job.State, job.Priority, string(tgt), job.Payload,
		job.Attempts, job.MaxAttempts, job.LeaseID, qtsPtr(job.LeasedUntil), job.LastError,
		qts(job.AvailableAt), qts(job.CreatedAt), qts(job.UpdatedAt))
	return err
}

func (q *SQLite) Lease(ctx context.Context, workerID string, scanID domain.ID, types []domain.JobType, leaseFor time.Duration) (*domain.TestJob, error) {
	now := q.now()
	until := now.Add(leaseFor)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	sel := `SELECT id FROM jobs WHERE state=? AND available_at<=?`
	args := []any{domain.JobQueued, qts(now)}
	if !scanID.Empty() {
		sel += ` AND scan_id=?`
		args = append(args, scanID)
	}
	if len(types) > 0 {
		sel += ` AND type IN (` + placeholders(len(types)) + `)`
		for _, ty := range types {
			args = append(args, ty)
		}
	}
	sel += ` ORDER BY priority DESC, available_at ASC LIMIT 1`

	var id domain.ID
	err = tx.QueryRowContext(ctx, sel, args...).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, ErrNoJobs
	}
	if err != nil {
		return nil, err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id=?, leased_until=?, attempts=attempts+1, updated_at=? WHERE id=? AND state=?`,
		domain.JobRunning, workerID, qts(until), qts(now), id, domain.JobQueued)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Lost the race; report no job this round rather than blocking.
		return nil, ErrNoJobs
	}

	row := tx.QueryRowContext(ctx, `SELECT `+sqJobCols+` FROM jobs WHERE id=?`, id)
	job, err := scanSQJob(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func (q *SQLite) Heartbeat(ctx context.Context, jobID domain.ID, leaseFor time.Duration) error {
	now := q.now()
	until := now.Add(leaseFor)
	res, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET leased_until=?, updated_at=? WHERE id=? AND state IN (?,?)`,
		qts(until), qts(now), jobID, domain.JobLeased, domain.JobRunning)
	return q.requireRow(res, err)
}

func (q *SQLite) Complete(ctx context.Context, jobID domain.ID) error {
	now := q.now()
	res, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id='', leased_until=NULL, updated_at=? WHERE id=? AND state IN (?,?)`,
		domain.JobSucceeded, qts(now), jobID, domain.JobLeased, domain.JobRunning)
	return q.requireRow(res, err)
}

func (q *SQLite) Fail(ctx context.Context, jobID domain.ID, cause string, retry bool) error {
	now := q.now()
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var attempts, maxAttempts int
	if err := tx.QueryRowContext(ctx, `SELECT attempts, max_attempts FROM jobs WHERE id=?`, jobID).
		Scan(&attempts, &maxAttempts); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotLeasable
		}
		return err
	}

	if retry && attempts < maxAttempts {
		availAt := now.Add(backoff(attempts))
		_, err = tx.ExecContext(ctx,
			`UPDATE jobs SET state=?, last_error=?, lease_id='', leased_until=NULL, available_at=?, updated_at=? WHERE id=?`,
			domain.JobQueued, cause, qts(availAt), qts(now), jobID)
	} else {
		_, err = tx.ExecContext(ctx,
			`UPDATE jobs SET state=?, last_error=?, lease_id='', leased_until=NULL, updated_at=? WHERE id=?`,
			domain.JobDead, cause, qts(now), jobID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (q *SQLite) Cancel(ctx context.Context, jobID domain.ID) error {
	now := q.now()
	_, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id='', leased_until=NULL, updated_at=? WHERE id=? AND state NOT IN (?,?,?)`,
		domain.JobCanceled, qts(now), jobID, domain.JobSucceeded, domain.JobCanceled, domain.JobDead)
	return err
}

func (q *SQLite) CancelScan(ctx context.Context, scanID domain.ID) (int, error) {
	now := q.now()
	res, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id='', leased_until=NULL, updated_at=? WHERE scan_id=? AND state NOT IN (?,?,?)`,
		domain.JobCanceled, qts(now), scanID, domain.JobSucceeded, domain.JobCanceled, domain.JobDead)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (q *SQLite) Recover(ctx context.Context) (int, error) {
	now := q.now()
	res, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id='', leased_until=NULL, available_at=?, updated_at=? WHERE state IN (?,?)`,
		domain.JobQueued, qts(now), qts(now), domain.JobLeased, domain.JobRunning)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (q *SQLite) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := q.db.ExecContext(ctx,
		`UPDATE jobs SET state=?, lease_id='', leased_until=NULL, available_at=?, updated_at=? WHERE state IN (?,?) AND leased_until IS NOT NULL AND leased_until<=?`,
		domain.JobQueued, qts(now), qts(now), domain.JobLeased, domain.JobRunning, qts(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (q *SQLite) Jobs(ctx context.Context, scanID domain.ID) ([]*domain.TestJob, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT `+sqJobCols+` FROM jobs WHERE scan_id=? ORDER BY created_at ASC, id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.TestJob
	for rows.Next() {
		j, err := scanSQJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (q *SQLite) Stats(ctx context.Context, scanID domain.ID) (Stats, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM jobs WHERE scan_id=? GROUP BY state`, scanID)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	var s Stats
	for rows.Next() {
		var state domain.JobState
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return Stats{}, err
		}
		switch state {
		case domain.JobQueued:
			s.Queued = n
		case domain.JobLeased:
			s.Leased = n
		case domain.JobRunning:
			s.Running = n
		case domain.JobSucceeded:
			s.Succeeded = n
		case domain.JobFailed:
			s.Failed = n
		case domain.JobCanceled:
			s.Canceled = n
		case domain.JobDead:
			s.Dead = n
		}
	}
	return s, rows.Err()
}

func (q *SQLite) requireRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotLeasable
	}
	return nil
}
