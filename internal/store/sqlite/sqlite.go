// Package sqlite provides the durable, local-first implementation of
// store.Store backed by SQLite via the pure-Go modernc.org/sqlite driver
// (no cgo). It is the default persistence backend for Indago.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/indago/indago/internal/store"
)

// closeCheckpointTimeout bounds the WAL checkpoint Close runs before closing
// the handle. The busy timeout is 5s, so a checkpoint that cannot complete
// promptly is abandoned (the WAL file stays, which SQLite tolerates) rather
// than holding process shutdown open.
const closeCheckpointTimeout = 5 * time.Second

// DB is the SQLite-backed store.
type DB struct {
	db *sql.DB

	// closeOnce makes Close idempotent: shutdown code closes the store
	// explicitly and defers a safety-net Close, and a second checkpoint on a
	// closed handle would fail with "database is closed" for no reason.
	closeOnce sync.Once
	closeErr  error
}

// Open opens (creating if necessary) a SQLite database at path and applies
// pragmas suited to a local-first, single-user workload. Use ":memory:" for an
// ephemeral database (tests).
//
// The caller must call Migrate before use and Close when done.
func Open(path string) (*DB, error) {
	dsn := buildDSN(path)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// Single-user, local-first: serialize access with one connection to avoid
	// writer-lock contention. WAL still provides durability benefits. This can
	// be revisited (separate read pool) if read concurrency becomes a need.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxLifetime(0)

	if err := sqlDB.PingContext(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	return &DB{db: sqlDB}, nil
}

func buildDSN(path string) string {
	// modernc.org/sqlite accepts connection pragmas via repeated _pragma params.
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(NORMAL)")
	return "file:" + path + "?" + q.Encode()
}

// Ping verifies the database is reachable.
func (d *DB) Ping(ctx context.Context) error { return d.db.PingContext(ctx) }

// Close checkpoints the write-ahead log into the main database file and then
// closes the handle. The TRUNCATE checkpoint leaves the WAL empty, so after a
// clean shutdown the database file alone is a complete backup — the same thing
// backup instructions assume when they tell an operator to stop the server and
// copy the data directory. SQLite's own last-connection close does a passive
// checkpoint, but it cannot truncate or remove the WAL while another
// connection still has the database open, so the explicit checkpoint is what
// makes the guarantee hold in that case.
//
// The checkpoint is bounded (closeCheckpointTimeout) and best effort: if it
// cannot complete, Close still closes the handle and returns an error naming
// the reason. Close is idempotent; later calls return the first result.
func (d *DB) Close() error {
	d.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), closeCheckpointTimeout)
		defer cancel()

		// PRAGMA wal_checkpoint returns one row (busy, log pages, checkpointed
		// pages) on a WAL database and (0, -1, -1) on a non-WAL one (":memory:"
		// in tests), so scanning the row is valid for both.
		var busy, logPages, checked int
		err := d.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logPages, &checked)
		if err == nil && busy != 0 {
			err = fmt.Errorf("checkpoint incomplete: %d WAL pages remain", logPages)
		}
		if err != nil {
			d.closeErr = fmt.Errorf("sqlite: wal checkpoint: %w", err)
		}
		if cerr := d.db.Close(); cerr != nil {
			d.closeErr = errors.Join(d.closeErr, cerr)
		}
	})
	return d.closeErr
}

// SQL exposes the underlying *sql.DB for advanced callers (e.g. a persistent
// queue implementation). Most code should use the repository interfaces.
func (d *DB) SQL() *sql.DB { return d.db }

// Ensure DB satisfies store.Store.
var _ store.Store = (*DB)(nil)

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

const tsLayout = time.RFC3339Nano

// ts formats a time as a UTC RFC3339Nano string for storage.
func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

// tsPtr formats a nullable time for storage (nil → SQL NULL).
func tsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(tsLayout)
}

// parseTS parses a stored timestamp string.
func parseTS(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(tsLayout, s)
}

// parseTSPtr parses a nullable stored timestamp.
func parseTSPtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := time.Parse(tsLayout, ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// boolToInt maps a bool to SQLite's 0/1 integer representation.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
