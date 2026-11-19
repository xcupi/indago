package sqlite_test

// Tests for the store's operational lifecycle: Ping (used by /readyz) and a
// Close that checkpoints the WAL so a stopped server leaves the database file
// complete on its own.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/sqlite"
)

func TestPingWhileOpenAndAfterClose(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "ping.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := db.Ping(ctx); err != nil {
		t.Fatalf("Ping on an open database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := db.Ping(ctx); err == nil {
		t.Fatal("Ping after Close succeeded; readiness would report a closed store as ready")
	}
}

// TestCloseCheckpointsWAL proves Close actually truncates the WAL rather than
// relying on SQLite's last-connection teardown. A second handle keeps the
// database open, so that teardown cannot remove or truncate the -wal file; a
// zero-length WAL afterwards can only come from the explicit TRUNCATE
// checkpoint Close runs.
func TestCloseCheckpointsWAL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "checkpoint.db")
	walPath := path + "-wal"

	db1, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	p := &domain.Project{ID: domain.NewID(), Name: "checkpointed", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db1.Projects().Create(ctx, p); err != nil {
		t.Fatal(err)
	}

	// A second connection to the same database, held open across db1.Close().
	db2, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	before, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("stat WAL before close: %v", err)
	}
	if before.Size() == 0 {
		t.Fatal("WAL is empty before close; the test did not produce any WAL pages")
	}

	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	after, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("stat WAL after close: %v", err)
	}
	if after.Size() != 0 {
		t.Fatalf("WAL is %d bytes after Close (was %d); the TRUNCATE checkpoint did not run", after.Size(), before.Size())
	}

	// The checkpoint must not lose the write: it is still readable, through the
	// other connection, from the main database file.
	if _, err := db2.Projects().Get(ctx, p.ID); err != nil {
		t.Fatalf("project unreadable after WAL checkpoint: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "idempotent.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
