package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/sqlite"
	"github.com/indago/indago/internal/store/storetest"
)

func mkProject(t *testing.T, ctx context.Context, s store.Store) domain.ID {
	t.Helper()
	p := &domain.Project{ID: domain.NewID(), Name: "persisted", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.Projects().Create(ctx, p); err != nil {
		t.Fatalf("create project: %v", err)
	}
	return p.ID
}

func newDB(t *testing.T) (store.Store, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "indago_test.db")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, func() { _ = db.Close() }
}

func TestSQLiteStoreConformance(t *testing.T) {
	storetest.Run(t, newDB)
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.db")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := db.Migrate(ctx); err != nil {
			t.Fatalf("migrate pass %d: %v", i, err)
		}
	}

	// schema_migrations should contain exactly the embedded migrations once each
	// (0001_init … 0004_test_case_detail).
	var count int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("expected 4 applied migrations, got %d", count)
	}
}

func TestReopenPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	ctx := context.Background()

	db1, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	pid := mkProject(t, ctx, db1)
	_ = db1.Close()

	// Reopen and confirm the project survived.
	db2, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if _, err := db2.Projects().Get(ctx, pid); err != nil {
		t.Fatalf("project did not persist across reopen: %v", err)
	}
}

// TestMigrationUpgradesExistingScans proves migration 0002 upgrades a database
// that already holds scan rows created under schema 1: existing rows get the
// column defaults and remain readable.
func TestMigrationUpgradesExistingScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	ctx := context.Background()

	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Apply only migration 0001 by hand, then insert a legacy scan row.
	raw := db.SQL()
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES ('0001_init.sql')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO scans (id, project_id, target_id, name, state, profile, created_at, updated_at) VALUES ('legacy','p','t','old','completed','balanced',?,?)`,
		now, now); err != nil {
		t.Fatal(err)
	}

	// Now run the real migrator: only 0002 should apply.
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migrate: %v", err)
	}
	got, err := db.Scans().Get(ctx, "legacy")
	if err != nil {
		t.Fatalf("legacy scan unreadable after upgrade: %v", err)
	}
	if got.Discovery != domain.DiscoveryPending || len(got.SeedURLs) != 0 {
		t.Fatalf("legacy defaults wrong: discovery=%q seeds=%v", got.Discovery, got.SeedURLs)
	}
}
