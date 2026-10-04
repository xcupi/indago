package sqlite_test

import (
	"context"
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

	// schema_migrations should contain exactly the embedded migrations once each.
	var count int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 applied migration, got %d", count)
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
