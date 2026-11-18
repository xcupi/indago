package sqlite_test

// Scheme/port restriction survives persistence, and a database written before
// the feature upgrades to a scope that still behaves exactly as it used to
// (empty origin list = legacy any scheme/port).

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/sqlite"
)

func TestScopeOriginsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "origins.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	project := &domain.Project{ID: domain.NewID(), Name: "p", CreatedAt: now, UpdatedAt: now}
	if err := db.Projects().Create(ctx, project); err != nil {
		t.Fatal(err)
	}
	sc := &domain.Scope{
		ID:                  domain.NewID(),
		ProjectID:           project.ID,
		IncludeHosts:        []string{"app.example.com"},
		AllowedOrigins:      []string{"http://app.example.com", "https://app.example.com:8443"},
		AllowAnySchemePorts: false,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := db.Scopes().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := db.Scopes().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := sc.AllowedOrigins; !slices.Equal(got.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want %v", got.AllowedOrigins, want)
	}
	if got.AllowAnySchemePorts {
		t.Fatal("allow_any_scheme_ports should be false")
	}
	if d := got.Permits("https://app.example.com:8443/x"); !d.Allowed {
		t.Fatalf("stored origin denied after reload: %+v", d)
	}
	if d := got.Permits("https://app.example.com:9443/x"); d.Allowed {
		t.Fatal("an undeclared port was allowed after reload")
	}

	// Update must persist both fields, including the explicit legacy opt-out.
	got.AllowedOrigins = []string{"https://app.example.com"}
	got.AllowAnySchemePorts = true
	got.UpdatedAt = now.Add(time.Minute)
	if err := db.Scopes().Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	reloaded, err := db.Scopes().GetByProject(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://app.example.com"}; !slices.Equal(reloaded.AllowedOrigins, want) {
		t.Fatalf("updated allowed_origins = %v, want %v", reloaded.AllowedOrigins, want)
	}
	if !reloaded.AllowAnySchemePorts {
		t.Fatal("allow_any_scheme_ports was not persisted")
	}
}

func TestMigrationKeepsLegacyScopeUnrestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy_origins.db")
	ctx := context.Background()

	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A database from before origin rules: schema 0001 only, with one scope.
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
		`INSERT INTO scopes (id, project_id, include_hosts, exclude_hosts, include_path_prefixes, exclude_path_prefixes, allow_subdomains, created_at, updated_at)
		 VALUES ('legacy-scope','p','["a.example.com"]','[]','[]','[]',1,?,?)`,
		now, now); err != nil {
		t.Fatal(err)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migrate: %v", err)
	}
	got, err := db.Scopes().Get(ctx, "legacy-scope")
	if err != nil {
		t.Fatalf("legacy scope unreadable after upgrade: %v", err)
	}
	if len(got.AllowedOrigins) != 0 {
		t.Fatalf("a legacy row must not gain origins: %v", got.AllowedOrigins)
	}
	if got.AllowAnySchemePorts {
		t.Fatal("a legacy row must not gain an explicit opt-out")
	}
	// The upgrade is the only way this shape can exist; it must be recognised
	// as legacy (so the write surfaces ask its operator for a policy) rather
	// than read as "an explicit choice of nothing".
	if !got.LegacySchemePorts() {
		t.Fatal("an upgraded row with no origin list must read as legacy")
	}
	// The columns' own defaults, not just the Go decoding, are the compatibility
	// promise: a row that predates the feature must read back as an empty list
	// and a false flag.
	var originsJSON string
	var allowAny int
	if err := raw.QueryRowContext(ctx,
		`SELECT allowed_origins, allow_any_scheme_ports FROM scopes WHERE id='legacy-scope'`).
		Scan(&originsJSON, &allowAny); err != nil {
		t.Fatalf("read upgraded columns: %v", err)
	}
	if originsJSON != "[]" || allowAny != 0 {
		t.Fatalf("upgraded legacy row = origins %q any %d, want []/0", originsJSON, allowAny)
	}
	// The documented compatibility promise: unchanged behaviour, any scheme and
	// any port of an in-scope host.
	for _, u := range []string{
		"http://a.example.com/x",
		"https://a.example.com:8443/x",
		"ftp://a.example.com/x",
	} {
		if d := got.Permits(u); !d.Allowed {
			t.Errorf("legacy scope denied %q after upgrade: %+v", u, d)
		}
	}
	// And the authority boundary keeps the same legacy answer.
	if !got.PermitsHost("a.example.com:8443") {
		t.Fatal("legacy scope lost its host-only authority behaviour")
	}
}
