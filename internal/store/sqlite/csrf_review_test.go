package sqlite_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/sqlite"
)

func TestReviewLegacyHTTPOnlyCSRF(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	raw := db.SQL()
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		name := filepath.Base(path)
		if name >= "0017_" {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		if _, err := raw.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES (?)`, name); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	scan := &domain.Scan{
		ID: "legacy-scan", ProjectID: "project", TargetID: "target", State: domain.ScanCompleted,
		CreatedAt: now, UpdatedAt: now, Stats: domain.ScanStats{FindingsConfirmed: 3, EndpointsDiscovered: 7},
	}
	if err := db.Scans().Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, engine string
		class      domain.VulnClass
	}{
		{"historical", "csrf", domain.VulnCSRF},
		{"independent", "manual_review", domain.VulnCSRF},
		{"other", "headers", domain.VulnClass("security_headers")},
	} {
		f := &domain.Finding{
			ID: domain.ID(row.id), ScanID: scan.ID, ProjectID: scan.ProjectID, Title: row.id,
			VulnClass: row.class, Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
			EvidenceIDs: []domain.ID{"stored-fixture-evidence"}, Provenance: domain.Provenance{Engine: row.engine, VerifiedAt: &now},
			Summary: "original HTTP record", Detail: []byte(`{"verdict":"confirmed","http_status":200}`), CreatedAt: now, UpdatedAt: now,
		}
		if err := db.Findings().Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 2; i++ {
		if err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reviewed, err := db.Findings().Get(ctx, "historical")
	if err != nil {
		t.Fatal(err)
	}
	if reviewed.Verdict != domain.VerdictInconclusive || reviewed.Severity != domain.SeverityInfo || reviewed.Confidence != domain.ConfidenceLow ||
		reviewed.Provenance.VerifiedAt != nil || len(reviewed.EvidenceIDs) != 1 || reviewed.EvidenceIDs[0] != "stored-fixture-evidence" {
		t.Fatalf("unexpected reclassification: %+v", reviewed)
	}
	var detail map[string]any
	if err := json.Unmarshal(reviewed.Detail, &detail); err != nil || detail["verdict"] != "inconclusive" || detail["http_status"] != float64(200) {
		t.Fatalf("unexpected reclassified detail: %s (%v)", reviewed.Detail, err)
	}
	var oldVerdict, oldSummary string
	if err := raw.QueryRowContext(ctx, `SELECT verdict, summary FROM legacy_csrf_reviews WHERE finding_id = 'historical'`).Scan(&oldVerdict, &oldSummary); err != nil ||
		oldVerdict != "confirmed" || oldSummary != "original HTTP record" {
		t.Fatalf("original assessment missing: %q %q (%v)", oldVerdict, oldSummary, err)
	}
	for _, id := range []domain.ID{"independent", "other"} {
		f, err := db.Findings().Get(ctx, id)
		if err != nil || f.Verdict != domain.VerdictConfirmed || f.Provenance.VerifiedAt == nil {
			t.Fatalf("unrelated finding changed: %+v (%v)", f, err)
		}
	}
	current, err := db.Scans().Get(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Stats.FindingsConfirmed != 2 || current.Stats.FindingsInconclusive != 1 || current.Stats.EndpointsDiscovered != 7 {
		t.Fatalf("unexpected scan statistics: %+v", current.Stats)
	}
}
