package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func TestReviewLegacyAutomatedVerdicts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.db.ExecContext(ctx, `CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		t.Fatal(err)
	}
	names, err := migrationNames()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name >= "0018_" {
			break
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.applyMigration(ctx, name, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Unix(1700000000, 0).UTC()
	scan := &domain.Scan{
		ID: "legacy-scan", ProjectID: "project", TargetID: "target", State: domain.ScanCompleted,
		CreatedAt: now, UpdatedAt: now, Stats: domain.ScanStats{FindingsConfirmed: 2, EndpointsDiscovered: 4},
	}
	if err := db.Scans().Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	const detail = `{"status":200}`
	for _, item := range []struct{ id, engine string }{{"legacy", "file_upload"}, {"independent", "manual_review"}} {
		prov, err := jsonEncode(domain.Provenance{Engine: item.engine, VerifiedAt: &now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.ExecContext(ctx,
			`INSERT INTO findings (`+findingCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			item.id, scan.ID, scan.ProjectID, domain.VulnFileUpload, domain.VerdictConfirmed, domain.SeverityHigh,
			domain.ConfidenceHigh, "Upload check", "original", "", "", "", "", `["stored-evidence"]`, prov, detail, ts(now), ts(now)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reviewed, err := db.Findings().Get(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if reviewed.Verdict != domain.VerdictInconclusive || reviewed.Provenance.Assessment != "upload_http_response" ||
		reviewed.Provenance.VerifiedAt != nil || string(reviewed.Detail) != detail ||
		len(reviewed.EvidenceIDs) != 1 || reviewed.EvidenceIDs[0] != "stored-evidence" {
		t.Fatalf("invalid reviewed finding: %+v", reviewed)
	}
	var verdict, summary string
	if err := db.db.QueryRowContext(ctx, `SELECT verdict, summary FROM legacy_verdict_reviews WHERE finding_id='legacy'`).Scan(&verdict, &summary); err != nil ||
		verdict != "confirmed" || summary != "original" {
		t.Fatalf("original assessment missing: %q %q (%v)", verdict, summary, err)
	}
	independent, err := db.Findings().Get(ctx, "independent")
	if err != nil || independent.Verdict != domain.VerdictConfirmed {
		t.Fatalf("independent finding was changed: %+v (%v)", independent, err)
	}
	scan, err = db.Scans().Get(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Stats.FindingsConfirmed != 1 || scan.Stats.FindingsInconclusive != 1 || scan.Stats.EndpointsDiscovered != 4 {
		t.Fatalf("wrong recalculated scan stats: %+v", scan.Stats)
	}
}
