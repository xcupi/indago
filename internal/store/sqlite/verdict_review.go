package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/indago/indago/internal/assessment"
	"github.com/indago/indago/internal/domain"
)

func reviewAutomatedVerdicts(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+findingCols+` FROM findings WHERE verdict = 'confirmed'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var review []*domain.Finding
	for rows.Next() {
		original, err := scanFinding(rows)
		if err != nil {
			return err
		}
		if finding, changed := assessment.Finding(original); changed {
			review = append(review, finding)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	now := ts(time.Now().UTC())
	for _, f := range review {
		prov, err := jsonEncode(f.Provenance)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO legacy_verdict_reviews
			SELECT id, verdict, severity, confidence, summary, provenance, updated_at FROM findings WHERE id=?`, f.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET verdict=?, severity=?, confidence=?, summary=?, provenance=?, updated_at=? WHERE id=?`,
			f.Verdict, f.Severity, f.Confidence, f.Summary, prov, now, f.ID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE scans
		SET stats = json_set(CASE WHEN json_valid(stats) THEN stats ELSE '{}' END,
			'$.findings_confirmed', (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id AND verdict = 'confirmed'),
			'$.findings_inconclusive', (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id AND verdict = 'inconclusive'))
		WHERE id IN (SELECT f.scan_id FROM findings f JOIN legacy_verdict_reviews r ON r.finding_id = f.id)`)
	return err
}
