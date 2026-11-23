package sqlite

import (
	"context"
	"database/sql"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

func (r *scanRepo) Overview(ctx context.Context, recentLimit int) (store.ScanOverview, error) {
	// A read transaction keeps the counters and recent rows on the same
	// snapshot even when a scan changes state between the two queries.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return store.ScanOverview{}, err
	}
	defer tx.Rollback()

	overview, err := scanOverviewTotals(ctx, tx)
	if err != nil {
		return store.ScanOverview{}, err
	}
	overview.Recent, err = recentScanOverview(ctx, tx, max(0, recentLimit))
	if err != nil {
		return store.ScanOverview{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.ScanOverview{}, err
	}
	return overview, nil
}

func scanOverviewTotals(ctx context.Context, tx *sql.Tx) (store.ScanOverview, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT state, COUNT(*),
			COALESCE(SUM(CASE WHEN json_valid(stats) THEN CAST(json_extract(stats, '$.findings_confirmed') AS INTEGER) END), 0),
			COALESCE(SUM(CASE WHEN json_valid(stats) THEN CAST(json_extract(stats, '$.findings_rejected') AS INTEGER) END), 0)
		FROM scans GROUP BY state`)
	if err != nil {
		return store.ScanOverview{}, err
	}
	defer rows.Close()

	overview := store.ScanOverview{States: make(map[domain.ScanState]int)}
	for rows.Next() {
		var state domain.ScanState
		var count, confirmed, rejected int
		if err := rows.Scan(&state, &count, &confirmed, &rejected); err != nil {
			return store.ScanOverview{}, err
		}
		overview.States[state] = count
		overview.Total += count
		overview.FindingsConfirmed += confirmed
		overview.FindingsRejected += rejected
	}
	return overview, rows.Err()
}

func recentScanOverview(ctx context.Context, tx *sql.Tx, limit int) ([]store.ScanOverviewItem, error) {
	// Stored timestamps are UTC RFC3339Nano. Trimming Z makes fractional
	// seconds sort correctly when either row has a shorter fractional part.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, state, created_at, stats, seed_urls
		FROM scans ORDER BY rtrim(created_at, 'Z') DESC, id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	recent := make([]store.ScanOverviewItem, 0)
	for rows.Next() {
		var item store.ScanOverviewItem
		var created, stats, seeds string
		if err := rows.Scan(&item.ID, &item.Name, &item.State, &created, &stats, &seeds); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = parseTS(created)
		var counts domain.ScanStats
		_ = jsonDecode(stats, &counts)
		item.FindingsConfirmed = counts.FindingsConfirmed
		item.EndpointsDiscovered = counts.EndpointsDiscovered
		if item.Name == "" {
			var urls []string
			_ = jsonDecode(seeds, &urls)
			if len(urls) > 0 {
				item.Name = urls[0]
			}
		}
		recent = append(recent, item)
	}
	return recent, rows.Err()
}
