-- The legacy HTTP probe treated a successful status as verification. Preserve
-- its original assessment, then qualify only findings produced by that engine.
CREATE TABLE legacy_csrf_reviews (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    summary TEXT NOT NULL,
    provenance TEXT NOT NULL,
    detail TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO legacy_csrf_reviews (finding_id, verdict, severity, confidence, summary, provenance, detail, updated_at)
SELECT id, verdict, severity, confidence, summary, provenance, detail, updated_at
FROM findings
WHERE vuln_class = 'csrf' AND verdict = 'confirmed'
  AND CASE WHEN json_valid(provenance) THEN json_extract(provenance, '$.engine') = 'csrf' ELSE 0 END;

UPDATE findings
SET verdict = 'inconclusive',
    severity = 'info',
    confidence = 'low',
    summary = 'Legacy HTTP probe. The response status did not establish authenticated browser behavior or a user-impacting action.',
    provenance = json_remove(provenance, '$.verified_at'),
    detail = CASE WHEN json_valid(detail) THEN json_set(detail, '$.verdict', 'inconclusive',
        '$.severity', 'info', '$.confidence', 'low', '$.reason',
        'HTTP acceptance alone did not establish authenticated browser behavior or impact.')
        ELSE detail END,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id IN (SELECT finding_id FROM legacy_csrf_reviews);

UPDATE scans
SET stats = json_set(CASE WHEN json_valid(stats) THEN stats ELSE '{}' END,
    '$.findings_confirmed', (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id AND verdict = 'confirmed'),
    '$.findings_inconclusive', (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id AND verdict = 'inconclusive'))
WHERE id IN (SELECT scan_id FROM findings WHERE id IN (SELECT finding_id FROM legacy_csrf_reviews));
