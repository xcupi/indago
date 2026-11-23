-- Keep each prior assessment alongside the finding. Its raw evidence and
-- original engine telemetry continue to live at their existing IDs.
CREATE TABLE legacy_verdict_reviews (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    summary TEXT NOT NULL,
    provenance TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
