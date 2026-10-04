-- Correlation/provenance additions for findings. parameter_id completes the
-- scan→endpoint→parameter→injection_point provenance chain (which the finding
-- already carries via endpoint_id/injection_point_id). detail is an opaque,
-- engine-specific JSON blob — the same pattern as test_cases.detail — holding
-- the correlation key, the contributing candidate(s)/context, the TestCase IDs
-- that back it, and an occurrence count, so repeated verification results
-- correlate into one finding without losing raw evidence.
ALTER TABLE findings ADD COLUMN parameter_id TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN detail TEXT NOT NULL DEFAULT '';
