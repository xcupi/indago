-- Engine-specific structured result for a test case (reflection report, etc.).
-- Opaque to the domain; stored as JSON text.

ALTER TABLE test_cases ADD COLUMN detail TEXT NOT NULL DEFAULT '';
