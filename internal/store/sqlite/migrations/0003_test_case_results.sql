-- Test execution results (test job executor).
--
-- A test_case row records one execution of a request for a job attempt: what was
-- sent, how it ended (outcome), and references to the request/response evidence.

ALTER TABLE test_cases ADD COLUMN attempt      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE test_cases ADD COLUMN outcome      TEXT    NOT NULL DEFAULT '';
ALTER TABLE test_cases ADD COLUMN method       TEXT    NOT NULL DEFAULT '';
ALTER TABLE test_cases ADD COLUMN url          TEXT    NOT NULL DEFAULT '';
ALTER TABLE test_cases ADD COLUMN http_status  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE test_cases ADD COLUMN duration_ms  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE test_cases ADD COLUMN error        TEXT    NOT NULL DEFAULT '';
ALTER TABLE test_cases ADD COLUMN evidence_ids TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE test_cases ADD COLUMN started_at   TEXT;
ALTER TABLE test_cases ADD COLUMN finished_at  TEXT;

CREATE INDEX idx_testcases_job ON test_cases (job_id);
