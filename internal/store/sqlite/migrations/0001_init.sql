-- Indago initial schema (Phase 0).
--
-- Conventions:
--   * IDs and enums are TEXT.
--   * Timestamps are TEXT in RFC3339Nano (UTC). Nullable timestamps are NULL.
--   * Structured sub-objects (config, provenance, summaries, string slices) are
--     stored as JSON TEXT. Opaque binary payloads are BLOB.
--   * Large evidence blobs live on the filesystem; only metadata is stored here.

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE targets (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    base_url   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_targets_project ON targets (project_id);

CREATE TABLE scopes (
    id                    TEXT PRIMARY KEY,
    project_id            TEXT NOT NULL,
    include_hosts         TEXT NOT NULL DEFAULT '[]',
    exclude_hosts         TEXT NOT NULL DEFAULT '[]',
    include_path_prefixes TEXT NOT NULL DEFAULT '[]',
    exclude_path_prefixes TEXT NOT NULL DEFAULT '[]',
    allow_subdomains      INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);
CREATE INDEX idx_scopes_project ON scopes (project_id);

CREATE TABLE scans (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL,
    profile     TEXT NOT NULL,
    config      TEXT NOT NULL DEFAULT '{}',
    stop_policy TEXT NOT NULL DEFAULT '{}',
    session_id  TEXT NOT NULL DEFAULT '',
    stats       TEXT NOT NULL DEFAULT '{}',
    error       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    updated_at  TEXT NOT NULL,
    ended_at    TEXT
);
CREATE INDEX idx_scans_project ON scans (project_id);

CREATE TABLE endpoints (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    url          TEXT NOT NULL,
    method       TEXT NOT NULL,
    source       TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    fingerprint  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_endpoints_scan ON endpoints (scan_id);

CREATE TABLE parameters (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    location    TEXT NOT NULL,
    example     TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_parameters_scan ON parameters (scan_id);
CREATE INDEX idx_parameters_endpoint ON parameters (endpoint_id);

CREATE TABLE injection_points (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    endpoint_id  TEXT NOT NULL,
    parameter_id TEXT NOT NULL,
    location     TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_injpoints_scan ON injection_points (scan_id);

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    type         TEXT NOT NULL,
    state        TEXT NOT NULL,
    priority     INTEGER NOT NULL DEFAULT 0,
    target       TEXT NOT NULL DEFAULT '{}',
    payload      BLOB,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 0,
    lease_id     TEXT NOT NULL DEFAULT '',
    leased_until TEXT,
    last_error   TEXT NOT NULL DEFAULT '',
    available_at TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX idx_jobs_scan_state ON jobs (scan_id, state);
-- Supports the lease query: next available queued job by priority then age.
CREATE INDEX idx_jobs_lease ON jobs (state, priority DESC, available_at ASC);

CREATE TABLE test_cases (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    job_id             TEXT NOT NULL,
    injection_point_id TEXT NOT NULL,
    vuln_class         TEXT NOT NULL,
    status             TEXT NOT NULL,
    note               TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX idx_testcases_scan ON test_cases (scan_id);

CREATE TABLE findings (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    project_id         TEXT NOT NULL,
    vuln_class         TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    severity           TEXT NOT NULL,
    confidence         TEXT NOT NULL,
    title              TEXT NOT NULL,
    summary            TEXT NOT NULL DEFAULT '',
    endpoint_id        TEXT NOT NULL DEFAULT '',
    injection_point_id TEXT NOT NULL DEFAULT '',
    location           TEXT NOT NULL DEFAULT '',
    evidence_ids       TEXT NOT NULL DEFAULT '[]',
    provenance         TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX idx_findings_scan ON findings (scan_id);
CREATE INDEX idx_findings_project ON findings (project_id);

CREATE TABLE evidence (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL,
    media_type TEXT NOT NULL DEFAULT '',
    blob_path  TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    sha256     TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_scan ON evidence (scan_id);
CREATE INDEX idx_evidence_finding ON evidence (finding_id);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    mode       TEXT NOT NULL,
    state      TEXT NOT NULL,
    state_path TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_scan ON sessions (scan_id);

CREATE TABLE reports (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    project_id TEXT NOT NULL,
    format     TEXT NOT NULL,
    path       TEXT NOT NULL,
    summary    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_reports_scan ON reports (scan_id);

CREATE TABLE ai_tasks (
    id         TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL,
    state      TEXT NOT NULL,
    provider   TEXT NOT NULL DEFAULT '',
    model      TEXT NOT NULL DEFAULT '',
    advisory   INTEGER NOT NULL DEFAULT 1,
    request    BLOB,
    response   BLOB,
    error      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_aitasks_scan ON ai_tasks (scan_id);
