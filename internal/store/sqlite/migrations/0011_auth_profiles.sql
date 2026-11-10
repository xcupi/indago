CREATE TABLE auth_profiles (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    login_url   TEXT NOT NULL DEFAULT '',
    success_url TEXT NOT NULL DEFAULT '',
    state_path  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX idx_auth_profiles_project ON auth_profiles (project_id);
ALTER TABLE targets ADD COLUMN auth_profile_id TEXT NOT NULL DEFAULT '';
