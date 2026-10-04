-- Scan discovery state (scan controller integration).
--
--   seed_urls        JSON array of operator-provided discovery seeds.
--   discovery_state  pending | running | complete | canceled. Persisted so a
--                    restarted scan knows whether discovery must run again.

ALTER TABLE scans ADD COLUMN seed_urls TEXT NOT NULL DEFAULT '[]';
ALTER TABLE scans ADD COLUMN discovery_state TEXT NOT NULL DEFAULT 'pending';
