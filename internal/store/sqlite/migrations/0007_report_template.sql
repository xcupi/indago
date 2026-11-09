-- A report row states which deliverable layout produced it (pentest /
-- bug_bounty / technical) so the UI and API do not have to infer it from the
-- file's content. Empty keeps meaning the technical evidence-first layout,
-- which is also what every report created before this column existed used.
ALTER TABLE reports ADD COLUMN template TEXT NOT NULL DEFAULT '';
