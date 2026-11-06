-- The crawl observes many values for one parameter name, but endpoints dedup by
-- path + parameter NAMES only, so only the first value survives on the
-- parameter row. Object-identifier differentials (IDOR) need the other values:
-- other users' ids appear as link values, and without them a scan can only ever
-- see the caller's own identifier. Stored as a bounded JSON array.
ALTER TABLE parameters ADD COLUMN examples TEXT NOT NULL DEFAULT '[]';
