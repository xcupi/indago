ALTER TABLE projects ADD COLUMN hunting_user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN hunting_user_agent_replace INTEGER NOT NULL DEFAULT 0;
