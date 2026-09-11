-- A live session is per provider. The same client_session_id on Claude and
-- Codex must not share queue, importance, or occupancy.

UPDATE work_sessions
SET platform = 'unknown'
WHERE platform IS NULL OR btrim(platform) = '';

ALTER TABLE work_sessions
    ALTER COLUMN platform SET DEFAULT 'unknown';

ALTER TABLE work_sessions
    DROP CONSTRAINT IF EXISTS work_sessions_user_session;

DROP INDEX IF EXISTS work_sessions_user_session;

CREATE UNIQUE INDEX IF NOT EXISTS work_sessions_user_platform_session
    ON work_sessions (user_id, platform, client_session_id);

CREATE INDEX IF NOT EXISTS idx_work_sessions_user_platform_seen
    ON work_sessions (user_id, platform, last_seen_at DESC);
