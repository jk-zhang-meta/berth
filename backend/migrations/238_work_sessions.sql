-- First-class work sessions: one row per user + client session_id.
-- usage_logs.session_id already correlates requests; this table owns assignment,
-- importance, and liveness so scheduling can pin accounts like PersonalWeb.

CREATE TABLE IF NOT EXISTS work_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    api_key_id BIGINT,
    client_session_id VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL DEFAULT '',
    title VARCHAR(200),
    cwd VARCHAR(512),
    host VARCHAR(200),
    importance SMALLINT NOT NULL DEFAULT 50,
    assigned_account_id BIGINT,
    last_account_id BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'live',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT work_sessions_user_session UNIQUE (user_id, client_session_id)
);

CREATE INDEX IF NOT EXISTS idx_work_sessions_user_seen
    ON work_sessions (user_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_work_sessions_live_account
    ON work_sessions (last_account_id)
    WHERE status = 'live' AND last_account_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_session
    ON usage_logs (user_id, session_id)
    WHERE session_id IS NOT NULL;

INSERT INTO work_sessions (
    user_id, api_key_id, client_session_id, last_account_id, last_seen_at, created_at, status
)
SELECT DISTINCT ON (user_id, session_id)
    user_id,
    api_key_id,
    session_id,
    account_id,
    created_at,
    created_at,
    'live'
FROM usage_logs
WHERE session_id IS NOT NULL AND session_id <> ''
ORDER BY user_id, session_id, created_at DESC
ON CONFLICT (user_id, client_session_id) DO NOTHING;
