-- Durable AGS / gateway work sessions. Keep this feature additive so Berth can
-- continue absorbing upstream Berth changes without moving account tables.

CREATE TABLE IF NOT EXISTS work_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    api_key_id BIGINT,
    client_session_id VARCHAR(255) NOT NULL DEFAULT '',
    platform VARCHAR(50) NOT NULL DEFAULT 'unknown',
    agent VARCHAR(32) NOT NULL DEFAULT '',
    ags_id VARCHAR(64),
    device_id VARCHAR(255),
    title VARCHAR(200),
    description TEXT,
    cwd VARCHAR(1024),
    host VARCHAR(255),
    importance SMALLINT NOT NULL DEFAULT 50,
    assigned_account_id BIGINT,
    last_account_id BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'live',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS work_sessions_user_platform_client
    ON work_sessions (user_id, platform, client_session_id)
    WHERE client_session_id <> '';

CREATE UNIQUE INDEX IF NOT EXISTS work_sessions_user_device
    ON work_sessions (user_id, device_id)
    WHERE device_id IS NOT NULL AND device_id <> '';

CREATE INDEX IF NOT EXISTS work_sessions_user_seen
    ON work_sessions (user_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS work_sessions_live_account
    ON work_sessions (last_account_id)
    WHERE status = 'live' AND last_account_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS usage_logs_user_session
    ON usage_logs (user_id, session_id)
    WHERE session_id IS NOT NULL AND session_id <> '';

CREATE TABLE IF NOT EXISTS work_session_queue (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES work_sessions(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL,
    priority INT NOT NULL DEFAULT 50,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, account_id)
);

CREATE INDEX IF NOT EXISTS work_session_queue_account
    ON work_session_queue (account_id);
