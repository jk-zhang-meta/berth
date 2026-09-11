ALTER TABLE work_sessions
    ADD COLUMN IF NOT EXISTS ags_id VARCHAR(64);

CREATE TABLE IF NOT EXISTS work_session_queue (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES work_sessions(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL,
    priority INT NOT NULL DEFAULT 50,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_work_session_queue_account
    ON work_session_queue (account_id);

CREATE TABLE IF NOT EXISTS account_rentals (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL,
    owner_user_id BIGINT NOT NULL,
    borrower_user_id BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'listed',
    token_quota BIGINT,
    duration_hours INT,
    concurrency INT,
    exclusive BOOLEAN NOT NULL DEFAULT TRUE,
    note TEXT,
    requested_at TIMESTAMPTZ,
    starts_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_rentals_account_status
    ON account_rentals (account_id, status);
CREATE INDEX IF NOT EXISTS idx_account_rentals_borrower
    ON account_rentals (borrower_user_id, status);
CREATE INDEX IF NOT EXISTS idx_account_rentals_owner
    ON account_rentals (owner_user_id, status);
