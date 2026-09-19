-- Berth: who docked an account/proxy. Admin still schedules the whole pool.

CREATE TABLE IF NOT EXISTS account_stewards (
    account_id BIGINT PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS account_stewards_user_id_idx ON account_stewards (user_id);

CREATE TABLE IF NOT EXISTS proxy_stewards (
    proxy_id   BIGINT PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS proxy_stewards_user_id_idx ON proxy_stewards (user_id);

CREATE TABLE IF NOT EXISTS pelican_tests (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL,
    owner_user_id BIGINT,
    model         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'running',
    html          TEXT,
    error         TEXT,
    duration_ms   BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pelican_tests_created_at_idx ON pelican_tests (created_at DESC);
