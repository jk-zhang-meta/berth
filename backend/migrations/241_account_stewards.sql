-- Per-user ownership for the Berth marketplace.
-- Existing accounts without a steward are assigned to the first admin.

CREATE TABLE IF NOT EXISTS account_stewards (
    account_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_stewards_user
    ON account_stewards (user_id);

CREATE TABLE IF NOT EXISTS proxy_stewards (
    proxy_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_proxy_stewards_user
    ON proxy_stewards (user_id);

INSERT INTO account_stewards (account_id, user_id)
SELECT a.id, u.id
FROM accounts a
CROSS JOIN LATERAL (
    SELECT id FROM users
    WHERE role = 'admin' AND deleted_at IS NULL
    ORDER BY id
    LIMIT 1
) u
WHERE a.deleted_at IS NULL
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO proxy_stewards (proxy_id, user_id)
SELECT p.id, u.id
FROM proxies p
CROSS JOIN LATERAL (
    SELECT id FROM users
    WHERE role = 'admin' AND deleted_at IS NULL
    ORDER BY id
    LIMIT 1
) u
WHERE p.deleted_at IS NULL
ON CONFLICT (proxy_id) DO NOTHING;
