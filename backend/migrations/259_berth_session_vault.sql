-- Migration 259: Berth Cloud Session Vault & Per-User Storage Quotas (Pure-Rust berth-vault)
-- Immutable snapshot + digest-bound tombstone sync model with atomic quota reservation
-- and SQL-enforced metadata confidentiality for E2EE (`encrypted = TRUE`) bundles.

CREATE TABLE IF NOT EXISTS berth_session_vault_settings (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    default_quota_bytes BIGINT NOT NULL DEFAULT 1073741824 CHECK (default_quota_bytes >= 0),
    max_item_bytes BIGINT NOT NULL DEFAULT 104857600 CHECK (max_item_bytes > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO berth_session_vault_settings (id, default_quota_bytes, max_item_bytes)
VALUES (1, 1073741824, 104857600)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS berth_user_vault_quotas (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- NULL override row means inherit default_quota_bytes; explicit 0 means uploads disabled.
    quota_bytes BIGINT NOT NULL CHECK (quota_bytes >= 0),
    notes TEXT NOT NULL DEFAULT '',
    updated_by BIGINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Atomic per-user quota counter + in-flight upload reservation (avoids holding DB locks over network I/O).
CREATE TABLE IF NOT EXISTS berth_user_vault_usage (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    used_bytes BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    reserved_bytes BIGINT NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    item_count INTEGER NOT NULL DEFAULT 0 CHECK (item_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Monotonic sequence for incremental multi-device delta sync (`GET /changes?since=<seq>`).
CREATE SEQUENCE IF NOT EXISTS berth_vault_change_seq START 1;

-- Immutable snapshots + tombstones (`deleted_at IS NOT NULL`).
-- Server derives physical blob paths deterministically from `(user_id, sha256)`; no client path stored.
CREATE TABLE IF NOT EXISTS berth_session_vault_items (
    id BIGSERIAL PRIMARY KEY,
    change_seq BIGINT NOT NULL DEFAULT nextval('berth_vault_change_seq'),
    vault_id VARCHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    logical_id VARCHAR(128) NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    parent_vault_id VARCHAR(64),
    provider VARCHAR(32) NOT NULL,
    source_session_id VARCHAR(192) NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    workspace_hint TEXT NOT NULL DEFAULT '',
    git_repo TEXT NOT NULL DEFAULT '',
    git_branch TEXT NOT NULL DEFAULT '',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags) = 'array'),
    sealed_meta BYTEA,
    message_count INTEGER NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    raw_bytes BIGINT NOT NULL DEFAULT 0 CHECK (raw_bytes >= 0),
    stored_bytes BIGINT NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0),
    sha256 CHAR(64) NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    encoding VARCHAR(16) NOT NULL DEFAULT 'zstd' CHECK (encoding IN ('zstd', 'gzip', 'none')),
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    redacted BOOLEAN NOT NULL DEFAULT TRUE,
    redacted_count INTEGER NOT NULL DEFAULT 0 CHECK (redacted_count >= 0),
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    tombstone_sha256 CHAR(64),
    -- Prevent plaintext metadata leakage on E2EE records!
    CONSTRAINT berth_vault_encrypted_meta_opaque CHECK (
        NOT encrypted OR (
            source_session_id = ''
            AND title = ''
            AND description = ''
            AND workspace_hint = ''
            AND git_repo = ''
            AND git_branch = ''
            AND tags = '[]'::jsonb
        )
    ),
    UNIQUE (user_id, logical_id, sha256)
);

CREATE INDEX IF NOT EXISTS idx_berth_vault_items_user_active
    ON berth_session_vault_items (user_id, pinned DESC, updated_at DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_berth_vault_items_user_changes
    ON berth_session_vault_items (user_id, change_seq ASC);

CREATE INDEX IF NOT EXISTS idx_berth_vault_items_user_logical
    ON berth_session_vault_items (user_id, logical_id, revision DESC);

CREATE INDEX IF NOT EXISTS idx_berth_vault_items_user_sha
    ON berth_session_vault_items (user_id, sha256)
    WHERE deleted_at IS NULL;

-- Admin quota audit trail (actor, target, before/after quota).
CREATE TABLE IF NOT EXISTS berth_vault_admin_audit (
    id BIGSERIAL PRIMARY KEY,
    admin_user_id BIGINT NOT NULL,
    target_user_id BIGINT,
    action VARCHAR(64) NOT NULL,
    old_quota_bytes BIGINT,
    new_quota_bytes BIGINT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
