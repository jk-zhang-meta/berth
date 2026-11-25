-- 253_berth_account_cages_and_refresh_journal.sql
-- Berth v2 Track A:
-- Persistent per-account isolation cages, immutable IPv4 first-use exit anchors,
-- HTTP/2 & wire-header TLS fingerprint extensions, and DB-backed WAL OAuth refresh journal.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10min';

-- 1. Extend tls_fingerprint_profiles with HTTP/2 & wire-header fidelity
ALTER TABLE tls_fingerprint_profiles
    ADD COLUMN IF NOT EXISTS plane               VARCHAR(20) NOT NULL DEFAULT 'inference',
    ADD COLUMN IF NOT EXISTS provider            VARCHAR(32) NOT NULL DEFAULT 'anthropic',
    ADD COLUMN IF NOT EXISTS utls_preset         VARCHAR(64),
    ADD COLUMN IF NOT EXISTS alpn_mode           VARCHAR(24) NOT NULL DEFAULT 'follow_negotiated',
    ADD COLUMN IF NOT EXISTS enable_psk_cache    BOOLEAN     NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS h2_settings         JSONB,
    ADD COLUMN IF NOT EXISTS h2_window_update    INTEGER,
    ADD COLUMN IF NOT EXISTS h2_pseudo_order     JSONB,
    ADD COLUMN IF NOT EXISTS h2_priority_frames  JSONB,
    ADD COLUMN IF NOT EXISTS header_order_preset VARCHAR(64),
    ADD COLUMN IF NOT EXISTS profile_hash        CHAR(64);

ALTER TABLE tls_fingerprint_profiles
    DROP CONSTRAINT IF EXISTS tls_fp_plane_check;
ALTER TABLE tls_fingerprint_profiles
    ADD CONSTRAINT tls_fp_plane_check CHECK (plane IN ('oauth', 'inference', 'unified'));

ALTER TABLE tls_fingerprint_profiles
    DROP CONSTRAINT IF EXISTS tls_fp_alpn_mode_check;
ALTER TABLE tls_fingerprint_profiles
    ADD CONSTRAINT tls_fp_alpn_mode_check CHECK (alpn_mode IN ('none', 'http1_only', 'follow_negotiated'));

-- 2. account_cages: 1:1 persistent identity & fail-closed egress envelope per account
CREATE TABLE IF NOT EXISTS account_cages (
    id                        BIGSERIAL    PRIMARY KEY,
    account_id                BIGINT       NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proxy_id                  BIGINT       NOT NULL REFERENCES proxies(id)  ON DELETE RESTRICT,

    -- Egress binding & fail-closed gate policy
    landing_binding_mode      VARCHAR(24)  NOT NULL DEFAULT 'exclusive_1to1',
    egress_policy             VARCHAR(24)  NOT NULL DEFAULT 'strict_proxy_only',
    allow_ipv6                BOOLEAN      NOT NULL DEFAULT FALSE,
    allow_udp                 BOOLEAN      NOT NULL DEFAULT FALSE,
    dns_mode                  VARCHAR(24)  NOT NULL DEFAULT 'proxy_doh_ipv4_only',
    drift_policy              VARCHAR(24)  NOT NULL DEFAULT 'same_ip',

    -- Geo-aligned linguistic & temporal identity (derived from verified proxy exit)
    timezone                  VARCHAR(64)  NOT NULL,
    locale                    VARCHAR(32)  NOT NULL,
    accept_language           VARCHAR(128) NOT NULL,
    oai_language              VARCHAR(32)  NOT NULL DEFAULT 'en-US',

    -- Transport & protocol fingerprint profiles (separate OAuth vs Inference planes)
    tls_oauth_profile_id      BIGINT       REFERENCES tls_fingerprint_profiles(id) ON DELETE RESTRICT,
    tls_inference_profile_id  BIGINT       REFERENCES tls_fingerprint_profiles(id) ON DELETE RESTRICT,

    -- Persistent virtual client hardware/runtime tuple
    client_os                 VARCHAR(32)  NOT NULL,
    client_os_version         VARCHAR(64)  NOT NULL DEFAULT '',
    client_arch               VARCHAR(32)  NOT NULL,
    client_runtime            VARCHAR(32)  NOT NULL DEFAULT 'node',
    client_runtime_version    VARCHAR(32)  NOT NULL DEFAULT 'v24.11.0',
    client_app_version        VARCHAR(64)  NOT NULL,
    user_agent_oauth          VARCHAR(255) NOT NULL,
    user_agent_inference      VARCHAR(255) NOT NULL,
    originator                VARCHAR(64)  NOT NULL DEFAULT '',
    hostname_alias            VARCHAR(64)  NOT NULL DEFAULT '',

    -- Deterministic device convergence seeds (generated once on cage creation)
    convergence_seed          BYTEA        NOT NULL,
    claude_device_id          CHAR(64),
    codex_installation_id     UUID,
    xai_client_identifier     UUID,
    extra_identity            JSONB        NOT NULL DEFAULT '{}',

    -- Fail-closed Gate runtime state (closed | checking | open | quarantined)
    gate_state                VARCHAR(16)  NOT NULL DEFAULT 'closed',
    gate_epoch                BIGINT       NOT NULL DEFAULT 1,
    lease_expires_at          TIMESTAMPTZ,
    last_verified_at          TIMESTAMPTZ,
    last_error                TEXT,

    -- Credential version for optimistic CAS refresh persistence
    credential_version        BIGINT       NOT NULL DEFAULT 1,
    locked_at                 TIMESTAMPTZ,

    created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at                TIMESTAMPTZ,

    CONSTRAINT account_cages_binding_mode_chk  CHECK (landing_binding_mode IN ('exclusive_1to1', 'shared_capped')),
    CONSTRAINT account_cages_egress_policy_chk CHECK (egress_policy IN ('strict_proxy_only')),
    CONSTRAINT account_cages_dns_mode_chk      CHECK (dns_mode IN ('proxy_doh_ipv4_only', 'socks5h_remote')),
    CONSTRAINT account_cages_drift_policy_chk  CHECK (drift_policy IN ('same_ip', 'same_asn_city', 'same_country')),
    CONSTRAINT account_cages_gate_state_chk    CHECK (gate_state IN ('closed', 'checking', 'open', 'quarantined')),
    CONSTRAINT account_cages_seed_len_chk      CHECK (octet_length(convergence_seed) = 32),
    CONSTRAINT account_cages_claude_dev_chk    CHECK (claude_device_id IS NULL OR claude_device_id ~ '^[0-9a-f]{64}$')
);

-- Strictly 1 active cage per account
CREATE UNIQUE INDEX IF NOT EXISTS uq_account_cages_account_active
    ON account_cages (account_id) WHERE deleted_at IS NULL;

-- Strictly 1:1 landing proxy exclusivity when landing_binding_mode = 'exclusive_1to1'
CREATE UNIQUE INDEX IF NOT EXISTS uq_account_cages_exclusive_proxy_active
    ON account_cages (proxy_id)
    WHERE deleted_at IS NULL AND landing_binding_mode = 'exclusive_1to1';

CREATE INDEX IF NOT EXISTS idx_account_cages_proxy_id
    ON account_cages (proxy_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_account_cages_gate_state
    ON account_cages (gate_state, lease_expires_at) WHERE deleted_at IS NULL;

-- 3. account_cage_exit_anchors: immutable IPv4 first-use exit baseline + re-anchor audit trail
CREATE TABLE IF NOT EXISTS account_cage_exit_anchors (
    id                 BIGSERIAL    PRIMARY KEY,
    cage_id            BIGINT       NOT NULL REFERENCES account_cages(id) ON DELETE CASCADE,
    anchor_version     INT          NOT NULL DEFAULT 1,
    is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
    proxy_id           BIGINT       NOT NULL REFERENCES proxies(id) ON DELETE RESTRICT,
    exit_ip            INET         NOT NULL,
    exit_country_code  VARCHAR(8)   NOT NULL,
    exit_region        VARCHAR(120) NOT NULL DEFAULT '',
    exit_city          VARCHAR(120) NOT NULL DEFAULT '',
    exit_timezone      VARCHAR(64)  NOT NULL,
    exit_asn           VARCHAR(128) NOT NULL DEFAULT '',
    exit_isp           VARCHAR(255) NOT NULL DEFAULT '',
    probe_source       VARCHAR(64)  NOT NULL,
    reason             VARCHAR(64)  NOT NULL DEFAULT 'first_use',
    anchored_by        VARCHAR(128) NOT NULL DEFAULT 'system',
    anchored_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT cage_anchor_ipv4_only_chk CHECK (family(exit_ip) = 4)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cage_exit_anchors_active
    ON account_cage_exit_anchors (cage_id) WHERE is_active = TRUE;

-- 4. oauth_refresh_journal: DB-backed Write-Ahead Log preventing rotating RT revocation
CREATE TABLE IF NOT EXISTS oauth_refresh_journal (
    id                         BIGSERIAL    PRIMARY KEY,
    account_id                 BIGINT       NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    cage_id                    BIGINT       NOT NULL REFERENCES account_cages(id) ON DELETE CASCADE,
    platform                   VARCHAR(32)  NOT NULL,
    token_fingerprint          CHAR(64)     NOT NULL,
    attempt_id                 UUID         NOT NULL,
    stage                      VARCHAR(24)  NOT NULL,
    base_credential_version    BIGINT       NOT NULL,
    new_credential_version     BIGINT,
    new_token_fingerprint      CHAR(64),
    error_class                VARCHAR(48),
    error_detail               TEXT,
    retry_after_until          TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT oauth_rj_stage_chk CHECK (
        stage IN ('pending', 'committed', 'pre_send_aborted', 'unknown_quarantined')
    )
);

-- At most ONE active/unknown in-flight refresh per refresh_token fingerprint
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_rj_active_token
    ON oauth_refresh_journal (platform, token_fingerprint)
    WHERE stage IN ('pending', 'unknown_quarantined');

CREATE INDEX IF NOT EXISTS idx_oauth_rj_account_recent
    ON oauth_refresh_journal (account_id, created_at DESC);

-- 5. Enforcement trigger: block silent proxy_id mutation & keep accounts.proxy_id synced
CREATE OR REPLACE FUNCTION enforce_account_cage_invariants()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.deleted_at IS NULL AND NEW.deleted_at IS NULL THEN
        IF NEW.proxy_id <> OLD.proxy_id THEN
            IF OLD.locked_at IS NOT NULL AND NEW.gate_epoch <= OLD.gate_epoch THEN
                RAISE EXCEPTION 'account_cage % proxy_id is locked; must use explicit re-anchor and increment gate_epoch', OLD.id
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.gate_state = 'open' THEN
                RAISE EXCEPTION 'account_cage % cannot stay open across proxy_id change', OLD.id
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    UPDATE accounts
       SET proxy_id = NEW.proxy_id,
           updated_at = NOW()
     WHERE id = NEW.account_id
       AND (proxy_id IS DISTINCT FROM NEW.proxy_id);

    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_account_cages_invariants ON account_cages;
CREATE TRIGGER trg_account_cages_invariants
BEFORE INSERT OR UPDATE ON account_cages
FOR EACH ROW EXECUTE FUNCTION enforce_account_cage_invariants();
