-- Berth v2 Track D: MeshHarbor Logical Zones, Edge Nodes, Server Links,
-- Admin Landing Node Grants, Work Session Leases, and Proxy Edge Bindings.
-- Strictly additive; does not touch user_platform_quotas_platform_check or
-- composite_model_routes_target_platform_check.

-- 0. Monotonic edge revocation / policy sequence state (single-row anchor).
CREATE TABLE IF NOT EXISTS berth_edge_revocation_state (
    id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    rev_seq     BIGINT NOT NULL DEFAULT 1 CHECK (rev_seq >= 1),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO berth_edge_revocation_state (id, rev_seq)
VALUES (1, 1)
ON CONFLICT (id) DO NOTHING;

-- 1. Logical Network Zones (MeshHarbor-aligned).
CREATE TABLE IF NOT EXISTS berth_network_zones (
    id                  BIGSERIAL PRIMARY KEY,
    slug                TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    display_name        TEXT NOT NULL CHECK (length(btrim(display_name)) > 0),
    is_centre           BOOLEAN NOT NULL DEFAULT FALSE,
    default_mgmt_policy TEXT NOT NULL DEFAULT 'entry_required'
                        CHECK (default_mgmt_policy IN ('direct_allowed', 'entry_required', 'direct_preferred')),
    dns_hint_domains    TEXT[] NOT NULL DEFAULT '{}',
    geo_country_codes   TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (NOT is_centre OR cardinality(geo_country_codes) = 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS berth_network_zones_single_centre_idx
    ON berth_network_zones (is_centre)
    WHERE is_centre = TRUE;

INSERT INTO berth_network_zones (slug, display_name, is_centre, default_mgmt_policy, dns_hint_domains, geo_country_codes)
VALUES
    ('centre_isvoro', 'Centre (Isvoro)', TRUE,  'direct_allowed',   '{}', '{}'),
    ('cn_mainland',   'China Mainland',  FALSE, 'entry_required',   '{}', '{CN}'),
    ('overseas',      'Overseas',        FALSE, 'direct_preferred', '{}', '{}'),
    ('home_direct',   'Home Direct',     FALSE, 'direct_preferred', '{}', '{}')
ON CONFLICT (slug) DO NOTHING;

-- 2. Berth Edge Nodes (ingress_relay, transit, landing, compat, mgmt_entry).
CREATE TABLE IF NOT EXISTS berth_edge_nodes (
    id                     BIGSERIAL PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE CHECK (length(btrim(name)) > 0),
    zone_id                BIGINT NOT NULL REFERENCES berth_network_zones(id) ON DELETE RESTRICT,
    roles                  TEXT[] NOT NULL DEFAULT '{}',
    public_addr            TEXT NOT NULL DEFAULT '',
    tunnel_addr            TEXT NOT NULL DEFAULT '',
    mgmt_entry_addr        TEXT NOT NULL DEFAULT '',
    connect_mode           TEXT NOT NULL DEFAULT 'direct'
                           CHECK (connect_mode IN ('direct', 'reverse_tunnel')),
    provider_region        TEXT NOT NULL DEFAULT '',
    exit_ip                TEXT NOT NULL DEFAULT '',
    exit_country_code      TEXT NOT NULL DEFAULT '',
    exit_timezone          TEXT NOT NULL DEFAULT '',
    exit_locale            TEXT NOT NULL DEFAULT '',
    exit_asn_class         TEXT NOT NULL DEFAULT '',
    pubkey_ed25519         TEXT NOT NULL DEFAULT '',
    agent_cert_fingerprint TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'offline'
                           CHECK (status IN ('active', 'draining', 'offline', 'suspended')),
    max_bytes_month        BIGINT NOT NULL DEFAULT 0 CHECK (max_bytes_month >= 0),
    used_bytes_month       BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes_month >= 0),
    reserved_bytes_month   BIGINT NOT NULL DEFAULT 0 CHECK (reserved_bytes_month >= 0),
    last_heartbeat_at      TIMESTAMPTZ,
    meta                   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS berth_edge_nodes_zone_idx ON berth_edge_nodes (zone_id);
CREATE INDEX IF NOT EXISTS berth_edge_nodes_status_idx ON berth_edge_nodes (status);
CREATE INDEX IF NOT EXISTS berth_edge_nodes_roles_gin_idx ON berth_edge_nodes USING GIN (roles);

-- 3. Explicit Server-to-Server Topology Links (bidirectional, 1-way IPLC, reverse-tunnel).
CREATE TABLE IF NOT EXISTS berth_server_links (
    id          BIGSERIAL PRIMARY KEY,
    src_node_id BIGINT NOT NULL REFERENCES berth_edge_nodes(id) ON DELETE CASCADE,
    dst_node_id BIGINT NOT NULL REFERENCES berth_edge_nodes(id) ON DELETE CASCADE,
    direction   TEXT NOT NULL DEFAULT 'one_way'
                CHECK (direction IN ('bidirectional', 'one_way')),
    link_class  TEXT NOT NULL DEFAULT 'direct'
                CHECK (link_class IN ('direct', 'iplc', 'reverse_tunnel')),
    weight      INT NOT NULL DEFAULT 100 CHECK (weight >= 0),
    rtt_ms      INT NOT NULL DEFAULT 0 CHECK (rtt_ms >= 0),
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (src_node_id <> dst_node_id),
    UNIQUE (src_node_id, dst_node_id)
);

CREATE INDEX IF NOT EXISTS berth_server_links_enabled_idx
    ON berth_server_links (enabled, src_node_id, dst_node_id);

-- 4. Admin Landing Node Grants & Immutable Idempotent Usage Audit Receipts.
CREATE TABLE IF NOT EXISTS berth_landing_node_grants (
    id                  BIGSERIAL PRIMARY KEY,
    node_id             BIGINT NOT NULL REFERENCES berth_edge_nodes(id) ON DELETE RESTRICT,
    grantee_user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by_admin_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    proxy_id            BIGINT REFERENCES proxies(id) ON DELETE SET NULL,
    expires_at          TIMESTAMPTZ,
    max_bytes           BIGINT NOT NULL DEFAULT 0 CHECK (max_bytes >= 0),
    used_bytes          BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    reserved_bytes      BIGINT NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    max_accounts        INTEGER NOT NULL DEFAULT 1 CHECK (max_accounts >= 1),
    max_rpm             INTEGER NOT NULL DEFAULT 0 CHECK (max_rpm >= 0),
    max_concurrency     INTEGER NOT NULL DEFAULT 0 CHECK (max_concurrency >= 0),
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'paused', 'revoked', 'expired', 'quota_exhausted')),
    notes               TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS berth_landing_node_grants_user_idx
    ON berth_landing_node_grants (grantee_user_id, status);
CREATE INDEX IF NOT EXISTS berth_landing_node_grants_node_idx
    ON berth_landing_node_grants (node_id, status);
CREATE INDEX IF NOT EXISTS berth_landing_node_grants_expiry_idx
    ON berth_landing_node_grants (expires_at)
    WHERE status = 'active' AND expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS berth_landing_node_grant_usage (
    id            BIGSERIAL PRIMARY KEY,
    receipt_id    TEXT NOT NULL UNIQUE,
    grant_id      BIGINT NOT NULL REFERENCES berth_landing_node_grants(id) ON DELETE CASCADE,
    node_id       BIGINT NOT NULL REFERENCES berth_edge_nodes(id) ON DELETE RESTRICT,
    lease_id      UUID,
    account_id    BIGINT,
    ingress_bytes BIGINT NOT NULL DEFAULT 0 CHECK (ingress_bytes >= 0),
    egress_bytes  BIGINT NOT NULL DEFAULT 0 CHECK (egress_bytes >= 0),
    total_bytes   BIGINT NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    ttft_ms       INTEGER,
    status_code   INTEGER,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS berth_landing_node_grant_usage_grant_idx
    ON berth_landing_node_grant_usage (grant_id, created_at DESC);

CREATE OR REPLACE FUNCTION berth_landing_node_grant_usage_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'berth_landing_node_grant_usage receipts are immutable'
        USING ERRCODE = '23514';
END;
$$;

DROP TRIGGER IF EXISTS berth_landing_node_grant_usage_no_mutate ON berth_landing_node_grant_usage;
CREATE TRIGGER berth_landing_node_grant_usage_no_mutate
BEFORE UPDATE OR DELETE ON berth_landing_node_grant_usage
FOR EACH ROW EXECUTE FUNCTION berth_landing_node_grant_usage_immutable();

-- 5. Signed Work Session Leases (AGS v2 + Edge Data-Plane Authorization).
CREATE TABLE IF NOT EXISTS berth_work_session_leases (
    lease_id            UUID PRIMARY KEY,
    work_session_id     BIGINT REFERENCES work_sessions(id) ON DELETE SET NULL,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id          BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    account_id          BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
    cage_id             BIGINT NOT NULL DEFAULT 0,
    cage_epoch          BIGINT NOT NULL DEFAULT 1,
    grant_id            BIGINT REFERENCES berth_landing_node_grants(id) ON DELETE SET NULL,
    landing_node_id     BIGINT REFERENCES berth_edge_nodes(id) ON DELETE SET NULL,
    ingress_node_id     BIGINT REFERENCES berth_edge_nodes(id) ON DELETE SET NULL,
    route_chain         JSONB NOT NULL DEFAULT '[]'::jsonb,
    cohort_timezone     TEXT NOT NULL DEFAULT '',
    cohort_country_code TEXT NOT NULL DEFAULT '',
    cohort_locale       TEXT NOT NULL DEFAULT '',
    lease_epoch         BIGINT NOT NULL DEFAULT 1,
    rev_seq             BIGINT NOT NULL DEFAULT 0,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS berth_work_session_leases_user_idx
    ON berth_work_session_leases (user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS berth_work_session_leases_session_idx
    ON berth_work_session_leases (work_session_id)
    WHERE work_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS berth_work_session_leases_grant_idx
    ON berth_work_session_leases (grant_id)
    WHERE grant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS berth_work_session_leases_revoked_idx
    ON berth_work_session_leases (revoked_at)
    WHERE revoked_at IS NOT NULL;

-- 6. Extend proxies with additive Edge Node & Landing Grant references.
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS edge_node_id BIGINT REFERENCES berth_edge_nodes(id) ON DELETE SET NULL;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS grant_id BIGINT REFERENCES berth_landing_node_grants(id) ON DELETE SET NULL;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'external_proxy';

ALTER TABLE proxies DROP CONSTRAINT IF EXISTS proxies_source_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_source_type_check
    CHECK (source_type IN ('external_proxy', 'edge_landing_grant', 'marketplace_rental'));

CREATE INDEX IF NOT EXISTS proxies_edge_node_id_idx ON proxies (edge_node_id) WHERE edge_node_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS proxies_grant_id_idx ON proxies (grant_id) WHERE grant_id IS NOT NULL;
