-- Migration 261: Berth Edge lease platform/order attribution, durable revocations,
-- marketplace order pricing snapshot & two-phase termination, rental proxy source
-- capacity binding, and idempotent landing byte-slice reservations.

-- 1. Persist canonical platform and optional marketplace order ID on work-session leases.
ALTER TABLE berth_work_session_leases
    ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT '';

ALTER TABLE berth_work_session_leases
    ADD COLUMN IF NOT EXISTS marketplace_order_id BIGINT REFERENCES berth_marketplace_orders(id) ON DELETE SET NULL;

-- Backfill historical lease platform from bound accounts.
UPDATE berth_work_session_leases l
SET platform = COALESCE(a.platform, '')
FROM accounts a
WHERE l.account_id = a.id
  AND l.platform = ''
  AND COALESCE(a.platform, '') <> '';

-- 2. Durable cage min-epoch floor and revoked API key registry for multi-replica Edge snapshots.
CREATE TABLE IF NOT EXISTS berth_edge_cage_min_epochs (
    cage_id    BIGINT PRIMARY KEY,
    min_epoch  BIGINT NOT NULL CHECK (min_epoch >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS berth_edge_revoked_api_keys (
    api_key_id BIGINT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Snapshot usage_rate_multiplier on marketplace orders and track two-phase termination.
ALTER TABLE berth_marketplace_orders
    ADD COLUMN IF NOT EXISTS usage_rate_multiplier NUMERIC(10,4) NOT NULL DEFAULT 1;

ALTER TABLE berth_marketplace_orders
    ADD COLUMN IF NOT EXISTS terminating_at TIMESTAMPTZ;

UPDATE berth_marketplace_orders o
SET usage_rate_multiplier = COALESCE(l.usage_rate_multiplier, 1)
FROM berth_marketplace_listings l
WHERE o.listing_id = l.id
  AND o.usage_rate_multiplier = 1
  AND COALESCE(l.usage_rate_multiplier, 1) <> 1;

-- 4. Track source_proxy_id on marketplace rental proxy clones so capacity limits
--    aggregate against the seller's physical proxy rather than multiplying per clone.
ALTER TABLE proxies
    ADD COLUMN IF NOT EXISTS source_proxy_id BIGINT REFERENCES proxies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS proxies_source_proxy_id_idx
    ON proxies (source_proxy_id)
    WHERE source_proxy_id IS NOT NULL;

UPDATE proxies p
SET source_proxy_id = o.resource_id,
    source_type = 'marketplace_rental'
FROM berth_marketplace_orders o
WHERE o.resource_type = 'proxy'
  AND o.rental_proxy_id = p.id
  AND p.source_proxy_id IS NULL;

-- 5. Idempotent landing grant byte-slice ledger (prevents duplicate slice reservations on retry).
CREATE TABLE IF NOT EXISTS berth_landing_grant_slices (
    operation_id  TEXT PRIMARY KEY,
    slice_id      TEXT NOT NULL UNIQUE,
    grant_id      BIGINT NOT NULL REFERENCES berth_landing_node_grants(id) ON DELETE CASCADE,
    node_id       BIGINT NOT NULL REFERENCES berth_edge_nodes(id) ON DELETE CASCADE,
    granted_bytes BIGINT NOT NULL CHECK (granted_bytes >= 0),
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS berth_landing_grant_slices_grant_idx
    ON berth_landing_grant_slices (grant_id, expires_at DESC);
