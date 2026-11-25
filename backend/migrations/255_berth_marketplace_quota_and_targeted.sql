-- Berth v2 Track C: Quota/Hybrid rental modes, targeted private offers,
-- pre-dispatch quota reservations, and append-only order quota usage ledger.

-- 1. Extend berth_marketplace_listings for rental modes (duration | quota | hybrid)
--    and targeted private offers (visibility + target_buyer_id).
ALTER TABLE berth_marketplace_listings
    ADD COLUMN IF NOT EXISTS rental_mode TEXT NOT NULL DEFAULT 'duration',
    ADD COLUMN IF NOT EXISTS quota_limit_usd NUMERIC(20,8),
    ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'public',
    ADD COLUMN IF NOT EXISTS target_buyer_id BIGINT REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS declined_at TIMESTAMPTZ;

ALTER TABLE berth_marketplace_listings
    ALTER COLUMN duration_hours DROP NOT NULL;

ALTER TABLE berth_marketplace_listings
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_duration_hours_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_rental_mode_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_quota_limit_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_mode_fields_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_proxy_mode_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_visibility_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_target_buyer_check;

ALTER TABLE berth_marketplace_listings
    ADD CONSTRAINT berth_marketplace_listings_rental_mode_check
        CHECK (rental_mode IN ('duration', 'quota', 'hybrid')),
    ADD CONSTRAINT berth_marketplace_listings_duration_hours_check
        CHECK (duration_hours IS NULL OR duration_hours BETWEEN 1 AND 8760),
    ADD CONSTRAINT berth_marketplace_listings_quota_limit_check
        CHECK (quota_limit_usd IS NULL OR (quota_limit_usd >= 0.01 AND quota_limit_usd <= 1000000)),
    ADD CONSTRAINT berth_marketplace_listings_mode_fields_check
        CHECK (
            (rental_mode = 'duration' AND duration_hours IS NOT NULL AND quota_limit_usd IS NULL)
            OR (rental_mode = 'quota' AND duration_hours IS NULL AND quota_limit_usd IS NOT NULL)
            OR (rental_mode = 'hybrid' AND duration_hours IS NOT NULL AND quota_limit_usd IS NOT NULL)
        ),
    ADD CONSTRAINT berth_marketplace_listings_proxy_mode_check
        CHECK (resource_type <> 'proxy' OR rental_mode = 'duration'),
    ADD CONSTRAINT berth_marketplace_listings_visibility_check
        CHECK (visibility IN ('public', 'targeted')),
    ADD CONSTRAINT berth_marketplace_listings_target_buyer_check
        CHECK (
            (visibility = 'public' AND target_buyer_id IS NULL)
            OR (visibility = 'targeted' AND target_buyer_id IS NOT NULL AND target_buyer_id <> seller_id)
        );

-- Replace global UNIQUE(resource_type, resource_id) so one resource can have a public
-- listing AND/OR distinct active targeted offers for different buyers.
ALTER TABLE berth_marketplace_listings
    DROP CONSTRAINT IF EXISTS berth_marketplace_listings_resource_type_resource_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS berth_marketplace_listings_public_resource_uidx
    ON berth_marketplace_listings (resource_type, resource_id)
    WHERE visibility = 'public' AND status <> 'removed';

CREATE UNIQUE INDEX IF NOT EXISTS berth_marketplace_listings_targeted_active_uidx
    ON berth_marketplace_listings (resource_type, resource_id, target_buyer_id)
    WHERE visibility = 'targeted' AND status = 'active';

CREATE INDEX IF NOT EXISTS berth_marketplace_listings_target_buyer_idx
    ON berth_marketplace_listings (target_buyer_id, id DESC)
    WHERE visibility = 'targeted' AND status = 'active';

-- 2. Extend berth_marketplace_orders for quota tracking, pre-dispatch reservation,
--    nullable duration/expiry, and explicit completion_reason.
ALTER TABLE berth_marketplace_orders
    ADD COLUMN IF NOT EXISTS rental_mode TEXT NOT NULL DEFAULT 'duration',
    ADD COLUMN IF NOT EXISTS quota_limit_usd NUMERIC(20,8),
    ADD COLUMN IF NOT EXISTS quota_used_usd NUMERIC(20,8) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS quota_reserved_usd NUMERIC(20,8) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS completion_reason TEXT;

ALTER TABLE berth_marketplace_orders
    ALTER COLUMN duration_hours DROP NOT NULL,
    ALTER COLUMN expires_at DROP NOT NULL;

ALTER TABLE berth_marketplace_orders
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_duration_hours_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_check1,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_expires_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_rental_mode_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_quota_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_mode_fields_check,
    DROP CONSTRAINT IF EXISTS berth_marketplace_orders_completion_reason_check;

ALTER TABLE berth_marketplace_orders
    ADD CONSTRAINT berth_marketplace_orders_rental_mode_check
        CHECK (rental_mode IN ('duration', 'quota', 'hybrid')),
    ADD CONSTRAINT berth_marketplace_orders_duration_hours_check
        CHECK (duration_hours IS NULL OR duration_hours BETWEEN 1 AND 8760),
    ADD CONSTRAINT berth_marketplace_orders_expires_check
        CHECK (expires_at IS NULL OR expires_at > starts_at),
    ADD CONSTRAINT berth_marketplace_orders_quota_check
        CHECK (
            quota_used_usd >= 0
            AND quota_reserved_usd >= 0
            AND (quota_limit_usd IS NULL OR (quota_limit_usd >= 0.01 AND quota_limit_usd <= 1000000))
        ),
    ADD CONSTRAINT berth_marketplace_orders_mode_fields_check
        CHECK (
            (rental_mode = 'duration' AND duration_hours IS NOT NULL AND expires_at IS NOT NULL AND quota_limit_usd IS NULL)
            OR (rental_mode = 'quota' AND duration_hours IS NULL AND expires_at IS NULL AND quota_limit_usd IS NOT NULL)
            OR (rental_mode = 'hybrid' AND duration_hours IS NOT NULL AND expires_at IS NOT NULL AND quota_limit_usd IS NOT NULL)
        ),
    ADD CONSTRAINT berth_marketplace_orders_completion_reason_check
        CHECK (
            completion_reason IS NULL
            OR completion_reason IN ('time_expired', 'quota_exhausted', 'buyer_terminated', 'seller_terminated', 'admin_terminated')
        );

CREATE INDEX IF NOT EXISTS berth_marketplace_orders_active_quota_due_idx
    ON berth_marketplace_orders (id)
    WHERE status = 'active' AND quota_limit_usd IS NOT NULL AND quota_used_usd >= quota_limit_usd;

CREATE INDEX IF NOT EXISTS berth_marketplace_orders_active_group_buyer_idx
    ON berth_marketplace_orders (group_id, buyer_id, id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS berth_marketplace_orders_active_resource_idx
    ON berth_marketplace_orders (resource_type, resource_id, id)
    WHERE status = 'active';

-- 3. Crash-safe pre-dispatch quota reservations for quota/hybrid rental orders.
CREATE TABLE IF NOT EXISTS berth_marketplace_quota_reservations (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES berth_marketplace_orders(id),
    operation_id VARCHAR(128) NOT NULL UNIQUE,
    buyer_id BIGINT NOT NULL REFERENCES users(id),
    reserved_usd NUMERIC(20,8) NOT NULL CHECK (reserved_usd > 0),
    status TEXT NOT NULL DEFAULT 'reserved'
        CHECK (status IN ('reserved', 'settled', 'released', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS berth_marketplace_quota_reservations_order_status_idx
    ON berth_marketplace_quota_reservations (order_id, status);

CREATE INDEX IF NOT EXISTS berth_marketplace_quota_reservations_expired_idx
    ON berth_marketplace_quota_reservations (expires_at, id)
    WHERE status = 'reserved';

-- 4. Append-only per-request quota usage audit ledger for quota/hybrid rental orders.
CREATE TABLE IF NOT EXISTS berth_marketplace_order_usage (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES berth_marketplace_orders(id),
    request_id TEXT NOT NULL,
    api_key_id BIGINT NOT NULL REFERENCES api_keys(id),
    buyer_id BIGINT NOT NULL REFERENCES users(id),
    seller_id BIGINT NOT NULL REFERENCES users(id),
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    group_id BIGINT NOT NULL REFERENCES groups(id),
    amount_usd NUMERIC(20,8) NOT NULL CHECK (amount_usd >= 0),
    quota_used_after_usd NUMERIC(20,8) NOT NULL CHECK (quota_used_after_usd >= 0),
    admitted_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (request_id, api_key_id)
);

CREATE INDEX IF NOT EXISTS berth_marketplace_order_usage_order_idx
    ON berth_marketplace_order_usage (order_id, created_at DESC);

DROP TRIGGER IF EXISTS berth_marketplace_order_usage_immutable ON berth_marketplace_order_usage;
CREATE TRIGGER berth_marketplace_order_usage_immutable
    BEFORE UPDATE OR DELETE ON berth_marketplace_order_usage
    FOR EACH ROW EXECUTE FUNCTION berth_marketplace_ledger_immutable();
