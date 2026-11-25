-- Berth v2 Track C: Crash-safe bridge linking payment_orders top-ups to automatic
-- marketplace checkout fulfillment.

CREATE TABLE IF NOT EXISTS berth_marketplace_payment_intents (
    id BIGSERIAL PRIMARY KEY,
    payment_order_id BIGINT NOT NULL UNIQUE REFERENCES payment_orders(id) ON DELETE CASCADE,
    buyer_id BIGINT NOT NULL REFERENCES users(id),
    listing_id BIGINT NOT NULL REFERENCES berth_marketplace_listings(id),
    checkout_idempotency_key VARCHAR(128) NOT NULL,
    listing_price_cents BIGINT NOT NULL CHECK (listing_price_cents > 0),
    shortfall_cents BIGINT NOT NULL CHECK (shortfall_cents > 0),
    topup_credited_usd NUMERIC(20,2) NOT NULL CHECK (topup_credited_usd > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'checkout_failed', 'cancelled', 'expired')),
    marketplace_order_id BIGINT UNIQUE REFERENCES berth_marketplace_orders(id),
    failure_code TEXT,
    failure_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    UNIQUE (buyer_id, checkout_idempotency_key)
);

CREATE INDEX IF NOT EXISTS berth_marketplace_payment_intents_buyer_idx
    ON berth_marketplace_payment_intents (buyer_id, id DESC);

CREATE INDEX IF NOT EXISTS berth_marketplace_payment_intents_status_idx
    ON berth_marketplace_payment_intents (status, created_at DESC)
    WHERE status = 'pending';
