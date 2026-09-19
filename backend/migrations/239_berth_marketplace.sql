-- Berth resource ownership remains separate from paid access.
CREATE TABLE berth_account_groups (
    account_id BIGINT PRIMARY KEY REFERENCES accounts(id),
    group_id BIGINT NOT NULL UNIQUE REFERENCES groups(id),
    owner_user_id BIGINT NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX berth_account_groups_owner_idx ON berth_account_groups(owner_user_id);

CREATE TABLE berth_marketplace_listings (
    id BIGSERIAL PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('account','proxy')),
    resource_id BIGINT NOT NULL CHECK (resource_id > 0),
    seller_id BIGINT NOT NULL REFERENCES users(id),
    title VARCHAR(100) NOT NULL CHECK (length(btrim(title)) > 0),
    description VARCHAR(2000) NOT NULL DEFAULT '',
    duration_hours INTEGER NOT NULL CHECK (duration_hours BETWEEN 1 AND 8760),
    price_cents BIGINT NOT NULL CHECK (price_cents BETWEEN 1 AND 100000000),
    capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 1000),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','removed')),
    admin_suspended BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (resource_type,resource_id)
);
CREATE INDEX berth_marketplace_listings_seller_idx ON berth_marketplace_listings(seller_id,id);
CREATE INDEX berth_marketplace_listings_status_idx ON berth_marketplace_listings(status,id);

CREATE TABLE berth_marketplace_orders (
    id BIGSERIAL PRIMARY KEY,
    listing_id BIGINT NOT NULL REFERENCES berth_marketplace_listings(id),
    buyer_id BIGINT NOT NULL REFERENCES users(id),
    seller_id BIGINT NOT NULL REFERENCES users(id),
    idempotency_key VARCHAR(128) NOT NULL,
    title VARCHAR(100) NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('account','proxy')),
    resource_id BIGINT NOT NULL CHECK (resource_id > 0),
    duration_hours INTEGER NOT NULL CHECK (duration_hours BETWEEN 1 AND 8760),
    price_cents BIGINT NOT NULL CHECK (price_cents BETWEEN 1 AND 100000000),
    group_id BIGINT REFERENCES groups(id),
    rental_proxy_id BIGINT UNIQUE REFERENCES proxies(id),
    starts_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','terminated')),
    seller_earned_cents BIGINT NOT NULL DEFAULT 0 CHECK (seller_earned_cents >= 0),
    refund_cents BIGINT NOT NULL DEFAULT 0 CHECK (refund_cents >= 0),
    settled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (buyer_id,idempotency_key),
    CHECK (buyer_id <> seller_id),
    CHECK (expires_at > starts_at),
    CHECK ((resource_type='account' AND group_id IS NOT NULL AND rental_proxy_id IS NULL)
        OR (resource_type='proxy' AND group_id IS NULL AND rental_proxy_id IS NOT NULL)),
    CHECK ((status='active' AND settled_at IS NULL AND seller_earned_cents=0 AND refund_cents=0)
        OR (status<>'active' AND settled_at IS NOT NULL AND seller_earned_cents+refund_cents=price_cents))
);
CREATE INDEX berth_marketplace_orders_capacity_idx ON berth_marketplace_orders(listing_id,expires_at) WHERE status='active';
CREATE INDEX berth_marketplace_orders_due_idx ON berth_marketplace_orders(expires_at,id) WHERE status='active';
CREATE INDEX berth_marketplace_orders_buyer_idx ON berth_marketplace_orders(buyer_id,id);
CREATE INDEX berth_marketplace_orders_seller_idx ON berth_marketplace_orders(seller_id,id);
CREATE INDEX berth_marketplace_orders_group_idx ON berth_marketplace_orders(group_id,buyer_id,expires_at) WHERE status='active';

-- Signed immutable movements reconcile held funds and terminal payout/refund.
CREATE TABLE berth_marketplace_ledger (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES berth_marketplace_orders(id),
    user_id BIGINT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN ('hold','payout','refund')),
    amount_cents BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(order_id,kind),
    CHECK ((kind='hold' AND amount_cents < 0) OR (kind IN ('payout','refund') AND amount_cents >= 0))
);
CREATE FUNCTION berth_marketplace_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'marketplace ledger is append-only';
END;
$$;
CREATE TRIGGER berth_marketplace_ledger_immutable BEFORE UPDATE OR DELETE ON berth_marketplace_ledger
FOR EACH ROW EXECUTE FUNCTION berth_marketplace_ledger_immutable();
