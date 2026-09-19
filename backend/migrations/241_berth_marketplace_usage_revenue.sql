-- One immutable revenue row per successfully applied peer-service bill.
CREATE TABLE berth_marketplace_usage_revenue (
 id BIGSERIAL PRIMARY KEY,
 request_id TEXT NOT NULL,
 api_key_id BIGINT NOT NULL REFERENCES api_keys(id),
 buyer_id BIGINT NOT NULL REFERENCES users(id),
 seller_id BIGINT NOT NULL REFERENCES users(id),
 account_id BIGINT NOT NULL REFERENCES accounts(id),
 group_id BIGINT NOT NULL REFERENCES groups(id),
 commission_bps INTEGER NOT NULL CHECK (commission_bps BETWEEN 0 AND 10000),
 gross_amount NUMERIC(20,8) NOT NULL CHECK (gross_amount >= 0),
 seller_amount NUMERIC(20,8) NOT NULL CHECK (seller_amount >= 0),
 platform_amount NUMERIC(20,8) NOT NULL CHECK (platform_amount >= 0),
	 funded_amount NUMERIC(20,8) NOT NULL CHECK (funded_amount >= 0 AND funded_amount <= gross_amount),
	 seller_paid_amount NUMERIC(20,8) NOT NULL CHECK (seller_paid_amount >= 0 AND seller_paid_amount <= seller_amount),
 admitted_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(request_id,api_key_id),
 CHECK (gross_amount = seller_amount + platform_amount)
);
CREATE INDEX berth_marketplace_usage_seller_idx ON berth_marketplace_usage_revenue(seller_id,created_at DESC);
CREATE INDEX berth_marketplace_usage_buyer_idx ON berth_marketplace_usage_revenue(buyer_id,created_at DESC);
