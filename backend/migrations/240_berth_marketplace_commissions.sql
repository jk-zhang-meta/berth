CREATE TABLE berth_marketplace_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1),
    rent_commission_bps INTEGER NOT NULL DEFAULT 0 CHECK (rent_commission_bps BETWEEN 0 AND 10000),
    usage_commission_bps INTEGER NOT NULL DEFAULT 0 CHECK (usage_commission_bps BETWEEN 0 AND 10000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO berth_marketplace_settings(id) VALUES(1);

ALTER TABLE berth_marketplace_listings ADD COLUMN usage_rate_multiplier DOUBLE PRECISION NOT NULL DEFAULT 1
 CHECK (usage_rate_multiplier>0 AND usage_rate_multiplier<=1000);

ALTER TABLE berth_marketplace_orders
 ADD COLUMN rent_commission_bps INTEGER NOT NULL DEFAULT 0 CHECK (rent_commission_bps BETWEEN 0 AND 10000),
 ADD COLUMN platform_commission_cents BIGINT NOT NULL DEFAULT 0 CHECK (platform_commission_cents >= 0),
 DROP CONSTRAINT berth_marketplace_orders_check3,
 ADD CONSTRAINT berth_marketplace_orders_settlement_check CHECK (
 (status='active' AND settled_at IS NULL AND seller_earned_cents=0 AND refund_cents=0 AND platform_commission_cents=0)
 OR (status<>'active' AND settled_at IS NOT NULL AND seller_earned_cents+refund_cents+platform_commission_cents=price_cents));

-- Platform receipts have no end-user balance; they remain explicitly audited.
ALTER TABLE berth_marketplace_ledger
 ALTER COLUMN user_id DROP NOT NULL,
 DROP CONSTRAINT berth_marketplace_ledger_kind_check,
 DROP CONSTRAINT berth_marketplace_ledger_check,
 ADD CONSTRAINT berth_marketplace_ledger_kind_check CHECK (kind IN ('hold','payout','refund','platform_commission')),
 ADD CONSTRAINT berth_marketplace_ledger_amount_check CHECK (
 (kind='hold' AND amount_cents<0) OR (kind IN ('payout','refund','platform_commission') AND amount_cents>=0)),
 ADD CONSTRAINT berth_marketplace_ledger_recipient_check CHECK (
 (kind='platform_commission' AND user_id IS NULL) OR (kind<>'platform_commission' AND user_id IS NOT NULL));
