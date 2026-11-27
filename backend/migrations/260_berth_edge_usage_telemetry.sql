-- 260_berth_edge_usage_telemetry.sql
-- Enrich Berth Edge landing usage receipts with latency, model, token, and cost telemetry
-- so Account Pool "今日统计" (today stats & latencies) accurately reflects Berth Edge / bh Cage traffic
-- without double-counting rows already mirrored into usage_logs.

ALTER TABLE berth_landing_node_grant_usage
    ADD COLUMN IF NOT EXISTS duration_ms INTEGER,
    ADD COLUMN IF NOT EXISTS model VARCHAR(100),
    ADD COLUMN IF NOT EXISTS input_tokens INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS output_tokens INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_cost NUMERIC(20,10) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS actual_cost NUMERIC(20,10) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS account_stats_cost NUMERIC(20,10),
    ADD COLUMN IF NOT EXISTS usage_log_id BIGINT;

CREATE INDEX IF NOT EXISTS berth_landing_node_grant_usage_account_created_idx
    ON berth_landing_node_grant_usage (account_id, created_at)
    WHERE account_id IS NOT NULL;
