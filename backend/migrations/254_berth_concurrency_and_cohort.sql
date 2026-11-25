-- Berth v2 Track B: Mandatory concurrency floor, concurrency telemetry instrumentation,
-- adaptive concurrency rollup/recommendation tables, proxy ASN classification,
-- and cage-cohort persistence on work_sessions.
--
-- Notes:
-- - Strictly additive and idempotent; does not alter unrelated platform check constraints.
-- - work_sessions.cage_strict_mode defaults to FALSE so existing legacy live
--   sessions are never stranded on live upgrade (new AGS v2 / caged sessions
--   explicitly opt into cage_strict_mode = TRUE).

-- 1. Direct concurrency instrumentation on telemetry tables (nullable for backward compatibility)
ALTER TABLE usage_logs
    ADD COLUMN IF NOT EXISTS account_concurrency_at_start SMALLINT,
    ADD COLUMN IF NOT EXISTS proxy_concurrency_at_start   SMALLINT,
    ADD COLUMN IF NOT EXISTS configured_concurrency       SMALLINT;

ALTER TABLE ops_error_logs
    ADD COLUMN IF NOT EXISTS account_concurrency_at_start SMALLINT,
    ADD COLUMN IF NOT EXISTS proxy_concurrency_at_start   SMALLINT,
    ADD COLUMN IF NOT EXISTS configured_concurrency       SMALLINT;

-- Covering/partial indexes for rolling 14d concurrency telemetry aggregation
CREATE INDEX IF NOT EXISTS idx_usage_logs_acct_created_conc
    ON usage_logs (account_id, created_at DESC)
    INCLUDE (upstream_model, input_tokens, cache_creation_tokens, first_token_ms, duration_ms, account_concurrency_at_start, configured_concurrency);

CREATE INDEX IF NOT EXISTS idx_ops_error_logs_acct_created_status
    ON ops_error_logs (account_id, created_at DESC)
    WHERE account_id IS NOT NULL AND is_business_limited = FALSE;

CREATE INDEX IF NOT EXISTS idx_pelican_tests_acct_created
    ON pelican_tests (account_id, created_at DESC);

-- 2. Hourly pre-aggregated concurrency bucket telemetry
CREATE TABLE IF NOT EXISTS berth_concurrency_bucket_hourly (
    bucket_hour        TIMESTAMPTZ      NOT NULL,
    platform           VARCHAR(50)      NOT NULL,
    account_type       VARCHAR(20)      NOT NULL,
    plan_tier          VARCHAR(64)      NOT NULL,
    concurrency_level  SMALLINT         NOT NULL CHECK (concurrency_level >= 1),
    total_requests     INTEGER          NOT NULL DEFAULT 0,
    distinct_accounts  INTEGER          NOT NULL DEFAULT 0,
    err_429_count      INTEGER          NOT NULL DEFAULT 0,
    err_403_count      INTEGER          NOT NULL DEFAULT 0,
    err_529_count      INTEGER          NOT NULL DEFAULT 0,
    err_5xx_count      INTEGER          NOT NULL DEFAULT 0,
    stream_disconnects INTEGER          NOT NULL DEFAULT 0,
    ttft_sample_count  INTEGER          NOT NULL DEFAULT 0,
    ttft_ratio_p50     DOUBLE PRECISION,
    ttft_ratio_p90     DOUBLE PRECISION,
    avg_duration_ms    DOUBLE PRECISION,
    pelican_total      INTEGER          NOT NULL DEFAULT 0,
    pelican_failed     INTEGER          NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    PRIMARY KEY (bucket_hour, platform, account_type, plan_tier, concurrency_level)
);

CREATE INDEX IF NOT EXISTS idx_berth_conc_hourly_lookup
    ON berth_concurrency_bucket_hourly (platform, account_type, plan_tier, bucket_hour DESC);

-- 3. Materialized recommendation snapshot (read by Create/Edit Account UI & API in O(1))
CREATE TABLE IF NOT EXISTS berth_concurrency_recommendations (
    platform                VARCHAR(50)      NOT NULL,
    account_type            VARCHAR(20)      NOT NULL,
    plan_tier               VARCHAR(64)      NOT NULL,
    recommended_concurrency SMALLINT         NOT NULL CHECK (recommended_concurrency >= 1),
    c_star_empirical        SMALLINT,
    c_prior                 SMALLINT         NOT NULL CHECK (c_prior >= 1),
    c_hard_max              SMALLINT         NOT NULL CHECK (c_hard_max >= 1),
    safety_factor           DOUBLE PRECISION NOT NULL,
    effective_samples       DOUBLE PRECISION NOT NULL DEFAULT 0,
    distinct_accounts       INTEGER          NOT NULL DEFAULT 0,
    confidence              VARCHAR(16)      NOT NULL, -- 'high' | 'medium' | 'low' | 'cold_start'
    limiting_factor         VARCHAR(32)      NOT NULL, -- 'prior' | '429_rate' | '403_rate' | '529_rate' | 'ttft_knee' | 'pelican' | 'hard_max' | 'min_samples'
    avg_request_duration_ms INTEGER          NOT NULL DEFAULT 18000,
    rationale_json          JSONB            NOT NULL DEFAULT '{}'::jsonb,
    window_days             SMALLINT         NOT NULL DEFAULT 14,
    computed_at             TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    PRIMARY KEY (platform, account_type, plan_tier)
);

-- 4. Mandatory concurrency >= 1 backfill & DB-level floor constraint
UPDATE accounts
SET concurrency = CASE
    WHEN platform = 'grok' AND type = 'oauth' THEN 1
    WHEN type IN ('oauth', 'setup-token') THEN 2
    ELSE 5
END,
    updated_at = NOW()
WHERE concurrency IS NULL OR concurrency < 1;

ALTER TABLE accounts
    ALTER COLUMN concurrency SET DEFAULT 2,
    DROP CONSTRAINT IF EXISTS chk_accounts_concurrency_gte_1,
    DROP CONSTRAINT IF EXISTS accounts_concurrency_positive,
    ADD CONSTRAINT accounts_concurrency_positive CHECK (concurrency >= 1);

-- 5. Proxy ASN class & Cage-Cohort persistence on work_sessions
ALTER TABLE proxies
    ADD COLUMN IF NOT EXISTS asn_class VARCHAR(24) NOT NULL DEFAULT 'unknown';

ALTER TABLE work_sessions
    ADD COLUMN IF NOT EXISTS cohort_timezone     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cohort_country_code TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cohort_asn_class    TEXT    NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS cage_strict_mode    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS failover_epoch      INT     NOT NULL DEFAULT 1;
