-- Persist the last verified network egress profile for each proxy.
-- These values describe the proxy exit, not the end user's device location.
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_ip VARCHAR(64);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_country VARCHAR(100);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_country_code VARCHAR(8);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_region VARCHAR(120);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_city VARCHAR(120);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_timezone VARCHAR(100);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_utc_offset_seconds INTEGER;
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_asn VARCHAR(128);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_isp VARCHAR(255);
ALTER TABLE proxies ADD COLUMN IF NOT EXISTS exit_checked_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS proxies_exit_ip_idx ON proxies (exit_ip);
