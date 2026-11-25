//go:build unit

package migrations

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthMarketplaceTrackCMigrations(t *testing.T) {
	m255, err := fs.ReadFile(FS, "255_berth_marketplace_quota_and_targeted.sql")
	require.NoError(t, err)
	sql255 := string(m255)
	for _, want := range []string{
		"rental_mode TEXT NOT NULL DEFAULT 'duration'",
		"quota_limit_usd NUMERIC(20,8)",
		"visibility TEXT NOT NULL DEFAULT 'public'",
		"target_buyer_id BIGINT REFERENCES users(id)",
		"declined_at TIMESTAMPTZ",
		"berth_marketplace_listings_proxy_mode_check",
		"berth_marketplace_listings_public_resource_uidx",
		"berth_marketplace_listings_targeted_active_uidx",
		"quota_used_usd NUMERIC(20,8) NOT NULL DEFAULT 0",
		"quota_reserved_usd NUMERIC(20,8) NOT NULL DEFAULT 0",
		"completion_reason TEXT",
		"CREATE TABLE IF NOT EXISTS berth_marketplace_quota_reservations",
		"operation_id VARCHAR(128) NOT NULL UNIQUE",
		"CREATE TABLE IF NOT EXISTS berth_marketplace_order_usage",
		"berth_marketplace_order_usage_immutable",
	} {
		require.Contains(t, sql255, want)
	}
	for _, forbidden := range []string{
		"user_platform_quotas_platform_check",
		"composite_model_routes_target_platform_check",
	} {
		require.NotContains(t, sql255, forbidden)
	}

	m256, err := fs.ReadFile(FS, "256_berth_marketplace_payment_intents.sql")
	require.NoError(t, err)
	sql256 := string(m256)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS berth_marketplace_payment_intents",
		"payment_order_id BIGINT NOT NULL UNIQUE REFERENCES payment_orders(id)",
		"UNIQUE (buyer_id, checkout_idempotency_key)",
		"CHECK (status IN ('pending', 'completed', 'checkout_failed', 'cancelled', 'expired'))",
		"marketplace_order_id BIGINT UNIQUE REFERENCES berth_marketplace_orders(id)",
	} {
		require.Contains(t, sql256, want)
	}
	require.False(t, strings.Contains(sql256, "user_platform_quotas_platform_check"))
	require.False(t, strings.Contains(sql256, "composite_model_routes_target_platform_check"))
}
