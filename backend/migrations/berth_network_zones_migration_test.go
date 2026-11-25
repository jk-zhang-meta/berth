package migrations

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthNetworkZonesAndEdgeNodesMigration(t *testing.T) {
	b, err := os.ReadFile("257_berth_network_zones_and_edge_nodes.sql")
	require.NoError(t, err)
	sql := string(b)

	// Must never touch forbidden platform check constraints.
	require.NotContains(t, sql, "ALTER TABLE user_platform_quotas")
	require.NotContains(t, sql, "ALTER TABLE composite_model_routes")

	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS berth_network_zones",
		"('centre_isvoro'",
		"('cn_mainland'",
		"('overseas'",
		"('home_direct'",
		"CREATE TABLE IF NOT EXISTS berth_edge_nodes",
		"reserved_bytes_month",
		"connect_mode",
		"CREATE TABLE IF NOT EXISTS berth_server_links",
		"UNIQUE (src_node_id, dst_node_id)",
		"CREATE TABLE IF NOT EXISTS berth_landing_node_grants",
		"reserved_bytes",
		"CREATE TABLE IF NOT EXISTS berth_landing_node_grant_usage",
		"receipt_id    TEXT NOT NULL UNIQUE",
		"CREATE TRIGGER berth_landing_node_grant_usage_no_mutate",
		"CREATE TABLE IF NOT EXISTS berth_work_session_leases",
		"cage_epoch",
		"rev_seq",
		"ALTER TABLE proxies ADD COLUMN IF NOT EXISTS edge_node_id",
		"ALTER TABLE proxies ADD COLUMN IF NOT EXISTS grant_id",
		"ALTER TABLE proxies ADD COLUMN IF NOT EXISTS source_type",
		"'external_proxy', 'edge_landing_grant', 'marketplace_rental'",
	} {
		require.True(t, strings.Contains(sql, want), "migration 257 missing %q", want)
	}
}
