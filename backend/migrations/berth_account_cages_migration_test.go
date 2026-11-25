package migrations

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthAccountCagesAndRefreshJournalMigration(t *testing.T) {
	b, err := os.ReadFile("253_berth_account_cages_and_refresh_journal.sql")
	require.NoError(t, err)
	sql := string(b)

	for _, want := range []string{
		"ALTER TABLE tls_fingerprint_profiles",
		"plane",
		"utls_preset",
		"alpn_mode",
		"enable_psk_cache",
		"h2_settings",
		"h2_window_update",
		"h2_pseudo_order",
		"h2_priority_frames",
		"header_order_preset",
		"profile_hash",
		"tls_fp_plane_check",
		"tls_fp_alpn_mode_check",
		"CREATE TABLE IF NOT EXISTS account_cages",
		"landing_binding_mode",
		"strict_proxy_only",
		"allow_ipv6",
		"allow_udp",
		"convergence_seed",
		"octet_length(convergence_seed) = 32",
		"claude_device_id",
		"codex_installation_id",
		"xai_client_identifier",
		"uq_account_cages_account_active",
		"uq_account_cages_exclusive_proxy_active",
		"CREATE TABLE IF NOT EXISTS account_cage_exit_anchors",
		"family(exit_ip) = 4",
		"uq_cage_exit_anchors_active",
		"CREATE TABLE IF NOT EXISTS oauth_refresh_journal",
		"stage IN ('pending', 'committed', 'pre_send_aborted', 'unknown_quarantined')",
		"uq_oauth_rj_active_token",
		"WHERE stage IN ('pending', 'unknown_quarantined')",
		"retry_after_until",
		"CREATE OR REPLACE FUNCTION enforce_account_cage_invariants()",
		"CREATE TRIGGER trg_account_cages_invariants",
	} {
		require.True(t, strings.Contains(sql, want), "migration 253 missing %q", want)
	}
}
