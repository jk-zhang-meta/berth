package migrations

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthLandingGrantApprovalFlowMigration(t *testing.T) {
	b, err := os.ReadFile("258_berth_landing_grant_approval_flow.sql")
	require.NoError(t, err)
	sql := string(b)

	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS request_reason",
		"ADD COLUMN IF NOT EXISTS review_note",
		"ADD COLUMN IF NOT EXISTS reviewed_at",
		"'pending', 'active', 'paused', 'revoked', 'rejected', 'expired', 'quota_exhausted'",
		"berth_landing_node_grants_pending_uniq",
	} {
		require.True(t, strings.Contains(sql, want), "migration 258 missing %q", want)
	}
}
