package migrations

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyCapacityLimitsMigration(t *testing.T) {
	b, err := os.ReadFile("244_proxy_capacity_limits.sql")
	require.NoError(t, err)
	sql := string(b)
	for _, want := range []string{
		"max_accounts INTEGER NOT NULL DEFAULT 0",
		"max_rpm INTEGER NOT NULL DEFAULT 0",
		"max_concurrency INTEGER NOT NULL DEFAULT 0",
		"CREATE TRIGGER accounts_enforce_proxy_capacity",
		"CREATE TRIGGER proxies_enforce_max_accounts_update",
	} {
		require.True(t, strings.Contains(sql, want), "migration missing %q", want)
	}
}
