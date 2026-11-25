package migrations

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthConcurrencyAndCohortMigration(t *testing.T) {
	b, err := os.ReadFile("254_berth_concurrency_and_cohort.sql")
	require.NoError(t, err)
	sql := string(b)

	// Must never touch forbidden upstream platform check constraints.
	require.NotContains(t, sql, "user_platform_quotas_platform_check")
	require.NotContains(t, sql, "composite_model_routes_target_platform_check")
	// Must not use CONCURRENTLY inside a transactional migration.
	require.NotContains(t, strings.ToUpper(sql), "CONCURRENTLY")

	for _, want := range []string{
		"account_concurrency_at_start SMALLINT",
		"proxy_concurrency_at_start   SMALLINT",
		"configured_concurrency       SMALLINT",
		"CREATE TABLE IF NOT EXISTS berth_concurrency_bucket_hourly",
		"CREATE TABLE IF NOT EXISTS berth_concurrency_recommendations",
		"ALTER COLUMN concurrency SET DEFAULT 2",
		"ADD CONSTRAINT accounts_concurrency_positive CHECK (concurrency >= 1)",
		"cohort_timezone     TEXT    NOT NULL DEFAULT ''",
		"cohort_country_code TEXT    NOT NULL DEFAULT ''",
		"cohort_asn_class    TEXT    NOT NULL DEFAULT 'unknown'",
		"cage_strict_mode    BOOLEAN NOT NULL DEFAULT FALSE",
		"failover_epoch      INT     NOT NULL DEFAULT 1",
	} {
		require.True(t, strings.Contains(sql, want), "migration missing %q", want)
	}
}
