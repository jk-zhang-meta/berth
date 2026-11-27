//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestGetAccountWindowStatsBatch_MergesEdgeGrantUsageWithoutDoubleCounting(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := &usageLogRepository{sql: db}
	start := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	// 1) Primary usage_logs batch query returns stats for account 23 only.
	mock.ExpectQuery(`SELECT[\s\S]*FROM usage_logs[\s\S]*WHERE account_id = ANY\(\$1\) AND created_at >= \$2[\s\S]*GROUP BY account_id`).
		WithArgs(sqlmock.AnyArg(), start).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "requests", "tokens", "cost", "standard_cost", "user_cost"}).
			AddRow(int64(23), int64(2), int64(500), 0.05, 0.05, 0.05))

	// 2) Unlinked berth_landing_node_grant_usage query (usage_log_id IS NULL AND COALESCE(status_code, 200) < 400)
	// adds edge-only requests for account 23 and account 24.
	mock.ExpectQuery(`FROM berth_landing_node_grant_usage[\s\S]*usage_log_id IS NULL[\s\S]*GROUP BY g\.account_id`).
		WithArgs(sqlmock.AnyArg(), start).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "requests", "tokens", "cost", "standard_cost", "user_cost"}).
			AddRow(int64(23), int64(3), int64(1200), 0.12, 0.12, 0.10).
			AddRow(int64(24), int64(5), int64(0), 0.0, 0.0, 0.0))

	got, err := repo.GetAccountWindowStatsBatch(context.Background(), []int64{23, 24, 25}, start)
	require.NoError(t, err)
	require.Len(t, got, 3)

	require.Equal(t, int64(5), got[23].Requests)
	require.Equal(t, int64(1700), got[23].Tokens)
	require.InDelta(t, 0.17, got[23].Cost, 1e-9)
	require.InDelta(t, 0.15, got[23].UserCost, 1e-9)

	require.Equal(t, int64(5), got[24].Requests)
	require.Equal(t, int64(0), got[24].Tokens)

	require.Equal(t, int64(0), got[25].Requests)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetAccountTodayStats_MergesEdgeGrantUsage(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := &usageLogRepository{sql: db}

	mock.ExpectQuery(`SELECT[\s\S]*FROM usage_logs[\s\S]*WHERE account_id = \$1 AND created_at >= \$2`).
		WithArgs(int64(23), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"requests", "tokens", "cost", "standard_cost", "user_cost"}).
			AddRow(int64(1), int64(100), 0.01, 0.01, 0.01))

	mock.ExpectQuery(`FROM berth_landing_node_grant_usage[\s\S]*usage_log_id IS NULL`).
		WithArgs(int64(23), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"requests", "tokens", "cost", "standard_cost", "user_cost"}).
			AddRow(int64(4), int64(900), 0.09, 0.09, 0.08))

	got, err := repo.GetAccountTodayStats(context.Background(), 23)
	require.NoError(t, err)
	require.Equal(t, int64(5), got.Requests)
	require.Equal(t, int64(1000), got.Tokens)
	require.InDelta(t, 0.10, got.Cost, 1e-9)
	require.InDelta(t, 0.09, got.UserCost, 1e-9)
	require.NoError(t, mock.ExpectationsWereMet())
}
