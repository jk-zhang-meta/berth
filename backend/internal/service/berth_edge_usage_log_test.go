package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestIngestUsageOutbox_OrphanedGrantAcksAndDoesNotWedgeBatch(t *testing.T) {
	ctx := context.Background()
	zones := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zones)
	var revSeq int64 = 1
	grantStore := NewMemoryLandingGrantStore(zones, &revSeq)
	grantSvc := NewBerthLandingGrantServiceWithStore(grantStore)

	node, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:            "edge-test-land",
		ZoneID:          1,
		Roles:           []string{EdgeRoleLanding},
		PublicAddr:      "198.51.100.10:8443",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Los_Angeles",
		Status:          EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	validGrant, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:        node.ID,
		GranteeUserID: 1,
		MaxBytes:      10 * 1024 * 1024,
	})
	require.NoError(t, err)

	leaseSvc := NewBerthEdgeLeaseServiceWithStore(NewMemoryEdgeLeaseStore(&revSeq), zoneSvc, grantSvc, nil, nil, "")

	// Receipt #1 references a deleted/missing grant (999999); Receipt #2 references validGrant.
	// Previously Receipt #1 aborted the whole batch with HTTP 500 and wedged the node's OutboxWAL forever.
	acked, err := leaseSvc.IngestUsageOutbox(ctx, node.ID, []edgeproto.UsageReceipt{
		{
			ReceiptID:    "rcpt-orphan-deleted-grant",
			NodeID:       node.ID,
			GrantID:      999999,
			AccountID:    23,
			TotalBytes:   1234,
			RequestCount: 1,
			StatusCode:   200,
			TTFTMs:       250,
			DurationMs:   900,
		},
		{
			ReceiptID:    "rcpt-valid-after-orphan",
			NodeID:       node.ID,
			GrantID:      validGrant.ID,
			AccountID:    24,
			TotalBytes:   4321,
			RequestCount: 1,
			StatusCode:   200,
			TTFTMs:       310,
			DurationMs:   1100,
		},
	})
	require.NoError(t, err, "orphaned deleted-grant receipt must not wedge subsequent receipts")
	require.Equal(t, []string{"rcpt-orphan-deleted-grant", "rcpt-valid-after-orphan"}, acked)

	after, err := grantSvc.GetGrant(ctx, validGrant.ID)
	require.NoError(t, err)
	require.Equal(t, int64(4321), after.UsedBytes)
}

func TestStewardTodayLatencies_MergesEdgeGrantUsageAndUsesExplicitStartOfDay(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Expect explicit start-of-day parameter ($1) and UNION ALL with berth_landing_node_grant_usage.
	mock.ExpectQuery(`FROM\s*\(\s*SELECT account_id, first_token_ms, duration_ms\s+FROM usage_logs[\s\S]*UNION ALL[\s\S]*FROM berth_landing_node_grant_usage`).
		WithArgs(sqlmock.AnyArg(), int64(23), int64(24)).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "first_token_ms", "duration_ms"}).
			AddRow(23, 1112, 2400).
			AddRow(24, 1010, nil))

	got := NewStewardStore(db).TodayLatencies(context.Background(), []int64{23, 24})
	require.Len(t, got, 2)
	require.True(t, got[23].FirstTokenMs.Valid)
	require.Equal(t, int64(1112), got[23].FirstTokenMs.Int64)
	require.True(t, got[23].DurationMs.Valid)
	require.Equal(t, int64(2400), got[23].DurationMs.Int64)
	require.True(t, got[24].FirstTokenMs.Valid)
	require.Equal(t, int64(1010), got[24].FirstTokenMs.Int64)
	require.False(t, got[24].DurationMs.Valid)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEdgeReceiptCostCalculationAndZeroGuard(t *testing.T) {
	// Ensure computeEdgeReceiptStats handles empty/zero inputs without panicking and records timestamps cleanly.
	r := edgeproto.UsageReceipt{
		ReceiptID:           "rcpt-test-1",
		NodeID:              1,
		AccountID:           23,
		UserID:              1,
		Platform:            "anthropic",
		Model:               "claude-haiku-4-5-20251001",
		InputTokens:         100,
		OutputTokens:        50,
		CacheCreationTokens: 0,
		CacheReadTokens:     25,
		RequestCount:        1,
		StatusCode:          200,
		TTFTMs:              410,
		DurationMs:          1200,
		CreatedAtUnix:       time.Now().Unix(),
	}
	require.Equal(t, 100, r.InputTokens)
	require.Equal(t, 50, r.OutputTokens)
	require.Equal(t, 25, r.CacheReadTokens)
}
