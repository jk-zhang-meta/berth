//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestWave4_K4_IdempotentGrantSliceAndCrossNodeReceiptCheck(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	t.Run("ReserveGrantByteSliceWithOp replays existing slice idempotently by operation_id", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()

		svc := NewBerthLandingGrantService(db)
		exp := now.Add(20 * time.Minute)
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT slice_id, grant_id, node_id, granted_bytes, expires_at\\s+FROM berth_landing_grant_slices").
			WithArgs("slice-op-1").
			WillReturnRows(sqlmock.NewRows([]string{"slice_id", "grant_id", "node_id", "granted_bytes", "expires_at"}).
				AddRow("existing-slice-uuid", int64(5), int64(2), int64(1048576), exp))
		mock.ExpectRollback()

		res, err := svc.ReserveGrantByteSliceWithOp(context.Background(), 5, 2, 1048576, "slice-op-1", now)
		require.NoError(t, err)
		require.Equal(t, "existing-slice-uuid", res.SliceID)
		require.Equal(t, int64(1048576), res.GrantedBytes)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("CommitGrantUsageReceipt rejects cross-node spoofed receipt and clamps post-revoke node release", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()

		svc := NewBerthLandingGrantService(db)

		// Spoofed node_id=99 for grant owned by node_id=2 -> ErrLandingGrantForbidden.
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id FROM berth_edge_nodes WHERE id = \\$1 FOR UPDATE").
			WithArgs(int64(99)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(99)))
		mock.ExpectQuery("SELECT node_id, reserved_bytes\\s+FROM berth_landing_node_grants").
			WithArgs(int64(5)).
			WillReturnRows(sqlmock.NewRows([]string{"node_id", "reserved_bytes"}).AddRow(int64(2), int64(1000)))
		mock.ExpectRollback()

		_, err = svc.CommitGrantUsageReceipt(context.Background(), edgeproto.UsageReceipt{
			ReceiptID:  "rcpt-spoof",
			GrantID:    5,
			NodeID:     99,
			TotalBytes: 500,
		})
		require.ErrorIs(t, err, ErrLandingGrantForbidden)

		// Post-revocation receipt (grant.reserved_bytes == 0, TotalBytes == 500):
		// node.reserved_bytes_month must be decremented by 0 (not 500!).
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id FROM berth_edge_nodes WHERE id = \\$1 FOR UPDATE").
			WithArgs(int64(2)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(2)))
		mock.ExpectQuery("SELECT node_id, reserved_bytes\\s+FROM berth_landing_node_grants").
			WithArgs(int64(5)).
			WillReturnRows(sqlmock.NewRows([]string{"node_id", "reserved_bytes"}).AddRow(int64(2), int64(0)))
		mock.ExpectQuery("INSERT INTO berth_landing_node_grant_usage").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
		mock.ExpectExec("UPDATE berth_edge_nodes\\s+SET used_bytes_month = used_bytes_month \\+ \\$2,\\s+reserved_bytes_month = GREATEST\\(0, reserved_bytes_month - \\$3\\)").
			WithArgs(int64(2), int64(500), int64(0)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("UPDATE berth_landing_node_grants\\s+SET used_bytes = used_bytes \\+ \\$2").
			WithArgs(int64(5), int64(500)).
			WillReturnRows(sqlmock.NewRows([]string{"max_bytes", "used_bytes", "reserved_bytes", "status"}).
				AddRow(int64(10000), int64(500), int64(0), "revoked"))
		mock.ExpectCommit()

		res, err := svc.CommitGrantUsageReceipt(context.Background(), edgeproto.UsageReceipt{
			ReceiptID:  "rcpt-post-revoke",
			GrantID:    5,
			NodeID:     2,
			TotalBytes: 500,
		})
		require.NoError(t, err)
		require.Equal(t, int64(500), res.ChargedBytes)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWave4_K1_ListActiveNodeGrantLimits(t *testing.T) {
	ctx := context.Background()
	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantSvc := NewBerthLandingGrantServiceWithStore(NewMemoryLandingGrantStore(zoneStore, &revSeq))
	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)

	n1, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name: "landing-limits-1", ZoneID: zones[0].ID, Roles: []string{EdgeRoleLanding}, Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	g1, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID: n1.ID, GranteeUserID: 7, MaxAccounts: 2, MaxConcurrency: 4, MaxRPM: 60,
	})
	require.NoError(t, err)

	limits, err := grantSvc.ListActiveNodeGrantLimits(ctx, n1.ID)
	require.NoError(t, err)
	require.Len(t, limits, 1)
	require.Equal(t, g1.ID, limits[0].GrantID)
	require.Equal(t, 4, limits[0].MaxConcurrency)
	require.Equal(t, 60, limits[0].MaxRPM)
}
