package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestBerthLandingGrantService_CreateSliceSettleAndRevoke(t *testing.T) {
	ctx := context.Background()
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	revSeq := int64(1)
	grantStore := NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := NewBerthLandingGrantServiceWithStore(grantStore)

	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	overseasID := zones[2].ID

	// Create landing node with a 1500-byte monthly cap.
	node, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:            "tokyo-home",
		ZoneID:          overseasID,
		Roles:           []string{EdgeRoleLanding},
		Status:          EdgeNodeStatusActive,
		ExitIP:          "203.0.113.55",
		ExitCountryCode: "JP",
		ExitTimezone:    "Asia/Tokyo",
		MaxBytesMonth:   1500,
	})
	require.NoError(t, err)

	exp := time.Now().Add(time.Hour)
	// Grant user 42 a 1000-byte cap on tokyo-home.
	grant, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:           node.ID,
		GranteeUserID:    42,
		GrantedByAdminID: 1,
		ExpiresAt:        &exp,
		MaxBytes:         1000,
		MaxAccounts:      2,
		MaxRPM:           60,
		MaxConcurrency:   4,
		Notes:            "tokyo test grant",
	})
	require.NoError(t, err)
	require.NotNil(t, grant.ProxyID)
	require.Equal(t, int64(1000), grant.RemainingBytes)

	// Verify redacted proxy projection created cleanly with source_type='edge_landing_grant'.
	proxies := grantStore.Proxies()
	require.Len(t, proxies, 1)
	require.Equal(t, ProxySourceTypeEdgeLandingGrant, proxies[0].SourceType)
	require.Equal(t, node.ID, proxies[0].EdgeNodeID)
	require.Equal(t, grant.ID, proxies[0].GrantID)
	require.Equal(t, 2, proxies[0].MaxAccounts)

	// Atomic disjoint slice reservation: first 600B succeeds, second 600B is clamped to remaining 400B!
	now := time.Now()
	s1, err := grantSvc.ReserveGrantByteSlice(ctx, grant.ID, node.ID, 600, now)
	require.NoError(t, err)
	require.Equal(t, int64(600), s1.GrantedBytes)
	require.Equal(t, int64(400), s1.GrantRemainingBytes)
	require.Equal(t, int64(900), s1.NodeRemainingBytes)

	s2, err := grantSvc.ReserveGrantByteSlice(ctx, grant.ID, node.ID, 600, now)
	require.NoError(t, err)
	require.Equal(t, int64(400), s2.GrantedBytes)
	require.Equal(t, int64(0), s2.GrantRemainingBytes)
	require.Equal(t, int64(500), s2.NodeRemainingBytes)

	// Third reservation fails closed (grant cap exhausted).
	_, err = grantSvc.ReserveGrantByteSlice(ctx, grant.ID, node.ID, 100, now)
	require.ErrorIs(t, err, ErrLandingGrantQuotaExhausted)

	// A second user's grant on the same node is bounded by node's remaining 500B monthly cap!
	grant2, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:        node.ID,
		GranteeUserID: 99,
		MaxBytes:      2000,
	})
	require.NoError(t, err)
	s3, err := grantSvc.ReserveGrantByteSlice(ctx, grant2.ID, node.ID, 800, now)
	require.NoError(t, err)
	require.Equal(t, int64(500), s3.GrantedBytes)
	require.Equal(t, int64(0), s3.NodeRemainingBytes)

	// Idempotent usage receipt settlement: first commit charges 700B, duplicate replay charges 0B!
	receipt := edgeproto.UsageReceipt{
		ReceiptID:    "rcpt-001",
		GrantID:      grant.ID,
		NodeID:       node.ID,
		IngressBytes: 200,
		EgressBytes:  500,
		TotalBytes:   700,
		RequestCount: 1,
		StatusCode:   200,
	}
	r1, err := grantSvc.CommitGrantUsageReceipt(ctx, receipt)
	require.NoError(t, err)
	require.False(t, r1.Duplicate)
	require.Equal(t, int64(700), r1.ChargedBytes)
	require.Equal(t, int64(700), r1.GrantUsedBytes)

	r2, err := grantSvc.CommitGrantUsageReceipt(ctx, receipt)
	require.NoError(t, err)
	require.True(t, r2.Duplicate)
	require.Equal(t, int64(0), r2.ChargedBytes)
	require.Equal(t, int64(700), r2.GrantUsedBytes)

	// Revoking grant bumps rev_seq immediately and disables proxy projection.
	newSeq, err := grantSvc.RevokeGrant(ctx, grant.ID, "abuse")
	require.NoError(t, err)
	require.Equal(t, int64(2), newSeq)
	gotGrant, err := grantSvc.GetGrant(ctx, grant.ID)
	require.NoError(t, err)
	require.Equal(t, GrantStatusRevoked, gotGrant.Status)
	require.Equal(t, "disabled", grantStore.Proxies()[0].Status)
}

func TestBerthLandingGrantService_SQLMockAtomicSliceReservation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	now := time.Now()
	exp := now.Add(time.Hour)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT status, max_bytes_month, used_bytes_month, reserved_bytes_month FROM berth_edge_nodes`).
		WithArgs(int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "max_bytes_month", "used_bytes_month", "reserved_bytes_month"}).
			AddRow("active", int64(10000), int64(1000), int64(500)))
	mock.ExpectQuery(`SELECT node_id, status, expires_at, max_bytes, used_bytes, reserved_bytes FROM berth_landing_node_grants`).
		WithArgs(int64(5)).
		WillReturnRows(sqlmock.NewRows([]string{"node_id", "status", "expires_at", "max_bytes", "used_bytes", "reserved_bytes"}).
			AddRow(int64(10), "active", sql.NullTime{Time: exp, Valid: true}, int64(5000), int64(1000), int64(1000)))
	mock.ExpectExec(`UPDATE berth_landing_node_grants SET reserved_bytes = reserved_bytes \+ \$2`).
		WithArgs(int64(5), int64(3000)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE berth_edge_nodes SET reserved_bytes_month = reserved_bytes_month \+ \$2`).
		WithArgs(int64(10), int64(3000)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	svc := NewBerthLandingGrantService(db)
	res, err := svc.ReserveGrantByteSlice(context.Background(), 5, 10, 4000, now)
	require.NoError(t, err)
	require.Equal(t, int64(3000), res.GrantedBytes)
	require.Equal(t, int64(0), res.GrantRemainingBytes)
	require.Equal(t, int64(5500), res.NodeRemainingBytes)
	require.NoError(t, mock.ExpectationsWereMet())
}
