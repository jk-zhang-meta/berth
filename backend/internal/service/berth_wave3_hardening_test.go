//go:build unit

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestWave3_R1_ReleaseErrorCheckAndDispatchReservationClamp(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

	t.Run("ReleaseQuotaReservation propagates DB error instead of swallowing it", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		dbErr := errors.New("connection reset by peer")
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT order_id FROM berth_marketplace_quota_reservations").WithArgs("op-err").
			WillReturnRows(sqlmock.NewRows([]string{"order_id"}).AddRow(int64(42)))
		mock.ExpectQuery("SELECT id FROM berth_marketplace_orders WHERE id=\\$1 FOR UPDATE").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
		mock.ExpectQuery("SELECT id,status,reserved_usd::text FROM berth_marketplace_quota_reservations").WithArgs("op-err").
			WillReturnError(dbErr)
		mock.ExpectRollback()

		err = svc.ReleaseQuotaReservation(context.Background(), "op-err")
		require.ErrorIs(t, err, dbErr)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ReserveQuotaForDispatch clamps to remaining headroom and blocks terminating orders", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		// Remaining is $0.08 (< $0.25 upper bound) -> reserves exact $0.08.
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id,order_id,operation_id").WithArgs("op-clamp").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT status,buyer_id,rental_mode,starts_at,expires_at,terminating_at").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{
				"status", "buyer_id", "rental_mode", "starts_at", "expires_at", "terminating_at",
				"quota_limit_usd", "quota_used_usd", "quota_reserved_usd", "now",
			}).AddRow("active", int64(7), "quota", now.Add(-time.Hour), nil, nil, "1.00000000", "0.92000000", "0.00000000", now))
		mock.ExpectQuery("INSERT INTO berth_marketplace_quota_reservations").
			WithArgs(int64(42), "op-clamp", int64(7), "0.08000000", now.Add(15*time.Minute), now).
			WillReturnRows(sqlmock.NewRows([]string{"id", "order_id", "operation_id", "buyer_id", "reserved_usd", "status", "expires_at", "created_at", "updated_at"}).
				AddRow(int64(201), int64(42), "op-clamp", int64(7), 0.08, "reserved", now.Add(15*time.Minute), now, now))
		mock.ExpectExec("UPDATE berth_marketplace_orders SET quota_reserved_usd=quota_reserved_usd").
			WithArgs(int64(42), "0.08000000").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		res, err := svc.ReserveQuotaForDispatch(context.Background(), 42, 7, "op-clamp", 0.25, 0)
		require.NoError(t, err)
		require.InDelta(t, 0.08, res.ReservedUSD, 1e-6)

		// Terminating order must be rejected immediately with ErrMarketplaceUnavailable.
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id,order_id,operation_id").WithArgs("op-term").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT status,buyer_id,rental_mode,starts_at,expires_at,terminating_at").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{
				"status", "buyer_id", "rental_mode", "starts_at", "expires_at", "terminating_at",
				"quota_limit_usd", "quota_used_usd", "quota_reserved_usd", "now",
			}).AddRow("active", int64(7), "quota", now.Add(-time.Hour), nil, now.Add(-time.Second), "1.00000000", "0.50000000", "0.00000000", now))
		mock.ExpectRollback()

		_, err = svc.ReserveQuotaForDispatch(context.Background(), 42, 7, "op-term", 0.25, 0)
		require.ErrorIs(t, err, ErrMarketplaceUnavailable)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestWave3_R3_TwoPhaseTerminationHoldsEscrowWhileReservationsInFlight(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	orderCols := []string{
		"id", "listing_id", "buyer_id", "seller_id", "title", "resource_type", "resource_id",
		"rental_mode", "duration_hours", "quota_limit_usd", "quota_used_usd", "quota_reserved_usd",
		"price_cents", "group_id", "rental_proxy_id", "starts_at", "expires_at",
		"status", "completion_reason", "seller_earned_cents", "refund_cents", "settled_at",
		"created_at", "rent_commission_bps", "platform_commission_cents",
	}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	svc := NewMarketplaceService(db)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE id=\\$1 FOR UPDATE").WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows(orderCols).AddRow(
			int64(77), int64(10), int64(2), int64(1), "Quota Account", "account", int64(11),
			"quota", nil, 10.0, 2.0, 0.25,
			int64(1000), int64(90), nil, now.Add(-time.Hour), nil,
			"active", nil, int64(0), int64(0), nil,
			now.Add(-time.Hour), 500, int64(0),
		))
	mock.ExpectQuery("SELECT id,status,deleted_at FROM users WHERE id IN").WithArgs(int64(2), int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "status", "deleted_at"}).
			AddRow(int64(1), "active", nil).
			AddRow(int64(2), "active", nil))
	mock.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
	mock.ExpectQuery("SELECT quota_used_usd::text,quota_limit_usd::text,terminating_at FROM berth_marketplace_orders").
		WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"quota_used_usd", "quota_limit_usd", "terminating_at"}).AddRow("2.00000000", "10.00000000", nil))
	// 1 unexpired in-flight reservation -> Phase 1 terminating state, NO escrow payout/refund yet!
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM berth_marketplace_quota_reservations").
		WithArgs(int64(77), now).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectExec("UPDATE berth_marketplace_orders\\s+SET terminating_at=COALESCE").
		WithArgs(int64(77), now, MarketplaceCompletionBuyerTerminated).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	ord, err := svc.Terminate(context.Background(), 2, false, 77)
	require.NoError(t, err)
	require.Equal(t, "active", ord.Status, "order must remain active until in-flight reservations settle")
	require.NotNil(t, ord.TerminatingAt)
	require.NotNil(t, ord.CompletionReason)
	require.Equal(t, MarketplaceCompletionBuyerTerminated, *ord.CompletionReason)
	require.Zero(t, ord.RefundCents, "escrow refund must not execute while in-flight reservations exist")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWave3_R6_OptionA_RejectsAccountMutationsWhileRented(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	market := NewMarketplaceService(db)
	adminSvc := &adminServiceImpl{marketplace: market}

	// Active rental exists -> 409 ACCOUNT_RENTAL_ACTIVE on DeleteAccount and SetAccountSchedulable(false)
	mock.ExpectQuery("SELECT EXISTS\\(\\s*SELECT 1 FROM berth_marketplace_orders").WithArgs(int64(23)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	err = adminSvc.DeleteAccount(context.Background(), 23)
	require.ErrorIs(t, err, ErrAccountRentalActive)
	var appErr *infraerrors.ApplicationError
	require.True(t, errors.As(err, &appErr))
	require.EqualValues(t, http.StatusConflict, appErr.Code)

	mock.ExpectQuery("SELECT EXISTS\\(\\s*SELECT 1 FROM berth_marketplace_orders").WithArgs(int64(23)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	_, err = adminSvc.SetAccountSchedulable(context.Background(), 23, false)
	require.ErrorIs(t, err, ErrAccountRentalActive)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWave3_R7_PhysicalProxyFamilyCapacityAggregatesClones(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	market := NewMarketplaceService(db)

	// Rental clone #55 points to physical root proxy #10 (max_accounts=2).
	// Across root #10 + clone #55 there are already 2 accounts bound.
	mock.ExpectQuery("SELECT COALESCE\\(p.source_proxy_id, p.id\\)").WithArgs(int64(55)).
		WillReturnRows(sqlmock.NewRows([]string{"root_id", "root_max"}).AddRow(int64(10), 2))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\)\\s*FROM accounts a").WithArgs(int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(2)))

	count, rootMax, err := market.PhysicalProxyFamilyCapacity(context.Background(), 55)
	require.NoError(t, err)
	require.Equal(t, int64(2), count)
	require.Equal(t, 2, rootMax)

	// ResolvePhysicalProxyCapacity maps clone #55 -> physical #10 with live limits (conc=4, rpm=60).
	mock.ExpectQuery("SELECT p.source_proxy_id, src.max_concurrency, src.max_rpm").WithArgs(int64(55)).
		WillReturnRows(sqlmock.NewRows([]string{"source_proxy_id", "max_concurrency", "max_rpm"}).AddRow(int64(10), int64(4), int64(60)))
	physID, conc, rpm, mapped, err := market.ResolvePhysicalProxyCapacity(context.Background(), 55)
	require.NoError(t, err)
	require.True(t, mapped)
	require.Equal(t, int64(10), physID)
	require.Equal(t, 4, conc)
	require.Equal(t, 60, rpm)
	require.NoError(t, mock.ExpectationsWereMet())
}

type wave3LeaseStoreStub struct {
	*MemoryEdgeLeaseStore
	orderID    int64
	orderExp   *time.Time
	accountExp *time.Time
}

func (s *wave3LeaseStoreStub) ResolveActiveMarketplaceOrderForLease(_ context.Context, _, _, _ int64) (int64, *time.Time, *time.Time, error) {
	return s.orderID, s.orderExp, s.accountExp, nil
}

func TestWave3_R5_LeaseExpiryCappedAtMarketplaceOrderAndAccountExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	ctx := context.Background()
	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	node, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name: "landing-1", ZoneID: zones[0].ID, Roles: []string{EdgeRoleIngressRelay, EdgeRoleLanding},
		PublicAddr: "https://landing-1.example.com", Status: EdgeNodeStatusActive,
		ExitTimezone: "America/Chicago", ExitCountryCode: "US",
	})
	require.NoError(t, err)

	orderExp := time.Now().Add(2 * time.Minute).UTC()
	store := &wave3LeaseStoreStub{
		MemoryEdgeLeaseStore: NewMemoryEdgeLeaseStore(&revSeq),
		orderID:              909,
		orderExp:             &orderExp,
	}
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(store, zoneSvc, nil, pub, priv, edgeproto.KeyIDFromPublicKey(pub))
	leaseSvc.SetLeaseTTL(15 * time.Minute)

	resp, err := leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID: 7, APIKeyID: 55, Platform: "openai", AccountID: 23, LandingNodeID: node.ID,
	})
	require.NoError(t, err)
	require.False(t, resp.ExpiresAt.After(orderExp.Add(time.Second)), "lease exp must be capped at marketplace order expiry")
	rec, err := store.GetLease(ctx, resp.LeaseID)
	require.NoError(t, err)
	require.Equal(t, int64(909), rec.MarketplaceOrderID)

	// Renew must also stay capped at order expiry.
	renewed, err := leaseSvc.RenewLeaseWithKey(ctx, 7, 55, resp.LeaseID)
	require.NoError(t, err)
	require.False(t, renewed.ExpiresAt.After(orderExp.Add(time.Second)), "renewed lease exp must stay capped at order expiry")
}

func TestWave3_R2_EdgeReceiptDebitsMarketplaceQuotaOrderAndSettlesOnExhaustion(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	revSeq := int64(1)
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(NewMemoryEdgeLeaseStore(&revSeq), nil, nil, pub, priv, edgeproto.KeyIDFromPublicKey(pub))

	now := time.Now().UTC()
	r := &edgeproto.UsageReceipt{
		ReceiptID: "rcpt-edge-quota-1",
		LeaseID:   "lease-909",
		UserID:    2,
		APIKeyID:  33,
		AccountID: 11,
		TotalCost: 2.0,
	}

	mock.ExpectQuery("SELECT marketplace_order_id\\s+FROM berth_work_session_leases").WithArgs("lease-909").
		WillReturnRows(sqlmock.NewRows([]string{"marketplace_order_id"}).AddRow(int64(77)))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT status, rental_mode, buyer_id, seller_id, group_id").WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "rental_mode", "buyer_id", "seller_id", "group_id",
			"price_cents", "rent_commission_bps", "usage_rate_multiplier",
			"quota_used_usd", "quota_limit_usd",
		}).AddRow("active", "quota", int64(2), int64(1), int64(90), int64(1000), 1000, 1.5, "7.00000000", "10.00000000"))
	mock.ExpectQuery("SELECT id,status,deleted_at FROM users WHERE id IN").WithArgs(int64(2), int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "status", "deleted_at"}).
			AddRow(int64(1), "active", nil).
			AddRow(int64(2), "active", nil))
	mock.ExpectQuery("SELECT id FROM berth_marketplace_order_usage").WithArgs(int64(77), "edge:rcpt-edge-quota-1").
		WillReturnError(sql.ErrNoRows)
	// $2.0 * 1.5 multiplier = $3.0 -> 7 + 3 = 10 >= 10 -> quota exhausted!
	mock.ExpectQuery("UPDATE berth_marketplace_orders\\s+SET quota_used_usd = quota_used_usd").WithArgs(3.0, int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"quota_used_usd"}).AddRow("10.00000000"))
	mock.ExpectExec("INSERT INTO berth_marketplace_order_usage").
		WithArgs(int64(77), "edge:rcpt-edge-quota-1", int64(33), int64(2), int64(1), int64(11), int64(90), 3.0, "10.00000000", now).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE users SET balance = balance \\+ \\$1::numeric/100").WithArgs(int64(900), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO berth_marketplace_ledger\\(order_id, user_id, kind, amount_cents\\)").WithArgs(int64(77), int64(1), int64(900), int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("INSERT INTO berth_marketplace_ledger\\(order_id, kind, amount_cents\\)").WithArgs(int64(77), int64(100)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE berth_marketplace_quota_reservations SET status = 'released'").WithArgs(int64(77)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE berth_marketplace_orders\\s+SET status = 'completed'").WithArgs(int64(77), int64(900), int64(100)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	leaseSvc.debitEdgeMarketplaceOrderUsage(context.Background(), db, r, now)
	require.InDelta(t, 3.0, r.ActualCost, 1e-6)
	require.NoError(t, mock.ExpectationsWereMet())
}
