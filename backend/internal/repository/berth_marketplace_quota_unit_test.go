//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceQuotaSettlementLocksInOrderAndSettlesExhaustionAtomically(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := &usageBillingRepository{db: db}
	admittedAt := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	cmd := &service.UsageBillingCommand{
		SettlementKind:         service.UsageSettlementMarketplaceQuota,
		RequestID:              "req-quota-exhaust",
		APIKeyID:               50,
		UserID:                 2,
		AccountID:              11,
		AccountType:            service.AccountTypeAPIKey,
		BalanceCost:            0,
		AccountQuotaCost:       5.0,
		MarketplaceQuotaCost:   5.0,
		MarketplaceOperationID: "op-res-1",
		MarketplaceUsage: &service.MarketplaceUsageSnapshot{
			GroupID:        90,
			AccountID:      11,
			SellerID:       1,
			OrderID:        77,
			RentalMode:     service.MarketplaceRentalModeQuota,
			OperationID:    "op-res-1",
			CommissionBPS:  500,
			RateMultiplier: 1.0,
			AdmittedAt:     admittedAt,
		},
	}

	mock.ExpectBegin()
	// 1. Dedup claim
	mock.ExpectQuery("INSERT INTO usage_billing_dedup").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)))
	mock.ExpectQuery("SELECT request_fingerprint\\s+FROM usage_billing_dedup_archive").
		WillReturnRows(sqlmock.NewRows([]string{"request_fingerprint"}))

	// 2. Strict global lock hierarchy: accounts -> berth_marketplace_orders -> users (ORDER BY id)
	mock.ExpectQuery("SELECT id FROM accounts WHERE id=\\$1 FOR UPDATE").
		WithArgs(int64(11)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectQuery("SELECT id FROM berth_marketplace_orders WHERE id=\\$1 FOR UPDATE").
		WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(77)))
	mock.ExpectQuery("SELECT id FROM users WHERE id IN \\(\\$1,\\$2\\) ORDER BY id FOR UPDATE").
		WithArgs(int64(2), int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(1)).AddRow(int64(2)))

	// 3. applyUsageBillingEffects: BalanceCost == 0 so NO user balance deduction!
	//    AccountQuotaCost == 5.0 -> increments account quota.
	mock.ExpectQuery("UPDATE accounts SET extra =").
		WithArgs(5.0, int64(11)).
		WillReturnRows(sqlmock.NewRows(accountQuotaStateColumns).AddRow(5.0, 100.0, 0.0, 0.0, 0.0, 0.0))

	// 4. settleMarketplaceQuotaUsage:
	//    a) Settle pre-dispatch reservation op-res-1 ($6.00 reserved)
	mock.ExpectQuery("UPDATE berth_marketplace_quota_reservations\\s+SET status='settled'").
		WithArgs("op-res-1", int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{"reserved_usd"}).AddRow("6.00000000"))

	//    b) Increment quota_used_usd by $5.00 (hits $20.00 limit!) & decrement quota_reserved_usd by $6.00
	mock.ExpectQuery("UPDATE berth_marketplace_orders\\s+SET quota_used_usd=quota_used_usd\\+\\$1::numeric").
		WithArgs(5.0, "6.00000000", int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "rental_mode", "quota_used_usd", "quota_limit_usd",
			"price_cents", "rent_commission_bps", "seller_id", "buyer_id",
		}).AddRow("active", "quota", "20.00000000", "20.00000000", int64(1500), 1000, int64(1), int64(2)))

	//    c) Insert append-only usage audit row
	mock.ExpectExec("INSERT INTO berth_marketplace_order_usage").
		WithArgs(int64(77), "req-quota-exhaust", int64(50), int64(2), int64(1), int64(11), int64(90), 5.0, "20.00000000", admittedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	//    d) Immediate 100% settlement inside SAME tx: 1500 cents, 10% commission (150), seller earned (1350), refund (0)!
	mock.ExpectExec("UPDATE users SET balance=balance\\+\\$1::numeric/100").
		WithArgs(int64(1350), int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO berth_marketplace_ledger\\(order_id,user_id,kind,amount_cents\\) VALUES\\(\\$1,\\$2,'payout',\\$3\\),\\(\\$1,\\$4,'refund',0\\)").
		WithArgs(int64(77), int64(1), int64(1350), int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("INSERT INTO berth_marketplace_ledger\\(order_id,kind,amount_cents\\) VALUES\\(\\$1,'platform_commission',\\$2\\)").
		WithArgs(int64(77), int64(150)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE berth_marketplace_quota_reservations SET status='released'").
		WithArgs(int64(77)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE berth_marketplace_orders\\s+SET status='completed',completion_reason='quota_exhausted'").
		WithArgs(int64(77), int64(1350), int64(150)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	res, err := repo.Apply(ctx, cmd)
	require.NoError(t, err)
	require.True(t, res.Applied)
	require.Nil(t, res.NewBalance, "buyer balance must NOT be deducted for quota rental")
	require.True(t, res.MarketplaceQuotaExhausted)
	require.Equal(t, int64(1), res.MarketplaceSellerID)
	require.Equal(t, int64(77), res.MarketplaceSettledOrderID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyBatchRejectsMarketplaceSettlementKind(t *testing.T) {
	ctx := context.Background()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := &usageBillingRepository{db: db}
	_, err = repo.ApplyBatch(ctx, []*service.UsageBillingCommand{
		{
			RequestID:            "batch-quota-1",
			APIKeyID:             1,
			UserID:               2,
			SettlementKind:       service.UsageSettlementMarketplaceQuota,
			MarketplaceQuotaCost: 1.0,
		},
	})
	require.ErrorContains(t, err, "must not enter ApplyBatch")
}
