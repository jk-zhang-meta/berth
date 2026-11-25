//go:build unit

package service

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/payment"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestCalculateShortfallPaymentAmount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		shortfallCents int64
		cfg            *PaymentConfig
		currency       string
		wantInput      float64
		wantMinCredit  float64
		wantPayAmount  float64
		wantErr        bool
	}{
		{
			name:           "0.14 multiplier exact ceil without min amount",
			shortfallCents: 1000, // $10.00 shortfall
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.14, MinAmount: 0, RechargeFeeRate: 0},
			currency:       "CNY",
			wantInput:      71.43,
			wantMinCredit:  10.00,
			wantPayAmount:  71.43,
		},
		{
			name:           "0.14 multiplier with MinAmount=100 and 2% fee",
			shortfallCents: 1000, // $10.00 shortfall -> raw 71.43 < MinAmount 100
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.14, MinAmount: 100, RechargeFeeRate: 2},
			currency:       "CNY",
			wantInput:      100.00,
			wantMinCredit:  14.00,
			wantPayAmount:  102.00,
		},
		{
			name:           "1 cent shortfall under 0.14 multiplier still credits >= $0.01",
			shortfallCents: 1,
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.14, MinAmount: 0, RechargeFeeRate: 0},
			currency:       "CNY",
			wantInput:      0.08,
			wantMinCredit:  0.01,
			wantPayAmount:  0.08,
		},
		{
			name:           "tricky rounding 701 cents under 0.14 multiplier",
			shortfallCents: 701,
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.14, MinAmount: 0, RechargeFeeRate: 1.5},
			currency:       "CNY",
			wantInput:      50.08,
			wantMinCredit:  7.01,
			wantPayAmount:  50.84, // ceil(50.08 * 1.015, 2dp) = 50.84
		},
		{
			name:           "bonus tier preserves credited >= shortfall",
			shortfallCents: 1500,
			cfg: &PaymentConfig{
				BalanceRechargeMultiplier: 0.14,
				MinAmount:                 10,
				RechargeFeeRate:           0,
				RechargeBonusMode:         RechargeBonusModeBonus,
				RechargeBonusTiers:        []RechargeBonusTier{{MinAmount: 100, BonusPercent: 10}},
			},
			currency:      "CNY",
			wantInput:     107.15,
			wantMinCredit: 15.00,
			wantPayAmount: 107.15,
		},
		{
			name:           "JPY 0-decimal currency rounds up to integer yen",
			shortfallCents: 500, // $5.00
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.0067, MinAmount: 0, RechargeFeeRate: 0},
			currency:       "JPY",
			wantInput:      747, // 5/0.0067 = 746.268 -> 747 JPY -> 747*0.0067 = 5.0049 -> $5.00
			wantMinCredit:  5.00,
			wantPayAmount:  747,
		},
		{
			name:           "exceeds MaxAmount returns INVALID_AMOUNT",
			shortfallCents: 50000, // $500
			cfg:            &PaymentConfig{BalanceRechargeMultiplier: 0.14, MaxAmount: 1000},
			currency:       "CNY",
			wantErr:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, quote, payAmt, err := CalculateShortfallPaymentAmount(tc.shortfallCents, tc.cfg, tc.currency)
			if tc.wantErr {
				require.Error(t, err)
				require.Equal(t, "INVALID_AMOUNT", infraerrors.Reason(err))
				return
			}
			require.NoError(t, err)
			require.InDelta(t, tc.wantInput, input, 1e-6)
			require.GreaterOrEqual(t, quote.Credited, tc.wantMinCredit)
			require.True(t, decimal.NewFromFloat(quote.Credited).GreaterThanOrEqual(decimal.New(tc.shortfallCents, -2)),
				"credited USD %.2f must cover shortfall %d cents", quote.Credited, tc.shortfallCents)
			require.InDelta(t, tc.wantPayAmount, payAmt, 0.01)
		})
	}
}

type stubMarketplacePaymentHook struct {
	completeCalls     int
	completeErrs      []error
	syncedStatuses    []string
	activeOrderResult bool
}

func (h *stubMarketplacePaymentHook) CompletePaymentIntent(_ context.Context, _ int64) error {
	h.completeCalls++
	if len(h.completeErrs) > 0 {
		err := h.completeErrs[0]
		h.completeErrs = h.completeErrs[1:]
		return err
	}
	return nil
}

func (h *stubMarketplacePaymentHook) SyncPaymentOrderTerminalStatus(_ context.Context, _ int64, status string) error {
	h.syncedStatuses = append(h.syncedStatuses, status)
	return nil
}

func (h *stubMarketplacePaymentHook) HasActiveMarketplaceOrderForPayment(_ context.Context, _ int64) (bool, error) {
	return h.activeOrderResult, nil
}

func TestPaymentFulfillmentTwoPhaseIdempotentHookAndNoDoubleCredit(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)

	user, err := client.User.Create().
		SetEmail("mkt-2phase@example.com").
		SetPasswordHash("hash").
		SetUsername("mkt-2phase").
		Save(ctx)
	require.NoError(t, err)

	order, err := client.PaymentOrder.Create().
		SetUserID(user.ID).
		SetUserEmail(user.Email).
		SetUserName(user.Username).
		SetAmount(20).
		SetPayAmount(142.86).
		SetFeeRate(0).
		SetRechargeCode("PAY-2PHASE-1").
		SetOutTradeNo("sub2_2phase_test_1").
		SetPaymentType(payment.TypeAlipay).
		SetPaymentTradeNo("ali-trade-1").
		SetOrderType(payment.OrderTypeBalance).
		SetStatus(OrderStatusPaid).
		SetExpiresAt(time.Now().Add(time.Hour)).
		SetPaidAt(time.Now()).
		SetClientIP("127.0.0.1").
		SetSrcHost("api.example.com").
		Save(ctx)
	require.NoError(t, err)

	balance := 0.0
	userRepo := &mockUserRepo{
		getByIDUser: &User{ID: user.ID, Email: user.Email, Username: user.Username, Balance: 0},
		updateBalanceFn: func(_ context.Context, id int64, amount float64) error {
			require.Equal(t, user.ID, id)
			balance += amount
			return nil
		},
	}
	redeemRepo := &paymentFulfillmentRedeemRepo{}
	redeemSvc := NewRedeemService(redeemRepo, userRepo, nil, nil, nil, client, nil, nil)

	// Simulate transient Phase 2 failure on first attempt, then success on retry!
	hook := &stubMarketplacePaymentHook{
		completeErrs: []error{errors.New("transient postgres timeout"), nil},
	}
	svc := &PaymentService{
		entClient:     client,
		redeemService: redeemSvc,
		userRepo:      userRepo,
	}
	svc.SetMarketplacePaymentHook(hook)

	// Attempt 1: Phase 1 credits +$20 once, Phase 2 returns transient error -> order marked FAILED.
	err = svc.ExecuteBalanceFulfillment(ctx, order.ID)
	require.ErrorContains(t, err, "transient postgres timeout")
	require.Equal(t, 20.0, balance, "Phase 1 must credit balance")
	require.Equal(t, 1, hook.completeCalls)

	midOrder, err := client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, OrderStatusFailed, midOrder.Status)

	// Attempt 2: Retry takes redeemActionSkipCompleted -> NO double credit -> Phase 2 succeeds -> COMPLETED!
	err = svc.ExecuteBalanceFulfillment(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, 20.0, balance, "retry must NEVER double-credit buyer balance")
	require.Equal(t, 2, hook.completeCalls)
	require.Len(t, redeemRepo.useCalls, 1)

	doneOrder, err := client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, OrderStatusCompleted, doneOrder.Status)
}

func TestPaymentRefundBlockedWhileMarketplaceOrderActive(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)

	user, err := client.User.Create().
		SetEmail("refund-mkt-guard@example.com").
		SetPasswordHash("hash").
		SetUsername("refund-mkt-guard").
		Save(ctx)
	require.NoError(t, err)

	inst, err := client.PaymentProviderInstance.Create().
		SetProviderKey(payment.TypeAlipay).
		SetName("alipay-mkt-refund").
		SetConfig("{}").
		SetSupportedTypes("alipay").
		SetEnabled(true).
		SetAllowUserRefund(true).
		SetRefundEnabled(true).
		Save(ctx)
	require.NoError(t, err)

	order, err := client.PaymentOrder.Create().
		SetUserID(user.ID).
		SetUserEmail(user.Email).
		SetUserName(user.Username).
		SetAmount(20).
		SetPayAmount(142.86).
		SetFeeRate(0).
		SetRechargeCode("PAY-REFUND-GUARD").
		SetOutTradeNo("sub2_refund_guard").
		SetPaymentType(payment.TypeAlipay).
		SetPaymentTradeNo("trade-refund-guard").
		SetOrderType(payment.OrderTypeBalance).
		SetStatus(OrderStatusCompleted).
		SetExpiresAt(time.Now().Add(time.Hour)).
		SetPaidAt(time.Now()).
		SetClientIP("127.0.0.1").
		SetSrcHost("api.example.com").
		SetProviderInstanceID(strconv.FormatInt(inst.ID, 10)).
		Save(ctx)
	require.NoError(t, err)

	hook := &stubMarketplacePaymentHook{activeOrderResult: true}
	svc := &PaymentService{entClient: client}
	svc.SetMarketplacePaymentHook(hook)

	_, err = svc.validateRefundRequest(ctx, order.ID, user.ID)
	require.Error(t, err)
	require.Equal(t, "MARKETPLACE_ORDER_ACTIVE_REFUND_BLOCKED", infraerrors.Reason(err))

	// Once rental order is no longer active, refund validation proceeds.
	hook.activeOrderResult = false
	got, err := svc.validateRefundRequest(ctx, order.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, order.ID, got.ID)
}

func TestPaymentCancelCoreSyncsMarketplaceIntentStatus(t *testing.T) {
	ctx := context.Background()
	client := newPaymentConfigServiceTestClient(t)

	user, err := client.User.Create().
		SetEmail("cancel-sync@example.com").
		SetPasswordHash("hash").
		SetUsername("cancel-sync").
		Save(ctx)
	require.NoError(t, err)

	order, err := client.PaymentOrder.Create().
		SetUserID(user.ID).
		SetUserEmail(user.Email).
		SetUserName(user.Username).
		SetAmount(10).
		SetPayAmount(10).
		SetFeeRate(0).
		SetRechargeCode("PAY-CANCEL-SYNC").
		SetOutTradeNo("sub2_cancel_sync").
		SetPaymentType(payment.TypeAlipay).
		SetPaymentTradeNo("").
		SetOrderType(payment.OrderTypeBalance).
		SetStatus(OrderStatusPending).
		SetExpiresAt(time.Now().Add(time.Hour)).
		SetClientIP("127.0.0.1").
		SetSrcHost("api.example.com").
		Save(ctx)
	require.NoError(t, err)

	hook := &stubMarketplacePaymentHook{}
	svc := &PaymentService{entClient: client, registry: payment.NewRegistry()}
	svc.SetMarketplacePaymentHook(hook)

	outcome, err := svc.CancelOrder(ctx, order.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, checkPaidResultCancelled, outcome)
	require.Equal(t, []string{OrderStatusCancelled}, hook.syncedStatuses)
}

func TestCompletePaymentIntentSlotRaceMarksCheckoutFailedAndPreservesBalance(t *testing.T) {
	now := time.Now()
	listingCols := []string{
		"id", "resource_type", "resource_id", "seller_id", "title", "description",
		"rental_mode", "duration_hours", "quota_limit_usd", "price_cents", "capacity",
		"visibility", "target_buyer_id", "declined_at", "status", "admin_suspended",
		"created_at", "updated_at", "usage_rate_multiplier", "email", "username", "active_rentals",
	}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	market := NewMarketplaceService(db)
	payMarket := NewMarketplacePaymentService(db, market, nil, nil)

	// Load intent for payment_order_id = 500
	mock.ExpectQuery("SELECT id,buyer_id,listing_id,checkout_idempotency_key,status FROM berth_marketplace_payment_intents").
		WithArgs(int64(500)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "buyer_id", "listing_id", "checkout_idempotency_key", "status"}).
			AddRow(int64(99), int64(2), int64(10), "chk-slot-race", "pending"))

	// Checkout runs and hits capacity limit (active_rentals == capacity)
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE buyer_id=\\$1 AND idempotency_key=\\$2").
		WithArgs(int64(2), "chk-slot-race").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT resource_type,resource_id FROM berth_marketplace_listings").
		WithArgs(int64(10)).WillReturnRows(sqlmock.NewRows([]string{"resource_type", "resource_id"}).AddRow("account", int64(11)))
	mock.ExpectQuery("SELECT COALESCE\\(\\(SELECT user_id FROM account_stewards").
		WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"owner"}).AddRow(int64(1)))
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE id=\\$1 FOR UPDATE OF l").
		WithArgs(int64(10)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
		int64(10), "account", int64(11), int64(1), "Popular Account", "",
		"duration", 24, nil, int64(1000), 1,
		"public", nil, nil, "active", false,
		now, now, 1.0, "", "", 1, // active_rentals == capacity!
	))
	mock.ExpectRollback()

	// Intent transitions cleanly to checkout_failed with MARKETPLACE_CAPACITY; returns nil error!
	mock.ExpectExec("UPDATE berth_marketplace_payment_intents\\s+SET status='checkout_failed'").
		WithArgs(int64(99), "MARKETPLACE_CAPACITY", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = payMarket.CompletePaymentIntent(context.Background(), 500)
	require.NoError(t, err, "terminal slot-race error must NOT fail payment_order fulfillment")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestReconcilePaidMarketplaceIntentsRecoversStrandedCompletedPayment(t *testing.T) {
	now := time.Now()
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

	market := NewMarketplaceService(db)
	payMarket := NewMarketplacePaymentService(db, market, nil, nil)

	// Reconciler finds 1 stranded intent whose payment_order is COMPLETED (crash happened after Phase 1!)
	mock.ExpectQuery("SELECT i.payment_order_id,po.status\\s+FROM berth_marketplace_payment_intents").
		WillReturnRows(sqlmock.NewRows([]string{"payment_order_id", "status"}).AddRow(int64(700), OrderStatusCompleted))

	// CompletePaymentIntent reads intent
	mock.ExpectQuery("SELECT id,buyer_id,listing_id,checkout_idempotency_key,status FROM berth_marketplace_payment_intents").
		WithArgs(int64(700)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "buyer_id", "listing_id", "checkout_idempotency_key", "status"}).
			AddRow(int64(88), int64(2), int64(10), "chk-crash-recover", "expired"))

	// Checkout replays idempotently (or creates order) and returns order #301
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE buyer_id=\\$1 AND idempotency_key=\\$2").
		WithArgs(int64(2), "chk-crash-recover").
		WillReturnRows(sqlmock.NewRows(orderCols).AddRow(
			int64(301), int64(10), int64(2), int64(1), "Recovered Account", "account", int64(11),
			"quota", nil, 20.0, 0.0, 0.0,
			int64(1000), int64(90), nil, now, nil,
			"active", nil, int64(0), int64(0), nil,
			now, 0, int64(0),
		))
	mock.ExpectRollback()

	// Intent marked completed with marketplace_order_id = 301!
	mock.ExpectExec("UPDATE berth_marketplace_payment_intents\\s+SET status='completed',marketplace_order_id=\\$2").
		WithArgs(int64(88), int64(301)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	reconciled, err := payMarket.ReconcilePaidMarketplaceIntents(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, reconciled)
	require.NoError(t, mock.ExpectationsWereMet())
}
