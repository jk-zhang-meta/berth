//go:build unit

package service

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func mktFloatPtr(v float64) *float64 { return &v }
func mktInt64Ptr(v int64) *int64     { return &v }

func TestMarketplacePublishValidationQuotaHybridAndTargeted(t *testing.T) {
	t.Parallel()

	// Valid quota listing (account, no duration, positive quota_limit_usd)
	quota := MarketplacePublishInput{
		ResourceType:  "account",
		ResourceID:    10,
		Title:         "Quota pack",
		RentalMode:    MarketplaceRentalModeQuota,
		QuotaLimitUSD: mktFloatPtr(25.5),
		PriceCents:    1500,
		Capacity:      2,
	}
	require.NoError(t, validateMarketplacePublish(&quota))

	// Valid hybrid listing (account, both duration and quota)
	hybrid := MarketplacePublishInput{
		ResourceType:  "account",
		ResourceID:    10,
		Title:         "Hybrid pack",
		RentalMode:    MarketplaceRentalModeHybrid,
		DurationHours: 48,
		QuotaLimitUSD: mktFloatPtr(50),
		PriceCents:    3000,
		Capacity:      1,
		Visibility:    MarketplaceVisibilityTargeted,
		TargetBuyer:   "buyer@example.com",
	}
	require.NoError(t, validateMarketplacePublish(&hybrid))

	// Invalid cases
	invalidCases := []struct {
		name  string
		input MarketplacePublishInput
		want  error
	}{
		{
			name: "proxy rejects quota mode",
			input: MarketplacePublishInput{
				ResourceType:  "proxy",
				ResourceID:    1,
				Title:         "Proxy quota",
				RentalMode:    MarketplaceRentalModeQuota,
				QuotaLimitUSD: mktFloatPtr(10),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "proxy rejects hybrid mode",
			input: MarketplacePublishInput{
				ResourceType:  "proxy",
				ResourceID:    1,
				Title:         "Proxy hybrid",
				RentalMode:    MarketplaceRentalModeHybrid,
				DurationHours: 24,
				QuotaLimitUSD: mktFloatPtr(10),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "quota rejects non-zero duration",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Quota with hours",
				RentalMode:    MarketplaceRentalModeQuota,
				DurationHours: 24,
				QuotaLimitUSD: mktFloatPtr(10),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "duration rejects quota_limit_usd",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Duration with quota",
				RentalMode:    MarketplaceRentalModeDuration,
				DurationHours: 24,
				QuotaLimitUSD: mktFloatPtr(10),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "hybrid requires quota_limit_usd",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Hybrid missing quota",
				RentalMode:    MarketplaceRentalModeHybrid,
				DurationHours: 24,
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "hybrid requires duration_hours",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Hybrid missing duration",
				RentalMode:    MarketplaceRentalModeHybrid,
				QuotaLimitUSD: mktFloatPtr(10),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "quota below min 0.01",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Tiny quota",
				RentalMode:    MarketplaceRentalModeQuota,
				QuotaLimitUSD: mktFloatPtr(0.005),
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "public rejects target_buyer",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Public with buyer",
				RentalMode:    MarketplaceRentalModeDuration,
				DurationHours: 24,
				PriceCents:    500,
				Capacity:      1,
				Visibility:    MarketplaceVisibilityPublic,
				TargetBuyer:   "buyer@example.com",
			},
			want: ErrMarketplaceInvalid,
		},
		{
			name: "targeted requires buyer",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Targeted missing buyer",
				RentalMode:    MarketplaceRentalModeDuration,
				DurationHours: 24,
				PriceCents:    500,
				Capacity:      1,
				Visibility:    MarketplaceVisibilityTargeted,
			},
			want: ErrMarketplaceTargetBuyerInvalid,
		},
		{
			name: "unknown rental mode",
			input: MarketplacePublishInput{
				ResourceType:  "account",
				ResourceID:    1,
				Title:         "Unknown mode",
				RentalMode:    "unlimited",
				DurationHours: 24,
				PriceCents:    500,
				Capacity:      1,
			},
			want: ErrMarketplaceInvalid,
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.input
			require.ErrorIs(t, validateMarketplacePublish(&in), tc.want)
		})
	}
}

func TestMarketplaceZeroSumSettlementExactCentsAllModes(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(10 * time.Hour)

	tests := []struct {
		name           string
		mode           string
		priceCents     int64
		commissionBPS  int
		elapsed        time.Duration
		quotaUsed      string
		quotaLimit     string
		wantSeller     int64
		wantCommission int64
		wantRefund     int64
	}{
		{
			name:           "duration half odd cent with 10% commission",
			mode:           MarketplaceRentalModeDuration,
			priceCents:     101,
			commissionBPS:  1000,
			elapsed:        5 * time.Hour,
			wantSeller:     45,
			wantCommission: 5,
			wantRefund:     51,
		},
		{
			name:           "quota 25% used ($5/$20) with 5% commission",
			mode:           MarketplaceRentalModeQuota,
			priceCents:     1500,
			commissionBPS:  500,
			quotaUsed:      "5",
			quotaLimit:     "20",
			wantSeller:     357, // earnedGross=375, comm=floor(375*500/10000)=18, seller=357
			wantCommission: 18,
			wantRefund:     1125,
		},
		{
			name:           "quota 1/3 floor exact cent zero-sum",
			mode:           MarketplaceRentalModeQuota,
			priceCents:     100,
			commissionBPS:  333,
			quotaUsed:      "1",
			quotaLimit:     "3",
			wantSeller:     32, // earnedGross=33, comm=floor(33*333/10000)=1, seller=32
			wantCommission: 1,
			wantRefund:     67,
		},
		{
			name:           "quota overshoot caps at 100% and refund 0",
			mode:           MarketplaceRentalModeQuota,
			priceCents:     1500,
			commissionBPS:  1000,
			quotaUsed:      "20.42",
			quotaLimit:     "20",
			wantSeller:     1350,
			wantCommission: 150,
			wantRefund:     0,
		},
		{
			name:           "quota zero used refunds 100%",
			mode:           MarketplaceRentalModeQuota,
			priceCents:     999,
			commissionBPS:  1000,
			quotaUsed:      "0",
			quotaLimit:     "10",
			wantSeller:     0,
			wantCommission: 0,
			wantRefund:     999,
		},
		{
			name:           "hybrid time-dominant (60% time vs 20% quota)",
			mode:           MarketplaceRentalModeHybrid,
			priceCents:     1000,
			commissionBPS:  1000,
			elapsed:        6 * time.Hour,
			quotaUsed:      "4",
			quotaLimit:     "20",
			wantSeller:     540, // earnedGross=600, comm=60, seller=540, refund=400
			wantCommission: 60,
			wantRefund:     400,
		},
		{
			name:           "hybrid quota-dominant (20% time vs 75% quota)",
			mode:           MarketplaceRentalModeHybrid,
			priceCents:     1000,
			commissionBPS:  1000,
			elapsed:        2 * time.Hour,
			quotaUsed:      "15",
			quotaLimit:     "20",
			wantSeller:     675, // earnedGross=750, comm=75, seller=675, refund=250
			wantCommission: 75,
			wantRefund:     250,
		},
		{
			name:           "hybrid quota exhausted before time expiry settles 100%",
			mode:           MarketplaceRentalModeHybrid,
			priceCents:     1234,
			commissionBPS:  250,
			elapsed:        1 * time.Hour,
			quotaUsed:      "20",
			quotaLimit:     "20",
			wantSeller:     1204, // comm=floor(1234*250/10000)=30
			wantCommission: 30,
			wantRefund:     0,
		},
		{
			name:           "hybrid time expired before quota exhaustion settles 100%",
			mode:           MarketplaceRentalModeHybrid,
			priceCents:     1234,
			commissionBPS:  250,
			elapsed:        10 * time.Hour,
			quotaUsed:      "1",
			quotaLimit:     "20",
			wantSeller:     1204,
			wantCommission: 30,
			wantRefund:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var endPtr *time.Time
			if tc.mode != MarketplaceRentalModeQuota {
				endPtr = &end
			}
			var used, limit decimal.Decimal
			if tc.quotaUsed != "" {
				used = decimal.RequireFromString(tc.quotaUsed)
			}
			if tc.quotaLimit != "" {
				limit = decimal.RequireFromString(tc.quotaLimit)
			}
			seller, comm, refund := marketplaceSettlementSplit(
				tc.mode, tc.priceCents, tc.commissionBPS,
				start, endPtr, start.Add(tc.elapsed), used, limit,
			)
			require.Equal(t, tc.wantSeller, seller)
			require.Equal(t, tc.wantCommission, comm)
			require.Equal(t, tc.wantRefund, refund)
			require.Equal(t, tc.priceCents, seller+comm+refund, "zero-sum escrow invariant must hold to the exact cent")
		})
	}
}

func TestMarketplaceTxRetryWrapper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("retries deadlock 40P01 and succeeds", func(t *testing.T) {
		var attempts atomic.Int32
		err := withMarketplaceTxRetry(ctx, func() error {
			n := attempts.Add(1)
			if n < 3 {
				return &pq.Error{Code: "40P01", Message: "deadlock detected"}
			}
			return nil
		})
		require.NoError(t, err)
		require.EqualValues(t, 3, attempts.Load())
	})

	t.Run("retries serialization failure 40001 up to max retries", func(t *testing.T) {
		var attempts atomic.Int32
		err := withMarketplaceTxRetry(ctx, func() error {
			attempts.Add(1)
			return &pq.Error{Code: "40001", Message: "could not serialize access"}
		})
		require.Error(t, err)
		require.EqualValues(t, marketplaceTxMaxRetries+1, attempts.Load())
	})

	t.Run("does not retry non-retryable error", func(t *testing.T) {
		var attempts atomic.Int32
		sentinel := errors.New("business error")
		err := withMarketplaceTxRetry(ctx, func() error {
			attempts.Add(1)
			return sentinel
		})
		require.ErrorIs(t, err, sentinel)
		require.EqualValues(t, 1, attempts.Load())
	})
}

func TestMarketplaceQuotaReserveReleaseAndReclaim(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	t.Run("rejects unbounded request cost before DB", func(t *testing.T) {
		svc := NewMarketplaceService(nil)
		for _, bad := range []float64{0, -1, math.NaN(), math.Inf(1)} {
			_, err := svc.ReserveQuota(context.Background(), 1, 2, "op-bad", bad, time.Minute)
			require.ErrorIs(t, err, ErrMarketplaceQuotaInsufficient)
		}
	})

	t.Run("reserves quota when headroom available", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id,order_id,operation_id").WithArgs("op-1").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT status,buyer_id,rental_mode").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"status", "buyer_id", "rental_mode", "starts_at", "expires_at", "quota_limit_usd", "quota_used_usd", "quota_reserved_usd", "now"}).
				AddRow("active", int64(7), "quota", now.Add(-time.Hour), nil, "20.00000000", "15.00000000", "2.00000000", now))
		mock.ExpectQuery("INSERT INTO berth_marketplace_quota_reservations").
			WithArgs(int64(42), "op-1", int64(7), "2.50000000", now.Add(15*time.Minute), now).
			WillReturnRows(sqlmock.NewRows([]string{"id", "order_id", "operation_id", "buyer_id", "reserved_usd", "status", "expires_at", "created_at", "updated_at"}).
				AddRow(int64(100), int64(42), "op-1", int64(7), 2.5, "reserved", now.Add(15*time.Minute), now, now))
		mock.ExpectExec("UPDATE berth_marketplace_orders SET quota_reserved_usd=quota_reserved_usd").
			WithArgs(int64(42), "2.50000000").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		res, err := svc.ReserveQuota(context.Background(), 42, 7, "op-1", 2.5, 0)
		require.NoError(t, err)
		require.Equal(t, int64(100), res.ID)
		require.Equal(t, 2.5, res.ReservedUSD)
		require.Equal(t, MarketplaceQuotaReservationStatusReserved, res.Status)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("rejects when used + reserved + bound exceeds limit", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id,order_id,operation_id").WithArgs("op-over").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT status,buyer_id,rental_mode").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"status", "buyer_id", "rental_mode", "starts_at", "expires_at", "quota_limit_usd", "quota_used_usd", "quota_reserved_usd", "now"}).
				AddRow("active", int64(7), "quota", now.Add(-time.Hour), nil, "20.00000000", "15.00000000", "4.00000000", now))
		mock.ExpectRollback()

		_, err = svc.ReserveQuota(context.Background(), 42, 7, "op-over", 1.5, 0)
		require.ErrorIs(t, err, ErrMarketplaceQuotaInsufficient)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("releases reservation decrementing quota_reserved_usd", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT order_id FROM berth_marketplace_quota_reservations").WithArgs("op-1").
			WillReturnRows(sqlmock.NewRows([]string{"order_id"}).AddRow(int64(42)))
		mock.ExpectQuery("SELECT id FROM berth_marketplace_orders WHERE id=\\$1 FOR UPDATE").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
		mock.ExpectQuery("SELECT id,status,reserved_usd::text FROM berth_marketplace_quota_reservations").WithArgs("op-1").
			WillReturnRows(sqlmock.NewRows([]string{"id", "status", "reserved_usd"}).AddRow(int64(100), "reserved", "2.50000000"))
		mock.ExpectExec("UPDATE berth_marketplace_quota_reservations SET status='released'").WithArgs(int64(100)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("UPDATE berth_marketplace_orders SET quota_reserved_usd=GREATEST").WithArgs(int64(42), "2.50000000").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		require.NoError(t, svc.ReleaseQuotaReservation(context.Background(), "op-1"))
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("reclaims expired reservations >15m old", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectQuery("SELECT DISTINCT order_id FROM berth_marketplace_quota_reservations").WithArgs(now).
			WillReturnRows(sqlmock.NewRows([]string{"order_id"}).AddRow(int64(42)))
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id FROM berth_marketplace_orders WHERE id=\\$1 FOR UPDATE").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
		mock.ExpectQuery("WITH expired AS").WithArgs(int64(42), now).
			WillReturnRows(sqlmock.NewRows([]string{"count", "sum"}).AddRow(2, "3.25000000"))
		mock.ExpectExec("UPDATE berth_marketplace_orders SET quota_reserved_usd=GREATEST").WithArgs(int64(42), "3.25000000").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		reclaimed, err := svc.ReclaimExpiredQuotaReservations(context.Background(), now)
		require.NoError(t, err)
		require.Equal(t, 2, reclaimed)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestMarketplaceTargetedVisibilityDeclineAndForbiddenCheckout(t *testing.T) {
	now := time.Now()
	listingCols := []string{
		"id", "resource_type", "resource_id", "seller_id", "title", "description",
		"rental_mode", "duration_hours", "quota_limit_usd", "price_cents", "capacity",
		"visibility", "target_buyer_id", "declined_at", "status", "admin_suspended",
		"created_at", "updated_at", "usage_rate_multiplier", "email", "username", "active_rentals",
	}

	t.Run("maskBuyerLabel and caller privacy redaction", func(t *testing.T) {
		require.Equal(t, "al***@example.com", maskBuyerLabel("alice@example.com", "alice"))
		require.Equal(t, "a***@example.com", maskBuyerLabel("a@example.com", ""))
		require.Equal(t, "bo***", maskBuyerLabel("", "bobby"))

		l := &MarketplaceListing{
			SellerID:         1,
			Visibility:       MarketplaceVisibilityTargeted,
			TargetBuyerID:    mktInt64Ptr(2),
			TargetBuyerLabel: "al***@example.com",
		}
		// Unrelated user cannot see target buyer fields
		lOther := *l
		sanitizeListingForCaller(&lOther, 3, false)
		require.Nil(t, lOther.TargetBuyerID)
		require.Empty(t, lOther.TargetBuyerLabel)

		// Seller, target buyer, and admin retain target buyer fields
		lSeller := *l
		sanitizeListingForCaller(&lSeller, 1, false)
		require.NotNil(t, lSeller.TargetBuyerID)
		require.Equal(t, "al***@example.com", lSeller.TargetBuyerLabel)
	})

	t.Run("non-target buyer gets 403 on targeted checkout", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE buyer_id=\\$1 AND idempotency_key=\\$2").
			WithArgs(int64(3), "key-1").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT resource_type,resource_id FROM berth_marketplace_listings").
			WithArgs(int64(55)).WillReturnRows(sqlmock.NewRows([]string{"resource_type", "resource_id"}).AddRow("account", int64(11)))
		mock.ExpectQuery("SELECT COALESCE\\(\\(SELECT user_id FROM account_stewards").
			WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"owner"}).AddRow(int64(1)))
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE id=\\$1 FOR UPDATE OF l").
			WithArgs(int64(55)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
			int64(55), "account", int64(11), int64(1), "VIP Offer", "",
			"quota", nil, 20.0, int64(1000), 1,
			"targeted", int64(2), nil, "active", false,
			now, now, 1.0, "buyer@example.com", "buyer", 0,
		))
		mock.ExpectRollback()

		_, err = svc.Checkout(context.Background(), 3, 55, "key-1")
		require.ErrorIs(t, err, ErrMarketplaceForbidden)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("cross-listing active capacity guard blocks second checkout across public+targeted", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE buyer_id=\\$1 AND idempotency_key=\\$2").
			WithArgs(int64(2), "key-cross").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT resource_type,resource_id FROM berth_marketplace_listings").
			WithArgs(int64(56)).WillReturnRows(sqlmock.NewRows([]string{"resource_type", "resource_id"}).AddRow("account", int64(11)))
		mock.ExpectQuery("SELECT COALESCE\\(\\(SELECT user_id FROM account_stewards").
			WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"owner"}).AddRow(int64(1)))
		// Listing 56 itself has active_rentals=0 and capacity=2, but another listing
		// on account 11 has an active exclusive rental (capacity=1, totalResourceActive=1).
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE id=\\$1 FOR UPDATE OF l").
			WithArgs(int64(56)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
			int64(56), "account", int64(11), int64(1), "Targeted Offer", "",
			"quota", nil, 20.0, int64(1000), 2,
			"targeted", int64(2), nil, "active", false,
			now, now, 1.0, "buyer@example.com", "buyer", 0,
		))
		mock.ExpectQuery("SELECT count\\(\\*\\),COALESCE\\(MIN\\(l2.capacity\\),0\\)").
			WithArgs("account", int64(11)).WillReturnRows(sqlmock.NewRows([]string{"count", "min_cap"}).AddRow(1, 1))
		mock.ExpectRollback()

		_, err = svc.Checkout(context.Background(), 2, 56, "key-cross")
		require.ErrorIs(t, err, ErrMarketplaceCapacity)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("target buyer declines offer and unrelated user gets 403", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		svc := NewMarketplaceService(db)

		// Wrong buyer -> 403
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE l.id=\\$1 FOR UPDATE OF l").
			WithArgs(int64(55)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
			int64(55), "account", int64(11), int64(1), "VIP Offer", "",
			"quota", nil, 20.0, int64(1000), 1,
			"targeted", int64(2), nil, "active", false,
			now, now, 1.0, "buyer@example.com", "buyer", 0,
		))
		mock.ExpectRollback()
		_, err = svc.DeclineListing(context.Background(), 3, 55)
		require.ErrorIs(t, err, ErrMarketplaceForbidden)

		// Target buyer -> removed + declined_at
		declinedAt := now.Add(time.Minute)
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE l.id=\\$1 FOR UPDATE OF l").
			WithArgs(int64(55)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
			int64(55), "account", int64(11), int64(1), "VIP Offer", "",
			"quota", nil, 20.0, int64(1000), 1,
			"targeted", int64(2), nil, "active", false,
			now, now, 1.0, "buyer@example.com", "buyer", 0,
		))
		mock.ExpectExec("UPDATE berth_marketplace_listings SET status='removed',declined_at=clock_timestamp\\(\\)").
			WithArgs(int64(55)).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE l.id=\\$1").
			WithArgs(int64(55)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
			int64(55), "account", int64(11), int64(1), "VIP Offer", "",
			"quota", nil, 20.0, int64(1000), 1,
			"targeted", int64(2), declinedAt, "removed", false,
			now, declinedAt, 1.0, "buyer@example.com", "buyer", 0,
		))
		mock.ExpectCommit()

		declined, err := svc.DeclineListing(context.Background(), 2, 55)
		require.NoError(t, err)
		require.Equal(t, "removed", declined.Status)
		require.NotNil(t, declined.DeclinedAt)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUsageBillingCommandSettlementKindAndLaneBypass(t *testing.T) {
	t.Run("buildUsageBillingCommand routes quota buyer to UsageSettlementMarketplaceQuota with BalanceCost=0", func(t *testing.T) {
		groupID := int64(90)
		p := &postUsageBillingParams{
			Cost: &CostBreakdown{TotalCost: 1.5, ActualCost: 2.25},
			User: &User{ID: 2},
			APIKey: &APIKey{
				ID:      33,
				UserID:  2,
				GroupID: &groupID,
				MarketplaceUsage: &MarketplaceUsageSnapshot{
					GroupID:        90,
					AccountID:      11,
					SellerID:       1,
					OrderID:        77,
					RentalMode:     MarketplaceRentalModeQuota,
					OperationID:    "op-abc",
					CommissionBPS:  500,
					RateMultiplier: 1.5,
					AdmittedAt:     time.Now(),
				},
			},
			Account: &Account{ID: 11, Type: AccountTypeOAuth},
		}
		cmd := buildUsageBillingCommand("req-quota-1", nil, p)
		require.NotNil(t, cmd)
		require.Equal(t, UsageSettlementMarketplaceQuota, cmd.SettlementKind)
		require.Zero(t, cmd.BalanceCost)
		require.Equal(t, 2.25, cmd.MarketplaceQuotaCost)
		require.Equal(t, "op-abc", cmd.MarketplaceOperationID)
		require.NotEmpty(t, cmd.RequestFingerprint)

		// Fingerprint changes if MarketplaceQuotaCost or OperationID changes
		cmd2 := *cmd
		cmd2.RequestFingerprint = ""
		cmd2.MarketplaceOperationID = "op-other"
		cmd2.Normalize()
		require.NotEqual(t, cmd.RequestFingerprint, cmd2.RequestFingerprint)
	})

	t.Run("lane combiner bypasses ApplyBatch based on explicit SettlementKind even if MarketplaceUsage is nil", func(t *testing.T) {
		repo := newLaneTestRepo()
		repo.balances[7] = 100
		c := newLaneTestCombiner(repo, 64)
		out := make(chan laneTestResult, 8)

		// Block normal lane for user 7
		release := repo.block("normal-1")
		applyAsync(c, laneTestCommand(7, "normal-1", 1), out)
		waitStarted(t, repo, "normal-1")

		quotaOut := make(chan laneTestResult, 2)
		cmdQuota := &UsageBillingCommand{
			RequestID:            "quota-req-1",
			APIKeyID:             1,
			UserID:               7,
			SettlementKind:       UsageSettlementMarketplaceQuota,
			MarketplaceQuotaCost: 3.5,
		}
		cmdDur := &UsageBillingCommand{
			RequestID:      "dur-req-1",
			APIKeyID:       1,
			UserID:         7,
			SettlementKind: UsageSettlementMarketplaceDuration,
			BalanceCost:    2.0,
		}
		applyAsync(c, cmdQuota, quotaOut)
		applyAsync(c, cmdDur, quotaOut)

		results := collectResults(t, quotaOut, 2)
		require.NoError(t, results["quota-req-1"].err)
		require.NoError(t, results["dur-req-1"].err)
		require.Empty(t, repo.batchCalls, "non-standard SettlementKind must NEVER enter ApplyBatch")

		close(release)
		collectResults(t, out, 1)
	})
}

type fakeQuotaExhaustedKeyInvalidator struct {
	keyInvalidated  []string
	userInvalidated []int64
}

func (f *fakeQuotaExhaustedKeyInvalidator) UpdateQuotaUsed(context.Context, int64, float64) error {
	return nil
}
func (f *fakeQuotaExhaustedKeyInvalidator) UpdateRateLimitUsage(context.Context, int64, float64) error {
	return nil
}
func (f *fakeQuotaExhaustedKeyInvalidator) InvalidateAuthCacheByKey(_ context.Context, key string) {
	f.keyInvalidated = append(f.keyInvalidated, key)
}
func (f *fakeQuotaExhaustedKeyInvalidator) InvalidateAuthCacheByUserID(_ context.Context, userID int64) {
	f.userInvalidated = append(f.userInvalidated, userID)
}

type fakeQuotaExhaustedBillingRepo struct {
	UsageBillingRepository
	res *UsageBillingApplyResult
}

func (f *fakeQuotaExhaustedBillingRepo) Apply(context.Context, *UsageBillingCommand) (*UsageBillingApplyResult, error) {
	return f.res, nil
}

func TestApplyUsageBillingInvalidatesAuthCacheOnMarketplaceQuotaExhausted(t *testing.T) {
	groupID := int64(90)
	inv := &fakeQuotaExhaustedKeyInvalidator{}
	repo := &fakeQuotaExhaustedBillingRepo{
		res: &UsageBillingApplyResult{
			Applied:                   true,
			MarketplaceQuotaExhausted: true,
			MarketplaceSellerID:       1,
			MarketplaceSettledOrderID: 77,
		},
	}
	p := &postUsageBillingParams{
		Cost: &CostBreakdown{TotalCost: 5, ActualCost: 5},
		User: &User{ID: 2, Balance: 0},
		APIKey: &APIKey{
			ID:      33,
			UserID:  2,
			Key:     "sk-buyer-quota",
			GroupID: &groupID,
			MarketplaceUsage: &MarketplaceUsageSnapshot{
				GroupID:        90,
				AccountID:      11,
				SellerID:       1,
				OrderID:        77,
				RentalMode:     MarketplaceRentalModeQuota,
				CommissionBPS:  500,
				RateMultiplier: 1.0,
				AdmittedAt:     time.Now(),
			},
		},
		Account:       &Account{ID: 11, Type: AccountTypeOAuth},
		APIKeyService: inv,
	}
	deps := &billingDeps{
		deferredService: NewDeferredService(nil, nil, 0),
	}
	applied, err := applyUsageBilling(context.Background(), "req-exhaust-1", nil, p, deps, repo)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, []string{"sk-buyer-quota"}, inv.keyInvalidated)
	require.Equal(t, []int64{2}, inv.userInvalidated)
}
