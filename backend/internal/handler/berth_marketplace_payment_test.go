//go:build unit

package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceCheckout402IncludesShortfallMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
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

	market := service.NewMarketplaceService(db)
	h := NewMarketplaceHandler(market, db, nil, nil, true)

	// Checkout runs up to balance deduction, which affects 0 rows -> ErrMarketplaceBalance
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_orders WHERE buyer_id=\\$1 AND idempotency_key=\\$2").
		WithArgs(int64(2), "chk-low").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT resource_type,resource_id FROM berth_marketplace_listings").
		WithArgs(int64(10)).WillReturnRows(sqlmock.NewRows([]string{"resource_type", "resource_id"}).AddRow("account", int64(11)))
	mock.ExpectQuery("SELECT COALESCE\\(\\(SELECT user_id FROM account_stewards").
		WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"owner"}).AddRow(int64(1)))
	mock.ExpectQuery("SELECT .+ FROM berth_marketplace_listings l WHERE id=\\$1 FOR UPDATE OF l").
		WithArgs(int64(10)).WillReturnRows(sqlmock.NewRows(listingCols).AddRow(
		int64(10), "account", int64(11), int64(1), "Quota Offer", "",
		"quota", nil, 20.0, int64(1000), 2,
		"public", nil, nil, "active", false,
		now, now, 1.0, "", "", 0,
	))
	mock.ExpectQuery("SELECT count\\(\\*\\),COALESCE\\(MIN\\(l2.capacity\\),0\\)").
		WithArgs("account", int64(11)).WillReturnRows(sqlmock.NewRows([]string{"count", "min_cap"}).AddRow(0, 0))
	mock.ExpectQuery("SELECT id,status,deleted_at FROM users WHERE id IN \\(\\$1,\\$2\\) ORDER BY id FOR UPDATE").
		WithArgs(int64(2), int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "status", "deleted_at"}).AddRow(int64(1), "active", nil).AddRow(int64(2), "active", nil))
	mock.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(sqlmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
	mock.ExpectQuery("SELECT a.platform,COALESCE").
		WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"platform", "owner"}).AddRow("openai", int64(1)))
	mock.ExpectQuery("SELECT group_id,owner_user_id FROM berth_account_groups").
		WithArgs(int64(11)).WillReturnRows(sqlmock.NewRows([]string{"group_id", "owner_user_id"}).AddRow(int64(90), int64(1)))
	mock.ExpectExec("INSERT INTO account_groups").WithArgs(int64(11), int64(90)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT status='active' AND deleted_at IS NULL FROM groups").
		WithArgs(int64(90)).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery("INSERT INTO berth_marketplace_orders").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(501)))
	mock.ExpectExec("UPDATE users SET balance=balance-\\$1::numeric/100").
		WithArgs(int64(1000), int64(2)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	// BalanceShortfall lookup for 402 enrichment
	mock.ExpectQuery("SELECT price_cents FROM berth_marketplace_listings").
		WithArgs(int64(10)).WillReturnRows(sqlmock.NewRows([]string{"price_cents"}).AddRow(int64(1000)))
	mock.ExpectQuery("SELECT \\(balance-COALESCE\\(frozen_balance,0\\)\\)::text FROM users").
		WithArgs(int64(2)).WillReturnRows(sqlmock.NewRows([]string{"avail"}).AddRow("2.50000000"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "10"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/marketplace/listings/10/checkout", strings.NewReader(`{"idempotency_key":"chk-low"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 2})
	c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)

	h.Checkout(c)
	require.Equal(t, http.StatusPaymentRequired, w.Code, w.Body.String())

	var payload struct {
		Code     int               `json:"code"`
		Reason   string            `json:"reason"`
		Metadata map[string]string `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	require.Equal(t, "MARKETPLACE_BALANCE", payload.Reason)
	require.Equal(t, "1000", payload.Metadata["price_cents"])
	require.Equal(t, "250", payload.Metadata["available_balance_cents"])
	require.Equal(t, "750", payload.Metadata["shortfall_cents"])
	require.Equal(t, "false", payload.Metadata["payment_enabled"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarketplacePaymentIntentGetIsStrictlyReadOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	market := service.NewMarketplaceService(db)
	payMarket := service.NewMarketplacePaymentService(db, market, nil, nil)
	h := NewMarketplaceHandler(market, db, nil, nil, true)
	h.SetMarketplacePayment(payMarket)

	// ONLY a single SELECT query should execute; zero UPDATE/INSERT/provider calls!
	mock.ExpectQuery("SELECT\\s+i.id,i.payment_order_id").
		WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "payment_order_id", "out_trade_no", "payment_status", "payment_type", "pay_amount",
			"buyer_id", "listing_id", "listing_price_cents", "shortfall_cents", "topup_credited_usd", "status",
			"marketplace_order_id", "failure_code", "failure_message", "created_at", "updated_at", "completed_at",
		}).AddRow(
			int64(77), int64(500), "sub2_ro_test", "PENDING", "alipay", 53.58,
			int64(2), int64(10), int64(1000), int64(750), 7.5, "pending",
			nil, nil, nil, now, now, nil,
		))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "77"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/marketplace/payment-intents/77", nil)
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 2})
	c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)

	h.GetPaymentIntent(c)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"out_trade_no":"sub2_ro_test"`)
	require.Contains(t, w.Body.String(), `"status":"pending"`)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarketplaceOrderUsageHandlerEnforcesParticipantAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Now()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	h := NewMarketplaceHandler(service.NewMarketplaceService(db), db, nil, nil, true)

	// Unrelated caller (user 9) -> 403 Forbidden
	mock.ExpectQuery("SELECT buyer_id,seller_id,quota_used_usd,quota_limit_usd FROM berth_marketplace_orders").
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"buyer_id", "seller_id", "quota_used_usd", "quota_limit_usd"}).
			AddRow(int64(2), int64(1), 5.25, 20.0))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "42"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/marketplace/orders/42/usage", nil)
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 9})
	c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)

	h.OrderUsage(c)
	require.Equal(t, http.StatusForbidden, w.Code)

	// Buyer (user 2) -> 200 OK with paginated usage items
	mock.ExpectQuery("SELECT buyer_id,seller_id,quota_used_usd,quota_limit_usd FROM berth_marketplace_orders").
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"buyer_id", "seller_id", "quota_used_usd", "quota_limit_usd"}).
			AddRow(int64(2), int64(1), 5.25, 20.0))
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM berth_marketplace_order_usage").
		WithArgs(int64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery("SELECT request_id,amount_usd,quota_used_after_usd,admitted_at,created_at\\s+FROM berth_marketplace_order_usage").
		WithArgs(int64(42), 20, 0).
		WillReturnRows(sqlmock.NewRows([]string{"request_id", "amount_usd", "quota_used_after_usd", "admitted_at", "created_at"}).
			AddRow("req-1", 5.25, 5.25, now, now))

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Params = gin.Params{{Key: "id", Value: "42"}}
	c2.Request = httptest.NewRequest(http.MethodGet, "/marketplace/orders/42/usage", nil)
	c2.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 2})
	c2.Set(string(middleware.ContextKeyUserRole), service.RoleUser)

	h.OrderUsage(c2)
	require.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
	require.Contains(t, w2.Body.String(), `"request_id":"req-1"`)
	require.Contains(t, w2.Body.String(), `"quota_used_usd":5.25`)
	require.NoError(t, mock.ExpectationsWereMet())
}
