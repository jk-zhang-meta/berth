package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	dbent "github.com/jk-zhang-meta/berth/ent"
	"github.com/jk-zhang-meta/berth/internal/payment"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/shopspring/decimal"
)

const (
	MarketplacePaymentIntentStatusPending        = "pending"
	MarketplacePaymentIntentStatusCompleted      = "completed"
	MarketplacePaymentIntentStatusCheckoutFailed = "checkout_failed"
	MarketplacePaymentIntentStatusCancelled      = "cancelled"
	MarketplacePaymentIntentStatusExpired        = "expired"

	MarketplaceCheckoutPaymentModeBalanceCompleted = "balance_completed"
	MarketplaceCheckoutPaymentModePaymentRequired  = "payment_required"
)

// MarketplacePaymentHook decouples PaymentService from direct SQL access to
// marketplace intent tables via thin hooks in payment_fulfillment.go,
// payment_order_lifecycle.go, and payment_refund.go.
type MarketplacePaymentHook interface {
	CompletePaymentIntent(ctx context.Context, paymentOrderID int64) error
	SyncPaymentOrderTerminalStatus(ctx context.Context, paymentOrderID int64, status string) error
	HasActiveMarketplaceOrderForPayment(ctx context.Context, paymentOrderID int64) (bool, error)
}

type MarketplaceCheckoutPaymentRequest struct {
	IdempotencyKey    string
	PaymentType       string
	ReturnURL         string
	OpenID            string
	WechatResumeToken string
	ClientIP          string
	IsMobile          bool
	IsWeChatBrowser   bool
	SrcHost           string
	SrcURL            string
	PaymentSource     string
	Locale            string
}

type MarketplaceCheckoutPaymentResponse struct {
	Mode           string               `json:"mode"`
	IntentID       *int64               `json:"intent_id,omitempty"`
	ShortfallCents int64                `json:"shortfall_cents,omitempty"`
	Order          *MarketplaceOrder    `json:"order,omitempty"`
	Payment        *CreateOrderResponse `json:"payment,omitempty"`
}

type MarketplacePaymentIntentView struct {
	ID                 int64             `json:"id"`
	PaymentOrderID     int64             `json:"payment_order_id"`
	OutTradeNo         string            `json:"out_trade_no"`
	PaymentStatus      string            `json:"payment_status"`
	PaymentType        string            `json:"payment_type"`
	PayAmount          float64           `json:"pay_amount"`
	BuyerID            int64             `json:"buyer_id"`
	ListingID          int64             `json:"listing_id"`
	ListingPriceCents  int64             `json:"listing_price_cents"`
	ShortfallCents     int64             `json:"shortfall_cents"`
	TopupCreditedUSD   float64           `json:"topup_credited_usd"`
	Status             string            `json:"status"`
	MarketplaceOrderID *int64            `json:"marketplace_order_id,omitempty"`
	MarketplaceOrder   *MarketplaceOrder `json:"marketplace_order,omitempty"`
	FailureCode        string            `json:"failure_code,omitempty"`
	FailureMessage     string            `json:"failure_message,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	CompletedAt        *time.Time        `json:"completed_at,omitempty"`
}

type MarketplacePaymentService struct {
	db            *sql.DB
	market        *MarketplaceService
	payment       *PaymentService
	paymentConfig *PaymentConfigService
}

func NewMarketplacePaymentService(
	db *sql.DB,
	market *MarketplaceService,
	paymentSvc *PaymentService,
	paymentConfig *PaymentConfigService,
) *MarketplacePaymentService {
	svc := &MarketplacePaymentService{
		db:            db,
		market:        market,
		payment:       paymentSvc,
		paymentConfig: paymentConfig,
	}
	if paymentSvc != nil {
		paymentSvc.SetMarketplacePaymentHook(svc)
	}
	if market != nil {
		market.SetPaymentReconciler(svc)
	}
	return svc
}

func (s *MarketplacePaymentService) IsCheckoutPaymentEnabled(ctx context.Context) bool {
	if s == nil || s.paymentConfig == nil {
		return false
	}
	cfg, err := s.paymentConfig.GetPaymentConfig(ctx)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && !cfg.BalanceDisabled
}

// CalculateShortfallPaymentAmount reverse-calculates the required balance top-up
// input amount using exact decimal arithmetic so that after BalanceRechargeMultiplier,
// RechargeBonusTiers, MinAmount, and RechargeFeeRate are applied, the credited USD
// balance is guaranteed >= shortfallCents / 100.
func CalculateShortfallPaymentAmount(shortfallCents int64, cfg *PaymentConfig, methodCurrency string) (inputAmount float64, quote rechargeBonusQuote, payAmount float64, err error) {
	if shortfallCents <= 0 {
		return 0, rechargeBonusQuote{}, 0, infraerrors.BadRequest("INVALID_AMOUNT", "shortfall must be positive")
	}
	if cfg == nil {
		cfg = &PaymentConfig{BalanceRechargeMultiplier: defaultBalanceRechargeMultiplier}
	}
	if strings.TrimSpace(methodCurrency) == "" {
		methodCurrency = payment.DefaultPaymentCurrency
	}

	shortfallUSD := decimal.New(shortfallCents, -2)
	mult := decimal.NewFromFloat(normalizeBalanceRechargeMultiplier(cfg.BalanceRechargeMultiplier))
	digits := int32(payment.CurrencyMaxFractionDigits(methodCurrency))

	// Exact ceiling division to currency fraction digits: ceil(shortfallUSD / mult)
	// Use high-precision quotient then round ceiling at `digits`.
	rawInput := shortfallUSD.DivRound(mult, digits+8)
	inputDec := rawInput.Shift(digits).Ceil().Shift(-digits)

	minUnit := decimal.New(1, -digits)
	if !inputDec.IsPositive() {
		inputDec = minUnit
	}
	if cfg.MinAmount > 0 {
		minDec := decimal.NewFromFloat(cfg.MinAmount).Shift(digits).Ceil().Shift(-digits)
		if inputDec.LessThan(minDec) {
			inputDec = minDec
		}
	}

	// Verify quoteRechargeBonus credits >= shortfallUSD (step up by 1 minor unit if
	// 2dp rounding in calculateCreditedBalance caused a 1-cent under-credit).
	var maxDec decimal.Decimal
	if cfg.MaxAmount > 0 {
		maxDec = decimal.NewFromFloat(cfg.MaxAmount)
	}
	for step := 0; step < 16; step++ {
		if cfg.MaxAmount > 0 && inputDec.GreaterThan(maxDec) {
			return 0, rechargeBonusQuote{}, 0, infraerrors.BadRequest("INVALID_AMOUNT", "shortfall exceeds maximum payment amount").
				WithMetadata(map[string]string{"max": fmt.Sprintf("%.2f", cfg.MaxAmount)})
		}
		candidate := inputDec.InexactFloat64()
		q := quoteRechargeBonus(cfg, candidate, methodCurrency)
		if decimal.NewFromFloat(q.Credited).GreaterThanOrEqual(shortfallUSD) {
			_, calculatedPay, payErr := calculateCreateOrderPayAmountForOrderType(
				q.PayBase,
				cfg.RechargeFeeRate,
				methodCurrency,
				payment.OrderTypeBalance,
				cfg.SubscriptionUSDToCNYRate,
			)
			if payErr != nil {
				return 0, rechargeBonusQuote{}, 0, payErr
			}
			return candidate, q, calculatedPay, nil
		}
		inputDec = inputDec.Add(minUnit)
	}
	return 0, rechargeBonusQuote{}, 0, infraerrors.BadRequest("INVALID_AMOUNT", "unable to compute payment amount covering shortfall")
}

// CreateCheckoutPaymentIntent initiates a built-in payment order covering the
// buyer's exact balance shortfall and links it crash-safely to an automatic
// marketplace checkout intent.
func (s *MarketplacePaymentService) CreateCheckoutPaymentIntent(
	ctx context.Context,
	buyerID, listingID int64,
	req MarketplaceCheckoutPaymentRequest,
) (*MarketplaceCheckoutPaymentResponse, error) {
	if s == nil || s.db == nil || s.market == nil || s.payment == nil || s.paymentConfig == nil {
		return nil, ErrMarketplacePaymentUnavailable
	}
	key := req.IdempotencyKey
	if buyerID <= 0 || listingID <= 0 || key == "" || len(key) > 128 || strings.TrimSpace(key) != key || !utf8.ValidString(key) || strings.ContainsRune(key, 0) {
		return nil, ErrMarketplaceInvalid
	}
	if strings.TrimSpace(req.WechatResumeToken) != "" {
		claims, err := s.payment.ParseWeChatPaymentResumeToken(req.WechatResumeToken)
		if err != nil {
			return nil, err
		}
		if claims != nil {
			if strings.TrimSpace(claims.OpenID) != "" {
				req.OpenID = strings.TrimSpace(claims.OpenID)
			}
			if pt := NormalizeVisibleMethod(claims.PaymentType); pt != "" {
				req.PaymentType = pt
			}
		}
	}
	paymentType := strings.TrimSpace(req.PaymentType)
	if normalized := NormalizeVisibleMethod(paymentType); normalized != "" {
		paymentType = normalized
	}
	if paymentType == "" {
		return nil, ErrMarketplaceInvalid
	}
	req.PaymentType = paymentType

	// 1. Check for an existing intent under (buyer_id, checkout_idempotency_key).
	var replaceExistingIntentID int64
	if existingResp, supersedeID, err := s.handleExistingPaymentIntent(ctx, buyerID, listingID, key, paymentType); err != nil {
		return nil, err
	} else if existingResp != nil {
		return existingResp, nil
	} else {
		replaceExistingIntentID = supersedeID
	}

	// 2. Pre-validate listing eligibility, visibility, capacity, resource expiry,
	//    and compute exact shortfall.
	priceCents, shortfallCents, err := s.prevalidateCheckoutForPayment(ctx, buyerID, listingID)
	if err != nil {
		return nil, err
	}

	// If buyer's balance is already sufficient, complete checkout directly.
	if shortfallCents <= 0 {
		order, err := s.market.Checkout(ctx, buyerID, listingID, key)
		if err != nil {
			return nil, err
		}
		return &MarketplaceCheckoutPaymentResponse{
			Mode:  MarketplaceCheckoutPaymentModeBalanceCompleted,
			Order: order,
		}, nil
	}

	// 3. Validate payment configuration and reverse-quote inputAmount.
	cfg, err := s.paymentConfig.GetPaymentConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("get payment config: %w", err)
	}
	if !cfg.Enabled {
		return nil, infraerrors.Forbidden("PAYMENT_DISABLED", "payment system is disabled")
	}
	if cfg.BalanceDisabled {
		return nil, infraerrors.Forbidden("BALANCE_PAYMENT_DISABLED", "balance recharge has been disabled")
	}
	methodCurrency, err := s.paymentConfig.ValidateMethodCurrencyConsistency(ctx, paymentType)
	if err != nil {
		return nil, err
	}
	inputAmount, _, _, err := CalculateShortfallPaymentAmount(shortfallCents, cfg, methodCurrency)
	if err != nil {
		return nil, err
	}

	// 4. Create the built-in balance payment order.
	payResp, err := s.payment.CreateOrder(ctx, CreateOrderRequest{
		UserID:          buyerID,
		Amount:          inputAmount,
		PaymentType:     paymentType,
		OpenID:          req.OpenID,
		ClientIP:        req.ClientIP,
		IsMobile:        req.IsMobile,
		IsWeChatBrowser: req.IsWeChatBrowser,
		SrcHost:         req.SrcHost,
		SrcURL:          req.SrcURL,
		ReturnURL:       req.ReturnURL,
		PaymentSource:   req.PaymentSource,
		OrderType:       payment.OrderTypeBalance,
		Locale:          req.Locale,
	})
	if err != nil {
		return nil, err
	}

	// WeChat in-app OAuth pre-step creates no payment_order yet (OrderID == 0).
	// Do NOT insert a payment intent row until OAuth resumes and creates a real order.
	if payResp.ResultType == payment.CreatePaymentResultOAuthRequired || payResp.OrderID <= 0 {
		return &MarketplaceCheckoutPaymentResponse{
			Mode:           MarketplaceCheckoutPaymentModePaymentRequired,
			ShortfallCents: shortfallCents,
			Payment:        payResp,
		}, nil
	}

	// 5. Persist berth_marketplace_payment_intents atomically BEFORE returning
	//    the payment payload to the buyer.
	intentID, err := s.upsertPendingPaymentIntent(ctx, replaceExistingIntentID, payResp.OrderID, buyerID, listingID, key, priceCents, shortfallCents, payResp.Amount)
	if err != nil {
		// Best-effort cancel the orphaned payment order so pending quota isn't leaked.
		_, _ = s.payment.CancelOrder(ctx, payResp.OrderID, buyerID)
		return nil, err
	}

	return &MarketplaceCheckoutPaymentResponse{
		Mode:           MarketplaceCheckoutPaymentModePaymentRequired,
		IntentID:       &intentID,
		ShortfallCents: shortfallCents,
		Payment:        payResp,
	}, nil
}

func (s *MarketplacePaymentService) handleExistingPaymentIntent(
	ctx context.Context,
	buyerID, listingID int64,
	key, paymentType string,
) (resp *MarketplaceCheckoutPaymentResponse, supersedeIntentID int64, err error) {
	var (
		intentID           int64
		paymentOrderID     int64
		existingListingID  int64
		shortfallCents     int64
		status             string
		marketplaceOrderID sql.NullInt64
	)
	err = s.db.QueryRowContext(ctx, `SELECT id,payment_order_id,listing_id,shortfall_cents,status,marketplace_order_id
 FROM berth_marketplace_payment_intents WHERE buyer_id=$1 AND checkout_idempotency_key=$2`, buyerID, key).Scan(
		&intentID, &paymentOrderID, &existingListingID, &shortfallCents, &status, &marketplaceOrderID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if existingListingID != listingID {
		return nil, 0, ErrMarketplaceIdempotency
	}

	switch status {
	case MarketplacePaymentIntentStatusCompleted:
		if marketplaceOrderID.Valid {
			order, oErr := s.loadMarketplaceOrder(ctx, marketplaceOrderID.Int64)
			if oErr == nil {
				return &MarketplaceCheckoutPaymentResponse{
					Mode:     MarketplaceCheckoutPaymentModeBalanceCompleted,
					IntentID: &intentID,
					Order:    order,
				}, 0, nil
			}
		}
		order, cErr := s.market.Checkout(ctx, buyerID, listingID, key)
		if cErr != nil {
			return nil, 0, cErr
		}
		return &MarketplaceCheckoutPaymentResponse{
			Mode:     MarketplaceCheckoutPaymentModeBalanceCompleted,
			IntentID: &intentID,
			Order:    order,
		}, 0, nil

	case MarketplacePaymentIntentStatusCheckoutFailed:
		return nil, 0, ErrMarketplaceConflict

	case MarketplacePaymentIntentStatusPending:
		po, poErr := s.payment.GetOrder(ctx, paymentOrderID, buyerID)
		if poErr != nil {
			return nil, 0, poErr
		}
		// If payment already succeeded, run Phase 2 idempotently now.
		if po.Status == OrderStatusPaid || po.Status == OrderStatusRecharging || po.Status == OrderStatusCompleted {
			if po.Status == OrderStatusPaid {
				_ = s.payment.ExecuteBalanceFulfillment(ctx, po.ID)
			}
			if cErr := s.CompletePaymentIntent(ctx, po.ID); cErr != nil {
				return nil, 0, cErr
			}
			view, vErr := s.GetPaymentIntent(ctx, buyerID, false, intentID)
			if vErr != nil {
				return nil, 0, vErr
			}
			if view.Status == MarketplacePaymentIntentStatusCompleted && view.MarketplaceOrder != nil {
				return &MarketplaceCheckoutPaymentResponse{
					Mode:     MarketplaceCheckoutPaymentModeBalanceCompleted,
					IntentID: &intentID,
					Order:    view.MarketplaceOrder,
				}, 0, nil
			}
			return nil, 0, ErrMarketplaceConflict
		}
		// Reuse active unexpired pending order for the same payment method.
		existingMethod := NormalizeVisibleMethod(po.PaymentType)
		if existingMethod == "" {
			existingMethod = po.PaymentType
		}
		if po.Status == OrderStatusPending && po.ExpiresAt.After(time.Now()) && existingMethod == paymentType {
			return &MarketplaceCheckoutPaymentResponse{
				Mode:           MarketplaceCheckoutPaymentModePaymentRequired,
				IntentID:       &intentID,
				ShortfallCents: shortfallCents,
				Payment:        rebuildCreateOrderResponseFromOrder(po),
			}, 0, nil
		}
		// Buyer switched payment method or pending order expired: cancel old order first
		// (CancelOrder runs checkPaid upstream before cancelling!).
		if po.Status == OrderStatusPending {
			outcome, cancelErr := s.payment.CancelOrder(ctx, po.ID, buyerID)
			if cancelErr != nil {
				return nil, 0, cancelErr
			}
			if outcome == checkPaidResultAlreadyPaid {
				if cErr := s.CompletePaymentIntent(ctx, po.ID); cErr != nil {
					return nil, 0, cErr
				}
				view, vErr := s.GetPaymentIntent(ctx, buyerID, false, intentID)
				if vErr != nil {
					return nil, 0, vErr
				}
				if view.Status == MarketplacePaymentIntentStatusCompleted && view.MarketplaceOrder != nil {
					return &MarketplaceCheckoutPaymentResponse{
						Mode:     MarketplaceCheckoutPaymentModeBalanceCompleted,
						IntentID: &intentID,
						Order:    view.MarketplaceOrder,
					}, 0, nil
				}
				return nil, 0, ErrMarketplaceConflict
			}
		}
		return nil, intentID, nil

	case MarketplacePaymentIntentStatusCancelled, MarketplacePaymentIntentStatusExpired:
		return nil, intentID, nil

	default:
		return nil, 0, ErrMarketplaceConflict
	}
}

func rebuildCreateOrderResponseFromOrder(po *dbent.PaymentOrder) *CreateOrderResponse {
	if po == nil {
		return nil
	}
	resp := &CreateOrderResponse{
		OrderID:     po.ID,
		Amount:      po.Amount,
		PayAmount:   po.PayAmount,
		FeeRate:     po.FeeRate,
		BonusAmount: po.BonusAmount,
		Status:      po.Status,
		ResultType:  payment.CreatePaymentResultOrderCreated,
		PaymentType: po.PaymentType,
		OutTradeNo:  po.OutTradeNo,
		Currency:    PaymentOrderCurrency(po),
		ExpiresAt:   po.ExpiresAt,
	}
	if po.PayURL != nil {
		resp.PayURL = *po.PayURL
	}
	if po.QrCode != nil {
		resp.QRCode = *po.QrCode
	}
	return resp
}

func (s *MarketplacePaymentService) upsertPendingPaymentIntent(
	ctx context.Context,
	replaceIntentID int64,
	paymentOrderID, buyerID, listingID int64,
	key string,
	priceCents, shortfallCents int64,
	topupCreditedUSD float64,
) (int64, error) {
	var id int64
	if replaceIntentID > 0 {
		err := s.db.QueryRowContext(ctx, `UPDATE berth_marketplace_payment_intents
 SET payment_order_id=$2,listing_price_cents=$3,shortfall_cents=$4,topup_credited_usd=$5,
     status='pending',marketplace_order_id=NULL,failure_code=NULL,failure_message=NULL,
     completed_at=NULL,updated_at=clock_timestamp()
 WHERE id=$1 AND buyer_id=$6 AND status IN ('pending','cancelled','expired')
 RETURNING id`, replaceIntentID, paymentOrderID, priceCents, shortfallCents, topupCreditedUSD, buyerID).Scan(&id)
		return id, err
	}
	err := s.db.QueryRowContext(ctx, `INSERT INTO berth_marketplace_payment_intents(
 payment_order_id,buyer_id,listing_id,checkout_idempotency_key,listing_price_cents,shortfall_cents,topup_credited_usd,status
) VALUES($1,$2,$3,$4,$5,$6,$7,'pending') RETURNING id`,
		paymentOrderID, buyerID, listingID, key, priceCents, shortfallCents, topupCreditedUSD).Scan(&id)
	return id, err
}

func (s *MarketplacePaymentService) prevalidateCheckoutForPayment(ctx context.Context, buyerID, listingID int64) (priceCents, shortfallCents int64, err error) {
	listing, err := scanMarketplaceListing(s.db.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE l.id=$1", listingID))
	if err != nil {
		return 0, 0, err
	}
	if listing.SellerID == buyerID {
		return 0, 0, ErrMarketplaceForbidden
	}
	if listing.Visibility == MarketplaceVisibilityTargeted && (listing.TargetBuyerID == nil || *listing.TargetBuyerID != buyerID) {
		return 0, 0, ErrMarketplaceForbidden
	}
	if listing.Status != "active" {
		return 0, 0, ErrMarketplaceUnavailable
	}
	if listing.ActiveRentals >= listing.Capacity {
		return 0, 0, ErrMarketplaceCapacity
	}

	// Cross-listing capacity check across all listings on the resource.
	var totalResourceActive, minActiveCap int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*),COALESCE(MIN(l2.capacity),0)
 FROM berth_marketplace_orders o
 JOIN berth_marketplace_listings l2 ON l2.id=o.listing_id
 WHERE o.resource_type=$1 AND o.resource_id=$2 AND o.status='active'
   AND (o.expires_at IS NULL OR o.expires_at>clock_timestamp())
   AND (o.quota_limit_usd IS NULL OR o.quota_used_usd<o.quota_limit_usd)`, listing.ResourceType, listing.ResourceID).Scan(&totalResourceActive, &minActiveCap); err != nil {
		return 0, 0, err
	}
	effectiveCap := listing.Capacity
	if totalResourceActive > 0 && minActiveCap > 0 && minActiveCap < effectiveCap {
		effectiveCap = minActiveCap
	}
	if totalResourceActive >= effectiveCap {
		return 0, 0, ErrMarketplaceCapacity
	}

	// Verify underlying resource active, owned by seller, and covers duration.
	var now time.Time
	if err = s.db.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return 0, 0, err
	}
	var endCheck time.Time
	if listing.DurationHours != nil {
		endCheck = now.Add(time.Duration(*listing.DurationHours) * time.Hour)
	}
	var resourceOK bool
	switch listing.ResourceType {
	case "account":
		if listing.DurationHours != nil {
			err = s.db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM accounts a JOIN account_stewards st ON st.account_id=a.id
 WHERE a.id=$1 AND st.user_id=$2 AND a.deleted_at IS NULL AND a.status='active' AND a.schedulable=true
   AND (a.expires_at IS NULL OR a.expires_at>=$3))`, listing.ResourceID, listing.SellerID, endCheck).Scan(&resourceOK)
		} else {
			err = s.db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM accounts a JOIN account_stewards st ON st.account_id=a.id
 WHERE a.id=$1 AND st.user_id=$2 AND a.deleted_at IS NULL AND a.status='active' AND a.schedulable=true
   AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()))`, listing.ResourceID, listing.SellerID).Scan(&resourceOK)
		}
	case "proxy":
		if listing.DurationHours == nil {
			return 0, 0, ErrMarketplaceInvalid
		}
		err = s.db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM proxies p JOIN proxy_stewards st ON st.proxy_id=p.id
 WHERE p.id=$1 AND st.user_id=$2 AND p.deleted_at IS NULL AND p.status='active'
   AND NULLIF(p.exit_ip,'') IS NOT NULL AND NULLIF(p.exit_timezone,'') IS NOT NULL AND p.exit_checked_at IS NOT NULL
   AND (p.expires_at IS NULL OR p.expires_at>=$3)
   AND NOT EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.rental_proxy_id=p.id))`, listing.ResourceID, listing.SellerID, endCheck).Scan(&resourceOK)
	default:
		return 0, 0, ErrMarketplaceInvalid
	}
	if err != nil {
		return 0, 0, err
	}
	if !resourceOK {
		return 0, 0, ErrMarketplaceUnavailable
	}

	shortfall, err := s.market.BalanceShortfall(ctx, buyerID, listingID)
	if err != nil {
		return 0, 0, err
	}
	return shortfall.PriceCents, shortfall.ShortfallCents, nil
}

// CompletePaymentIntent executes Phase 2 of crash-safe marketplace payment
// fulfillment after Phase 1 has credited the buyer's USD balance.
//
// Invariants:
//   - Idempotent: safe to call concurrently from doBalance (including
//     redeemActionSkipCompleted retries) and ReconcilePaidMarketplaceIntents.
//   - Terminal business errors (slot filled, listing paused, forbidden) mark
//     the intent checkout_failed and return nil so the payment_order finishes
//     cleanly and the buyer's credited balance remains safely intact.
//   - Transient DB/infra errors return err so Phase 2 is retried without
//     double-crediting balance.
func (s *MarketplacePaymentService) CompletePaymentIntent(ctx context.Context, paymentOrderID int64) error {
	if s == nil || s.db == nil || s.market == nil || paymentOrderID <= 0 {
		return nil
	}
	var (
		intentID       int64
		buyerID        int64
		listingID      int64
		idempotencyKey string
		status         string
	)
	err := s.db.QueryRowContext(ctx, `SELECT id,buyer_id,listing_id,checkout_idempotency_key,status
 FROM berth_marketplace_payment_intents WHERE payment_order_id=$1`, paymentOrderID).Scan(
		&intentID, &buyerID, &listingID, &idempotencyKey, &status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status == MarketplacePaymentIntentStatusCompleted || status == MarketplacePaymentIntentStatusCheckoutFailed {
		return nil
	}
	// Accept pending, expired, and cancelled so late webhooks recovered within
	// PaymentService's 5-minute grace window still complete Phase 2 cleanly.
	if status != MarketplacePaymentIntentStatusPending &&
		status != MarketplacePaymentIntentStatusExpired &&
		status != MarketplacePaymentIntentStatusCancelled {
		return nil
	}

	order, checkoutErr := s.market.Checkout(ctx, buyerID, listingID, idempotencyKey)
	if checkoutErr == nil {
		_, err = s.db.ExecContext(ctx, `UPDATE berth_marketplace_payment_intents
 SET status='completed',marketplace_order_id=$2,failure_code=NULL,failure_message=NULL,
     completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp()
 WHERE id=$1 AND status IN ('pending','expired','cancelled')`, intentID, order.ID)
		return err
	}

	if code, msg, terminal := classifyTerminalMarketplaceCheckoutError(checkoutErr); terminal {
		_, err = s.db.ExecContext(ctx, `UPDATE berth_marketplace_payment_intents
 SET status='checkout_failed',failure_code=$2,failure_message=$3,
     completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp()
 WHERE id=$1 AND status IN ('pending','expired','cancelled')`, intentID, code, msg)
		if err != nil {
			return err
		}
		slog.Warn("[MarketplacePayment] checkout failed after balance credit; balance preserved",
			"intent_id", intentID, "payment_order_id", paymentOrderID, "code", code, "err", checkoutErr)
		return nil
	}

	// Transient DB/infra failure: return error so caller retries Phase 2 without
	// double-crediting Phase 1.
	return checkoutErr
}

func classifyTerminalMarketplaceCheckoutError(err error) (code, msg string, terminal bool) {
	switch {
	case errors.Is(err, ErrMarketplaceCapacity):
		return "MARKETPLACE_CAPACITY", "all simultaneous rental slots are occupied; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceUnavailable):
		return "MARKETPLACE_UNAVAILABLE", "listing or resource is no longer available; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceForbidden):
		return "MARKETPLACE_FORBIDDEN", "not permitted to check out this listing; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceNotFound):
		return "MARKETPLACE_NOT_FOUND", "listing not found; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceIdempotency):
		return "MARKETPLACE_IDEMPOTENCY", "checkout key conflicts with another listing; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceInvalid):
		return "MARKETPLACE_INVALID", "invalid marketplace checkout request; your payment was safely credited to your account balance", true
	case errors.Is(err, ErrMarketplaceBalance):
		return "MARKETPLACE_BALANCE", "available balance still insufficient after top-up (e.g. concurrent spend or price change); your payment was safely credited to your account balance", true
	default:
		return "", "", false
	}
}

// ReconcilePaidMarketplaceIntents is the background crash-recovery worker wired
// into the 15-second marketplace ticker. It scans intents still in
// pending/expired/cancelled whose linked payment_orders are already PAID or
// COMPLETED and drives Phase 2 to completion so a mid-fulfillment crash never
// strands a paid buyer.
func (s *MarketplacePaymentService) ReconcilePaidMarketplaceIntents(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT i.payment_order_id,po.status
 FROM berth_marketplace_payment_intents i
 JOIN payment_orders po ON po.id=i.payment_order_id
 WHERE i.status IN ('pending','expired','cancelled')
   AND po.status IN ('PAID','COMPLETED')
 ORDER BY i.id ASC
 LIMIT 100`)
	if err != nil {
		return 0, err
	}
	type candidate struct {
		paymentOrderID int64
		poStatus       string
	}
	var items []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.paymentOrderID, &c.poStatus); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, c)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}

	reconciled := 0
	var firstErr error
	for _, item := range items {
		var stepErr error
		if item.poStatus == OrderStatusPaid && s.payment != nil {
			stepErr = s.payment.ExecuteBalanceFulfillment(ctx, item.paymentOrderID)
		} else {
			stepErr = s.CompletePaymentIntent(ctx, item.paymentOrderID)
		}
		if stepErr != nil {
			if firstErr == nil {
				firstErr = stepErr
			}
			continue
		}
		reconciled++
	}
	return reconciled, firstErr
}

// SyncPaymentOrderTerminalStatus syncs CANCELLED/EXPIRED payment order status
// onto any pending marketplace payment intent.
func (s *MarketplacePaymentService) SyncPaymentOrderTerminalStatus(ctx context.Context, paymentOrderID int64, status string) error {
	if s == nil || s.db == nil || paymentOrderID <= 0 {
		return nil
	}
	var target string
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case OrderStatusCancelled:
		target = MarketplacePaymentIntentStatusCancelled
	case OrderStatusExpired:
		target = MarketplacePaymentIntentStatusExpired
	default:
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE berth_marketplace_payment_intents
 SET status=$2,updated_at=clock_timestamp()
 WHERE payment_order_id=$1 AND status='pending'`, paymentOrderID, target)
	return err
}

// HasActiveMarketplaceOrderForPayment reports whether a completed payment order
// currently funds an active marketplace rental order (used to block self-service
// payment refund while the rental is still active).
func (s *MarketplacePaymentService) HasActiveMarketplaceOrderForPayment(ctx context.Context, paymentOrderID int64) (bool, error) {
	if s == nil || s.db == nil || paymentOrderID <= 0 {
		return false, nil
	}
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM berth_marketplace_payment_intents i
 JOIN berth_marketplace_orders o ON o.id=i.marketplace_order_id
 WHERE i.payment_order_id=$1 AND i.status='completed' AND o.status='active')`, paymentOrderID).Scan(&active)
	return active, err
}

// GetPaymentIntent performs a strictly read-only lookup of a marketplace
// payment intent and its associated payment/rental order states.
func (s *MarketplacePaymentService) GetPaymentIntent(ctx context.Context, callerID int64, isAdmin bool, intentID int64) (*MarketplacePaymentIntentView, error) {
	if s == nil || s.db == nil {
		return nil, ErrMarketplacePaymentUnavailable
	}
	if callerID <= 0 || intentID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	var (
		v               MarketplacePaymentIntentView
		marketOrderID   sql.NullInt64
		failureCode     sql.NullString
		failureMessage  sql.NullString
		completedAt     sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `SELECT
 i.id,i.payment_order_id,COALESCE(po.out_trade_no,''),COALESCE(po.status,''),COALESCE(po.payment_type,''),COALESCE(po.pay_amount,0),
 i.buyer_id,i.listing_id,i.listing_price_cents,i.shortfall_cents,i.topup_credited_usd,i.status,
 i.marketplace_order_id,i.failure_code,i.failure_message,i.created_at,i.updated_at,i.completed_at
 FROM berth_marketplace_payment_intents i
 LEFT JOIN payment_orders po ON po.id=i.payment_order_id
 WHERE i.id=$1`, intentID).Scan(
		&v.ID, &v.PaymentOrderID, &v.OutTradeNo, &v.PaymentStatus, &v.PaymentType, &v.PayAmount,
		&v.BuyerID, &v.ListingID, &v.ListingPriceCents, &v.ShortfallCents, &v.TopupCreditedUSD, &v.Status,
		&marketOrderID, &failureCode, &failureMessage, &v.CreatedAt, &v.UpdatedAt, &completedAt,
	)
	if err != nil {
		return nil, marketplaceNotFound(err)
	}
	if !isAdmin && v.BuyerID != callerID {
		return nil, ErrMarketplaceForbidden
	}
	if marketOrderID.Valid {
		id := marketOrderID.Int64
		v.MarketplaceOrderID = &id
		order, oErr := s.loadMarketplaceOrder(ctx, id)
		if oErr == nil {
			v.MarketplaceOrder = order
		}
	}
	if failureCode.Valid {
		v.FailureCode = failureCode.String
	}
	if failureMessage.Valid {
		v.FailureMessage = failureMessage.String
	}
	if completedAt.Valid {
		t := completedAt.Time
		v.CompletedAt = &t
	}
	return &v, nil
}

// VerifyPaymentIntent explicitly triggers upstream payment verification via
// PaymentService.VerifyOrderByOutTradeNo and completes Phase 2 if paid.
func (s *MarketplacePaymentService) VerifyPaymentIntent(ctx context.Context, callerID int64, isAdmin bool, intentID int64) (*MarketplacePaymentIntentView, error) {
	view, err := s.GetPaymentIntent(ctx, callerID, isAdmin, intentID)
	if err != nil {
		return nil, err
	}
	if view.Status == MarketplacePaymentIntentStatusCompleted || view.Status == MarketplacePaymentIntentStatusCheckoutFailed {
		return view, nil
	}
	if s.payment != nil && strings.TrimSpace(view.OutTradeNo) != "" {
		po, vErr := s.payment.VerifyOrderByOutTradeNo(ctx, view.OutTradeNo, view.BuyerID)
		if vErr != nil {
			return nil, vErr
		}
		if po != nil {
			if po.Status == OrderStatusPaid {
				if fErr := s.payment.ExecuteBalanceFulfillment(ctx, po.ID); fErr != nil {
					return nil, fErr
				}
			} else if po.Status == OrderStatusCompleted {
				if cErr := s.CompletePaymentIntent(ctx, po.ID); cErr != nil {
					return nil, cErr
				}
			}
		}
	}
	return s.GetPaymentIntent(ctx, callerID, isAdmin, intentID)
}

func (s *MarketplacePaymentService) loadMarketplaceOrder(ctx context.Context, orderID int64) (*MarketplaceOrder, error) {
	return scanMarketplaceOrder(s.db.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE id=$1", orderID))
}

// --- Thin PaymentService hook wrappers ---

func (s *PaymentService) completeMarketplacePaymentIntent(ctx context.Context, o *dbent.PaymentOrder) error {
	if s == nil || s.marketplacePaymentHook == nil || o == nil {
		return nil
	}
	return s.marketplacePaymentHook.CompletePaymentIntent(ctx, o.ID)
}

func (s *PaymentService) syncMarketplacePaymentIntentStatus(ctx context.Context, orderID int64, status string) {
	if s == nil || s.marketplacePaymentHook == nil || orderID <= 0 {
		return
	}
	if err := s.marketplacePaymentHook.SyncPaymentOrderTerminalStatus(ctx, orderID, status); err != nil {
		slog.Warn("[PaymentService] sync marketplace payment intent status failed", "orderID", orderID, "status", status, "error", err)
	}
}

func (s *PaymentService) checkMarketplaceRefundGuard(ctx context.Context, orderID int64) error {
	if s == nil || s.marketplacePaymentHook == nil || orderID <= 0 {
		return nil
	}
	active, err := s.marketplacePaymentHook.HasActiveMarketplaceOrderForPayment(ctx, orderID)
	if err != nil {
		return fmt.Errorf("check marketplace rental refund guard: %w", err)
	}
	if active {
		return infraerrors.BadRequest(
			"MARKETPLACE_ORDER_ACTIVE_REFUND_BLOCKED",
			"cannot request refund while linked marketplace rental order is active; please terminate the rental order first",
		)
	}
	return nil
}
