package service

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/lib/pq"
	"github.com/shopspring/decimal"
)

const (
	MarketplaceRentalModeDuration = "duration"
	MarketplaceRentalModeQuota    = "quota"
	MarketplaceRentalModeHybrid   = "hybrid"

	MarketplaceVisibilityPublic   = "public"
	MarketplaceVisibilityTargeted = "targeted"

	MarketplaceCompletionTimeExpired      = "time_expired"
	MarketplaceCompletionQuotaExhausted   = "quota_exhausted"
	MarketplaceCompletionBuyerTerminated  = "buyer_terminated"
	MarketplaceCompletionSellerTerminated = "seller_terminated"
	MarketplaceCompletionAdminTerminated  = "admin_terminated"

	MarketplaceQuotaReservationStatusReserved = "reserved"
	MarketplaceQuotaReservationStatusSettled  = "settled"
	MarketplaceQuotaReservationStatusReleased = "released"
	MarketplaceQuotaReservationStatusExpired  = "expired"

	MarketplaceQuotaReservationDefaultTTL = 15 * time.Minute

	marketplaceTxMaxRetries = 3
)

var (
	ErrMarketplaceQuotaInsufficient  = infraerrors.New(http.StatusPaymentRequired, "MARKETPLACE_QUOTA_INSUFFICIENT", "Insufficient remaining rental quota")
	ErrMarketplaceTargetBuyerInvalid = infraerrors.New(http.StatusBadRequest, "MARKETPLACE_TARGET_BUYER_INVALID", "Invalid target buyer")
	ErrMarketplacePaymentUnavailable = infraerrors.New(http.StatusServiceUnavailable, "MARKETPLACE_PAYMENT_UNAVAILABLE", "Online payment for marketplace checkout is unavailable")
)

type MarketplaceQuotaReservation struct {
	ID          int64     `json:"id"`
	OrderID     int64     `json:"order_id"`
	OperationID string    `json:"operation_id"`
	BuyerID     int64     `json:"buyer_id"`
	ReservedUSD float64   `json:"reserved_usd"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type MarketplaceOrderUsageItem struct {
	RequestID         string    `json:"request_id"`
	AmountUSD         float64   `json:"amount_usd"`
	QuotaUsedAfterUSD float64   `json:"quota_used_after_usd"`
	AdmittedAt        time.Time `json:"admitted_at"`
	CreatedAt         time.Time `json:"created_at"`
}

type MarketplaceOrderUsagePage struct {
	Items         []MarketplaceOrderUsageItem `json:"items"`
	Total         int64                       `json:"total"`
	Page          int                         `json:"page"`
	PageSize      int                         `json:"page_size"`
	QuotaUsedUSD  float64                     `json:"quota_used_usd"`
	QuotaLimitUSD *float64                    `json:"quota_limit_usd,omitempty"`
}

type MarketplaceBalanceShortfall struct {
	PriceCents            int64 `json:"price_cents"`
	AvailableBalanceCents int64 `json:"available_balance_cents"`
	ShortfallCents        int64 `json:"shortfall_cents"`
}

// isRetryablePGError identifies PostgreSQL deadlock (40P01) and serialization
// failure (40001) errors that are safe to retry for idempotent transactions.
func isRetryablePGError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		code := string(pqErr.Code)
		return code == "40P01" || code == "40001"
	}
	var sqlStateErr interface{ SQLState() string }
	if errors.As(err, &sqlStateErr) {
		code := sqlStateErr.SQLState()
		return code == "40P01" || code == "40001"
	}
	return false
}

// withMarketplaceTxRetry retries idempotent transactional operations on
// PostgreSQL deadlock (40P01) or serialization failure (40001) up to 3 retries
// with bounded jittered backoff.
func withMarketplaceTxRetry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt <= marketplaceTxMaxRetries; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		err = fn()
		if err == nil || !isRetryablePGError(err) || attempt == marketplaceTxMaxRetries {
			return err
		}
		backoff := time.Duration(10*(attempt+1)+rand.IntN(25)) * time.Millisecond
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

// marketplaceSettlementByMode computes exact cent-level earned gross and refund
// amounts preserving earnedGross + refund == priceCents across all rental modes.
// Uses exact integer / shopspring/decimal division without float64 precision loss.
func marketplaceSettlementByMode(
	mode string,
	priceCents int64,
	start time.Time,
	end *time.Time,
	at time.Time,
	quotaUsedUSD, quotaLimitUSD decimal.Decimal,
) (earnedGross, refund int64) {
	if priceCents <= 0 {
		return 0, 0
	}
	switch mode {
	case "", MarketplaceRentalModeDuration:
		if end == nil {
			return 0, priceCents
		}
		return marketplaceSettlement(priceCents, start, *end, at)
	case MarketplaceRentalModeQuota:
		return marketplaceQuotaSettlement(priceCents, quotaUsedUSD, quotaLimitUSD)
	case MarketplaceRentalModeHybrid:
		timeExhausted := end != nil && !at.Before(*end)
		quotaExhausted := quotaLimitUSD.IsPositive() && quotaUsedUSD.GreaterThanOrEqual(quotaLimitUSD)
		if timeExhausted || quotaExhausted {
			return priceCents, 0
		}
		var elapsedUS, durationUS int64
		if end != nil && end.After(start) {
			durationUS = end.Sub(start).Microseconds()
			if at.After(start) {
				elapsedUS = at.Sub(start).Microseconds()
			}
		}
		used := quotaUsedUSD
		if used.IsNegative() {
			used = decimal.Zero
		}
		hasTime := durationUS > 0
		hasQuota := quotaLimitUSD.IsPositive()
		if !hasTime && !hasQuota {
			return 0, priceCents
		}
		if hasTime && !hasQuota {
			return marketplaceSettlement(priceCents, start, *end, at)
		}
		if !hasTime && hasQuota {
			return marketplaceQuotaSettlement(priceCents, used, quotaLimitUSD)
		}
		// Cross-multiply exact fractions to avoid DivisionPrecision truncation:
		// elapsedUS / durationUS >= used / quotaLimitUSD  <=>  elapsedUS * quotaLimitUSD >= used * durationUS
		timeLHS := decimal.NewFromInt(elapsedUS).Mul(quotaLimitUSD)
		quotaRHS := used.Mul(decimal.NewFromInt(durationUS))
		if timeLHS.GreaterThanOrEqual(quotaRHS) {
			return marketplaceSettlement(priceCents, start, *end, at)
		}
		return marketplaceQuotaSettlement(priceCents, used, quotaLimitUSD)
	default:
		if end == nil {
			return 0, priceCents
		}
		return marketplaceSettlement(priceCents, start, *end, at)
	}
}

func marketplaceQuotaSettlement(priceCents int64, quotaUsedUSD, quotaLimitUSD decimal.Decimal) (earnedGross, refund int64) {
	if !quotaLimitUSD.IsPositive() || !quotaUsedUSD.IsPositive() {
		return 0, priceCents
	}
	if quotaUsedUSD.GreaterThanOrEqual(quotaLimitUSD) {
		return priceCents, 0
	}
	// Exact integer floor: floor(priceCents * quotaUsedUSD / quotaLimitUSD)
	numerator := decimal.NewFromInt(priceCents).Mul(quotaUsedUSD)
	quotient, _ := numerator.QuoRem(quotaLimitUSD, 0)
	earnedGross = quotient.IntPart()
	if earnedGross < 0 {
		earnedGross = 0
	}
	if earnedGross > priceCents {
		earnedGross = priceCents
	}
	return earnedGross, priceCents - earnedGross
}

// marketplaceSettlementSplit computes exact zero-sum escrow split:
// sellerEarned + platformCommission + refund == priceCents ALWAYS holds to the exact cent.
func marketplaceSettlementSplit(
	mode string,
	priceCents int64,
	rentCommissionBPS int,
	start time.Time,
	end *time.Time,
	at time.Time,
	quotaUsedUSD, quotaLimitUSD decimal.Decimal,
) (sellerEarned, platformCommission, refund int64) {
	earnedGross, refund := marketplaceSettlementByMode(mode, priceCents, start, end, at, quotaUsedUSD, quotaLimitUSD)
	if rentCommissionBPS < 0 {
		rentCommissionBPS = 0
	}
	if rentCommissionBPS > 10000 {
		rentCommissionBPS = 10000
	}
	hi, lo := bits.Mul64(uint64(earnedGross), uint64(rentCommissionBPS))
	commQ, _ := bits.Div64(hi, lo, 10000)
	platformCommission = int64(commQ)
	sellerEarned = earnedGross - platformCommission
	return sellerEarned, platformCommission, refund
}

func maskBuyerLabel(email, username string) string {
	email = strings.TrimSpace(email)
	if at := strings.IndexByte(email, '@'); at > 0 && at < len(email)-1 {
		local := []rune(email[:at])
		domain := email[at+1:]
		if len(local) <= 1 {
			return string(local) + "***@" + domain
		}
		if len(local) == 2 {
			return string(local[:1]) + "***@" + domain
		}
		return string(local[:2]) + "***@" + domain
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return ""
	}
	runes := []rune(username)
	if len(runes) <= 2 {
		return string(runes[:1]) + "***"
	}
	return string(runes[:2]) + "***"
}

func sanitizeListingForCaller(v *MarketplaceListing, callerID int64, isAdmin bool) {
	if v == nil {
		return
	}
	if v.Visibility != MarketplaceVisibilityTargeted {
		v.TargetBuyerID = nil
		v.TargetBuyerLabel = ""
		return
	}
	allowed := isAdmin || v.SellerID == callerID || (v.TargetBuyerID != nil && *v.TargetBuyerID == callerID)
	if !allowed {
		v.TargetBuyerID = nil
		v.TargetBuyerLabel = ""
	}
}

// ReserveQuota atomically reserves a conservative upper bound of USD quota
// before upstream request dispatch for quota/hybrid rental orders.
func (s *MarketplaceService) ReserveQuota(
	ctx context.Context,
	orderID, buyerID int64,
	operationID string,
	conservativeUpperBoundUSD float64,
	ttl time.Duration,
) (*MarketplaceQuotaReservation, error) {
	operationID = strings.TrimSpace(operationID)
	if orderID <= 0 || buyerID <= 0 || operationID == "" || len(operationID) > 128 || !utf8.ValidString(operationID) || strings.ContainsRune(operationID, 0) {
		return nil, ErrMarketplaceInvalid
	}
	if math.IsNaN(conservativeUpperBoundUSD) || math.IsInf(conservativeUpperBoundUSD, 0) || conservativeUpperBoundUSD <= 0 {
		return nil, ErrMarketplaceQuotaInsufficient
	}
	if ttl <= 0 {
		ttl = MarketplaceQuotaReservationDefaultTTL
	}
	boundDec := decimal.NewFromFloat(conservativeUpperBoundUSD).RoundCeil(UsageBillingMonetaryScale)
	if !boundDec.IsPositive() {
		return nil, ErrMarketplaceQuotaInsufficient
	}

	var result *MarketplaceQuotaReservation
	err := withMarketplaceTxRetry(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		var existing MarketplaceQuotaReservation
		err = tx.QueryRowContext(ctx, `SELECT id,order_id,operation_id,buyer_id,reserved_usd,status,expires_at,created_at,updated_at
 FROM berth_marketplace_quota_reservations WHERE operation_id=$1 FOR UPDATE`, operationID).Scan(
			&existing.ID, &existing.OrderID, &existing.OperationID, &existing.BuyerID,
			&existing.ReservedUSD, &existing.Status, &existing.ExpiresAt, &existing.CreatedAt, &existing.UpdatedAt,
		)
		if err == nil {
			if existing.OrderID == orderID && existing.BuyerID == buyerID && existing.Status == MarketplaceQuotaReservationStatusReserved {
				result = &existing
				return nil
			}
			return ErrMarketplaceConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		var (
			status           string
			orderBuyerID     int64
			rentalMode       string
			startsAt         time.Time
			expiresAt        sql.NullTime
			quotaLimitStr    sql.NullString
			quotaUsedStr     string
			quotaReservedStr string
			now              time.Time
		)
		err = tx.QueryRowContext(ctx, `SELECT status,buyer_id,rental_mode,starts_at,expires_at,quota_limit_usd::text,quota_used_usd::text,quota_reserved_usd::text,clock_timestamp()
 FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE`, orderID).Scan(
			&status, &orderBuyerID, &rentalMode, &startsAt, &expiresAt, &quotaLimitStr, &quotaUsedStr, &quotaReservedStr, &now,
		)
		if err != nil {
			return marketplaceNotFound(err)
		}
		if orderBuyerID != buyerID {
			return ErrMarketplaceForbidden
		}
		if status != "active" || now.Before(startsAt) || (expiresAt.Valid && !now.Before(expiresAt.Time)) {
			return ErrMarketplaceUnavailable
		}
		if (rentalMode != MarketplaceRentalModeQuota && rentalMode != MarketplaceRentalModeHybrid) || !quotaLimitStr.Valid {
			return ErrMarketplaceInvalid
		}
		quotaLimit, err := decimal.NewFromString(quotaLimitStr.String)
		if err != nil {
			return err
		}
		quotaUsed, err := decimal.NewFromString(quotaUsedStr)
		if err != nil {
			return err
		}
		quotaReserved, err := decimal.NewFromString(quotaReservedStr)
		if err != nil {
			return err
		}
		remaining := quotaLimit.Sub(quotaUsed).Sub(quotaReserved)
		if !remaining.IsPositive() || quotaUsed.Add(quotaReserved).Add(boundDec).GreaterThan(quotaLimit) {
			return ErrMarketplaceQuotaInsufficient
		}

		resExpires := now.Add(ttl)
		var res MarketplaceQuotaReservation
		err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_quota_reservations(order_id,operation_id,buyer_id,reserved_usd,status,expires_at,created_at,updated_at)
 VALUES($1,$2,$3,$4::numeric,'reserved',$5,$6,$6)
 RETURNING id,order_id,operation_id,buyer_id,reserved_usd,status,expires_at,created_at,updated_at`,
			orderID, operationID, buyerID, boundDec.StringFixed(UsageBillingMonetaryScale), resExpires, now).Scan(
			&res.ID, &res.OrderID, &res.OperationID, &res.BuyerID,
			&res.ReservedUSD, &res.Status, &res.ExpiresAt, &res.CreatedAt, &res.UpdatedAt,
		)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders SET quota_reserved_usd=quota_reserved_usd+$2::numeric WHERE id=$1`,
			orderID, boundDec.StringFixed(UsageBillingMonetaryScale)); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		result = &res
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReleaseQuotaReservation releases a pre-dispatch reservation when an upstream
// request fails or is aborted before usage billing executes.
func (s *MarketplaceService) ReleaseQuotaReservation(ctx context.Context, operationID string) error {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return nil
	}
	return withMarketplaceTxRetry(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		var orderID int64
		err = tx.QueryRowContext(ctx, `SELECT order_id FROM berth_marketplace_quota_reservations WHERE operation_id=$1`, operationID).Scan(&orderID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// Preserve global lock order: berth_marketplace_orders before reservations.
		var lockedOrderID int64
		if err = tx.QueryRowContext(ctx, `SELECT id FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE`, orderID).Scan(&lockedOrderID); err != nil {
			return marketplaceNotFound(err)
		}
		var resID int64
		var status string
		var reservedStr string
		err = tx.QueryRowContext(ctx, `SELECT id,status,reserved_usd::text FROM berth_marketplace_quota_reservations WHERE operation_id=$1 FOR UPDATE`, operationID).Scan(&resID, &status, &reservedStr)
		if errors.Is(err, sql.ErrNoRows) || status != MarketplaceQuotaReservationStatusReserved {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_quota_reservations SET status='released',updated_at=clock_timestamp() WHERE id=$1`, resID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders SET quota_reserved_usd=GREATEST(0,quota_reserved_usd-$2::numeric) WHERE id=$1`, orderID, reservedStr); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// ReclaimExpiredQuotaReservations expires stale pre-dispatch quota reservations
// (e.g. >15m after a crashed process) and decrements order.quota_reserved_usd.
func (s *MarketplaceService) ReclaimExpiredQuotaReservations(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT order_id FROM berth_marketplace_quota_reservations WHERE status='reserved' AND expires_at<=$1 ORDER BY order_id LIMIT 100`, now)
	if err != nil {
		return 0, err
	}
	var orderIDs []int64
	for rows.Next() {
		var oid int64
		if err = rows.Scan(&oid); err != nil {
			_ = rows.Close()
			return 0, err
		}
		orderIDs = append(orderIDs, oid)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}

	reclaimed := 0
	for _, oid := range orderIDs {
		var orderReclaimed int
		err := withMarketplaceTxRetry(ctx, func() error {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()

			var locked int64
			if err = tx.QueryRowContext(ctx, `SELECT id FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE`, oid).Scan(&locked); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			var count int
			var sumStr string
			err = tx.QueryRowContext(ctx, `WITH expired AS (
 UPDATE berth_marketplace_quota_reservations
 SET status='expired',updated_at=clock_timestamp()
 WHERE order_id=$1 AND status='reserved' AND expires_at<=$2
 RETURNING reserved_usd
)
SELECT count(*),COALESCE(sum(reserved_usd),0)::text FROM expired`, oid, now).Scan(&count, &sumStr)
			if err != nil {
				return err
			}
			if count > 0 {
				if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders SET quota_reserved_usd=GREATEST(0,quota_reserved_usd-$2::numeric) WHERE id=$1`, oid, sumStr); err != nil {
					return err
				}
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			orderReclaimed = count
			return nil
		})
		if err != nil {
			return reclaimed, err
		}
		reclaimed += orderReclaimed
	}
	return reclaimed, nil
}

// DeclineListing lets the target buyer decline an active targeted offer.
func (s *MarketplaceService) DeclineListing(ctx context.Context, buyerID, listingID int64) (*MarketplaceListing, error) {
	if buyerID <= 0 || listingID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	var result *MarketplaceListing
	err := withMarketplaceTxRetry(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		listing, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE l.id=$1 FOR UPDATE OF l", listingID))
		if err != nil {
			return err
		}
		if listing.Visibility != MarketplaceVisibilityTargeted || listing.TargetBuyerID == nil || *listing.TargetBuyerID != buyerID {
			return ErrMarketplaceForbidden
		}
		if listing.Status != "active" {
			return ErrMarketplaceConflict
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_listings SET status='removed',declined_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, listingID); err != nil {
			return err
		}
		updated, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE l.id=$1", listingID))
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		sanitizeListingForCaller(updated, buyerID, false)
		result = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListOrderUsage returns the paginated append-only quota usage audit trail for a rental order.
func (s *MarketplaceService) ListOrderUsage(ctx context.Context, callerID int64, isAdmin bool, orderID int64, page, pageSize int) (*MarketplaceOrderUsagePage, error) {
	if callerID <= 0 || orderID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var buyerID, sellerID int64
	var quotaUsed float64
	var quotaLimit sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `SELECT buyer_id,seller_id,quota_used_usd,quota_limit_usd FROM berth_marketplace_orders WHERE id=$1`, orderID).Scan(&buyerID, &sellerID, &quotaUsed, &quotaLimit)
	if err != nil {
		return nil, marketplaceNotFound(err)
	}
	if !isAdmin && callerID != buyerID && callerID != sellerID {
		return nil, ErrMarketplaceForbidden
	}

	var total int64
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM berth_marketplace_order_usage WHERE order_id=$1`, orderID).Scan(&total); err != nil {
		return nil, err
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `SELECT request_id,amount_usd,quota_used_after_usd,admitted_at,created_at
 FROM berth_marketplace_order_usage WHERE order_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3`, orderID, pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := []MarketplaceOrderUsageItem{}
	for rows.Next() {
		var item MarketplaceOrderUsageItem
		if err = rows.Scan(&item.RequestID, &item.AmountUSD, &item.QuotaUsedAfterUSD, &item.AdmittedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := &MarketplaceOrderUsagePage{
		Items:        items,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		QuotaUsedUSD: quotaUsed,
	}
	if quotaLimit.Valid {
		limit := quotaLimit.Float64
		out.QuotaLimitUSD = &limit
	}
	return out, nil
}

// BalanceShortfall computes the exact cent-level shortfall for a buyer attempting
// to check out a marketplace listing.
func (s *MarketplaceService) BalanceShortfall(ctx context.Context, userID, listingID int64) (*MarketplaceBalanceShortfall, error) {
	if userID <= 0 || listingID <= 0 {
		return nil, ErrMarketplaceInvalid
	}
	var priceCents int64
	if err := s.db.QueryRowContext(ctx, `SELECT price_cents FROM berth_marketplace_listings WHERE id=$1`, listingID).Scan(&priceCents); err != nil {
		return nil, marketplaceNotFound(err)
	}
	var availStr string
	if err := s.db.QueryRowContext(ctx, `SELECT (balance-COALESCE(frozen_balance,0))::text FROM users WHERE id=$1 AND deleted_at IS NULL`, userID).Scan(&availStr); err != nil {
		return nil, marketplaceNotFound(err)
	}
	availDec, err := decimal.NewFromString(availStr)
	if err != nil {
		return nil, err
	}
	availCents := availDec.Shift(2).Floor().IntPart()
	if availCents < 0 {
		availCents = 0
	}
	shortfall := priceCents - availCents
	if shortfall < 0 {
		shortfall = 0
	}
	return &MarketplaceBalanceShortfall{
		PriceCents:            priceCents,
		AvailableBalanceCents: availCents,
		ShortfallCents:        shortfall,
	}, nil
}
