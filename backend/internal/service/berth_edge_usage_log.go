package service

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math"
	"math/bits"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/shopspring/decimal"
)

// SetEdgeUsageTelemetry wires PostgreSQL persistence, BillingService pricing, and an optional
// cache invalidation hook so Berth Edge usage receipts automatically populate token costs,
// usage_logs (when an API key is bound), accounts.last_used_at, and Account Pool "今日统计".
func (s *BerthEdgeLeaseService) SetEdgeUsageTelemetry(db *sql.DB, billing *BillingService, onUsageIngested func()) {
	s.mu.Lock()
	s.telemetryDB = db
	s.billingSvc = billing
	s.onUsageIngested = onUsageIngested
	s.mu.Unlock()
}

func (s *BerthEdgeLeaseService) notifyUsageIngested() {
	s.mu.RLock()
	fn := s.onUsageIngested
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func edgeUsageRequestID(receiptID string) string {
	id := "edge:" + strings.TrimSpace(receiptID)
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}

// prepareEdgeReceiptTelemetry computes token pricing, updates accounts.last_used_at, and
// mirrors token-bearing API-key Edge receipts into usage_logs (setting receipt.UsageLogID so
// account today-stats queries never double-count). All operations are best-effort and idempotent.
func (s *BerthEdgeLeaseService) prepareEdgeReceiptTelemetry(ctx context.Context, r *edgeproto.UsageReceipt) {
	if r == nil || r.AccountID <= 0 {
		return
	}
	// Only successful upstream exchanges count toward usage telemetry / last_used_at.
	if r.StatusCode <= 0 || r.StatusCode >= 400 {
		return
	}

	s.mu.RLock()
	db := s.telemetryDB
	billing := s.billingSvc
	s.mu.RUnlock()

	eventAt := time.Now()
	if r.CreatedAtUnix > 0 {
		eventAt = time.Unix(r.CreatedAtUnix, 0)
	}

	accountRateMultiplier := 1.0
	if db != nil {
		var mult sql.NullFloat64
		if err := db.QueryRowContext(ctx, `SELECT rate_multiplier FROM accounts WHERE id = $1`, r.AccountID).Scan(&mult); err == nil && mult.Valid && mult.Float64 >= 0 {
			accountRateMultiplier = mult.Float64
		}
		// Keep accounts.last_used_at fresh for Berth Edge / bh Cage traffic.
		_, _ = db.ExecContext(ctx, `
			UPDATE accounts
			SET last_used_at = GREATEST(COALESCE(last_used_at, $2), $2)
			WHERE id = $1`, r.AccountID, eventAt)
	}

	totalTokens := max(r.InputTokens, 0) + max(r.OutputTokens, 0) + max(r.CacheCreationTokens, 0) + max(r.CacheReadTokens, 0)
	model := strings.TrimSpace(r.Model)
	if len(model) > 100 {
		model = model[:100]
		r.Model = model
	}

	var inputCost, outputCost, cacheCreationCost, cacheReadCost float64
	if billing != nil && model != "" && totalTokens > 0 {
		tokens := UsageTokens{
			InputTokens:         max(r.InputTokens, 0),
			OutputTokens:        max(r.OutputTokens, 0),
			CacheCreationTokens: max(r.CacheCreationTokens, 0),
			CacheReadTokens:     max(r.CacheReadTokens, 0),
		}
		if breakdown, err := billing.CalculateCost(model, tokens, 1.0); err == nil && breakdown != nil {
			inputCost = breakdown.InputCost
			outputCost = breakdown.OutputCost
			cacheCreationCost = breakdown.CacheCreationCost
			cacheReadCost = breakdown.CacheReadCost
			r.TotalCost = breakdown.TotalCost
			r.ActualCost = breakdown.ActualCost
			r.AccountStatsCost = breakdown.TotalCost * accountRateMultiplier
		}
	}

	// Debit marketplace rental order usage for Berth Edge sessions bound to an
	// active marketplace rental order (R-2), preventing free USD spend over Edge.
	if db != nil && r.TotalCost > 0 && strings.TrimSpace(r.LeaseID) != "" {
		s.debitEdgeMarketplaceOrderUsage(ctx, db, r, eventAt)
	}

	// Mirror token-bearing API-key Edge requests into usage_logs so Admin Usage / Dashboard /
	// Account Stats Modal also show complete request-level telemetry with zero double counting.
	if db == nil || r.UserID <= 0 || r.APIKeyID <= 0 || totalTokens <= 0 {
		return
	}

	var groupID sql.NullInt64
	var keyRateMult sql.NullFloat64
	err := db.QueryRowContext(ctx, `
		SELECT k.group_id, COALESCE(g.rate_multiplier, 1.0)
		FROM api_keys k
		LEFT JOIN groups g ON g.id = k.group_id
		WHERE k.id = $1 AND k.user_id = $2`,
		r.APIKeyID, r.UserID,
	).Scan(&groupID, &keyRateMult)
	if err != nil {
		// API key was hard-deleted or does not belong to user; keep stats on berth_landing_node_grant_usage only.
		return
	}

	userRateMult := 1.0
	if keyRateMult.Valid && keyRateMult.Float64 >= 0 {
		userRateMult = keyRateMult.Float64
	}
	actualCost := r.TotalCost * userRateMult
	r.ActualCost = actualCost

	logModel := model
	if logModel == "" {
		logModel = strings.TrimSpace(r.Platform)
		if logModel == "" {
			logModel = "berth-edge"
		}
	}

	var ttft sql.NullInt32
	if r.TTFTMs > 0 {
		ttft = sql.NullInt32{Int32: int32(r.TTFTMs), Valid: true}
	}
	var dur sql.NullInt32
	if r.DurationMs > 0 {
		dur = sql.NullInt32{Int32: int32(r.DurationMs), Valid: true}
	}

	reqID := edgeUsageRequestID(r.ReceiptID)
	var insertedID int64
	err = db.QueryRowContext(ctx, `
		INSERT INTO usage_logs (
			user_id, api_key_id, account_id, request_id, model, requested_model,
			group_id, input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
			input_cost, output_cost, cache_creation_cost, cache_read_cost,
			total_cost, actual_cost, account_stats_cost,
			rate_multiplier, account_rate_multiplier,
			stream, duration_ms, first_token_ms,
			inbound_endpoint, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17,
			$18, $19,
			$20, $21, $22,
			'berth-edge', $23
		)
		ON CONFLICT (request_id, api_key_id) DO NOTHING
		RETURNING id`,
		r.UserID, r.APIKeyID, r.AccountID, reqID, logModel,
		groupID, max(r.InputTokens, 0), max(r.OutputTokens, 0),
		max(r.CacheCreationTokens, 0), max(r.CacheReadTokens, 0),
		inputCost, outputCost, cacheCreationCost, cacheReadCost,
		r.TotalCost, actualCost, r.TotalCost,
		userRateMult, accountRateMultiplier,
		r.Stream, dur, ttft, eventAt,
	).Scan(&insertedID)
	if err == nil && insertedID > 0 {
		r.UsageLogID = insertedID
		return
	}
	if err == sql.ErrNoRows {
		// Duplicate replay: resolve existing usage_logs.id so grant_usage links cleanly.
		var existingID int64
		if qErr := db.QueryRowContext(ctx, `SELECT id FROM usage_logs WHERE request_id = $1 AND api_key_id = $2`, reqID, r.APIKeyID).Scan(&existingID); qErr == nil && existingID > 0 {
			r.UsageLogID = existingID
		}
		return
	}
	if err != nil {
		log.Printf("[BerthEdge] usage_logs mirror skipped for receipt %s (account=%d): %v", r.ReceiptID, r.AccountID, err)
	}
}

// debitEdgeMarketplaceOrderUsage idempotently charges a Berth Edge usage receipt
// against the marketplace rental order attributed to r.LeaseID (R-2).
// Quota/hybrid orders debit quota_used_usd and settle + revoke Edge leases on
// exhaustion; duration orders debit buyer balance and credit seller revenue.
func (s *BerthEdgeLeaseService) debitEdgeMarketplaceOrderUsage(
	ctx context.Context,
	db *sql.DB,
	r *edgeproto.UsageReceipt,
	eventAt time.Time,
) {
	if db == nil || r == nil || r.TotalCost <= 0 || strings.TrimSpace(r.LeaseID) == "" {
		return
	}
	var orderID sql.NullInt64
	if err := db.QueryRowContext(ctx, `
		SELECT marketplace_order_id
		FROM berth_work_session_leases
		WHERE lease_id = $1`, strings.TrimSpace(r.LeaseID)).Scan(&orderID); err != nil || !orderID.Valid || orderID.Int64 <= 0 {
		return
	}

	reqID := edgeUsageRequestID(r.ReceiptID)
	var revokeBuyerID, revokeGroupID int64
	txErr := withMarketplaceTxRetry(ctx, func() error {
		revokeBuyerID, revokeGroupID = 0, 0
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		var (
			status            string
			rentalMode        string
			buyerID           int64
			sellerID          int64
			groupID           sql.NullInt64
			priceCents        int64
			rentCommissionBPS int
			rateMult          float64
			quotaUsedStr      string
			quotaLimitStr     sql.NullString
		)
		err = tx.QueryRowContext(ctx, `
			SELECT status, rental_mode, buyer_id, seller_id, group_id,
			       price_cents, rent_commission_bps, COALESCE(usage_rate_multiplier, 1.0),
			       quota_used_usd::text, quota_limit_usd::text
			FROM berth_marketplace_orders
			WHERE id = $1
			FOR UPDATE`, orderID.Int64).Scan(
			&status, &rentalMode, &buyerID, &sellerID, &groupID,
			&priceCents, &rentCommissionBPS, &rateMult, &quotaUsedStr, &quotaLimitStr,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if buyerID <= 0 || sellerID <= 0 || buyerID == sellerID {
			return nil
		}
		if rateMult <= 0 {
			rateMult = 1.0
		}
		billedUSD := QuantizeUsageBillingAmount(r.TotalCost * rateMult)
		if billedUSD <= 0 {
			return nil
		}
		r.ActualCost = billedUSD

		if err = marketplaceLockUsers(ctx, tx, buyerID, sellerID, false); err != nil {
			return err
		}

		if rentalMode == MarketplaceRentalModeQuota || rentalMode == MarketplaceRentalModeHybrid {
			var existingID int64
			err = tx.QueryRowContext(ctx, `
				SELECT id FROM berth_marketplace_order_usage
				WHERE order_id = $1 AND request_id = $2`, orderID.Int64, reqID).Scan(&existingID)
			if err == nil {
				return nil // Idempotent replay
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}

			var newQuotaUsedStr string
			if err = tx.QueryRowContext(ctx, `
				UPDATE berth_marketplace_orders
				SET quota_used_usd = quota_used_usd + $1::numeric
				WHERE id = $2
				RETURNING quota_used_usd::text`, billedUSD, orderID.Int64).Scan(&newQuotaUsedStr); err != nil {
				return err
			}
			gid := groupID.Int64
			if _, err = tx.ExecContext(ctx, `
				INSERT INTO berth_marketplace_order_usage
					(order_id, request_id, api_key_id, buyer_id, seller_id, account_id, group_id, amount_usd, quota_used_after_usd, admitted_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::numeric, $10)`,
				orderID.Int64, reqID, r.APIKeyID, buyerID, sellerID, r.AccountID, gid, billedUSD, newQuotaUsedStr, eventAt); err != nil {
				return err
			}

			if status == "active" && quotaLimitStr.Valid {
				usedDec, uErr := decimal.NewFromString(newQuotaUsedStr)
				limitDec, lErr := decimal.NewFromString(quotaLimitStr.String)
				if uErr == nil && lErr == nil && limitDec.IsPositive() && !usedDec.LessThan(limitDec) {
					bps := rentCommissionBPS
					if bps < 0 {
						bps = 0
					}
					if bps > 10000 {
						bps = 10000
					}
					hi, lo := bits.Mul64(uint64(priceCents), uint64(bps))
					commQ, _ := bits.Div64(hi, lo, 10000)
					commission := int64(commQ)
					earned := priceCents - commission
					if _, err = tx.ExecContext(ctx, `UPDATE users SET balance = balance + $1::numeric/100, updated_at = clock_timestamp() WHERE id = $2`, earned, sellerID); err != nil {
						return err
					}
					if _, err = tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id, user_id, kind, amount_cents) VALUES ($1,$2,'payout',$3),($1,$4,'refund',0)`, orderID.Int64, sellerID, earned, buyerID); err != nil {
						return err
					}
					if commission > 0 {
						if _, err = tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id, kind, amount_cents) VALUES ($1,'platform_commission',$2)`, orderID.Int64, commission); err != nil {
							return err
						}
					}
					if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_quota_reservations SET status = 'released', updated_at = clock_timestamp() WHERE order_id = $1 AND status = 'reserved'`, orderID.Int64); err != nil {
						return err
					}
					if _, err = tx.ExecContext(ctx, `
						UPDATE berth_marketplace_orders
						SET status = 'completed',
						    completion_reason = 'quota_exhausted',
						    seller_earned_cents = $2,
						    refund_cents = 0,
						    platform_commission_cents = $3,
						    quota_reserved_usd = 0,
						    settled_at = clock_timestamp()
						WHERE id = $1`, orderID.Int64, earned, commission); err != nil {
						return err
					}
					if groupID.Valid && groupID.Int64 > 0 {
						revokeBuyerID, revokeGroupID = buyerID, groupID.Int64
					}
				}
			}
			return tx.Commit()
		}

		// Duration rental order: idempotently debit buyer balance and credit seller usage revenue.
		var usageCommBPS int
		_ = tx.QueryRowContext(ctx, `SELECT usage_commission_bps FROM berth_marketplace_settings WHERE id = 1`).Scan(&usageCommBPS)
		if usageCommBPS < 0 {
			usageCommBPS = 0
		}
		if usageCommBPS > 10000 {
			usageCommBPS = 10000
		}
		var dup int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM berth_marketplace_usage_revenue WHERE request_id = $1`, reqID).Scan(&dup)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var newBalance float64
		if err = tx.QueryRowContext(ctx, `UPDATE users SET balance = balance - $1::numeric, updated_at = clock_timestamp() WHERE id = $2 RETURNING balance`, billedUSD, buyerID).Scan(&newBalance); err != nil {
			return err
		}
		funded := billedUSD
		if newBalance < 0 {
			funded = math.Max(0, billedUSD+newBalance)
		}
		var sellerNet string
		if err = tx.QueryRowContext(ctx, `
			INSERT INTO berth_marketplace_usage_revenue
				(request_id, api_key_id, buyer_id, seller_id, account_id, group_id, commission_bps, gross_amount, seller_amount, platform_amount, admitted_at, funded_amount, seller_paid_amount)
			VALUES ($1,$2,$3,$4,$5,$6,$7::integer,$8::numeric,
				$8::numeric-trunc($8::numeric*($7::integer)/10000,8),trunc($8::numeric*($7::integer)/10000,8),$9,$10::numeric,
				$10::numeric-trunc($10::numeric*($7::integer)/10000,8))
			RETURNING seller_paid_amount::text`,
			reqID, r.APIKeyID, buyerID, sellerID, r.AccountID, groupID.Int64, usageCommBPS, billedUSD, eventAt, QuantizeUsageBillingAmount(funded)).Scan(&sellerNet); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET balance = balance + $2::numeric, updated_at = clock_timestamp() WHERE id = $1`, sellerID, sellerNet); err != nil {
			return err
		}
		return tx.Commit()
	})
	if txErr != nil {
		log.Printf("[BerthEdge] marketplace order usage debit failed for receipt %s (order=%d): %v", r.ReceiptID, orderID.Int64, txErr)
		return
	}
	if revokeBuyerID > 0 && revokeGroupID > 0 {
		revCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		_, _ = s.RevokeLeasesForUserGroup(revCtx, revokeBuyerID, revokeGroupID)
		cancel()
	}
}
