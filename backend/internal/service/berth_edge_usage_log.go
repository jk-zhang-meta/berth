package service

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
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
