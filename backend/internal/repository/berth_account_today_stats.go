package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/usagestats"
	"github.com/lib/pq"
)

func isEdgeGrantTelemetrySchemaUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		// 42P01 = undefined_table, 42703 = undefined_column (pre-migration or minimal test DB)
		return pqErr.Code == "42P01" || pqErr.Code == "42703"
	}
	return false
}

// mergeEdgeGrantWindowStats adds unlinked Berth Edge landing receipts (usage_log_id IS NULL or
// orphaned usage_log_id) into an account's window stats without double-counting rows that already
// exist in usage_logs.
func (r *usageLogRepository) mergeEdgeGrantWindowStats(ctx context.Context, accountID int64, startTime time.Time, stats *usagestats.AccountStats) {
	if r == nil || r.sql == nil || stats == nil || accountID <= 0 {
		return
	}
	query := `
		SELECT
			COALESCE(SUM(GREATEST(g.request_count, 1)), 0) AS requests,
			COALESCE(SUM(g.input_tokens + g.output_tokens + g.cache_creation_tokens + g.cache_read_tokens), 0) AS tokens,
			COALESCE(SUM(COALESCE(g.account_stats_cost, g.total_cost)), 0) AS cost,
			COALESCE(SUM(g.total_cost), 0) AS standard_cost,
			COALESCE(SUM(g.actual_cost), 0) AS user_cost
		FROM berth_landing_node_grant_usage g
		WHERE g.account_id = $1
		  AND g.created_at >= $2
		  AND COALESCE(g.status_code, 200) > 0
		  AND COALESCE(g.status_code, 200) < 400
		  AND (g.usage_log_id IS NULL OR NOT EXISTS (SELECT 1 FROM usage_logs ul WHERE ul.id = g.usage_log_id))
	`
	var edge usagestats.AccountStats
	if err := scanSingleRow(
		ctx,
		r.sql,
		query,
		[]any{accountID, startTime},
		&edge.Requests,
		&edge.Tokens,
		&edge.Cost,
		&edge.StandardCost,
		&edge.UserCost,
	); err != nil {
		if isEdgeGrantTelemetrySchemaUnavailable(err) {
			return
		}
		return
	}
	stats.Requests += edge.Requests
	stats.Tokens += edge.Tokens
	stats.Cost += edge.Cost
	stats.StandardCost += edge.StandardCost
	stats.UserCost += edge.UserCost
}

// mergeEdgeGrantWindowStatsBatch batch-merges unlinked Berth Edge landing receipts into the
// per-account window stats map without double-counting rows already present in usage_logs.
func (r *usageLogRepository) mergeEdgeGrantWindowStatsBatch(ctx context.Context, accountIDs []int64, startTime time.Time, result map[int64]*usagestats.AccountStats) {
	if r == nil || r.sql == nil || len(accountIDs) == 0 || result == nil {
		return
	}
	query := `
		SELECT
			g.account_id,
			COALESCE(SUM(GREATEST(g.request_count, 1)), 0) AS requests,
			COALESCE(SUM(g.input_tokens + g.output_tokens + g.cache_creation_tokens + g.cache_read_tokens), 0) AS tokens,
			COALESCE(SUM(COALESCE(g.account_stats_cost, g.total_cost)), 0) AS cost,
			COALESCE(SUM(g.total_cost), 0) AS standard_cost,
			COALESCE(SUM(g.actual_cost), 0) AS user_cost
		FROM berth_landing_node_grant_usage g
		WHERE g.account_id = ANY($1)
		  AND g.created_at >= $2
		  AND COALESCE(g.status_code, 200) > 0
		  AND COALESCE(g.status_code, 200) < 400
		  AND (g.usage_log_id IS NULL OR NOT EXISTS (SELECT 1 FROM usage_logs ul WHERE ul.id = g.usage_log_id))
		GROUP BY g.account_id
	`
	rows, err := r.sql.QueryContext(ctx, query, pq.Array(accountIDs), startTime)
	if err != nil {
		if isEdgeGrantTelemetrySchemaUnavailable(err) {
			return
		}
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var accountID int64
		var edge usagestats.AccountStats
		if err := rows.Scan(
			&accountID,
			&edge.Requests,
			&edge.Tokens,
			&edge.Cost,
			&edge.StandardCost,
			&edge.UserCost,
		); err != nil {
			return
		}
		cur := result[accountID]
		if cur == nil {
			cur = &usagestats.AccountStats{}
			result[accountID] = cur
		}
		cur.Requests += edge.Requests
		cur.Tokens += edge.Tokens
		cur.Cost += edge.Cost
		cur.StandardCost += edge.StandardCost
		cur.UserCost += edge.UserCost
	}
}
