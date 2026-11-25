package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type StewardStore struct {
	db          *sql.DB
	marketplace *MarketplaceService
}

func NewStewardStore(db *sql.DB) *StewardStore {
	if db == nil {
		return nil
	}
	return &StewardStore{db: db}
}

type OwnerLabel struct {
	UserID int64
	Label  string
}

func (s *StewardStore) ClaimAccount(ctx context.Context, accountID, userID int64) error {
	if s == nil || s.db == nil || accountID <= 0 || userID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO account_stewards (account_id, user_id) VALUES ($1, $2)
		ON CONFLICT (account_id) DO NOTHING
	`, accountID, userID)
	if err == nil && s.marketplace != nil {
		_, err = s.marketplace.EnsureAccountGroup(ctx, accountID, userID)
	}
	return err
}

func (s *StewardStore) ClaimProxy(ctx context.Context, proxyID, userID int64) error {
	if s == nil || s.db == nil || proxyID <= 0 || userID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO proxy_stewards (proxy_id, user_id) VALUES ($1, $2)
		ON CONFLICT (proxy_id) DO NOTHING
	`, proxyID, userID)
	return err
}

func (s *StewardStore) OwnsAccount(ctx context.Context, accountID, userID int64) bool {
	return s.owns(ctx, `SELECT 1 FROM account_stewards WHERE account_id = $1 AND user_id = $2`, accountID, userID)
}

func (s *StewardStore) OwnsProxy(ctx context.Context, proxyID, userID int64) bool {
	return s.owns(ctx, `SELECT 1 FROM proxy_stewards WHERE proxy_id = $1 AND user_id = $2`, proxyID, userID)
}

func (s *StewardStore) ListAccountIDs(ctx context.Context, userID int64) []int64 {
	return s.listIDs(ctx, `SELECT account_id FROM account_stewards WHERE user_id = $1 ORDER BY account_id`, userID)
}

func (s *StewardStore) ListProxyIDs(ctx context.Context, userID int64) []int64 {
	return s.listIDs(ctx, `SELECT proxy_id FROM proxy_stewards WHERE user_id = $1 ORDER BY proxy_id`, userID)
}

type RentalProxyInfo struct {
	ProxyID   int64
	OrderID   int64
	ExpiresAt *time.Time
}

// ListActiveRentalProxies returns active rented proxy clones for the given buyer.
func (s *StewardStore) ListActiveRentalProxies(ctx context.Context, userID int64) []RentalProxyInfo {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.rental_proxy_id, o.id, o.expires_at
		FROM berth_marketplace_orders o
		JOIN proxies p ON p.id = o.rental_proxy_id
		WHERE o.buyer_id = $1
		  AND o.resource_type = 'proxy'
		  AND o.rental_proxy_id IS NOT NULL
		  AND o.status = 'active'
		  AND o.starts_at <= clock_timestamp()
		  AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		  AND p.deleted_at IS NULL
		  AND p.status = 'active'
		  AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp())
		ORDER BY o.rental_proxy_id
	`, userID)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []RentalProxyInfo
	for rows.Next() {
		var item RentalProxyInfo
		var expiresAt sql.NullTime
		if err := rows.Scan(&item.ProxyID, &item.OrderID, &expiresAt); err == nil {
			if expiresAt.Valid {
				t := expiresAt.Time
				item.ExpiresAt = &t
			}
			out = append(out, item)
		}
	}
	return out
}

func (s *StewardStore) LabelsForAccounts(ctx context.Context, ids []int64) map[int64]OwnerLabel {
	return s.labels(ctx, `SELECT s.account_id, u.id, COALESCE(NULLIF(u.email, ''), NULLIF(u.username, ''), '#' || u.id::text)
		FROM account_stewards s JOIN users u ON u.id = s.user_id
		WHERE s.account_id IN (%s)`, ids)
}

func (s *StewardStore) LabelsForProxies(ctx context.Context, ids []int64) map[int64]OwnerLabel {
	return s.labels(ctx, `SELECT s.proxy_id, u.id, COALESCE(NULLIF(u.email, ''), NULLIF(u.username, ''), '#' || u.id::text)
		FROM proxy_stewards s JOIN users u ON u.id = s.user_id
		WHERE s.proxy_id IN (%s)`, ids)
}

type AccountTodayLatency struct {
	FirstTokenMs sql.NullInt64
	DurationMs   sql.NullInt64
}

func (s *StewardStore) TodayLatencies(ctx context.Context, ids []int64) map[int64]AccountTodayLatency {
	out := map[int64]AccountTodayLatency{}
	if s == nil || s.db == nil || len(ids) == 0 {
		return out
	}
	placeholders, args := idPlaceholders(ids)
	if len(args) == 0 {
		return out
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT account_id, ROUND(AVG(first_token_ms))::bigint, ROUND(AVG(duration_ms))::bigint
		FROM usage_logs
		WHERE account_id IN (`+placeholders+`)
		  AND created_at >= date_trunc('day', now())
		GROUP BY account_id
	`, args...)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		var latency AccountTodayLatency
		if err := rows.Scan(&id, &latency.FirstTokenMs, &latency.DurationMs); err == nil {
			out[id] = latency
		}
	}
	return out
}

func (s *StewardStore) owns(ctx context.Context, query string, objectID, userID int64) bool {
	if s == nil || s.db == nil || objectID <= 0 || userID <= 0 {
		return false
	}
	var n int
	err := s.db.QueryRowContext(ctx, query, objectID, userID).Scan(&n)
	return err == nil
}

func (s *StewardStore) listIDs(ctx context.Context, query string, userID int64) []int64 {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *StewardStore) labels(ctx context.Context, queryTemplate string, ids []int64) map[int64]OwnerLabel {
	out := map[int64]OwnerLabel{}
	if s == nil || s.db == nil || len(ids) == 0 {
		return out
	}
	placeholders, args := idPlaceholders(ids)
	if len(args) == 0 {
		return out
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(queryTemplate, placeholders), args...)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, userID int64
		var label string
		if err := rows.Scan(&id, &userID, &label); err == nil {
			out[id] = OwnerLabel{UserID: userID, Label: label}
		}
	}
	return out
}

func idPlaceholders(ids []int64) (string, []any) {
	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	seen := map[int64]struct{}{}
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)+1))
		args = append(args, id)
	}
	return strings.Join(placeholders, ","), args
}
