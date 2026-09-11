package service

import (
	"context"
	"database/sql"
)

// StewardStore maps accounts and proxies to the user who docked them.
type StewardStore struct {
	db *sql.DB
}

func NewStewardStore(db *sql.DB) *StewardStore {
	if db == nil {
		return nil
	}
	return &StewardStore{db: db}
}

func (s *StewardStore) ClaimAccount(ctx context.Context, accountID, userID int64) error {
	if s == nil || s.db == nil || accountID <= 0 || userID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO account_stewards (account_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (account_id) DO NOTHING
	`, accountID, userID)
	return err
}

func (s *StewardStore) ClaimProxy(ctx context.Context, proxyID, userID int64) error {
	if s == nil || s.db == nil || proxyID <= 0 || userID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO proxy_stewards (proxy_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (proxy_id) DO NOTHING
	`, proxyID, userID)
	return err
}

func (s *StewardStore) OwnsAccount(ctx context.Context, accountID, userID int64) bool {
	if s == nil || s.db == nil || accountID <= 0 || userID <= 0 {
		return false
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `
		SELECT 1 FROM account_stewards WHERE account_id = $1 AND user_id = $2
	`, accountID, userID).Scan(&n)
	return n == 1
}

func (s *StewardStore) OwnsProxy(ctx context.Context, proxyID, userID int64) bool {
	if s == nil || s.db == nil || proxyID <= 0 || userID <= 0 {
		return false
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `
		SELECT 1 FROM proxy_stewards WHERE proxy_id = $1 AND user_id = $2
	`, proxyID, userID).Scan(&n)
	return n == 1
}

func (s *StewardStore) ListAccountIDs(ctx context.Context, userID int64) []int64 {
	return s.listIDs(ctx, `SELECT account_id FROM account_stewards WHERE user_id = $1 ORDER BY account_id`, userID)
}

func (s *StewardStore) ListProxyIDs(ctx context.Context, userID int64) []int64 {
	return s.listIDs(ctx, `SELECT proxy_id FROM proxy_stewards WHERE user_id = $1 ORDER BY proxy_id`, userID)
}

func (s *StewardStore) listIDs(ctx context.Context, query string, userID int64) []int64 {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// AllowedAccountIDs is the personal pool: owned numbers not exclusively rented
// out, plus numbers currently borrowed. Empty means "use the house group pool".
func (s *StewardStore) AllowedAccountIDs(ctx context.Context, userID int64, rentals *RentalStore) map[int64]struct{} {
	owned := s.ListAccountIDs(ctx, userID)
	borrowed := rentals.BorrowedAccountIDs(ctx, userID)
	blocked := rentals.BlockedAccounts(ctx, userID)
	out := map[int64]struct{}{}
	for _, id := range owned {
		if _, taken := blocked[id]; taken {
			continue
		}
		out[id] = struct{}{}
	}
	for _, id := range borrowed {
		out[id] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func bindBerthPref(ctx context.Context, userID int64, rentals *RentalStore, stewards *StewardStore) {
	pref := WorkSessionPrefFromContext(ctx)
	if pref == nil {
		return
	}
	if rentals != nil {
		pref.BlockedAccountIDs = rentals.BlockedAccounts(ctx, userID)
	}
	if stewards != nil {
		pref.AllowedAccountIDs = stewards.AllowedAccountIDs(ctx, userID, rentals)
	}
}

func FilterAccountsForBerth(ctx context.Context, accounts []Account) []Account {
	pref := WorkSessionPrefFromContext(ctx)
	if pref == nil || len(pref.AllowedAccountIDs) == 0 {
		return accounts
	}
	out := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if _, ok := pref.AllowedAccountIDs[account.ID]; ok {
			out = append(out, account)
		}
	}
	return out
}

func berthAllowsAccount(pref *WorkSessionPref, accountID int64) bool {
	if pref == nil || len(pref.AllowedAccountIDs) == 0 {
		return true
	}
	_, ok := pref.AllowedAccountIDs[accountID]
	return ok
}
