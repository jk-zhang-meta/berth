package service

import (
	"context"
	"time"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/lib/pq"
)

func (s *SchedulerSnapshotService) SetMarketplace(m *MarketplaceService) { s.marketplace = m }
func (s *GatewayService) SetMarketplace(m *MarketplaceService)           { s.marketplace = m }

func (s *GatewayService) filterMarketplaceDiscovery(ctx context.Context, groupID *int64, accounts []Account) []Account {
	if groupID != nil || s.marketplace == nil {
		return accounts
	}
	ids := make([]int64, len(accounts))
	for i := range accounts {
		ids[i] = accounts[i].ID
	}
	allowed, err := s.marketplace.publicAccountIDs(ctx, ids, s.cfg != nil && s.cfg.RunMode == config.RunModeSimple)
	if err != nil {
		return nil
	}
	filtered := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if allowed[account.ID] {
			filtered = append(filtered, account)
		}
	}
	return filtered
}

// Read ownership from the database even on a hot Redis snapshot. Old snapshots
// and newly claimed resources must not grant access to the legacy global pool.
func (s *MarketplaceService) publicAccountIDs(ctx context.Context, ids []int64, includeGrouped bool) (map[int64]bool, error) {
	allowed := make(map[int64]bool, len(ids))
	if len(ids) == 0 {
		return allowed, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT a.id FROM accounts a WHERE a.id=ANY($1) AND a.deleted_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM account_stewards st JOIN users u ON u.id=st.user_id WHERE st.account_id=a.id AND u.role<>'admin')
 AND ($2 OR NOT EXISTS(SELECT 1 FROM account_groups ag LEFT JOIN berth_account_groups bg ON bg.group_id=ag.group_id WHERE ag.account_id=a.id AND bg.group_id IS NULL))`, pq.Array(ids), includeGrouped)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		allowed[id] = true
	}
	return allowed, rows.Err()
}

func (s *SchedulerSnapshotService) filterMarketplacePublicAccounts(ctx context.Context, accounts []Account, groupID *int64) ([]Account, error) {
	if s.marketplace == nil || (!s.isRunModeSimple() && groupID != nil && *groupID > 0) {
		return accounts, nil
	}
	ids := make([]int64, len(accounts))
	for i := range accounts {
		ids[i] = accounts[i].ID
	}
	allowed, err := s.marketplace.publicAccountIDs(ctx, ids, s.isRunModeSimple())
	if err != nil {
		return nil, err
	}
	filtered := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if allowed[account.ID] {
			filtered = append(filtered, account)
		}
	}
	return filtered, nil
}

func (s *GatewayService) isAccountInGroup(ctx context.Context, account *Account, groupID *int64) bool {
	if account == nil {
		return false
	}
	if groupID == nil && s.marketplace != nil {
		allowed, err := s.marketplace.publicAccountIDs(ctx, []int64{account.ID}, s.cfg != nil && s.cfg.RunMode == config.RunModeSimple)
		return err == nil && allowed[account.ID]
	}
	if groupID == nil {
		return len(account.AccountGroups) == 0
	}
	for _, ag := range account.AccountGroups {
		if ag.GroupID == *groupID {
			return true
		}
	}
	return false
}
