package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MarketplaceUsageSnapshot is immutable and private to one admitted request.
// It survives expiry while that request finishes; it must never enter auth caches.
type MarketplaceUsageSnapshot struct {
	GroupID        int64
	AccountID      int64
	SellerID       int64
	CommissionBPS  int
	RateMultiplier float64
	AdmittedAt     time.Time
}

func (s *MarketplaceService) usageSnapshot(ctx context.Context, groupID int64) (*MarketplaceUsageSnapshot, error) {
	var v MarketplaceUsageSnapshot
	err := s.db.QueryRowContext(ctx, `SELECT m.group_id,m.account_id,m.owner_user_id,
 s.usage_commission_bps,g.rate_multiplier,clock_timestamp()
 FROM berth_account_groups m JOIN groups g ON g.id=m.group_id
 CROSS JOIN berth_marketplace_settings s WHERE m.group_id=$1 AND s.id=1`, groupID).
		Scan(&v.GroupID, &v.AccountID, &v.SellerID, &v.CommissionBPS, &v.RateMultiplier, &v.AdmittedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupNotAllowed
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot marketplace pricing: %w", err)
	}
	return &v, nil
}

// RefreshMarketplaceKey returns a fresh copy so asynchronous billing cannot see
// a later WebSocket turn's rates. Unmanaged keys keep their original behavior.
func (s *APIKeyService) RefreshMarketplaceKey(ctx context.Context, key *APIKey) (*APIKey, error) {
	if err := s.CheckMarketplaceAccountKey(ctx, key); err != nil {
		return nil, err
	}
	if s == nil || s.marketplace == nil || key == nil || key.MarketplaceUsage == nil {
		return key, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	snapshot, err := s.marketplace.usageSnapshot(ctx, *key.GroupID)
	if err != nil {
		return nil, err
	}
	copyKey := *key
	copyKey.MarketplaceUsage = snapshot
	if key.Group != nil {
		group := *key.Group
		group.RateMultiplier = snapshot.RateMultiplier
		copyKey.Group = &group
	}
	return &copyKey, nil
}
