package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jk-zhang-meta/berth/internal/config"
)

// CheckMarketplaceAccountKey revalidates captured key entitlements for each new
// request on a long-lived connection, independently of API-key auth caches and
// whether the rented account uses a rental proxy.
func (s *APIKeyService) CheckMarketplaceAccountKey(ctx context.Context, key *APIKey) error {
	if s == nil || s.marketplace == nil || key == nil || key.GroupID == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	managed, allowed, err := s.marketplace.GroupAccess(ctx, key.UserID, *key.GroupID)
	if err != nil {
		return fmt.Errorf("check resource entitlement: %w", err)
	}
	if managed && (!allowed || (s.cfg != nil && s.cfg.RunMode == config.RunModeSimple)) {
		return ErrGroupNotAllowed
	}
	return nil
}
