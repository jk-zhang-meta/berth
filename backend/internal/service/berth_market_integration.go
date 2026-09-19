package service

import "context"

func (s *APIKeyService) SetMarketplace(market *MarketplaceService) { s.marketplace = market }

func (s *StewardStore) SetMarketplace(market *MarketplaceService) { s.marketplace = market }

func (s *StewardStore) HasVerifiedProxyExit(ctx context.Context, proxyID int64) bool {
	if s == nil || s.db == nil || proxyID <= 0 {
		return false
	}
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM proxies
		WHERE id=$1 AND deleted_at IS NULL AND status='active'
		  AND NULLIF(exit_ip,'') IS NOT NULL
		  AND NULLIF(exit_timezone,'') IS NOT NULL
		  AND exit_checked_at IS NOT NULL
	)`, proxyID).Scan(&ok)
	return err == nil && ok
}

func (s *StewardStore) CanUseProxy(ctx context.Context, proxyID, userID int64) bool {
	if s == nil || !s.HasVerifiedProxyExit(ctx, proxyID) {
		return false
	}
	if s.OwnsProxy(ctx, proxyID, userID) {
		return true
	}
	if s.marketplace == nil {
		return false
	}
	allowed, err := s.marketplace.CanUseRentalProxy(ctx, userID, proxyID)
	return err == nil && allowed
}
