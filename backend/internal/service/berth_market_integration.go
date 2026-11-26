package service

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

func (s *APIKeyService) SetMarketplace(market *MarketplaceService) { s.marketplace = market }

func (s *StewardStore) SetMarketplace(market *MarketplaceService) { s.marketplace = market }

type LandingGrantProxyInfo struct {
	ProxyID   int64
	GrantID   int64
	ExpiresAt *time.Time
}

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

// HasActiveLandingGrantProxy reports whether proxyID is a materialized active
// Admin Landing Node grant projection belonging to userID.
func (s *StewardStore) HasActiveLandingGrantProxy(ctx context.Context, proxyID, userID int64) bool {
	if s == nil || s.db == nil || proxyID <= 0 || userID <= 0 {
		return false
	}
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1
		FROM berth_landing_node_grants g
		JOIN proxies p ON p.id = g.proxy_id
		WHERE g.proxy_id = $1
		  AND g.grantee_user_id = $2
		  AND g.status = 'active'
		  AND (g.expires_at IS NULL OR g.expires_at > clock_timestamp())
		  AND p.deleted_at IS NULL
		  AND p.status = 'active'
		  AND p.source_type = $3
	)`, proxyID, userID, ProxySourceTypeEdgeLandingGrant).Scan(&ok)
	return err == nil && ok
}

// ListActiveLandingGrantProxies returns active materialized landing-grant proxy
// projections usable by userID for binding accounts (with raw exit IP redacted by callers).
func (s *StewardStore) ListActiveLandingGrantProxies(ctx context.Context, userID int64) []LandingGrantProxyInfo {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.proxy_id, g.id, g.expires_at
		FROM berth_landing_node_grants g
		JOIN proxies p ON p.id = g.proxy_id
		WHERE g.grantee_user_id = $1
		  AND g.proxy_id IS NOT NULL
		  AND g.status = 'active'
		  AND (g.expires_at IS NULL OR g.expires_at > clock_timestamp())
		  AND p.deleted_at IS NULL
		  AND p.status = 'active'
		  AND p.source_type = $2
		ORDER BY g.proxy_id
	`, userID, ProxySourceTypeEdgeLandingGrant)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []LandingGrantProxyInfo
	for rows.Next() {
		var item LandingGrantProxyInfo
		var expiresAt sql.NullTime
		if err := rows.Scan(&item.ProxyID, &item.GrantID, &expiresAt); err == nil {
			if expiresAt.Valid {
				t := expiresAt.Time
				item.ExpiresAt = &t
			}
			out = append(out, item)
		}
	}
	return out
}

// IsActiveEdgeLandingGrantProxy reports whether proxyID backs an active Admin
// Landing Node grant (which is a virtual *.edge.internal projection and cannot
// be directly HTTP-probed from Central once >15m have elapsed since approval).
func (s *MarketplaceService) IsActiveEdgeLandingGrantProxy(ctx context.Context, proxyID int64) (bool, error) {
	if s == nil || s.db == nil || proxyID <= 0 {
		return false, nil
	}
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1
		FROM berth_landing_node_grants g
		JOIN proxies p ON p.id = g.proxy_id
		WHERE g.proxy_id = $1
		  AND g.status = 'active'
		  AND (g.expires_at IS NULL OR g.expires_at > clock_timestamp())
		  AND p.deleted_at IS NULL
		  AND p.status = 'active'
		  AND p.source_type = $2
	)`, proxyID, ProxySourceTypeEdgeLandingGrant).Scan(&ok)
	return ok, err
}

func (s *adminServiceImpl) isActiveEdgeLandingGrantProxy(ctx context.Context, proxy *Proxy) bool {
	if proxy == nil || proxy.ID <= 0 {
		return false
	}
	if s != nil && s.marketplace != nil {
		ok, err := s.marketplace.IsActiveEdgeLandingGrantProxy(ctx, proxy.ID)
		return err == nil && ok
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(proxy.Host)), ".edge.internal")
}

func (s *StewardStore) CanUseProxy(ctx context.Context, proxyID, userID int64) bool {
	if s == nil || !s.HasVerifiedProxyExit(ctx, proxyID) {
		return false
	}
	if s.OwnsProxy(ctx, proxyID, userID) {
		return true
	}
	if s.HasActiveLandingGrantProxy(ctx, proxyID, userID) {
		return true
	}
	if s.marketplace == nil {
		return false
	}
	allowed, err := s.marketplace.CanUseRentalProxy(ctx, userID, proxyID)
	return err == nil && allowed
}
