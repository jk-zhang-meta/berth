package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
)

var (
	ErrReservedEdgeInternalHost = infraerrors.New(http.StatusBadRequest, "PROXY_HOST_RESERVED", "Proxy host in reserved *.edge.internal namespace can only be created via Landing Node grants")
	ErrProxyManagedInUse        = infraerrors.New(http.StatusConflict, "PROXY_MANAGED_IN_USE", "Proxy is backed by an active landing grant or marketplace rental and cannot be deleted directly")
	ErrAccountRentalActive      = infraerrors.New(http.StatusConflict, "ACCOUNT_RENTAL_ACTIVE", "Account has active marketplace rental orders; terminate them in Marketplace first")
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

// EdgeLandingProxyBinding reports whether proxyID is a materialized Berth
// `edge_landing_grant` proxy and returns its bound edge_node_id (if present).
func (s *MarketplaceService) EdgeLandingProxyBinding(ctx context.Context, proxyID int64) (bool, int64, error) {
	if s == nil || s.db == nil || proxyID <= 0 {
		return false, 0, nil
	}
	var sourceType string
	var edgeNodeID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(source_type, ''), edge_node_id
		FROM proxies
		WHERE id = $1 AND deleted_at IS NULL
	`, proxyID).Scan(&sourceType, &edgeNodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, nil
		}
		return false, 0, err
	}
	if sourceType != ProxySourceTypeEdgeLandingGrant {
		return false, 0, nil
	}
	return true, edgeNodeID.Int64, nil
}

// enforceEdgeLandingProxyTransport keeps virtual `*.edge.internal` landing proxy
// transport fields (`protocol`, `host`, `port`, credentials) managed by Berth so
// renaming or editing quota/status in the Web UI can never corrupt edge routing.
// Returns (isManaged, err). Fails closed if the DB binding check errors.
func (s *adminServiceImpl) enforceEdgeLandingProxyTransport(
	ctx context.Context,
	proxy *Proxy,
	origProtocol, origHost string,
	origPort int,
) (bool, error) {
	if proxy == nil {
		return false, nil
	}
	isManaged := IsReservedEdgeInternalHost(origHost)
	var edgeNodeID int64
	if s != nil && s.marketplace != nil && proxy.ID > 0 {
		bound, nid, err := s.marketplace.EdgeLandingProxyBinding(ctx, proxy.ID)
		if err != nil {
			return false, fmt.Errorf("verify edge landing proxy binding: %w", err)
		}
		if bound {
			isManaged = true
			edgeNodeID = nid
		}
	}
	if !isManaged {
		if IsReservedEdgeInternalHost(proxy.Host) {
			return false, ErrReservedEdgeInternalHost
		}
		return false, nil
	}
	proxy.Protocol = "https"
	if edgeNodeID > 0 {
		proxy.Host = EdgeInternalProxyHost(edgeNodeID)
	} else {
		proxy.Host = origHost
	}
	proxy.Port = 443
	if origPort > 0 && edgeNodeID <= 0 {
		proxy.Port = origPort
	}
	if origProtocol != "" && edgeNodeID <= 0 {
		proxy.Protocol = origProtocol
	}
	proxy.Username = ""
	proxy.Password = ""
	return true, nil
}

// CheckManagedProxyDeleteAllowed blocks deleting proxies still referenced by an
// active/pending landing grant or an active marketplace rental order.
func (s *MarketplaceService) CheckManagedProxyDeleteAllowed(ctx context.Context, proxyID int64) error {
	if s == nil || s.db == nil || proxyID <= 0 {
		return nil
	}
	var hasGrant bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM berth_landing_node_grants
			WHERE proxy_id = $1 AND status IN ('pending', 'active')
		)`, proxyID).Scan(&hasGrant); err != nil {
		return err
	}
	if hasGrant {
		return fmt.Errorf("%w: revoke the landing node grant first", ErrProxyManagedInUse)
	}
	var hasOrder bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM berth_marketplace_orders
			WHERE status = 'active'
			  AND (rental_proxy_id = $1 OR (resource_type = 'proxy' AND resource_id = $1))
		)`, proxyID).Scan(&hasOrder); err != nil {
		return err
	}
	if hasOrder {
		return fmt.Errorf("%w: terminate active rental orders first", ErrProxyManagedInUse)
	}
	return nil
}

// UpdateProxyExitProfile persists ONLY verified exit-profile columns on proxies
// conditioned on the connection identity (protocol/host/port) still matching what
// was probed, preventing slow probes from overwriting concurrent renames or revocations.
func (s *MarketplaceService) UpdateProxyExitProfile(
	ctx context.Context,
	proxy *Proxy,
	expectedProto, expectedHost string,
	expectedPort int,
) (bool, error) {
	if s == nil || s.db == nil || proxy == nil || proxy.ID <= 0 {
		return false, nil
	}
	var utcOffset sql.NullInt64
	if proxy.ExitUTCOffsetSeconds != nil {
		utcOffset = sql.NullInt64{Int64: int64(*proxy.ExitUTCOffsetSeconds), Valid: true}
	}
	var checkedAt sql.NullTime
	if proxy.ExitCheckedAt != nil {
		checkedAt = sql.NullTime{Time: *proxy.ExitCheckedAt, Valid: true}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE proxies
		SET exit_ip = NULLIF($2, ''),
		    exit_country = NULLIF($3, ''),
		    exit_country_code = NULLIF($4, ''),
		    exit_region = NULLIF($5, ''),
		    exit_city = NULLIF($6, ''),
		    exit_timezone = NULLIF($7, ''),
		    exit_utc_offset_seconds = $8,
		    exit_asn = NULLIF($9, ''),
		    exit_isp = NULLIF($10, ''),
		    exit_checked_at = $11,
		    updated_at = NOW()
		WHERE id = $1
		  AND deleted_at IS NULL
		  AND protocol = $12
		  AND host = $13
		  AND port = $14`,
		proxy.ID,
		proxy.ExitIP, proxy.ExitCountry, proxy.ExitCountryCode, proxy.ExitRegion, proxy.ExitCity,
		proxy.ExitTimezone, utcOffset, proxy.ExitASN, proxy.ExitISP, checkedAt,
		expectedProto, expectedHost, expectedPort,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CheckAccountRentalProtection blocks deleting, disabling, or unscheduling an
// account while any marketplace rental order on that account is still active or
// draining in-flight reservations (R-6, Option A).
func (s *MarketplaceService) CheckAccountRentalProtection(ctx context.Context, accountID int64) error {
	if s == nil || s.db == nil || accountID <= 0 {
		return nil
	}
	var active bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM berth_marketplace_orders
			WHERE resource_type = 'account'
			  AND resource_id = $1
			  AND status = 'active'
			  AND (
			    terminating_at IS NOT NULL
			    OR (
			      (expires_at IS NULL OR expires_at > clock_timestamp())
			      AND (quota_limit_usd IS NULL OR quota_used_usd < quota_limit_usd)
			    )
			  )
		)`, accountID).Scan(&active)
	if err != nil {
		return err
	}
	if active {
		return ErrAccountRentalActive
	}
	return nil
}

// PhysicalProxyFamilyCapacity returns the aggregate bound account count and
// authoritative max_accounts limit across the physical root proxy and all of
// its marketplace rental clones (R-7).
func (s *MarketplaceService) PhysicalProxyFamilyCapacity(ctx context.Context, proxyID int64) (familyCount int64, effectiveMaxAccounts int, err error) {
	if s == nil || s.db == nil || proxyID <= 0 {
		return 0, 0, nil
	}
	var rootID int64
	var rootMax int
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(p.source_proxy_id, p.id),
		       COALESCE(root.max_accounts, p.max_accounts, 0)
		FROM proxies p
		LEFT JOIN proxies root ON root.id = COALESCE(p.source_proxy_id, p.id) AND root.deleted_at IS NULL
		WHERE p.id = $1 AND p.deleted_at IS NULL`, proxyID).Scan(&rootID, &rootMax)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM accounts a
		JOIN proxies p ON p.id = a.proxy_id AND p.deleted_at IS NULL
		WHERE a.deleted_at IS NULL
		  AND (p.id = $1 OR p.source_proxy_id = $1)`, rootID).Scan(&familyCount)
	if err != nil {
		return 0, 0, err
	}
	return familyCount, rootMax, nil
}

// ResolvePhysicalProxyCapacity maps a rental proxy clone ID to its physical
// source proxy ID and live concurrency/RPM limits (R-7).
func (s *MarketplaceService) ResolvePhysicalProxyCapacity(ctx context.Context, proxyID int64) (physicalID int64, maxConcurrency, maxRPM int, ok bool, err error) {
	if s == nil || s.db == nil || proxyID <= 0 {
		return proxyID, 0, 0, false, nil
	}
	var srcID sql.NullInt64
	var srcConc, srcRPM sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT p.source_proxy_id, src.max_concurrency, src.max_rpm
		FROM proxies p
		LEFT JOIN proxies src ON src.id = p.source_proxy_id AND src.deleted_at IS NULL
		WHERE p.id = $1 AND p.deleted_at IS NULL`, proxyID).Scan(&srcID, &srcConc, &srcRPM)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return proxyID, 0, 0, false, nil
		}
		return proxyID, 0, 0, false, err
	}
	if !srcID.Valid || srcID.Int64 <= 0 {
		return proxyID, 0, 0, false, nil
	}
	return srcID.Int64, int(srcConc.Int64), int(srcRPM.Int64), true, nil
}

func (s *adminServiceImpl) checkAccountRentalModificationAllowed(ctx context.Context, accountID int64) error {
	if s == nil || s.marketplace == nil || accountID <= 0 {
		return nil
	}
	return s.marketplace.CheckAccountRentalProtection(ctx, accountID)
}

func (s *adminServiceImpl) checkManagedProxyDeletable(ctx context.Context, proxyID int64) error {
	if s == nil || s.marketplace == nil {
		return nil
	}
	return s.marketplace.CheckManagedProxyDeleteAllowed(ctx, proxyID)
}

func (s *adminServiceImpl) persistProxyExitProfile(ctx context.Context, proxy *Proxy, origProto, origHost string, origPort int) error {
	if s != nil && s.marketplace != nil && s.marketplace.db != nil {
		_, err := s.marketplace.UpdateProxyExitProfile(ctx, proxy, origProto, origHost, origPort)
		return err
	}
	return s.proxyRepo.Update(ctx, proxy)
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
