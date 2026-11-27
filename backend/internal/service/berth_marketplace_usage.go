package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// DefaultMarketplaceQuotaReserveUSD is the conservative per-request pre-dispatch
// quota reservation floor for prepaid quota/hybrid marketplace rentals (clamped
// to remaining headroom so small remaining balances can still finish one turn).
const DefaultMarketplaceQuotaReserveUSD = 0.25

// MarketplaceUsageSnapshot is immutable and private to one admitted request.
// It survives expiry while that request finishes; it must never enter auth caches.
type MarketplaceUsageSnapshot struct {
	GroupID        int64
	AccountID      int64
	SellerID       int64
	OrderID        int64  // 0 for owner/admin self-use; >0 for buyer rental order
	RentalMode     string // "", "duration", "quota", "hybrid"
	OperationID    string // optional pre-dispatch quota reservation operation_id
	CommissionBPS  int
	RateMultiplier float64
	AdmittedAt     time.Time

	billingEnqueued *atomic.Bool
}

// MarkBillingEnqueued records that usage billing has taken ownership of settling
// this snapshot's pre-dispatch quota reservation.
func (m *MarketplaceUsageSnapshot) MarkBillingEnqueued() {
	if m != nil && m.billingEnqueued != nil {
		m.billingEnqueued.Store(true)
	}
}

// IsBillingEnqueued reports whether usage billing took ownership of the reservation.
func (m *MarketplaceUsageSnapshot) IsBillingEnqueued() bool {
	return m != nil && m.billingEnqueued != nil && m.billingEnqueued.Load()
}

func (s *MarketplaceService) usageSnapshot(ctx context.Context, groupID int64) (*MarketplaceUsageSnapshot, error) {
	return s.usageSnapshotForUser(ctx, 0, groupID)
}

func (s *MarketplaceService) usageSnapshotForUser(ctx context.Context, userID, groupID int64) (*MarketplaceUsageSnapshot, error) {
	var v MarketplaceUsageSnapshot
	err := s.db.QueryRowContext(ctx, `SELECT m.group_id,m.account_id,m.owner_user_id,
 s.usage_commission_bps,COALESCE(o.usage_rate_multiplier,g.rate_multiplier),clock_timestamp(),
 COALESCE(o.id,0),COALESCE(o.rental_mode,'')
 FROM berth_account_groups m JOIN groups g ON g.id=m.group_id
 CROSS JOIN berth_marketplace_settings s
 LEFT JOIN LATERAL (
   SELECT ord.id,ord.rental_mode,ord.usage_rate_multiplier
   FROM berth_marketplace_orders ord
   WHERE ord.group_id=m.group_id
     AND ord.buyer_id=$2
     AND ord.buyer_id<>m.owner_user_id
     AND ord.status='active'
     AND ord.terminating_at IS NULL
     AND ord.starts_at<=clock_timestamp()
     AND (ord.expires_at IS NULL OR ord.expires_at>clock_timestamp())
     AND (ord.quota_limit_usd IS NULL OR ord.quota_used_usd<ord.quota_limit_usd)
   ORDER BY CASE WHEN ord.rental_mode IN ('quota','hybrid') THEN 0 ELSE 1 END,
            ord.expires_at ASC NULLS LAST,
            ord.id ASC
   LIMIT 1
 ) o ON true
 WHERE m.group_id=$1 AND s.id=1`, groupID, userID).
		Scan(&v.GroupID, &v.AccountID, &v.SellerID, &v.CommissionBPS, &v.RateMultiplier, &v.AdmittedAt, &v.OrderID, &v.RentalMode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGroupNotAllowed
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot marketplace pricing: %w", err)
	}
	return &v, nil
}

// ReserveMarketplaceQuota atomically reserves a conservative pre-dispatch quota
// slice for prepaid quota/hybrid marketplace rental buyers (R-1). Call the
// returned release function when the request/turn exits; it releases the
// reservation immediately if usage billing did not take ownership.
func (s *APIKeyService) ReserveMarketplaceQuota(ctx context.Context, key *APIKey) (func(), error) {
	noop := func() {}
	if s == nil || s.marketplace == nil || key == nil || key.MarketplaceUsage == nil {
		return noop, nil
	}
	m := key.MarketplaceUsage
	buyerID := key.UserID
	if buyerID <= 0 && key.User != nil {
		buyerID = key.User.ID
	}
	if m.OrderID <= 0 || buyerID <= 0 || buyerID == m.SellerID {
		return noop, nil
	}
	if m.RentalMode != MarketplaceRentalModeQuota && m.RentalMode != MarketplaceRentalModeHybrid {
		return noop, nil
	}
	opID := "gw-" + uuid.NewString()
	reserveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := s.marketplace.ReserveQuotaForDispatch(
		reserveCtx,
		m.OrderID,
		buyerID,
		opID,
		DefaultMarketplaceQuotaReserveUSD,
		MarketplaceQuotaReservationDefaultTTL,
	); err != nil {
		return noop, err
	}
	m.OperationID = opID
	m.billingEnqueued = &atomic.Bool{}
	var released atomic.Bool
	return func() {
		if !released.CompareAndSwap(false, true) {
			return
		}
		if m.IsBillingEnqueued() {
			return
		}
		relCtx, relCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer relCancel()
		_ = s.marketplace.ReleaseQuotaReservation(relCtx, opID)
	}, nil
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
	snapshot, err := s.marketplace.usageSnapshotForUser(ctx, key.UserID, *key.GroupID)
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
