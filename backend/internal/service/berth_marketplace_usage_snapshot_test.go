//go:build integration

package service

import (
	"context"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceUsageSnapshotIsRequestLocalAndRefreshes(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	market := NewMarketplaceService(db)
	rate := 2.5
	offer := marketplaceOffer("account", 11)
	offer.UsageRateMultiplier = &rate
	listing, err := market.Publish(ctx, 1, false, offer)
	require.NoError(t, err)
	rental, err := market.Checkout(ctx, 2, listing.ID, "usage-snapshot")
	require.NoError(t, err)
	_, err = market.UpdateCommissionSettings(ctx, MarketplaceCommissionSettings{UsageCommissionBPS: 1250})
	require.NoError(t, err)
	cache := &berthMarketAccessCache{entry: &APIKeyAuthCacheEntry{Snapshot: &APIKeyAuthSnapshot{
		Version: apiKeyAuthSnapshotVersion, APIKeyID: 21, UserID: 2, GroupID: rental.GroupID, Status: StatusActive,
		User:  APIKeyAuthUserSnapshot{ID: 2, Role: RoleUser, Status: StatusActive},
		Group: &APIKeyAuthGroupSnapshot{ID: *rental.GroupID, Platform: PlatformOpenAI, Status: StatusActive, IsExclusive: true, SubscriptionType: SubscriptionTypeStandard, RateMultiplier: 99},
	}}}
	svc := NewAPIKeyService(nil, nil, nil, nil, nil, cache, &config.Config{APIKeyAuth: config.APIKeyAuthCacheConfig{L2TTLSeconds: 60}})
	svc.SetMarketplace(market)
	first, err := svc.GetByKey(ctx, "same-cached-key")
	require.NoError(t, err)
	require.NotNil(t, first.MarketplaceUsage)
	require.Equal(t, 1250, first.MarketplaceUsage.CommissionBPS)
	require.Equal(t, 2.5, first.MarketplaceUsage.RateMultiplier)
	require.Equal(t, 2.5, first.Group.RateMultiplier)
	require.Equal(t, int64(11), first.MarketplaceUsage.AccountID)
	require.Equal(t, int64(1), first.MarketplaceUsage.SellerID)
	original := *first.MarketplaceUsage
	rate = 4
	_, err = market.Publish(ctx, 1, false, offer)
	require.NoError(t, err)
	_, err = market.UpdateCommissionSettings(ctx, MarketplaceCommissionSettings{UsageCommissionBPS: 5000})
	require.NoError(t, err)
	second, err := svc.GetByKey(ctx, "same-cached-key")
	require.NoError(t, err)
	require.Equal(t, 5000, second.MarketplaceUsage.CommissionBPS)
	require.Equal(t, 4.0, second.Group.RateMultiplier)
	require.Equal(t, original, *first.MarketplaceUsage)
	require.Equal(t, 2.5, first.Group.RateMultiplier)
	require.Equal(t, 99.0, cache.entry.Snapshot.Group.RateMultiplier)
	require.Empty(t, cache.entry.Snapshot.User.AllowedGroups)
	refreshed, err := svc.RefreshMarketplaceKey(ctx, first)
	require.NoError(t, err)
	require.NotSame(t, first, refreshed)
	require.NotSame(t, first.MarketplaceUsage, refreshed.MarketplaceUsage)
	require.Equal(t, 5000, refreshed.MarketplaceUsage.CommissionBPS)
	require.Equal(t, 4.0, refreshed.Group.RateMultiplier)
	require.Equal(t, original, *first.MarketplaceUsage)
	require.Equal(t, 2.5, first.Group.RateMultiplier)
	_, err = market.Terminate(ctx, 2, false, rental.ID)
	require.NoError(t, err)
	_, err = svc.RefreshMarketplaceKey(ctx, first)
	require.ErrorIs(t, err, ErrGroupNotAllowed)
	require.Equal(t, original, *first.MarketplaceUsage, "an admitted request retains its original billing terms after lease termination")
}

func TestMarketplaceUsageInvalidBillingContextCannotApply(t *testing.T) {
	for _, name := range []string{"group", "account", "subscription", "repository"} {
		t.Run(name, func(t *testing.T) {
			groupID := int64(4)
			p := &postUsageBillingParams{APIKey: &APIKey{GroupID: &groupID, MarketplaceUsage: &MarketplaceUsageSnapshot{GroupID: 4, AccountID: 11, SellerID: 1}}, Account: &Account{ID: 11}}
			var repo UsageBillingRepository = &berthUsageMustNotApply{}
			switch name {
			case "group":
				groupID = 5
			case "account":
				p.Account.ID = 12
			case "subscription":
				p.IsSubscriptionBill = true
			case "repository":
				repo = nil
			}
			applied, err := applyUsageBilling(context.Background(), "invalid", nil, p, &billingDeps{}, repo)
			require.Error(t, err)
			require.False(t, applied)
		})
	}
}

type berthUsageMustNotApply struct{ UsageBillingRepository }

func (*berthUsageMustNotApply) Apply(context.Context, *UsageBillingCommand) (*UsageBillingApplyResult, error) {
	panic("invalid marketplace billing must not debit")
}
