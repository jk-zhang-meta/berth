//go:build integration

package service

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarketplaceSQLCommissionSnapshotAndSettlement(t *testing.T) {
	for _, tc := range []struct {
		name             string
		bps              int
		half             bool
		net, fee, refund int64
	}{
		{"zero", 0, false, 1000, 0, 0}, {"all", 10000, false, 0, 1000, 0}, {"prorata", 2500, true, 375, 125, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := marketplaceTestDB(t)
			ctx := context.Background()
			s := NewMarketplaceService(db)
			settings, err := s.GetCommissionSettings(ctx)
			require.NoError(t, err)
			require.Zero(t, settings.RentCommissionBPS)
			require.Zero(t, settings.UsageCommissionBPS)
			_, err = s.UpdateCommissionSettings(ctx, MarketplaceCommissionSettings{RentCommissionBPS: tc.bps, UsageCommissionBPS: 1234})
			require.NoError(t, err)
			listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
			require.NoError(t, err)
			order, err := s.Checkout(ctx, 2, listing.ID, "commission")
			require.NoError(t, err)
			require.Equal(t, tc.bps, order.RentCommissionBPS)
			_, err = s.UpdateCommissionSettings(ctx, MarketplaceCommissionSettings{RentCommissionBPS: 9999})
			require.NoError(t, err)
			replay, err := s.Checkout(ctx, 2, listing.ID, "commission")
			require.NoError(t, err)
			require.Equal(t, tc.bps, replay.RentCommissionBPS)
			if tc.half {
				_, err = db.Exec("UPDATE berth_marketplace_orders SET starts_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1", order.ID)
			} else {
				_, err = db.Exec("UPDATE berth_marketplace_orders SET starts_at=clock_timestamp()-interval '3 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", order.ID)
			}
			require.NoError(t, err)
			settled, err := s.Terminate(ctx, 2, false, order.ID)
			require.NoError(t, err)
			require.Equal(t, tc.net, settled.SellerEarnedCents)
			require.Equal(t, tc.fee, settled.PlatformCommissionCents)
			require.Equal(t, tc.refund, settled.RefundCents)
			again, err := s.Terminate(ctx, 2, false, order.ID)
			require.NoError(t, err)
			require.Equal(t, settled, again)
			var sum, fee, net int64
			require.NoError(t, db.QueryRow("SELECT sum(amount_cents),COALESCE(sum(amount_cents) FILTER(WHERE kind='platform_commission'),0),COALESCE(sum(amount_cents) FILTER(WHERE kind='payout'),0) FROM berth_marketplace_ledger WHERE order_id=$1", order.ID).Scan(&sum, &fee, &net))
			require.Zero(t, sum)
			require.Equal(t, tc.fee, fee)
			require.Equal(t, tc.net, net)
			var sellerBalance, buyerBalance int64
			require.NoError(t, db.QueryRow("SELECT (balance*100)::bigint FROM users WHERE id=1").Scan(&sellerBalance))
			require.Equal(t, int64(10000)+tc.net, sellerBalance)
			require.NoError(t, db.QueryRow("SELECT (balance*100)::bigint FROM users WHERE id=2").Scan(&buyerBalance))
			require.Equal(t, int64(9000)+tc.refund, buyerBalance)
		})
	}
}

func TestMarketplaceSQLCommissionSettingsAndDedicatedUsagePrice(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	for _, v := range []MarketplaceCommissionSettings{{RentCommissionBPS: -1}, {UsageCommissionBPS: 10001}} {
		_, err := s.UpdateCommissionSettings(ctx, v)
		require.ErrorIs(t, err, ErrMarketplaceInvalid)
	}
	_, err := db.Exec("INSERT INTO groups(id,name,platform,rate_multiplier) VALUES(100,'original pool','openai',7); INSERT INTO account_groups(account_id,group_id) VALUES(11,100)")
	require.NoError(t, err)
	for _, rate := range []float64{0, -1, 0.000001, 1001, math.NaN(), math.Inf(1)} {
		offer := marketplaceOffer("account", 11)
		offer.UsageRateMultiplier = &rate
		_, err := s.Publish(ctx, 1, false, offer)
		require.ErrorIs(t, err, ErrMarketplaceInvalid)
	}
	rate := 2.5
	offer := marketplaceOffer("account", 11)
	offer.UsageRateMultiplier = &rate
	listing, err := s.Publish(ctx, 1, false, offer)
	require.NoError(t, err)
	require.Equal(t, 2.5, listing.UsageRateMultiplier)
	var privateRate, originalRate float64
	require.NoError(t, db.QueryRow("SELECT g.rate_multiplier FROM berth_account_groups m JOIN groups g ON g.id=m.group_id WHERE m.account_id=11").Scan(&privateRate))
	require.Equal(t, 2.5, privateRate)
	require.NoError(t, db.QueryRow("SELECT rate_multiplier FROM groups WHERE id=100").Scan(&originalRate))
	require.Equal(t, 7.0, originalRate)
	_, err = s.SetListingStatus(ctx, 4, true, listing.ID, "paused")
	require.NoError(t, err)
	rate = 3
	_, err = s.Publish(ctx, 1, false, offer)
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	require.NoError(t, db.QueryRow("SELECT g.rate_multiplier FROM berth_account_groups m JOIN groups g ON g.id=m.group_id WHERE m.account_id=11").Scan(&privateRate))
	require.Equal(t, 2.5, privateRate, "failed publication must roll back price update")
}
