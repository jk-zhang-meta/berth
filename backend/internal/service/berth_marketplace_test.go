package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMarketplacePublishValidation(t *testing.T) {
	valid := MarketplacePublishInput{ResourceType: "account", ResourceID: 1, Title: "Offer", DurationHours: 1, PriceCents: 1, Capacity: 1}
	require.NoError(t, validateMarketplacePublish(&valid))
	cases := []MarketplacePublishInput{valid, valid, valid, valid, valid, valid}
	cases[0].ResourceType = "users"
	cases[1].DurationHours = 8761
	cases[2].PriceCents = 0
	cases[3].PriceCents = 100000001
	cases[4].Capacity = 1001
	cases[5].Title = " \x00 "
	for _, v := range cases {
		require.ErrorIs(t, validateMarketplacePublish(&v), ErrMarketplaceInvalid)
	}
}

func TestMarketplaceSettlementExactCents(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name              string
		price             int64
		duration, elapsed time.Duration
		earned            int64
	}{
		{"before", 101, time.Hour, -time.Second, 0}, {"start", 101, time.Hour, 0, 0},
		{"half cent floors", 101, time.Hour, 30 * time.Minute, 50}, {"end", 101, time.Hour, time.Hour, 101},
		{"late", 101, time.Hour, 2 * time.Hour, 101}, {"max price and duration", 100000000, 8760 * time.Hour, 4380 * time.Hour, 50000000},
		{"one microsecond before end", 100000000, 8760 * time.Hour, 8760*time.Hour - time.Microsecond, 99999999},
	} {
		t.Run(tt.name, func(t *testing.T) {
			earned, refund := marketplaceSettlement(tt.price, start, start.Add(tt.duration), start.Add(tt.elapsed))
			require.Equal(t, tt.earned, earned)
			require.Equal(t, tt.price-earned, refund)
		})
	}
}
