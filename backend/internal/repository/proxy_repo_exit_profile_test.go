package repository

import (
	"testing"
	"time"

	dbent "github.com/jk-zhang-meta/berth/ent"
	"github.com/stretchr/testify/require"
)

func TestProxyEntityToServicePreservesVerifiedExitProfile(t *testing.T) {
	exitIP := "8.8.8.8"
	country := "United States"
	countryCode := "US"
	region := "Texas"
	city := "Houston"
	timezone := "America/Chicago"
	offsetSeconds := -5 * 60 * 60
	asn := "AS15169 Google LLC"
	isp := "Google LLC"
	checkedAt := time.Date(2026, time.September, 17, 20, 0, 0, 0, time.UTC)

	got := proxyEntityToService(&dbent.Proxy{
		ID:                   42,
		ExitIP:               &exitIP,
		ExitCountry:          &country,
		ExitCountryCode:      &countryCode,
		ExitRegion:           &region,
		ExitCity:             &city,
		ExitTimezone:         &timezone,
		ExitUtcOffsetSeconds: &offsetSeconds,
		ExitAsn:              &asn,
		ExitIsp:              &isp,
		ExitCheckedAt:        &checkedAt,
	})

	require.NotNil(t, got)
	require.Equal(t, exitIP, got.ExitIP)
	require.Equal(t, country, got.ExitCountry)
	require.Equal(t, countryCode, got.ExitCountryCode)
	require.Equal(t, region, got.ExitRegion)
	require.Equal(t, city, got.ExitCity)
	require.Equal(t, timezone, got.ExitTimezone)
	require.NotNil(t, got.ExitUTCOffsetSeconds)
	require.Equal(t, offsetSeconds, *got.ExitUTCOffsetSeconds)
	require.Equal(t, asn, got.ExitASN)
	require.Equal(t, isp, got.ExitISP)
	require.NotNil(t, got.ExitCheckedAt)
	require.True(t, got.ExitCheckedAt.Equal(checkedAt))
	require.True(t, got.HasVerifiedExitProfile())
}
