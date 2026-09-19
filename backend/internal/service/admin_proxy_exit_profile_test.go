//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestApplyVerifiedProxyExitProfileRequiresIPAndIanaTimezone(t *testing.T) {
	checkedAt := time.Date(2026, time.July, 1, 12, 0, 0, 0, time.UTC)

	proxy := &Proxy{}
	info := &ProxyExitInfo{IP: "8.8.8.8", Country: "United States", CountryCode: "US", Region: "New York", City: "New York", Timezone: "America/New_York", ASN: "AS15169", ISP: "Google"}
	require.NoError(t, applyVerifiedProxyExitProfile(proxy, info, checkedAt))
	require.True(t, proxy.HasVerifiedExitProfile())
	require.Equal(t, "8.8.8.8", proxy.ExitIP)
	require.Equal(t, "America/New_York", proxy.ExitTimezone)
	require.NotNil(t, proxy.ExitUTCOffsetSeconds)
	require.Equal(t, -4*60*60, *proxy.ExitUTCOffsetSeconds)
	require.Equal(t, checkedAt, *proxy.ExitCheckedAt)

	require.Error(t, applyVerifiedProxyExitProfile(&Proxy{}, &ProxyExitInfo{IP: "not-an-ip", Timezone: "UTC"}, checkedAt))
	require.Error(t, applyVerifiedProxyExitProfile(&Proxy{}, &ProxyExitInfo{IP: "127.0.0.1", Timezone: "UTC"}, checkedAt))
	require.Error(t, applyVerifiedProxyExitProfile(&Proxy{}, &ProxyExitInfo{IP: "10.0.0.8", Timezone: "UTC"}, checkedAt))
	require.Error(t, applyVerifiedProxyExitProfile(&Proxy{}, &ProxyExitInfo{IP: "1.1.1.1"}, checkedAt))
	require.Error(t, applyVerifiedProxyExitProfile(&Proxy{}, &ProxyExitInfo{IP: "1.1.1.1", Timezone: "Not/AZone"}, checkedAt))
}

type recordingProxyExitProber struct {
	url string
}

func (p *recordingProxyExitProber) ProbeProxy(_ context.Context, proxyURL string) (*ProxyExitInfo, int64, error) {
	p.url = proxyURL
	return &ProxyExitInfo{IP: "8.8.8.8", Timezone: "America/Chicago"}, 12, nil
}

func TestProbeVerifiedProxyExitUsesRawConnectionURLBeforeProxyHasID(t *testing.T) {
	check := func(context.Context, int64) (bool, bool, error) {
		return false, false, errors.New("rental checker must not be consulted during verification")
	}
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{proxy: check, account: check})
	prober := &recordingProxyExitProber{}
	svc := &adminServiceImpl{proxyProber: prober}
	proxy := &Proxy{Protocol: "http", Host: "proxy.example", Port: 8080, Username: "user", Password: "pass"}

	_, _, _, err := svc.probeVerifiedProxyExit(context.Background(), proxy)
	require.NoError(t, err)
	require.Equal(t, "http://user:pass@proxy.example:8080", prober.url)
}

type verifiedBindingProxyRepo struct {
	proxyRepoStub
	proxy *Proxy
	err   error
}

func (r *verifiedBindingProxyRepo) GetByID(context.Context, int64) (*Proxy, error) {
	return r.proxy, r.err
}

func freshVerifiedBindingProxyRepo(proxyID int64) *verifiedBindingProxyRepo {
	checkedAt := time.Now().UTC()
	return &verifiedBindingProxyRepo{proxy: &Proxy{
		ID:            proxyID,
		ExitIP:        "8.8.8.8",
		ExitTimezone:  "America/Chicago",
		ExitCheckedAt: &checkedAt,
	}}
}

func TestValidateVerifiedProxyBindingRequiresPersistedExitProfile(t *testing.T) {
	proxyID := int64(42)
	repo := &verifiedBindingProxyRepo{proxy: &Proxy{ID: proxyID}}
	svc := &adminServiceImpl{proxyRepo: repo}

	require.Error(t, svc.validateVerifiedProxyBinding(context.Background(), &proxyID))

	checkedAt := time.Now().UTC()
	repo.proxy.ExitIP = "8.8.8.8"
	repo.proxy.ExitTimezone = "America/Chicago"
	repo.proxy.ExitCheckedAt = &checkedAt
	require.NoError(t, svc.validateVerifiedProxyBinding(context.Background(), &proxyID))

	staleCheckedAt := time.Now().UTC().Add(-verifiedProxyExitProfileMaxAge - time.Minute)
	repo.proxy.ExitCheckedAt = &staleCheckedAt
	require.Error(t, svc.validateVerifiedProxyBinding(context.Background(), &proxyID))

	zero := int64(0)
	require.NoError(t, svc.validateVerifiedProxyBinding(context.Background(), &zero))
	require.NoError(t, svc.validateVerifiedProxyBinding(context.Background(), nil))
}

func TestValidateVerifiedProxyBindingEnforcesAccountCapacity(t *testing.T) {
	proxyID := int64(42)
	repo := freshVerifiedBindingProxyRepo(proxyID)
	repo.proxy.MaxAccounts = 3
	repo.accountCount = 2
	svc := &adminServiceImpl{proxyRepo: repo}

	require.NoError(t, svc.validateVerifiedProxyBindingCapacity(context.Background(), &proxyID, 1))
	err := svc.validateVerifiedProxyBindingCapacity(context.Background(), &proxyID, 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proxy account capacity exceeded")

	repo.proxy.MaxAccounts = 0
	require.NoError(t, svc.validateVerifiedProxyBindingCapacity(context.Background(), &proxyID, 100))
}
