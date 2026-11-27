//go:build unit

package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/stretchr/testify/require"
)

func TestDeriveGeoIdentity_NeverHardcodesZhCN(t *testing.T) {
	us := DeriveGeoIdentity("US", "America/New_York")
	require.Equal(t, "America/New_York", us.Timezone)
	require.Equal(t, "en_US.UTF-8", us.Locale)
	require.Equal(t, "en-US,en;q=0.9", us.AcceptLanguage)
	require.Equal(t, "en-US", us.OAILanguage)

	jp := DeriveGeoIdentity("jp", "")
	require.Equal(t, "Asia/Tokyo", jp.Timezone)
	require.Equal(t, "ja_JP.UTF-8", jp.Locale)
	require.Contains(t, jp.AcceptLanguage, "ja-JP")
	require.Equal(t, "ja-JP", jp.OAILanguage)

	unknown := DeriveGeoIdentity("", "")
	require.Equal(t, "UTC", unknown.Timezone)
	require.Equal(t, "en-US", unknown.OAILanguage)
	require.NotContains(t, unknown.AcceptLanguage, "zh-CN")
	require.NotEqual(t, "zh-CN", unknown.OAILanguage)

	// DeriveOAILanguageFromAccount uses proxy exit country/timezone.
	acc := &Account{Proxy: &Proxy{ExitCountryCode: "DE", ExitTimezone: "Europe/Berlin"}}
	oaiLang, acceptLang := DeriveOAILanguageFromAccount(acc)
	require.Equal(t, "de-DE", oaiLang)
	require.Contains(t, acceptLang, "de-DE")
}

func TestCageDeterministicIdentityAndHostnameSanity(t *testing.T) {
	seed, err := GenerateConvergenceSeed()
	require.NoError(t, err)
	require.Len(t, seed, 32)

	claudeDev := DeriveClaudeDeviceID(seed)
	require.Len(t, claudeDev, 64)
	require.Equal(t, claudeDev, DeriveClaudeDeviceID(seed))
	for _, r := range claudeDev {
		require.True(t, (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'), "must be lowercase hex")
	}

	codexID := DeriveCodexInstallationID(seed)
	parsedCodex, err := uuid.Parse(codexID)
	require.NoError(t, err)
	require.Equal(t, uuid.Version(4), parsedCodex.Version())
	require.Equal(t, codexID, DeriveCodexInstallationID(seed))

	xaiID := DeriveXAIClientIdentifier(seed)
	parsedXAI, err := uuid.Parse(xaiID)
	require.NoError(t, err)
	require.Equal(t, uuid.Version(4), parsedXAI.Version())
	require.NotEqual(t, codexID, xaiID)

	for _, osName := range []string{"MacOS", "Windows", "Linux"} {
		alias := DeriveHostnameAlias(seed, osName)
		require.NotEmpty(t, alias)
		lower := strings.ToLower(alias)
		require.NotContains(t, lower, "berth")
		require.NotContains(t, lower, "cage")
		require.NotContains(t, lower, "proxy")
		require.NotContains(t, lower, "sub2api")
	}
}

func TestCheckExitDrift_PoliciesAndIPv4Enforcement(t *testing.T) {
	anchor := &AccountCageExitAnchor{
		ExitIP:          "198.51.100.10",
		ExitCountryCode: "US",
		ExitCity:        "Los Angeles",
		ExitASN:         "AS7922",
	}

	// Same IPv4 matches all policies.
	same := &ProxyExitInfo{IP: "198.51.100.10", CountryCode: "US", City: "Los Angeles", ASN: "AS7922"}
	for _, pol := range []string{CageDriftPolicySameIP, CageDriftPolicySameASNCity, CageDriftPolicySameCountry} {
		drifted, _ := CheckExitDrift(anchor, same, pol)
		require.False(t, drifted, "policy %s should not drift", pol)
	}

	// Different IP in same city+ASN drifts under same_ip, passes under same_asn_city & same_country.
	diffIP := &ProxyExitInfo{IP: "198.51.100.11", CountryCode: "US", City: "Los Angeles", ASN: "AS7922"}
	drifted, reason := CheckExitDrift(anchor, diffIP, CageDriftPolicySameIP)
	require.True(t, drifted)
	require.Contains(t, reason, "exit_ip_drifted")

	drifted, _ = CheckExitDrift(anchor, diffIP, CageDriftPolicySameASNCity)
	require.False(t, drifted)

	// Different city drifts under same_asn_city, passes under same_country.
	diffCity := &ProxyExitInfo{IP: "198.51.100.12", CountryCode: "US", City: "Seattle", ASN: "AS7922"}
	drifted, reason = CheckExitDrift(anchor, diffCity, CageDriftPolicySameASNCity)
	require.True(t, drifted)
	require.Contains(t, reason, "exit_city_drifted")

	drifted, _ = CheckExitDrift(anchor, diffCity, CageDriftPolicySameCountry)
	require.False(t, drifted)

	// Different country drifts under same_country.
	diffCountry := &ProxyExitInfo{IP: "203.0.113.5", CountryCode: "JP", City: "Tokyo", ASN: "AS2516"}
	drifted, reason = CheckExitDrift(anchor, diffCountry, CageDriftPolicySameCountry)
	require.True(t, drifted)
	require.Contains(t, reason, "exit_country_drifted")

	// IPv6 exit observation ALWAYS fails closed.
	ipv6Obs := &ProxyExitInfo{IP: "2606:4700:4700::1111", CountryCode: "US", City: "Los Angeles", ASN: "AS7922"}
	drifted, reason = CheckExitDrift(anchor, ipv6Obs, CageDriftPolicySameCountry)
	require.True(t, drifted)
	require.Contains(t, reason, "non_ipv4_exit_observed")
}

func TestBerthAccountCageService_ProvisionAnchorAndQuarantineOnDrift(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	pool := cage.NewCageTransportPool()
	svc := NewBerthAccountCageService(db, pool)
	now := time.Now().UTC()

	// 1. Provision requires proxy_id > 0.
	_, err = svc.ProvisionCage(context.Background(), ProvisionCageInput{AccountID: 10, Platform: PlatformAnthropic, ProxyID: 0})
	require.ErrorIs(t, err, ErrCageProxyRequired)

	// 2. Provision succeeds with 32-byte seed & derived fields.
	mock.ExpectQuery(`INSERT INTO account_cages`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "gate_state", "gate_epoch", "credential_version", "created_at", "updated_at"}).
			AddRow(int64(77), "closed", int64(1), int64(1), now, now))

	provisioned, err := svc.ProvisionCage(context.Background(), ProvisionCageInput{
		AccountID:       10,
		Platform:        PlatformAnthropic,
		ProxyID:         5,
		ExitCountryCode: "JP",
		ExitTimezone:    "Asia/Tokyo",
	})
	require.NoError(t, err)
	require.Equal(t, int64(77), provisioned.ID)
	require.Equal(t, "Asia/Tokyo", provisioned.Timezone)
	require.Equal(t, "ja-JP", provisioned.OAILanguage)
	require.Len(t, provisioned.ConvergenceSeed, 32)
	require.Len(t, provisioned.ClaudeDeviceID, 64)

	// 3. First-use exit anchor locks cage and opens live gate.
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO account_cage_exit_anchors`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "anchored_at"}).AddRow(int64(900), now))
	mock.ExpectExec(`UPDATE account_cages`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	anchor, err := svc.AnchorFirstUseExit(context.Background(), 77, 5, &ProxyExitInfo{
		IP:          "198.51.100.20",
		CountryCode: "JP",
		City:        "Tokyo",
		Timezone:    "Asia/Tokyo",
		ASN:         "AS2516",
		ISP:         "KDDI",
	}, "ipwho.is")
	require.NoError(t, err)
	require.Equal(t, "198.51.100.20", anchor.ExitIP)
	require.Equal(t, cage.GateOpen, svc.LiveGate(77).Snapshot().State)

	// 4. Drift check detects IP jump -> quarantines DB + bumps live gate epoch!
	cageCols := []string{
		"id", "account_id", "proxy_id",
		"landing_binding_mode", "egress_policy", "allow_ipv6", "allow_udp", "dns_mode", "drift_policy",
		"timezone", "locale", "accept_language", "oai_language",
		"tls_oauth_profile_id", "tls_inference_profile_id",
		"client_os", "client_os_version", "client_arch", "client_runtime", "client_runtime_version",
		"client_app_version", "user_agent_oauth", "user_agent_inference", "originator", "hostname_alias",
		"convergence_seed", "claude_device_id", "codex_installation_id", "xai_client_identifier", "extra_identity",
		"gate_state", "gate_epoch", "lease_expires_at", "last_verified_at", "last_error",
		"credential_version", "locked_at", "created_at", "updated_at",
	}
	mock.ExpectQuery(`SELECT id, account_id, proxy_id`).
		WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows(cageCols).AddRow(
			int64(77), int64(10), int64(5),
			"exclusive_1to1", "strict_proxy_only", false, false, "proxy_doh_ipv4_only", "same_ip",
			"Asia/Tokyo", "ja_JP.UTF-8", "ja-JP,ja;q=0.9", "ja-JP",
			nil, nil,
			"MacOS", "15.3.1", "arm64", "node", "v24.11.0",
			"2.1.220", "axios/1.15.2", "claude-cli/2.1.220 (external, cli)", "", "MacBook-Pro-a1b2",
			provisioned.ConvergenceSeed, provisioned.ClaudeDeviceID, provisioned.CodexInstallationID, provisioned.XAIClientIdentifier, []byte(`{}`),
			"open", int64(1), now.Add(90*time.Second), now, "",
			int64(1), now, now, now,
		))

	anchorCols := []string{
		"id", "cage_id", "anchor_version", "is_active", "proxy_id",
		"host", "exit_country_code", "exit_region", "exit_city", "exit_timezone",
		"exit_asn", "exit_isp", "probe_source", "reason", "anchored_by", "anchored_at",
	}
	mock.ExpectQuery(`SELECT id, cage_id, anchor_version`).
		WithArgs(int64(77)).
		WillReturnRows(sqlmock.NewRows(anchorCols).AddRow(
			int64(900), int64(77), 1, true, int64(5),
			"198.51.100.20", "JP", "Tokyo", "Tokyo", "Asia/Tokyo",
			"AS2516", "KDDI", "ipwho.is", "first_use", "system", now,
		))

	mock.ExpectQuery(`UPDATE account_cages\s+SET gate_state = 'quarantined'`).
		WithArgs(int64(77), "exit_ip_drifted:198.51.100.20->203.0.113.99").
		WillReturnRows(sqlmock.NewRows([]string{"gate_epoch"}).AddRow(int64(2)))

	prevEpoch := svc.LiveGate(77).Snapshot().Epoch
	drifted, reason, err := svc.VerifyExitAndCheckDrift(context.Background(), 77, &ProxyExitInfo{
		IP:          "203.0.113.99",
		CountryCode: "JP",
		City:        "Tokyo",
		ASN:         "AS2516",
	})
	require.NoError(t, err)
	require.True(t, drifted)
	require.Equal(t, "exit_ip_drifted:198.51.100.20->203.0.113.99", reason)
	require.Equal(t, cage.GateQuarantined, svc.LiveGate(77).Snapshot().State)
	require.Equal(t, prevEpoch+1, svc.LiveGate(77).Snapshot().Epoch)
	require.NoError(t, mock.ExpectationsWereMet())
}
