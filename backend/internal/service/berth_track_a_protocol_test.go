//go:build unit

package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/pkg/antigravity"
	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/stretchr/testify/require"
)

type failingProxyRepoStub struct {
	ProxyRepository
	proxy *Proxy
	err   error
}

func (r *failingProxyRepoStub) GetByID(context.Context, int64) (*Proxy, error) {
	return r.proxy, r.err
}

func TestResolveRequiredProxyURL_FailClosedOnErrorNilOrInactive(t *testing.T) {
	pid := int64(99)

	// 1. Repo error fails closed (never falls back to "").
	_, err := resolveRequiredProxyURL(context.Background(), &failingProxyRepoStub{err: errors.New("db down")}, &pid, nil)
	require.ErrorIs(t, err, cage.ErrProxyUnavailable)

	// 2. Missing proxy (nil, nil) fails closed.
	_, err = resolveRequiredProxyURL(context.Background(), &failingProxyRepoStub{proxy: nil, err: nil}, &pid, nil)
	require.ErrorIs(t, err, cage.ErrProxyUnavailable)

	// 3. Inactive/disabled proxy fails closed.
	_, err = resolveRequiredProxyURL(context.Background(), &failingProxyRepoStub{
		proxy: &Proxy{ID: 99, Protocol: "http", Host: "1.2.3.4", Port: 8080, Status: StatusDisabled},
	}, &pid, nil)
	require.ErrorIs(t, err, cage.ErrProxyUnavailable)

	// 4. Nil repo with positive proxyID fails closed.
	_, err = resolveRequiredProxyURL(context.Background(), nil, &pid, nil)
	require.ErrorIs(t, err, cage.ErrProxyUnavailable)

	// 5. Active proxy succeeds.
	got, err := resolveRequiredProxyURL(context.Background(), &failingProxyRepoStub{
		proxy: &Proxy{ID: 99, Protocol: "http", Host: "1.2.3.4", Port: 8080, Status: StatusActive},
	}, &pid, nil)
	require.NoError(t, err)
	require.Equal(t, "http://1.2.3.4:8080", got)

	// 6. Nil proxyID returns empty (uncaged).
	got, err = resolveRequiredProxyURL(context.Background(), nil, nil, nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestIsOfficialOpenAIAPIKeyAccount(t *testing.T) {
	officialDefault := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	require.True(t, isOfficialOpenAIAPIKeyAccount(officialDefault))

	officialExplicit := &Account{
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Credentials: map[string]any{"base_url": "https://api.openai.com/v1"},
	}
	require.True(t, isOfficialOpenAIAPIKeyAccount(officialExplicit))

	thirdPartyRelay := &Account{
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Credentials: map[string]any{"base_url": "https://relay.example.com/v1"},
	}
	require.False(t, isOfficialOpenAIAPIKeyAccount(thirdPartyRelay))

	oauthAccount := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	require.False(t, isOfficialOpenAIAPIKeyAccount(oauthAccount))
}

func TestAntigravityScopesAndPerAccountPlatformUA(t *testing.T) {
	require.True(t, strings.Contains(antigravity.Scopes, "https://www.googleapis.com/auth/aicode"))

	ctx := antigravity.WithUserAgentPlatform(context.Background(), "MacOS", "arm64")
	ua := antigravity.GetUserAgentForContext(ctx)
	require.Contains(t, ua, "darwin/arm64")
	require.NotContains(t, ua, "windows/amd64")

	linuxUA := antigravity.BuildUserAgentForPlatform("2.23.0", "linux", "x64")
	require.Equal(t, "antigravity/hub/2.23.0 linux/amd64", linuxUA)
}

func TestBuildCodexCommonHeaders_UsesNeutralEnglishDefaultNotZhCN(t *testing.T) {
	headers := buildCodexCommonHeaders("tok", "acct-1", false)
	require.Equal(t, "en-US", headers["oai-language"])
	require.NotEqual(t, "zh-CN", headers["oai-language"])
	require.Equal(t, "codex_cli_rs", headers["originator"])
}

func TestOAuthRefreshAPI_SetRefreshWALRoutesThroughWAL(t *testing.T) {
	account := &Account{
		ID:       501,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Status:   StatusActive,
		Credentials: map[string]any{
			"access_token":  "old-at",
			"refresh_token": "old-rt",
		},
	}
	repo := &refreshAPIAccountRepo{account: account}
	cache := &refreshAPICacheStub{lockResult: true}
	walStore := newMemoryWALStore(88, 1)
	wal := NewBerthOAuthRefreshWAL(walStore, nil)

	executor := &refreshAPIExecutorStub{
		needsRefresh: true,
		credentials:  map[string]any{"access_token": "new-at", "refresh_token": "new-rt"},
	}

	api := NewOAuthRefreshAPI(repo, cache)
	api.SetRefreshWAL(wal)

	res, err := api.RefreshIfNeeded(context.Background(), account, executor, 0)
	require.NoError(t, err)
	require.True(t, res.Refreshed)
	require.Equal(t, "new-rt", walStore.credentials["refresh_token"])
	require.Len(t, walStore.entries, 1)
	require.Equal(t, RefreshJournalStageCommitted, walStore.entries[0].Stage)
}
