package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeEdgeAccountLookup struct {
	accounts map[int64]*Account
}

func (f *fakeEdgeAccountLookup) GetAccount(_ context.Context, id int64) (*Account, error) {
	acc, ok := f.accounts[id]
	if !ok {
		return nil, ErrEdgeCredentialForbidden
	}
	return acc, nil
}

func TestResolveUpstreamCredentialForLease_AllPlatformsAndAuthChecks(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	zoneStore := NewMemoryZoneStore(true)
	zones := NewBerthZoneServiceWithStore(zoneStore)
	zList, err := zones.ListZones(ctx)
	require.NoError(t, err)
	overseasID := zList[2].ID

	landing, err := zones.CreateNode(ctx, EdgeNode{
		Name:            "hyonix-la",
		ZoneID:          overseasID,
		Roles:           []string{EdgeRoleIngressRelay, EdgeRoleTransit, EdgeRoleLanding},
		PublicAddr:      "http://5.6.7.8:19443",
		TunnelAddr:      "5.6.7.8:19443",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Los_Angeles",
		ExitLocale:      "en_US.UTF-8",
		Status:          EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	otherNode, err := zones.CreateNode(ctx, EdgeNode{
		Name:       "hyonix-sg",
		ZoneID:     overseasID,
		Roles:      []string{EdgeRoleLanding},
		PublicAddr: "http://9.9.9.9:19443",
		Status:     EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	var revSeq int64 = 1
	grantStore := NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grants := NewBerthLandingGrantServiceWithStore(grantStore)
	grant, err := grants.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:         landing.ID,
		GranteeUserID:  7,
		MaxBytes:       1024 * 1024 * 1024,
		MaxAccounts:    10,
		MaxRPM:         60,
		MaxConcurrency: 10,
	})
	require.NoError(t, err)

	leaseStore := NewMemoryEdgeLeaseStore(&revSeq)
	leases := NewBerthEdgeLeaseServiceWithStore(leaseStore, zones, grants, pub, priv, "test-k1")

	parentID := int64(101)
	lookup := &fakeEdgeAccountLookup{
		accounts: map[int64]*Account{
			101: {
				ID:       101,
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Status:   StatusActive,
				Credentials: map[string]any{
					"access_token": "oa-secret-token",
				},
				Extra: map[string]any{
					"chatgpt_account_id": "acct-chatgpt-42",
				},
			},
			102: {
				ID:              102,
				Platform:        PlatformOpenAI,
				Type:            AccountTypeOAuth,
				Status:          StatusActive,
				ParentAccountID: &parentID, // Shadow account delegating to 101
			},
			103: {
				ID:       103,
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Status:   StatusActive,
				Credentials: map[string]any{
					"access_token": "anth-oauth-token",
				},
			},
			104: {
				ID:       104,
				Platform: PlatformAntigravity,
				Type:     AccountTypeAPIKey,
				Status:   StatusActive,
				Credentials: map[string]any{
					"api_key": "goog-key-123",
				},
			},
			105: {
				ID:       105,
				Platform: PlatformGrok,
				Type:     AccountTypeAPIKey,
				Status:   StatusActive,
				Credentials: map[string]any{
					"api_key": "xai-key-999",
				},
			},
		},
	}

	mint := func(platform string, accID int64) *MintedLeaseResponse {
		res, mErr := leases.MintLease(ctx, MintLeaseInput{
			UserID:            7,
			Platform:          platform,
			AccountID:         accID,
			GrantID:           grant.ID,
			LandingNodeID:     landing.ID,
			PreferredZoneSlug: "overseas",
		})
		require.NoError(t, mErr)
		return res
	}

	now := time.Now()

	// 1. OpenAI OAuth shadow account resolves parent's access_token + Chatgpt-Account-Id + codex base URL.
	lOpenAI := mint(PlatformOpenAI, 102)
	cred, err := ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lOpenAI.LeaseID, 102, now)
	require.NoError(t, err)
	require.Equal(t, "Bearer oa-secret-token", cred.Headers["Authorization"])
	require.Equal(t, "acct-chatgpt-42", cred.Headers["Chatgpt-Account-Id"])
	require.Equal(t, "https://chatgpt.com/backend-api/codex", cred.BaseURL)
	require.LessOrEqual(t, cred.ExpiresAtUnix, now.Add(maxEdgeCredentialTTL).Unix())

	// 2. Wrong landing node MUST be rejected (403 forbidden).
	_, err = ResolveUpstreamCredentialForLease(ctx, leases, lookup, otherNode.ID, lOpenAI.LeaseID, 102, now)
	require.ErrorIs(t, err, ErrEdgeCredentialForbidden)

	// 3. Wrong account ID MUST be rejected (403 forbidden).
	_, err = ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lOpenAI.LeaseID, 103, now)
	require.ErrorIs(t, err, ErrEdgeCredentialForbidden)

	// 4. Revoked lease MUST be rejected.
	_, err = leases.RevokeLease(ctx, 7, false, lOpenAI.LeaseID)
	require.NoError(t, err)
	_, err = ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lOpenAI.LeaseID, 102, now)
	require.ErrorIs(t, err, ErrEdgeLeaseRevoked)

	// 5. Anthropic OAuth resolves Bearer token + oauth beta header.
	lAnth := mint(PlatformAnthropic, 103)
	credAnth, err := ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lAnth.LeaseID, 103, now)
	require.NoError(t, err)
	require.Equal(t, "Bearer anth-oauth-token", credAnth.Headers["Authorization"])
	require.Equal(t, "oauth-2025-04-20", credAnth.Headers["anthropic-beta"])

	// 6. Antigravity / Gemini API key resolves x-goog-api-key.
	lAGY := mint(PlatformAntigravity, 104)
	credAGY, err := ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lAGY.LeaseID, 104, now)
	require.NoError(t, err)
	require.Equal(t, "goog-key-123", credAGY.Headers["x-goog-api-key"])

	// 7. Grok / xAI API key resolves Authorization Bearer + https://api.x.ai.
	lGrok := mint(PlatformGrok, 105)
	credGrok, err := ResolveUpstreamCredentialForLease(ctx, leases, lookup, landing.ID, lGrok.LeaseID, 105, now)
	require.NoError(t, err)
	require.Equal(t, "Bearer xai-key-999", credGrok.Headers["Authorization"])
	require.Equal(t, "https://api.x.ai", credGrok.BaseURL)
}

type fakeEdgeCageLookup struct {
	cages map[int64]*AccountCage
}

func (f *fakeEdgeCageLookup) GetActiveCageByAccountID(_ context.Context, accountID int64) (*AccountCage, error) {
	c, ok := f.cages[accountID]
	if !ok {
		return nil, ErrCageNotFound
	}
	return c, nil
}

type fakeEdgeTokenRefresher struct {
	token string
	exp   *time.Time
	err   error
	calls int
}

func (f *fakeEdgeTokenRefresher) EnsureFreshAccessToken(_ context.Context, _ *Account) (string, *time.Time, error) {
	f.calls++
	return f.token, f.exp, f.err
}

type revocableEdgeAuthStore struct {
	BerthEdgeLeaseStore
	mu      sync.Mutex
	allowed map[int64]int64
}

func (s *revocableEdgeAuthStore) VerifyAccountEdgeLandingAuthorization(_ context.Context, accountID, nodeID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pinned, ok := s.allowed[accountID]; ok && pinned == nodeID {
		return nil
	}
	return ErrEdgeCredentialForbidden
}

func TestResolveUpstreamCredential_ExtremeHardeningAndFailClosed(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	zoneStore := NewMemoryZoneStore(true)
	zones := NewBerthZoneServiceWithStore(zoneStore)
	zList, err := zones.ListZones(ctx)
	require.NoError(t, err)
	overseasID := zList[2].ID

	landing, err := zones.CreateNode(ctx, EdgeNode{
		Name:            "houston-host",
		ZoneID:          overseasID,
		Roles:           []string{EdgeRoleLanding},
		PublicAddr:      "http://68.77.201.111:19443",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Chicago",
		ExitLocale:      "en_US.UTF-8",
		Status:          EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	var revSeq int64 = 1
	grantStore := NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grants := NewBerthLandingGrantServiceWithStore(grantStore)
	grant, err := grants.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:         landing.ID,
		GranteeUserID:  7,
		MaxBytes:       1024 * 1024 * 1024,
		MaxAccounts:    10,
		MaxRPM:         60,
		MaxConcurrency: 10,
	})
	require.NoError(t, err)

	baseStore := NewMemoryEdgeLeaseStore(&revSeq)
	authStore := &revocableEdgeAuthStore{
		BerthEdgeLeaseStore: baseStore,
		allowed: map[int64]int64{
			201: landing.ID,
			202: landing.ID,
			203: landing.ID,
			204: landing.ID,
		},
	}
	leases := NewBerthEdgeLeaseServiceWithStore(authStore, zones, grants, pub, priv, "test-k2")
	now := time.Now()
	futureExp := now.Add(10 * time.Minute)
	shortExp := now.Add(75 * time.Second)
	pastExp := now.Add(-5 * time.Minute)

	disabledParentID := int64(200)
	lookup := &fakeEdgeAccountLookup{
		accounts: map[int64]*Account{
			200: {
				ID:       200,
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Status:   StatusDisabled,
				Credentials: map[string]any{
					"access_token": "disabled-parent-tok",
				},
			},
			201: {
				ID:       201,
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Status:   StatusActive,
				Credentials: map[string]any{
					"access_token":               "old-oa-tok",
					"chatgpt_account_id":         "cred-chatgpt-id-99",
					"chatgpt_account_is_fedramp": true,
					"expires_at":                 shortExp.Format(time.RFC3339),
				},
			},
			202: {
				ID:       202,
				Platform: PlatformAntigravity,
				Type:     AccountTypeOAuth,
				Status:   StatusActive,
				Credentials: map[string]any{
					"access_token": "agy-ultra-tok",
					"plan_type":    "Ultra",
					"project_id":   "aicode-consumers",
					"expires_at":   futureExp.Format(time.RFC3339),
				},
			},
			203: {
				ID:              203,
				Platform:        PlatformOpenAI,
				Type:            AccountTypeOAuth,
				Status:          StatusActive,
				ParentAccountID: &disabledParentID,
			},
			204: {
				ID:       204,
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Status:   StatusActive,
				Credentials: map[string]any{
					"access_token": "expired-anth-tok",
					"expires_at":   pastExp.Format(time.RFC3339),
				},
				Extra: map[string]any{
					"account_uuid": "acct-uuid-1234",
				},
			},
		},
	}
	cages := &fakeEdgeCageLookup{
		cages: map[int64]*AccountCage{
			201: {
				ID:                  11,
				AccountID:           201,
				ClientOS:            "Windows",
				ClientOSVersion:     "10.0.22631",
				ClientArch:          "x64",
				ClientAppVersion:    "0.114.0", // Stale; must be floored to >= 0.144.0!
				Originator:          "codex-tui",
				AcceptLanguage:      "en-US,en;q=0.9",
				OAILanguage:         "en-US",
				CodexInstallationID: "6878c0a3-a067-423e-9c9f-aebd007eb6a6",
			},
			202: {
				ID:               12,
				AccountID:        202,
				ClientOS:         "MacOS",
				ClientArch:       "arm64",
				ClientAppVersion: "2.23.0",
				AcceptLanguage:   "en-US,en;q=0.9",
			},
		},
	}

	mint := func(platform string, accID int64) *MintedLeaseResponse {
		res, mErr := leases.MintLease(ctx, MintLeaseInput{
			UserID:            7,
			Platform:          platform,
			AccountID:         accID,
			GrantID:           grant.ID,
			LandingNodeID:     landing.ID,
			PreferredZoneSlug: "overseas",
		})
		require.NoError(t, mErr)
		return res
	}

	// 1. Codex reads Chatgpt-Account-Id from credentials + FedRAMP + refreshes token + caps TTL at tokenExp-30s + floors stale version.
	refresher := &fakeEdgeTokenRefresher{token: "fresh-oa-tok", exp: &shortExp}
	lOA := mint(PlatformOpenAI, 201)
	credOA, err := ResolveUpstreamCredentialForLeaseWithDeps(ctx, leases, lookup, cages, refresher, landing.ID, lOA.LeaseID, 201, now)
	require.NoError(t, err)
	require.Equal(t, 1, refresher.calls)
	require.Equal(t, "Bearer fresh-oa-tok", credOA.Headers["Authorization"])
	require.Equal(t, "cred-chatgpt-id-99", credOA.Headers["Chatgpt-Account-Id"])
	require.Equal(t, "true", credOA.Headers["x-openai-fedramp"])
	require.Equal(t, shortExp.Add(-edgeCredentialTokenExpirySkew).Unix(), credOA.ExpiresAtUnix)
	require.NotNil(t, credOA.CageIdentity)
	require.Equal(t, "codex_cli_rs", credOA.CageIdentity.Originator)
	require.True(t, CompareVersions(credOA.CageIdentity.ClientAppVersion, codexUpstreamMinVersion) >= 0)
	require.Equal(t, "6878c0a3-a067-423e-9c9f-aebd007eb6a6", credOA.CageIdentity.CodexInstallationID)

	// 2. Antigravity Ultra routes to daily-cloudcode-pa.googleapis.com and delivers project_id.
	lAGY := mint(PlatformAntigravity, 202)
	credAGY, err := ResolveUpstreamCredentialForLeaseWithDeps(ctx, leases, lookup, cages, nil, landing.ID, lAGY.LeaseID, 202, now)
	require.NoError(t, err)
	require.Equal(t, "https://daily-cloudcode-pa.googleapis.com", credAGY.BaseURL)
	require.NotNil(t, credAGY.CageIdentity)
	require.Equal(t, "aicode-consumers", credAGY.CageIdentity.AntigravityProjectID)
	require.Equal(t, "Ultra", credAGY.CageIdentity.AntigravityPlanType)

	// 3. Shadow account with disabled parent MUST fail closed (403).
	lShadow := mint(PlatformOpenAI, 203)
	_, err = ResolveUpstreamCredentialForLeaseWithDeps(ctx, leases, lookup, cages, nil, landing.ID, lShadow.LeaseID, 203, now)
	require.ErrorIs(t, err, ErrEdgeCredentialForbidden)

	// 4. Expired upstream OAuth token MUST fail closed (never deliver expired token).
	lExpired := mint(PlatformAnthropic, 204)
	_, err = ResolveUpstreamCredentialForLeaseWithDeps(ctx, leases, lookup, cages, nil, landing.ID, lExpired.LeaseID, 204, now)
	require.ErrorIs(t, err, ErrEdgeCredentialUnavailable)

	// 5. Mid-queue OAuth task claim re-verification: revoking binding drops task with ZERO secret bytes released.
	leases.EnqueueOAuthTask(EdgeOAuthTask{
		NodeID:     landing.ID,
		AccountID:  201,
		Kind:       "oauth_exchange",
		TargetURL:  "https://auth.openai.com/oauth/token",
		Method:     "POST",
		Headers:    map[string]string{"Authorization": "Bearer super-secret"},
		BodyBase64: "c2VjcmV0",
	})
	authStore.mu.Lock()
	delete(authStore.allowed, 201)
	authStore.mu.Unlock()
	claimed := leases.ListPendingOAuthTasksForNode(ctx, landing.ID)
	require.Empty(t, claimed)
}
