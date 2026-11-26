package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
