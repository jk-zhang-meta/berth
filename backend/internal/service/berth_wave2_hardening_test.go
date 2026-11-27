package service

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/util/urlvalidator"
	"github.com/stretchr/testify/require"
)

func TestWave2_StrictStickyCohortCheck(t *testing.T) {
	tokyoAcc := &Account{
		ID: 1,
		Proxy: &Proxy{
			ID:              10,
			ExitCountryCode: "JP",
			ExitTimezone:    "Asia/Tokyo",
		},
	}
	usAcc := &Account{
		ID: 2,
		Proxy: &Proxy{
			ID:              11,
			ExitCountryCode: "US",
			ExitTimezone:    "America/Chicago",
		},
	}
	unverifiedAcc := &Account{ID: 3}

	strictCtx := WithCageCohortRequest(context.Background(), &CageCohortRequest{
		Target:     CageCohort{Timezone: "America/Chicago", CountryCode: "US"},
		StrictMode: true,
	})
	require.True(t, stickyAccountMatchesCohort(strictCtx, usAcc))
	require.False(t, stickyAccountMatchesCohort(strictCtx, tokyoAcc))
	require.False(t, stickyAccountMatchesCohort(strictCtx, unverifiedAcc))

	// Explicit handover allows cross-cohort selection.
	handoverCtx := WithCageCohortRequest(context.Background(), &CageCohortRequest{
		Target:        CageCohort{Timezone: "America/Chicago", CountryCode: "US"},
		StrictMode:    true,
		AllowHandover: true,
	})
	require.True(t, stickyAccountMatchesCohort(handoverCtx, tokyoAcc))

	// Non-strict request without cohort target allows any account.
	require.True(t, stickyAccountMatchesCohort(context.Background(), tokyoAcc))
}

func TestWave2_OAuthWAL_StalePendingRecoveryAndRetainedRefreshToken(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	// 1. Abandoned pending row older than refreshWALStalePendingTimeout transitions to unknown_quarantined.
	store := &wave2MockWALStore{
		cageID:  77,
		credVer: 3,
		latest: &OAuthRefreshJournalEntry{
			ID:                    901,
			AccountID:             24,
			CageID:                77,
			Platform:              PlatformOpenAI,
			Stage:                 RefreshJournalStagePending,
			BaseCredentialVersion: 3,
			CreatedAt:             now.Add(-5 * time.Minute),
			UpdatedAt:             now.Add(-5 * time.Minute),
		},
	}
	wal := NewBerthOAuthRefreshWAL(store, nil)
	wal.nowFn = func() time.Time { return now }

	called := false
	_, err := wal.ExecuteRefresh(context.Background(), WALRefreshRequest{
		AccountID:    24,
		Platform:     PlatformOpenAI,
		ClientID:     "cid",
		RefreshToken: "rt-abandoned",
	}, func(context.Context, *RefreshTraceTracker) (map[string]any, error) {
		called = true
		return nil, nil
	})
	require.ErrorIs(t, err, ErrRefreshOutcomeUnknownQuarantined)
	require.False(t, called)
	require.Equal(t, int64(901), store.quarantinedJournalID)

	// 2. Non-rotating retained refresh_token (e.g. Gemini) is NOT blocked on subsequent refresh cycle
	// when latest committed row recorded NewTokenFingerprint == tokenFP and NewCredentialVersion == current credVer.
	rt := "gemini-static-rt"
	fp := ComputeRefreshTokenFingerprint("gem-cid", rt)
	v4 := int64(4)
	storeRetained := &wave2MockWALStore{
		cageID:  88,
		credVer: 4,
		latest: &OAuthRefreshJournalEntry{
			ID:                    902,
			AccountID:             25,
			CageID:                88,
			Platform:              PlatformGemini,
			TokenFingerprint:      fp,
			NewTokenFingerprint:   fp,
			Stage:                 RefreshJournalStageCommitted,
			BaseCredentialVersion: 3,
			NewCredentialVersion:  &v4,
		},
	}
	walRetained := NewBerthOAuthRefreshWAL(storeRetained, nil)
	walRetained.nowFn = func() time.Time { return now }

	res, err := walRetained.ExecuteRefresh(context.Background(), WALRefreshRequest{
		AccountID:    25,
		Platform:     PlatformGemini,
		ClientID:     "gem-cid",
		RefreshToken: rt,
	}, func(context.Context, *RefreshTraceTracker) (map[string]any, error) {
		return map[string]any{"access_token": "new-at-2", "refresh_token": rt}, nil
	})
	require.NoError(t, err)
	require.True(t, res.Committed)
	require.False(t, res.AlreadyCommitted)
	require.Equal(t, int64(5), res.NewCredentialVersion)
}

type wave2MockWALStore struct {
	cageID               int64
	credVer              int64
	latest               *OAuthRefreshJournalEntry
	quarantinedJournalID int64
}

func (m *wave2MockWALStore) LoadActiveCageForAccount(context.Context, int64) (int64, int64, error) {
	return m.cageID, m.credVer, nil
}
func (m *wave2MockWALStore) FindLatestByTokenFingerprint(context.Context, string, string) (*OAuthRefreshJournalEntry, error) {
	return m.latest, nil
}
func (m *wave2MockWALStore) InsertPending(context.Context, *OAuthRefreshJournalEntry) (int64, error) {
	return 999, nil
}
func (m *wave2MockWALStore) MarkPreSendAborted(context.Context, int64, string, string, *time.Time) error {
	return nil
}
func (m *wave2MockWALStore) MarkUnknownQuarantined(_ context.Context, journalID, _ int64, _, _ string) error {
	m.quarantinedJournalID = journalID
	return nil
}
func (m *wave2MockWALStore) CommitRefreshTx(_ context.Context, in CommitRefreshTxInput) (int64, bool, error) {
	return in.BaseCredentialVersion + 1, true, nil
}

func TestWave2_SSRFBlockedIPsAndSafeDialer(t *testing.T) {
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("127.0.0.1")))
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("169.254.169.254")))
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("10.0.0.5")))
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("100.64.0.1")))    // CGNAT / Tailscale
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("100.127.255.1"))) // CGNAT upper bound
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("0.0.0.0")))
	require.True(t, urlvalidator.IsBlockedIP(net.ParseIP("::1")))
	require.False(t, urlvalidator.IsBlockedIP(net.ParseIP("1.1.1.1")))
	require.False(t, urlvalidator.IsBlockedIP(net.ParseIP("68.77.201.111")))

	dial := urlvalidator.NewSafeDialContext(&net.Dialer{Timeout: time.Second}, false)
	_, err := dial(context.Background(), "tcp", "127.0.0.1:8080")
	require.Error(t, err)
	_, err = dial(context.Background(), "tcp", "169.254.169.254:80")
	require.Error(t, err)
	_, err = dial(context.Background(), "tcp", "100.64.10.2:19443")
	require.Error(t, err)
}

func TestWave2_ResolveRequiredProxyURL_FailsClosedOnMissingOrInactive(t *testing.T) {
	pid := int64(55)
	// Bound proxy with nil preloaded and nil repo MUST fail closed instead of returning empty direct URL.
	_, err := resolveRequiredProxyURL(context.Background(), nil, &pid, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, cage.ErrProxyUnavailable))

	// Inactive proxy MUST fail closed.
	_, err = resolveRequiredProxyURL(context.Background(), nil, &pid, &Proxy{ID: 55, Status: "inactive", Protocol: "http", Host: "1.2.3.4", Port: 8080})
	require.Error(t, err)
	require.True(t, errors.Is(err, cage.ErrProxyUnavailable))
}

type wave2CageAwareStore struct {
	*MemoryEdgeLeaseStore
	cageID    int64
	gateEpoch int64
	gateState string
	tz        string
	cc        string
	locale    string
}

func (s *wave2CageAwareStore) ResolveAccountCageState(context.Context, int64) (int64, int64, string, string, string, string, bool, error) {
	return s.cageID, s.gateEpoch, s.gateState, s.tz, s.cc, s.locale, true, nil
}

func TestWave2_MintAndRenewUseAuthoritativeCageAndRejectQuarantined(t *testing.T) {
	ctx := context.Background()
	pub, priv, kid, err := LoadOrGenerateEdgeSigningKey("", filepath.Join(t.TempDir(), "k.pem"))
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantSvc := NewBerthLandingGrantServiceWithStore(NewMemoryLandingGrantStore(zoneStore, &revSeq))
	store := &wave2CageAwareStore{
		MemoryEdgeLeaseStore: NewMemoryEdgeLeaseStore(&revSeq),
		cageID:               500,
		gateEpoch:            7,
		gateState:            CageGateStateOpen,
		tz:                   "America/Chicago",
		cc:                   "US",
		locale:               "en_US.UTF-8",
	}
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(store, zoneSvc, grantSvc, pub, priv, kid)

	zones, _ := zoneSvc.ListZones(ctx)
	relay, _ := zoneSvc.CreateNode(ctx, EdgeNode{Name: "r1", ZoneID: zones[2].ID, Roles: []string{EdgeRoleIngressRelay}, PublicAddr: "https://r.example.com", TunnelAddr: "10.0.0.1:19443", Status: EdgeNodeStatusActive})
	land, _ := zoneSvc.CreateNode(ctx, EdgeNode{Name: "l1", ZoneID: zones[2].ID, Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.0.0.2:19443", Status: EdgeNodeStatusActive, ExitCountryCode: "US", ExitTimezone: "America/Chicago"})
	_, _ = zoneSvc.CreateLink(ctx, ServerLink{SrcNodeID: relay.ID, DstNodeID: land.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Weight: 1, RTTMs: 10, Enabled: true})
	grant, _ := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{NodeID: land.ID, GranteeUserID: 42, MaxBytes: 1024 * 1024})

	// Caller tries to spoof cage_id=1, cage_epoch=1, timezone=Asia/Tokyo -> DB cage overrides all!
	minted, err := leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID: 42, APIKeyID: 10, Platform: "openai", AccountID: 24,
		CageID: 1, CageEpoch: 1, CohortTimezone: "Asia/Tokyo", CohortCountryCode: "JP",
		GrantID: grant.ID, LandingNodeID: land.ID,
	})
	require.NoError(t, err)
	require.Equal(t, int64(500), minted.Cage.CageID)
	require.Equal(t, int64(7), minted.Cage.CageEpoch)
	require.Equal(t, "America/Chicago", minted.Cage.Timezone)

	// Bumping DB cage epoch rejects renewal of old-epoch lease.
	store.gateEpoch = 8
	_, err = leaseSvc.RenewLeaseWithKey(ctx, 42, 10, minted.LeaseID)
	require.ErrorIs(t, err, ErrEdgeLeaseRevoked)

	// Quarantined cage rejects minting.
	store.gateState = CageGateStateQuarantined
	_, err = leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID: 42, APIKeyID: 10, Platform: "openai", AccountID: 24,
		GrantID: grant.ID, LandingNodeID: land.ID,
	})
	require.ErrorIs(t, err, ErrEdgeLeaseForbidden)
}

func TestWave2_DurableRevocationPersistsCageMinEpochAndRevokedAPIKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := &sqlEdgeLeaseStore{db: db}

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO berth_edge_cage_min_epochs`).
		WithArgs(int64(500), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE berth_edge_revocation_state`).
		WillReturnRows(sqlmock.NewRows([]string{"rev_seq"}).AddRow(int64(42)))
	mock.ExpectCommit()

	seq, err := store.PersistCageMinEpoch(context.Background(), 500, 9)
	require.NoError(t, err)
	require.Equal(t, int64(42), seq)

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO berth_edge_revoked_api_keys`).
		WithArgs(int64(77), "revoked").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`UPDATE berth_edge_revocation_state`).
		WillReturnRows(sqlmock.NewRows([]string{"rev_seq"}).AddRow(int64(43)))
	mock.ExpectCommit()

	seq, err = store.PersistRevokedAPIKey(context.Background(), 77, "revoked")
	require.NoError(t, err)
	require.Equal(t, int64(43), seq)
	require.NoError(t, mock.ExpectationsWereMet())
}
