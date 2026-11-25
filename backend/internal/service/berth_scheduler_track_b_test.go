//go:build unit

package service

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/jk-zhang-meta/berth/internal/domain"
	"github.com/stretchr/testify/require"
)

func makeCohortAccount(id int64, tz, cc string, offsetSec int, isp string) *Account {
	return &Account{
		ID:          id,
		Platform:    PlatformAnthropic,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 2,
		Proxy: &Proxy{
			ID:                   id * 10,
			Status:               StatusActive,
			ExitIP:               "198.51.100.1",
			ExitTimezone:         tz,
			ExitCountryCode:      cc,
			ExitUTCOffsetSeconds: intPtr(offsetSec),
			ExitISP:              isp,
		},
	}
}

func TestFilterCandidatesByCohort_4LevelLadderAndStrictDST(t *testing.T) {
	// Phoenix (America/Phoenix, -7h, no DST) vs Denver (America/Denver, -7h in winter).
	// Under strict mode, equal UTC offsets MUST NOT match different IANA timezones (Codex Review #3.3)!
	aDenverRes := makeCohortAccount(1, "America/Denver", "US", -25200, "Comcast Cable")
	aDenverDC := makeCohortAccount(2, "America/Denver", "US", -25200, "Amazon AWS Cloud")
	aPhoenixRes := makeCohortAccount(3, "America/Phoenix", "US", -25200, "Cox Residential")
	aChicagoRes := makeCohortAccount(4, "America/Chicago", "US", -21600, "AT&T Fiber")
	aTokyoRes := makeCohortAccount(5, "Asia/Tokyo", "JP", 32400, "NTT Communications")

	targetDenverRes := CageCohort{
		Timezone:         "America/Denver",
		UTCOffsetSeconds: intPtr(-25200),
		CountryCode:      "US",
		ASNClass:         ASNClassResidentialISP,
	}

	// Level 2A: exact TZ + country + ASN class
	matched, lvl, handover, err := FilterCandidatesByCohort([]*Account{aDenverRes, aDenverDC, aPhoenixRes}, targetDenverRes, true, false)
	require.NoError(t, err)
	require.Equal(t, CohortLevel2AExact, lvl)
	require.Empty(t, handover)
	require.Len(t, matched, 1)
	require.Equal(t, int64(1), matched[0].ID)

	// Level 2B: exact TZ + country (any ASN class)
	matched, lvl, handover, err = FilterCandidatesByCohort([]*Account{aDenverDC, aPhoenixRes}, targetDenverRes, true, false)
	require.NoError(t, err)
	require.Equal(t, CohortLevel2BSameTZ, lvl)
	require.Empty(t, handover)
	require.Len(t, matched, 1)
	require.Equal(t, int64(2), matched[0].ID)

	// Level 2C: NON-STRICT mode allows equal UTC offset + same country (Phoenix matches Denver -7h)
	matched, lvl, handover, err = FilterCandidatesByCohort([]*Account{aPhoenixRes, aChicagoRes}, targetDenverRes, false, false)
	require.NoError(t, err)
	require.Equal(t, CohortLevel2CSameOffset, lvl)
	require.Empty(t, handover)
	require.Len(t, matched, 1)
	require.Equal(t, int64(3), matched[0].ID)

	// Strict mode MUST reject Level 2C equal-offset DST trap and return ErrCageRebindRequired!
	matched, _, _, err = FilterCandidatesByCohort([]*Account{aPhoenixRes, aChicagoRes, aTokyoRes}, targetDenverRes, true, false)
	require.Nil(t, matched)
	var rebindErr *ErrCageRebindRequired
	require.ErrorAs(t, err, &rebindErr)
	require.Equal(t, "America/Denver", rebindErr.CurrentCohortTZ)
	require.Equal(t, "America/Phoenix", rebindErr.RecommendedCohortTZ, "closest UTC offset in same country should be recommended")
	require.NotEmpty(t, rebindErr.AvailableCohorts)
	require.Contains(t, rebindErr.FormatAvailableCohortsHeader(), "America/Phoenix:1")

	// Explicit handover (allowHandover=true) picks closest UTC offset + same country first.
	matched, lvl, handover, err = FilterCandidatesByCohort([]*Account{aTokyoRes, aChicagoRes}, targetDenverRes, true, true)
	require.NoError(t, err)
	require.Equal(t, CohortLevel2DHandover, lvl)
	require.Equal(t, "America/Chicago", handover)
	require.Len(t, matched, 1)
	require.Equal(t, int64(4), matched[0].ID)
}

func TestExtractCageCohortRequest_StrictVsLegacy(t *testing.T) {
	// Legacy WorkSession (cage_strict_mode=false) remains non-strict unless header overrides.
	legacyPref := &WorkSessionPref{CohortTimezone: "America/New_York", CohortCountryCode: "US", CageStrictMode: false}
	req := ExtractCageCohortRequest(http.Header{}, legacyPref)
	require.NotNil(t, req)
	require.Equal(t, "America/New_York", req.Target.Timezone)
	require.False(t, req.StrictMode)

	// Explicit X-Berth-Cage-TZ activates strict mode automatically.
	h := http.Header{}
	h.Set(HeaderBerthCageTZ, "Europe/Berlin")
	h.Set(HeaderBerthCageCountry, "de")
	h.Set(HeaderBerthAllowCageHandover, "true")
	req = ExtractCageCohortRequest(h, legacyPref)
	require.NotNil(t, req)
	require.Equal(t, "Europe/Berlin", req.Target.Timezone)
	require.Equal(t, "DE", req.Target.CountryCode)
	require.True(t, req.StrictMode)
	require.True(t, req.AllowHandover)
}

func TestStickyMicroWait_SlotFreeAndQueueCap(t *testing.T) {
	// Budget scaling checks
	require.Equal(t, 2*time.Second, ComputeStickyMicroWaitBudget(0, 45*time.Second, false, 0))
	require.Equal(t, 5*time.Second, ComputeStickyMicroWaitBudget(50000, 45*time.Second, false, 0))
	require.Equal(t, 8*time.Second, ComputeStickyMicroWaitBudget(200000, 45*time.Second, false, 0))
	require.Equal(t, 10*time.Second, ComputeStickyMicroWaitBudget(200000, 45*time.Second, true, 0))
	require.Equal(t, 1500*time.Millisecond, ComputeStickyMicroWaitBudget(200000, 45*time.Second, false, 14))

	// Slot-free micro-wait lands on sticky account when slot frees on 2nd poll.
	tracker := NewStickyMicroWaiterTracker()
	var attempts atomic.Int32
	res, waited, queueFull, err := WaitForStickySlotFree(context.Background(), StickyMicroWaitOptions{
		AccountID:    77,
		CLive:        2,
		Budget:       200 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
		Tracker:      tracker,
	}, func(_ context.Context) (*AcquireResult, error) {
		if attempts.Add(1) >= 2 {
			return &AcquireResult{Acquired: true, ReleaseFunc: func() {}}, nil
		}
		return &AcquireResult{Acquired: false}, nil
	})
	require.NoError(t, err)
	require.True(t, waited)
	require.False(t, queueFull)
	require.NotNil(t, res)
	require.True(t, res.Acquired)
	require.Equal(t, 0, tracker.ActiveWaiters(77), "waiter count must be released after exit")

	// Queue cap max(2, c_live): fill 2 waiters -> 3rd returns queueFull=true immediately without waiting.
	l1, ok1 := tracker.TryEnter(88, 2)
	l2, ok2 := tracker.TryEnter(88, 2)
	require.True(t, ok1 && ok2)
	defer l1()
	defer l2()
	res, waited, queueFull, err = WaitForStickySlotFree(context.Background(), StickyMicroWaitOptions{
		AccountID:    88,
		CLive:        2,
		Budget:       200 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
		Tracker:      tracker,
	}, func(_ context.Context) (*AcquireResult, error) {
		return &AcquireResult{Acquired: false}, nil
	})
	require.NoError(t, err)
	require.Nil(t, res)
	require.False(t, waited)
	require.True(t, queueFull)
}

func TestShouldEscapeStickyAccountSane(t *testing.T) {
	// Single slow reasoning request (sampleCount=1, TTFT=12s on o3) MUST NOT trigger escape!
	reason, esc := ShouldEscapeStickyAccountSane(StickyEscapeMetrics{
		SampleCount: 1,
		TTFTEWMA:    12000,
		HasTTFT:     true,
		Model:       "o3",
	})
	require.False(t, esc)
	require.Empty(t, reason)

	// 3 consecutive failures ALWAYS escapes even with < 5 samples.
	reason, esc = ShouldEscapeStickyAccountSane(StickyEscapeMetrics{
		SampleCount:         3,
		ConsecutiveFailures: 3,
	})
	require.True(t, esc)
	require.Equal(t, "consecutive_failures", reason)

	// Error rate > 0.35 with samples >= 5 escapes.
	reason, esc = ShouldEscapeStickyAccountSane(StickyEscapeMetrics{
		SampleCount:   5,
		ErrorRateEWMA: 0.40,
	})
	require.True(t, esc)
	require.Equal(t, "error_rate", reason)

	// Normalized TTFT ratio > 2.5 on standard model (base 2500ms -> 7000ms = 2.8x) escapes when samples >= 5.
	reason, esc = ShouldEscapeStickyAccountSane(StickyEscapeMetrics{
		SampleCount: 6,
		TTFTEWMA:    7000,
		HasTTFT:     true,
		Model:       "gpt-4o",
	})
	require.True(t, esc)
	require.Equal(t, "ttft_ratio", reason)

	// Same 7000ms TTFT on o3 reasoning model (expected 8000ms -> ratio 0.875) MUST NOT escape!
	reason, esc = ShouldEscapeStickyAccountSane(StickyEscapeMetrics{
		SampleCount: 6,
		TTFTEWMA:    7000,
		HasTTFT:     true,
		Model:       "o3",
	})
	require.False(t, esc)
	require.Empty(t, reason)
}

func TestBlastRadiusGuard_403CrossHopCapAndSessionToxic(t *testing.T) {
	guard := NewBerthBlastRadiusGuard()

	// Hop 1: Account 101 returns 403 -> allowed to switch ONCE (max 2 distinct accounts).
	d1 := guard.RecordAndCheckFailover("op-abc", "sess-1", 101, http.StatusForbidden, 0)
	require.True(t, d1.AllowSwitch)
	require.False(t, d1.SessionToxic)
	require.Equal(t, 1, d1.Distinct403Accounts)

	// Hop 2 (even a fresh HTTP retry carrying the same X-Berth-Operation-ID): Account 102 returns 403 ->
	// reaches 2 distinct accounts -> BLOCKED & trips session_toxic breaker!
	d2 := guard.RecordAndCheckFailover("op-abc", "sess-1", 102, http.StatusForbidden, 0)
	require.False(t, d2.AllowSwitch)
	require.True(t, d2.SessionToxic)
	require.Equal(t, 2, d2.Distinct403Accounts)
	require.True(t, guard.IsSessionFailoverBlocked("sess-1"))

	// Subsequent non-403 request on the same toxic session also refuses failover.
	d3 := guard.RecordAndCheckFailover("op-new", "sess-1", 103, http.StatusTooManyRequests, 0)
	require.False(t, d3.AllowSwitch)
	require.True(t, d3.SessionToxic)

	// Decorrelated jitter strictly within [150ms, 2s].
	prev := time.Duration(0)
	for i := 0; i < 30; i++ {
		j := DecorrelatedFailoverJitter(prev)
		require.GreaterOrEqual(t, j, 150*time.Millisecond)
		require.LessOrEqual(t, j, 2*time.Second)
		prev = j
	}
}

func TestAIMDLimiter_ThrottleVegasAndRecovery(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	limiter := NewBerthAIMDLimiter()
	limiter.nowFn = func() time.Time { return now }

	require.Equal(t, 6, limiter.EffectiveLimit(1, 6))
	// 429 throttle halves c_live: 6 -> 3
	require.Equal(t, 3, limiter.OnThrottle(1, 6))
	require.Equal(t, 3, limiter.EffectiveLimit(1, 6))

	// Vegas proactive decrease when >=5 completions have median ratio > 1.80 at c_live
	for i := 0; i < 4; i++ {
		require.Equal(t, 3, limiter.OnCompletion(1, 6, 3, 2.0))
	}
	require.Equal(t, 2, limiter.OnCompletion(1, 6, 3, 2.0))

	// Additive recovery requires hold expiry + >=20 clean requests with ratio < 1.25
	now = now.Add(15 * time.Minute)
	for i := 0; i < 19; i++ {
		require.Equal(t, 2, limiter.OnCompletion(1, 6, 1, 1.05))
	}
	require.Equal(t, 3, limiter.OnCompletion(1, 6, 1, 1.05))
}

func TestGatewayForward_OAuth403ZeroSameAccountRetries(t *testing.T) {
	svc := &GatewayService{}
	oauthAcc := &Account{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	require.False(t, svc.shouldRetryUpstreamError(oauthAcc, http.StatusForbidden), "OAuth 403 must never perform same-account retries (Bug B12)")
}

func TestRateLimitService_UnifiedAnthropic403ThreeStrikeAndHTML(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	acc := &Account{ID: 701, Platform: PlatformAnthropic, Type: AccountTypeOAuth}

	// 1. HTML 403 -> skips account penalty completely.
	require.False(t, svc.HandleUpstreamError(context.Background(), acc, http.StatusForbidden, http.Header{}, []byte("<!DOCTYPE html><html><body>403</body></html>")))
	require.Equal(t, 0, repo.setErrorCalls)
	require.Equal(t, 0, repo.tempCalls)

	// 2. Ambiguous JSON 403 -> 1st & 2nd hits temp-unschedulable (NOT 1-hit permanent SetError!), 3rd hit SetError.
	ambiguous := []byte(`{"error":{"type":"forbidden","message":"temporarily blocked by edge rule"}}`)
	require.True(t, svc.HandleUpstreamError(context.Background(), acc, http.StatusForbidden, http.Header{}, ambiguous))
	require.Equal(t, 1, repo.tempCalls)
	require.Equal(t, 0, repo.setErrorCalls)

	require.True(t, svc.HandleUpstreamError(context.Background(), acc, http.StatusForbidden, http.Header{}, ambiguous))
	require.Equal(t, 2, repo.tempCalls)
	require.Equal(t, 0, repo.setErrorCalls)

	require.True(t, svc.HandleUpstreamError(context.Background(), acc, http.StatusForbidden, http.Header{}, ambiguous))
	require.Equal(t, 1, repo.setErrorCalls)

	// 3. Explicit account suspension JSON 403 -> immediate SetError.
	repo2 := &rateLimitAccountRepoStub{}
	svc2 := NewRateLimitService(repo2, nil, &config.Config{}, nil, nil)
	require.True(t, svc2.HandleUpstreamError(context.Background(), acc, http.StatusForbidden, http.Header{}, []byte(`{"error":{"type":"permission_error","message":"Your account has been disabled"}}`)))
	require.Equal(t, 1, repo2.setErrorCalls)
}

func TestAnthropicTurnInvariantSessionAnchor_BugB4(t *testing.T) {
	svc := &GatewayService{}
	ctx := &SessionContext{ClientIP: "10.0.0.1", UserAgent: "claude-sdk/1.0", APIKeyID: 55}

	turn1, err := ParseGatewayRequest(NewRequestBodyRef([]byte(`{"model":"claude-sonnet-4-5","system":"Be helpful","tools":[{"name":"read_file"},{"name":"write_file"}],"messages":[{"role":"user","content":"Help me refactor auth.go"}]}`)), domain.PlatformAnthropic)
	require.NoError(t, err)
	turn1.SessionContext = ctx

	turn2, err := ParseGatewayRequest(NewRequestBodyRef([]byte(`{"model":"claude-sonnet-4-5","system":"Be helpful","tools":[{"name":"write_file"},{"name":"read_file"}],"messages":[{"role":"user","content":"Help me refactor auth.go"},{"role":"assistant","content":"Sure!"},{"role":"user","content":"Now add tests"}]}`)), domain.PlatformAnthropic)
	require.NoError(t, err)
	turn2.SessionContext = ctx

	k1, _, _, _, _ := svc.ResolveAnthropicStickySessionKey(context.Background(), nil, turn1)
	k2, _, _, _, _ := svc.ResolveAnthropicStickySessionKey(context.Background(), nil, turn2)
	require.NotEmpty(t, k1)
	require.Equal(t, k1, k2, "multi-turn Anthropic requests without metadata.user_id must keep identical sticky key")

	// Different API key gets distinct anchor.
	turnOtherUser, err := ParseGatewayRequest(NewRequestBodyRef([]byte(`{"model":"claude-sonnet-4-5","system":"Be helpful","messages":[{"role":"user","content":"Help me refactor auth.go"}]}`)), domain.PlatformAnthropic)
	require.NoError(t, err)
	turnOtherUser.SessionContext = &SessionContext{ClientIP: "10.0.0.1", UserAgent: "claude-sdk/1.0", APIKeyID: 99}
	kOther, _, _, _, _ := svc.ResolveAnthropicStickySessionKey(context.Background(), nil, turnOtherUser)
	require.NotEqual(t, k1, kOther)
}

func TestProxyFallback_NonAdminStewardNeverMigratesToDirect(t *testing.T) {
	now := time.Now()
	expiredDirect := Proxy{
		ID:           10,
		Status:       StatusActive,
		FallbackMode: FallbackModeDirect,
	}
	byID := map[int64]Proxy{10: expiredDirect}

	// Admin (allowDirect=true) may migrate to direct (target=nil, change=true).
	target, change := ResolveProxyFallbackTargetWithPolicy(expiredDirect, byID, now, true)
	require.True(t, change)
	require.Nil(t, target)

	// Non-admin stewarded account (allowDirect=false) MUST fail closed (no direct egress fallback!).
	target, change = ResolveProxyFallbackTargetWithPolicy(expiredDirect, byID, now, false)
	require.False(t, change, "non-admin stewarded accounts must never migrate to direct egress")
	require.Nil(t, target)

	// Chained backup pointing to an expired backup with FallbackModeDirect must ALSO fail closed when allowDirect=false!
	backupID := int64(20)
	expiredAt := now.Add(-1 * time.Hour)
	chained := Proxy{ID: 11, Status: StatusActive, FallbackMode: FallbackModeProxy, BackupProxyID: &backupID}
	expiredBackup := Proxy{ID: 20, Status: StatusActive, ExpiresAt: &expiredAt, FallbackMode: FallbackModeDirect}
	byID[11] = chained
	byID[20] = expiredBackup
	target, change = ResolveProxyFallbackTargetWithPolicy(chained, byID, now, false)
	require.False(t, change, "chained direct fallback must fail closed for non-admin")
	require.Nil(t, target)

	// Active non-expired backup proxy still resolves cleanly for non-admin!
	activeBackupID := int64(30)
	activeBackup := Proxy{ID: 30, Status: StatusActive}
	chainedOK := Proxy{ID: 12, Status: StatusActive, FallbackMode: FallbackModeProxy, BackupProxyID: &activeBackupID}
	byID[12] = chainedOK
	byID[30] = activeBackup
	target, change = ResolveProxyFallbackTargetWithPolicy(chainedOK, byID, now, false)
	require.True(t, change)
	require.NotNil(t, target)
	require.Equal(t, int64(30), *target)
}

type staleRentalProxyRepoStub struct {
	ProxyRepository
	proxy *Proxy
}

func (s *staleRentalProxyRepoStub) GetByID(_ context.Context, _ int64) (*Proxy, error) {
	cp := *s.proxy
	return &cp, nil
}
func (s *staleRentalProxyRepoStub) CountAccountsByProxyID(_ context.Context, _ int64) (int64, error) {
	return 0, nil
}

func TestAdminProxy_RentedProxyFreshnessFixBeyond15Minutes(t *testing.T) {
	staleCheckedAt := time.Now().Add(-2 * time.Hour)
	staleVerifiedProxy := &Proxy{
		ID:              501,
		Status:          StatusActive,
		Protocol:        "socks5",
		Host:            "198.51.100.10",
		Port:            1080,
		ExitIP:          "198.51.100.10",
		ExitTimezone:    "Asia/Tokyo",
		ExitCountryCode: "JP",
		ExitCheckedAt:   &staleCheckedAt,
	}
	require.True(t, staleVerifiedProxy.HasVerifiedExitProfile())
	require.False(t, staleVerifiedProxy.HasFreshVerifiedExitProfile(time.Now()))

	// 1. Non-rented stale proxy MUST still be rejected (>15m freshness rule preserved for owned proxies).
	svcOwned := &adminServiceImpl{
		proxyRepo: &staleRentalProxyRepoStub{proxy: staleVerifiedProxy},
	}
	pid := int64(501)
	err := svcOwned.validateVerifiedProxyBindingCapacity(context.Background(), &pid, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified recently")

	// 2. Active rented proxy clone (>15m since checkout probe) with verified exit profile MUST succeed!
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{
		proxy: func(_ context.Context, proxyID int64) (bool, bool, error) {
			if proxyID == 501 {
				return true, true, nil
			}
			return false, false, nil
		},
	})

	err = svcOwned.validateVerifiedProxyBindingCapacity(context.Background(), &pid, 1)
	require.NoError(t, err, "active rented proxy with verified exit profile must remain bindable >15m after checkout")
}
