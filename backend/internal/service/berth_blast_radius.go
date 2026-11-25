package service

import (
	"bytes"
	"context"
	"encoding/json"
	mathrand "math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	HeaderBerthOperationID = "X-Berth-Operation-ID"
	HeaderBerthCircuitOpen = "X-Berth-Circuit-Open"

	blastRadius403MaxAccounts  = 2 // 0 same-account retries, max 1 cross-account switch
	blastRadiusSessionWindow   = 5 * time.Minute
	blastRadius5xxIdenticalWin = 10 * time.Second
	blastRadiusFailoverMinJit  = 150 * time.Millisecond
	blastRadiusFailoverMaxJit  = 2 * time.Second

	oauthPaceBaseDelay = 400 * time.Millisecond

	aimdHoldOnThrottle     = 10 * time.Minute
	aimdHoldOnVegas        = 5 * time.Minute
	aimdRecoveryInterval   = 5 * time.Minute
	aimdRecoveryCleanCount = 20
	aimdVegasMinSamples    = 5
	aimdVegasKneeRatio     = 1.80
	aimdRecoveryMaxRatio   = 1.25
)

// Forbidden403Class distinguishes permanent account bans from WAF/HTML/ambiguous 403s.
type Forbidden403Class uint8

const (
	Forbidden403WAFOrAmbiguous Forbidden403Class = iota
	Forbidden403AccountBan
)

// Classify403Action inspects an upstream 403 response body and classifies whether
// it represents an explicit permanent account/key ban vs a WAF/HTML/ambiguous 403
// that must use 3-strike temporary cooldown instead of 1-hit permanent SetError.
func Classify403Action(body []byte) Forbidden403Class {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Forbidden403WAFOrAmbiguous
	}
	if isCloudflareBotBlockResponse(trimmed) || isHTMLResponse(trimmed) {
		return Forbidden403WAFOrAmbiguous
	}
	// Only structured JSON with explicit account-ban / disabled / invalid-key markers
	// should immediately permanently disable an account.
	var payload map[string]any
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return Forbidden403WAFOrAmbiguous
	}
	lower := strings.ToLower(string(trimmed))
	permanentMarkers := []string{
		"account_suspended",
		"account suspended",
		"account has been disabled",
		"account is disabled",
		"organization has been disabled",
		"organization_disabled",
		"api_key_revoked",
		"invalid_api_key",
		"invalid api key",
		"invalid x-api-key",
		"account_banned",
		"your account has been banned",
		"has been denied access",
		"credit balance is too low",
	}
	for _, marker := range permanentMarkers {
		if strings.Contains(lower, marker) {
			return Forbidden403AccountBan
		}
	}
	return Forbidden403WAFOrAmbiguous
}

// MaxSwitchesForStatus returns the error-class differentiated cross-account switch cap (Report 02 §4.4C).
func MaxSwitchesForStatus(statusCode int) int {
	switch statusCode {
	case http.StatusForbidden:
		return 1 // max 2 distinct accounts touched total
	case http.StatusTooManyRequests:
		return 3
	case 529, http.StatusServiceUnavailable:
		return 2
	case http.StatusUnauthorized:
		return 2
	default:
		if statusCode >= 500 {
			return 2
		}
		return 3
	}
}

// DecorrelatedFailoverJitter computes AWS-style decorrelated jitter in [150ms, 2s].
func DecorrelatedFailoverJitter(prev time.Duration) time.Duration {
	if prev < blastRadiusFailoverMinJit {
		prev = blastRadiusFailoverMinJit
	}
	upper := prev * 3
	if upper > blastRadiusFailoverMaxJit {
		upper = blastRadiusFailoverMaxJit
	}
	if upper <= blastRadiusFailoverMinJit {
		return blastRadiusFailoverMinJit
	}
	span := int64(upper - blastRadiusFailoverMinJit)
	return blastRadiusFailoverMinJit + time.Duration(mathrand.Int63n(span+1))
}

// BlastRadiusDecision describes whether failover may proceed after an upstream failure.
type BlastRadiusDecision struct {
	AllowSwitch         bool
	SessionToxic        bool
	Distinct403Accounts int
	Reason              string
}

type opAccountRecord struct {
	accounts map[int64]time.Time
	expires  time.Time
}

type sessionToxicRecord struct {
	accounts403 map[int64]time.Time
	accounts5xx map[int64]time.Time
	blockedTill time.Time
}

// BerthBlastRadiusGuard tracks cross-hop X-Berth-Operation-ID 403 blast radius
// and per-session toxicity circuit breaking (Report 02 §4.4C + Codex Review #3.4).
type BerthBlastRadiusGuard struct {
	mu       sync.Mutex
	nowFn    func() time.Time
	ops403   map[string]*opAccountRecord
	ops5xx   map[string]*opAccountRecord
	sessions map[string]*sessionToxicRecord
}

var defaultBlastRadiusGuard = NewBerthBlastRadiusGuard()

func NewBerthBlastRadiusGuard() *BerthBlastRadiusGuard {
	return &BerthBlastRadiusGuard{
		nowFn:    time.Now,
		ops403:   make(map[string]*opAccountRecord),
		ops5xx:   make(map[string]*opAccountRecord),
		sessions: make(map[string]*sessionToxicRecord),
	}
}

func DefaultBlastRadiusGuard() *BerthBlastRadiusGuard {
	return defaultBlastRadiusGuard
}

func (g *BerthBlastRadiusGuard) now() time.Time {
	if g != nil && g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

// IsSessionFailoverBlocked returns true when the session toxicity circuit breaker is open.
func (g *BerthBlastRadiusGuard) IsSessionFailoverBlocked(sessionHash string) bool {
	if g == nil || strings.TrimSpace(sessionHash) == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	rec := g.sessions[sessionHash]
	if rec == nil {
		return false
	}
	return g.now().Before(rec.blockedTill)
}

// RecordAndCheckFailover records an upstream failure for (operationID, sessionHash, accountID)
// and enforces cross-hop 403 blast-radius caps (max 2 distinct accounts total = 1 switch),
// rapid identical-5xx caps, and the 5-minute session toxicity breaker.
func (g *BerthBlastRadiusGuard) RecordAndCheckFailover(
	operationID string,
	sessionHash string,
	accountID int64,
	statusCode int,
	currentSwitchCount int,
) BlastRadiusDecision {
	if g == nil {
		return BlastRadiusDecision{AllowSwitch: true}
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	g.gcLocked(now)

	// 1. Cross-hop operation tracking for 403.
	if statusCode == http.StatusForbidden {
		distinct403 := 1
		if opKey := strings.TrimSpace(operationID); opKey != "" {
			rec := g.ops403[opKey]
			if rec == nil || now.After(rec.expires) {
				rec = &opAccountRecord{accounts: make(map[int64]time.Time)}
				g.ops403[opKey] = rec
			}
			if accountID > 0 {
				rec.accounts[accountID] = now
			}
			rec.expires = now.Add(blastRadiusSessionWindow)
			distinct403 = len(rec.accounts)
		}

		sessionToxic := false
		if sKey := strings.TrimSpace(sessionHash); sKey != "" {
			srec := g.getOrCreateSessionLocked(sKey)
			pruneTimeMap(srec.accounts403, now.Add(-blastRadiusSessionWindow))
			if accountID > 0 {
				srec.accounts403[accountID] = now
			}
			if len(srec.accounts403) >= blastRadius403MaxAccounts {
				srec.blockedTill = now.Add(blastRadiusSessionWindow)
				sessionToxic = true
			}
			if len(srec.accounts403) > distinct403 {
				distinct403 = len(srec.accounts403)
			}
		}

		if distinct403 >= blastRadius403MaxAccounts || currentSwitchCount >= MaxSwitchesForStatus(http.StatusForbidden) {
			return BlastRadiusDecision{
				AllowSwitch:         false,
				SessionToxic:        sessionToxic || distinct403 >= blastRadius403MaxAccounts,
				Distinct403Accounts: distinct403,
				Reason:              "blast_radius_403_cap",
			}
		}
		return BlastRadiusDecision{
			AllowSwitch:         true,
			Distinct403Accounts: distinct403,
		}
	}

	// 2. Identical 500/5xx rapid poisoning guard + session 5xx breaker.
	if statusCode >= 500 && statusCode != 529 && statusCode != http.StatusServiceUnavailable {
		if opKey := strings.TrimSpace(operationID); opKey != "" {
			rec := g.ops5xx[opKey]
			if rec == nil || now.After(rec.expires) {
				rec = &opAccountRecord{accounts: make(map[int64]time.Time)}
				g.ops5xx[opKey] = rec
			}
			pruneTimeMap(rec.accounts, now.Add(-blastRadius5xxIdenticalWin))
			if accountID > 0 {
				rec.accounts[accountID] = now
			}
			rec.expires = now.Add(blastRadiusSessionWindow)
			if statusCode == http.StatusInternalServerError && len(rec.accounts) >= 2 {
				return BlastRadiusDecision{
					AllowSwitch: false,
					Reason:      "payload_500_cap",
				}
			}
		}

		if sKey := strings.TrimSpace(sessionHash); sKey != "" {
			srec := g.getOrCreateSessionLocked(sKey)
			pruneTimeMap(srec.accounts5xx, now.Add(-blastRadiusSessionWindow))
			if accountID > 0 {
				srec.accounts5xx[accountID] = now
			}
			if len(srec.accounts5xx) >= 3 {
				srec.blockedTill = now.Add(blastRadiusSessionWindow)
				return BlastRadiusDecision{
					AllowSwitch:  false,
					SessionToxic: true,
					Reason:       "session_toxic_5xx",
				}
			}
		}
	}

	// 3. Enforce general session toxicity breaker & error-class cap.
	if sKey := strings.TrimSpace(sessionHash); sKey != "" {
		if srec := g.sessions[sKey]; srec != nil && now.Before(srec.blockedTill) {
			return BlastRadiusDecision{
				AllowSwitch:  false,
				SessionToxic: true,
				Reason:       "session_toxic",
			}
		}
	}

	if capSwitches := MaxSwitchesForStatus(statusCode); currentSwitchCount >= capSwitches {
		return BlastRadiusDecision{
			AllowSwitch: false,
			Reason:      "status_switch_cap",
		}
	}

	return BlastRadiusDecision{AllowSwitch: true}
}

func (g *BerthBlastRadiusGuard) getOrCreateSessionLocked(sessionHash string) *sessionToxicRecord {
	rec := g.sessions[sessionHash]
	if rec == nil {
		rec = &sessionToxicRecord{
			accounts403: make(map[int64]time.Time),
			accounts5xx: make(map[int64]time.Time),
		}
		g.sessions[sessionHash] = rec
	}
	return rec
}

func (g *BerthBlastRadiusGuard) gcLocked(now time.Time) {
	if len(g.ops403) > 4096 {
		for k, v := range g.ops403 {
			if now.After(v.expires) {
				delete(g.ops403, k)
			}
		}
	}
	if len(g.ops5xx) > 4096 {
		for k, v := range g.ops5xx {
			if now.After(v.expires) {
				delete(g.ops5xx, k)
			}
		}
	}
	if len(g.sessions) > 4096 {
		cutoff := now.Add(-blastRadiusSessionWindow)
		for k, v := range g.sessions {
			pruneTimeMap(v.accounts403, cutoff)
			pruneTimeMap(v.accounts5xx, cutoff)
			if len(v.accounts403) == 0 && len(v.accounts5xx) == 0 && !now.Before(v.blockedTill) {
				delete(g.sessions, k)
			}
		}
	}
}

func pruneTimeMap(m map[int64]time.Time, cutoff time.Time) {
	for id, ts := range m {
		if ts.Before(cutoff) {
			delete(m, id)
		}
	}
}

// BerthOAuthPacer enforces jittered minimum inter-dispatch spacing per OAuth account
// so two requests never hit the exact same millisecond on one OAuth token/IP.
type BerthOAuthPacer struct {
	mu           sync.Mutex
	baseDelay    time.Duration
	lastDispatch map[int64]time.Time
}

var defaultOAuthPacer = NewBerthOAuthPacer(oauthPaceBaseDelay)

func NewBerthOAuthPacer(baseDelay time.Duration) *BerthOAuthPacer {
	if baseDelay <= 0 {
		baseDelay = oauthPaceBaseDelay
	}
	return &BerthOAuthPacer{
		baseDelay:    baseDelay,
		lastDispatch: make(map[int64]time.Time),
	}
}

func DefaultOAuthPacer() *BerthOAuthPacer {
	return defaultOAuthPacer
}

// Pace waits for the jittered OAuth inter-dispatch interval (Uniform[0.75*d0, 1.25*d0])
// for OAuth/setup-token accounts. APIKey accounts return immediately (0ms).
func (p *BerthOAuthPacer) Pace(ctx context.Context, account *Account) error {
	if p == nil || account == nil || !account.IsOAuth() {
		return nil
	}
	minGap := time.Duration(float64(p.baseDelay) * (0.75 + 0.5*mathrand.Float64()))
	now := time.Now()

	p.mu.Lock()
	nextAllowed := p.lastDispatch[account.ID].Add(minGap)
	var wait time.Duration
	if nextAllowed.After(now) {
		wait = nextAllowed.Sub(now)
		p.lastDispatch[account.ID] = nextAllowed
	} else {
		p.lastDispatch[account.ID] = now
	}
	p.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// BerthAIMDLimiter maintains per-account dynamic runtime concurrency c_live in [1, c_effective]
// using AIMD multiplicative decrease on 429/529, Vegas TTFT knee decrease, and additive recovery.
type BerthAIMDLimiter struct {
	mu     sync.Mutex
	nowFn  func() time.Time
	states map[int64]*aimdAccountState
}

type aimdAccountState struct {
	cLive            int
	holdUntil        time.Time
	lastIncrementAt  time.Time
	consecutiveClean int
	recentTTFTRatios []float64
}

var defaultAIMDLimiter = NewBerthAIMDLimiter()

func NewBerthAIMDLimiter() *BerthAIMDLimiter {
	return &BerthAIMDLimiter{
		nowFn:  time.Now,
		states: make(map[int64]*aimdAccountState),
	}
}

func DefaultAIMDLimiter() *BerthAIMDLimiter {
	return defaultAIMDLimiter
}

func (l *BerthAIMDLimiter) now() time.Time {
	if l != nil && l.nowFn != nil {
		return l.nowFn()
	}
	return time.Now()
}

// EffectiveLimit returns c_live clamped strictly inside [1, max(1, cEffective)].
func (l *BerthAIMDLimiter) EffectiveLimit(accountID int64, cEffective int) int {
	if cEffective < 1 {
		cEffective = 1
	}
	if l == nil || accountID <= 0 {
		return cEffective
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.states[accountID]
	if st == nil {
		return cEffective
	}
	if st.cLive < 1 {
		st.cLive = 1
	}
	if st.cLive > cEffective {
		st.cLive = cEffective
	}
	return st.cLive
}

// OnThrottle applies AIMD multiplicative decrease (c_live = max(1, floor(0.5*c_live)))
// and sets a 10-minute hold window.
func (l *BerthAIMDLimiter) OnThrottle(accountID int64, cEffective int) int {
	if cEffective < 1 {
		cEffective = 1
	}
	if l == nil || accountID <= 0 {
		return 1
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.getOrInitLocked(accountID, cEffective)
	if st.cLive > cEffective {
		st.cLive = cEffective
	}
	st.cLive = maxInt(1, st.cLive/2)
	st.holdUntil = now.Add(aimdHoldOnThrottle)
	st.consecutiveClean = 0
	st.recentTTFTRatios = nil
	return st.cLive
}

// OnCompletion feeds streaming completion telemetry for Vegas proactive backoff
// and additive recovery.
func (l *BerthAIMDLimiter) OnCompletion(accountID int64, cEffective int, inFlight int, ttftRatio float64) int {
	if cEffective < 1 {
		cEffective = 1
	}
	if l == nil || accountID <= 0 {
		return cEffective
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.getOrInitLocked(accountID, cEffective)
	if st.cLive > cEffective {
		st.cLive = cEffective
	}

	if ttftRatio > 0 {
		st.recentTTFTRatios = append(st.recentTTFTRatios, ttftRatio)
		if len(st.recentTTFTRatios) > aimdRecoveryCleanCount {
			st.recentTTFTRatios = st.recentTTFTRatios[len(st.recentTTFTRatios)-aimdRecoveryCleanCount:]
		}
	}

	// Vegas proactive decrease: last >=5 streaming completions have median ratio > 1.80 while at c_live.
	if len(st.recentTTFTRatios) >= aimdVegasMinSamples && inFlight >= st.cLive {
		tail := st.recentTTFTRatios[len(st.recentTTFTRatios)-aimdVegasMinSamples:]
		if medianFloat64(tail) > aimdVegasKneeRatio {
			st.cLive = maxInt(1, st.cLive-1)
			st.holdUntil = now.Add(aimdHoldOnVegas)
			st.consecutiveClean = 0
			st.recentTTFTRatios = nil
			return st.cLive
		}
	}

	st.consecutiveClean++
	// Additive recovery: hold expired, >=20 clean requests, median TTFT ratio < 1.25, >=5m since last increment.
	if st.cLive < cEffective &&
		now.After(st.holdUntil) &&
		st.consecutiveClean >= aimdRecoveryCleanCount &&
		(st.lastIncrementAt.IsZero() || now.Sub(st.lastIncrementAt) >= aimdRecoveryInterval) {
		if len(st.recentTTFTRatios) == 0 || medianFloat64(st.recentTTFTRatios) < aimdRecoveryMaxRatio {
			st.cLive = min(cEffective, st.cLive+1)
			st.lastIncrementAt = now
			st.consecutiveClean = 0
		}
	}

	return st.cLive
}

func (l *BerthAIMDLimiter) getOrInitLocked(accountID int64, cEffective int) *aimdAccountState {
	st := l.states[accountID]
	if st == nil {
		st = &aimdAccountState{cLive: maxInt(1, cEffective)}
		l.states[accountID] = st
	}
	return st
}

func medianFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2.0
}
