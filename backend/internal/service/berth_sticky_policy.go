package service

import (
	"context"
	"math"
	mathrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stickyMicroWaitMin           = 2 * time.Second
	stickyMicroWaitMax           = 8 * time.Second
	stickyMicroWaitStep          = 1500 * time.Millisecond
	stickyMicroWaitTokensPerStep = 25000
	stickyMicroWaitHighImpBoost  = 2 * time.Second
	stickyMicroWaitHighImpMax    = 10 * time.Second
	stickyMicroWaitOpenAIRPMCap  = 1500 * time.Millisecond
	stickyMicroWaitPollBase      = 100 * time.Millisecond
	stickyMicroWaitPollJitter    = 50 * time.Millisecond
	stickyMicroWaitDeadlineGuard = 100 * time.Millisecond

	stickyEscapeMinSamples          = 5
	stickyEscapeConsecutiveFailures = 3
	stickyEscapeErrorRateThreshold  = 0.35
	stickyEscapeTTFTRatioThreshold  = 2.5
)

type requestPrefixTokensCtxKey struct{}
type stickyMicroWaitOverrideCtxKey struct{}

// WithStickyMicroWaitBudgetOverride overrides the computed micro-wait budget on ctx
// (useful in deterministic tests or callers requesting explicit micro-wait bounds).
func WithStickyMicroWaitBudgetOverride(ctx context.Context, budget time.Duration) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, stickyMicroWaitOverrideCtxKey{}, budget)
}

func StickyMicroWaitBudgetOverrideFromContext(ctx context.Context) (time.Duration, bool) {
	if ctx == nil {
		return 0, false
	}
	v, ok := ctx.Value(stickyMicroWaitOverrideCtxKey{}).(time.Duration)
	return v, ok
}

// ShouldRunStickyMicroWait reports whether this request context opted into
// Tier 1 slot-free micro-wait (true for all gateway requests carrying estimated
// prefix tokens or an explicit override).
func ShouldRunStickyMicroWait(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if _, ok := StickyMicroWaitBudgetOverrideFromContext(ctx); ok {
		return true
	}
	return RequestPrefixTokensFromContext(ctx) > 0
}

// WithRequestPrefixTokens attaches the estimated cacheable prefix token count
// to the request context so Tier 1 micro-wait & sane sticky escape can scale properly.
func WithRequestPrefixTokens(ctx context.Context, prefixTokens int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if prefixTokens < 0 {
		prefixTokens = 0
	}
	return context.WithValue(ctx, requestPrefixTokensCtxKey{}, prefixTokens)
}

func RequestPrefixTokensFromContext(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	v, _ := ctx.Value(requestPrefixTokensCtxKey{}).(int)
	return v
}

// EstimatePrefixTokens approximates cacheable prompt prefix tokens from JSON body bytes.
func EstimatePrefixTokens(bodyBytes int) int {
	if bodyBytes <= 0 {
		return 0
	}
	return bodyBytes / 4
}

// ComputeStickyMicroWaitBudget implements Report 02 §4.2B cache-economics wait budget:
//
//	T_wait(L) = clamp(2.0s + 1.5s * floor(L / 25,000), 2.0s, 8.0s)
//
// Boosted by +2s (up to 10s) for high-importance WorkSessions, capped at 1.5s
// when OpenAI prompt_cache_key RPM >= 14, and bounded by configured ceiling.
func ComputeStickyMicroWaitBudget(
	prefixTokens int,
	maxConfigTimeout time.Duration,
	highImportance bool,
	openAISessionRPM int,
) time.Duration {
	if prefixTokens < 0 {
		prefixTokens = 0
	}
	steps := prefixTokens / stickyMicroWaitTokensPerStep
	budget := stickyMicroWaitMin + time.Duration(steps)*stickyMicroWaitStep
	maxCap := stickyMicroWaitMax
	if highImportance {
		budget += stickyMicroWaitHighImpBoost
		maxCap = stickyMicroWaitHighImpMax
	}
	if budget < stickyMicroWaitMin {
		budget = stickyMicroWaitMin
	}
	if budget > maxCap {
		budget = maxCap
	}
	if openAISessionRPM >= 14 && budget > stickyMicroWaitOpenAIRPMCap {
		budget = stickyMicroWaitOpenAIRPMCap
	}
	if maxConfigTimeout > 0 && budget > maxConfigTimeout {
		budget = maxConfigTimeout
	}
	return budget
}

// StickyMicroWaiterTracker bounds concurrent slot-free waiters per account to
// prevent waiter herds (Codex Review #3.3: max(2, c_live)).
type StickyMicroWaiterTracker struct {
	mu      sync.Mutex
	waiters map[int64]*atomic.Int64
}

var defaultStickyMicroWaiterTracker = NewStickyMicroWaiterTracker()

func NewStickyMicroWaiterTracker() *StickyMicroWaiterTracker {
	return &StickyMicroWaiterTracker{
		waiters: make(map[int64]*atomic.Int64),
	}
}

func DefaultStickyMicroWaiterTracker() *StickyMicroWaiterTracker {
	return defaultStickyMicroWaiterTracker
}

func (t *StickyMicroWaiterTracker) counter(accountID int64) *atomic.Int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.waiters[accountID]
	if c == nil {
		c = &atomic.Int64{}
		t.waiters[accountID] = c
	}
	return c
}

// TryEnter increments the waiter count if current waiters < maxWaiters.
func (t *StickyMicroWaiterTracker) TryEnter(accountID int64, maxWaiters int) (leave func(), ok bool) {
	if t == nil || accountID <= 0 {
		return func() {}, true
	}
	if maxWaiters < 2 {
		maxWaiters = 2
	}
	ctr := t.counter(accountID)
	for {
		cur := ctr.Load()
		if cur >= int64(maxWaiters) {
			return nil, false
		}
		if ctr.CompareAndSwap(cur, cur+1) {
			var once sync.Once
			return func() {
				once.Do(func() {
					ctr.Add(-1)
				})
			}, true
		}
	}
}

func (t *StickyMicroWaiterTracker) ActiveWaiters(accountID int64) int {
	if t == nil || accountID <= 0 {
		return 0
	}
	return int(t.counter(accountID).Load())
}

// StickyMicroWaitOptions configures slot-free micro-waiting before acquiring either slot.
type StickyMicroWaitOptions struct {
	AccountID    int64
	CLive        int
	Budget       time.Duration
	PollInterval time.Duration // defaults to 100ms (+0..50ms jitter)
	Tracker      *StickyMicroWaiterTracker
}

// WaitForStickySlotFree waits up to min(Budget, remaining caller context deadline)
// WITHOUT holding any account or proxy slot (Codex Review #3.3), retrying tryAcquire
// until the sticky slot opens, the budget expires, or context cancels.
func WaitForStickySlotFree(
	ctx context.Context,
	opts StickyMicroWaitOptions,
	tryAcquire func(context.Context) (*AcquireResult, error),
) (res *AcquireResult, waited bool, queueFull bool, err error) {
	if tryAcquire == nil || opts.Budget <= 0 {
		return nil, false, false, nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, false, false, ctx.Err()
	}

	budget := opts.Budget
	if ctx != nil {
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			rem := time.Until(deadline) - stickyMicroWaitDeadlineGuard
			if rem <= 0 {
				return nil, false, false, nil
			}
			if rem < budget {
				budget = rem
			}
		}
	}

	tracker := opts.Tracker
	if tracker == nil {
		tracker = DefaultStickyMicroWaiterTracker()
	}
	maxWaiters := maxInt(2, opts.CLive)
	leave, entered := tracker.TryEnter(opts.AccountID, maxWaiters)
	if !entered {
		return nil, false, true, nil
	}
	defer leave()

	pollBase := opts.PollInterval
	if pollBase <= 0 {
		pollBase = stickyMicroWaitPollBase
	}
	deadlineTime := time.Now().Add(budget)
	waited = true

	for {
		remaining := time.Until(deadlineTime)
		if remaining <= 0 {
			return nil, waited, false, nil
		}
		sleepDur := pollBase
		if stickyMicroWaitPollJitter > 0 && opts.PollInterval <= 0 {
			sleepDur += time.Duration(mathrand.Int63n(int64(stickyMicroWaitPollJitter)))
		}
		if sleepDur > remaining {
			sleepDur = remaining
		}
		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, waited, false, ctx.Err()
		case <-timer.C:
		}

		acq, acqErr := tryAcquire(ctx)
		if acqErr != nil {
			return nil, waited, false, acqErr
		}
		if acq != nil && acq.Acquired {
			return acq, waited, false, nil
		}
	}
}

// ExpectedTTFTMs returns a model- and prefill-aware baseline TTFT (milliseconds)
// so reasoning models (o3/o4/gpt-5/thinking) and large prefills never trigger false sticky escape.
func ExpectedTTFTMs(model string, prefixTokens int) float64 {
	m := strings.ToLower(strings.TrimSpace(model))
	base := 2500.0
	switch {
	case strings.Contains(m, "o3") || strings.Contains(m, "o4") || strings.Contains(m, "o1") ||
		strings.Contains(m, "gpt-5") || strings.Contains(m, "opus") || strings.Contains(m, "thinking") || strings.Contains(m, "pro"):
		base = 8000.0
	case strings.Contains(m, "haiku") || strings.Contains(m, "flash") || strings.Contains(m, "mini") || strings.Contains(m, "nano"):
		base = 1200.0
	}
	prefillAdd := float64(maxInt(0, prefixTokens)) / 1000.0 * 40.0 // +40ms per 1K prefix tokens
	return math.Max(1000.0, base+prefillAdd)
}

// StickyEscapeMetrics summarizes recent sticky account health for sane escape evaluation.
type StickyEscapeMetrics struct {
	SampleCount         int
	ConsecutiveFailures int
	ErrorRateEWMA       float64
	TTFTEWMA            float64
	HasTTFT             bool
	Model               string
	PrefixTokens        int
}

// ShouldEscapeStickyAccountSane enforces Report 02 §4.2C sane sticky escape:
//   - Requires minSamples >= 5 (ignores single-request noise!)
//   - Escapes ONLY when:
//     1. consecutiveFailures >= 3, OR
//     2. errorRateEWMA > 0.35 (with samples >= 5), OR
//     3. normalized TTFT ratio ewmaTTFT / expectedTTFT(model, prefixTokens) > 2.5 (with samples >= 5)
func ShouldEscapeStickyAccountSane(m StickyEscapeMetrics) (reason string, shouldEscape bool) {
	if m.ConsecutiveFailures >= stickyEscapeConsecutiveFailures {
		return "consecutive_failures", true
	}
	if m.SampleCount < stickyEscapeMinSamples {
		return "", false
	}
	if m.ErrorRateEWMA > stickyEscapeErrorRateThreshold {
		return "error_rate", true
	}
	if m.HasTTFT && m.TTFTEWMA > 0 {
		expected := ExpectedTTFTMs(m.Model, m.PrefixTokens)
		if m.TTFTEWMA/expected > stickyEscapeTTFTRatioThreshold {
			return "ttft_ratio", true
		}
	}
	return "", false
}
