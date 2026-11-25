package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	berthConcurrencyWindowDays       = 14
	berthConcurrencyHalfLifeDays     = 5.0
	berthConcurrencyMinEffSamples    = 200.0
	berthConcurrencyFastDownSamples  = 100.0
	berthConcurrencyMinAccounts      = 3
	berthConcurrencyCredibilityN0    = 500.0
	berthConcurrencyPriorPseudocount = 20.0
	berthConcurrencyWilsonZ95        = 1.96
	berthConcurrencyTTFTMedianLimit  = 1.35
	berthConcurrencyTTFTP90Limit     = 1.65
	berthConcurrencyPelicanMinN      = 15
	berthConcurrencyPelicanUCBLimit  = 0.08
	berthConcurrencyPelicanDeltaMax  = 0.04
	berthConcurrencyDefaultDurSec    = 18.0
)

// ConcurrencyBucket identifies a canonical (platform, account_type, plan_tier) telemetry bucket.
type ConcurrencyBucket struct {
	Platform    string `json:"platform"`
	AccountType string `json:"account_type"`
	PlanTier    string `json:"plan_tier"`
}

// ConcurrencyPriorSpec defines conservative anti-ban cold-start bounds and stability thresholds.
type ConcurrencyPriorSpec struct {
	Prior        int
	HardMax      int
	SafetyFactor float64
	Max429Rate   float64
	Max403Rate   float64
	Max529Rate   float64
}

// ConcurrencyHourlyRow represents a single row in berth_concurrency_bucket_hourly.
type ConcurrencyHourlyRow struct {
	BucketHour        time.Time
	Platform          string
	AccountType       string
	PlanTier          string
	ConcurrencyLevel  int
	TotalRequests     int
	DistinctAccounts  int
	Err429Count       int
	Err403Count       int
	Err529Count       int
	Err5xxCount       int
	StreamDisconnects int
	TTFTSampleCount   int
	TTFTRatioP50      *float64
	TTFTRatioP90      *float64
	AvgDurationMs     *float64
	PelicanTotal      int
	PelicanFailed     int
}

// ConcurrencyLevelStats captures decayed metrics and gate pass/fail status at concurrency level c.
type ConcurrencyLevelStats struct {
	ConcurrencyLevel int     `json:"concurrency_level"`
	EffectiveSamples float64 `json:"effective_samples"`
	DistinctAccounts int     `json:"distinct_accounts"`
	UCB429           float64 `json:"ucb_429"`
	UCB403           float64 `json:"ucb_403"`
	UCB529           float64 `json:"ucb_529"`
	TTFTRatioP50     float64 `json:"ttft_ratio_p50,omitempty"`
	TTFTRatioP90     float64 `json:"ttft_ratio_p90,omitempty"`
	PelicanSamples   int     `json:"pelican_samples"`
	PelicanUCB       float64 `json:"pelican_ucb,omitempty"`
	Gate1MinEvidence bool    `json:"gate1_min_evidence"`
	Gate2RiskRates   bool    `json:"gate2_risk_rates"`
	Gate3TTFTKnee    bool    `json:"gate3_ttft_knee"`
	Gate4Pelican     bool    `json:"gate4_pelican"`
	Passed           bool    `json:"passed"`
	FailReason       string  `json:"fail_reason,omitempty"`
}

// ConcurrencyEvaluation holds the empirical recommendation for one bucket before proxy coupling.
type ConcurrencyEvaluation struct {
	Bucket               ConcurrencyBucket       `json:"bucket"`
	Recommended          int                     `json:"recommended_concurrency"`
	CStarEmpirical       *int                    `json:"c_star_empirical,omitempty"`
	CPrior               int                     `json:"c_prior"`
	CHardMax             int                     `json:"c_hard_max"`
	SafetyFactor         float64                 `json:"safety_factor"`
	EffectiveSamples     float64                 `json:"effective_samples"`
	DistinctAccounts     int                     `json:"distinct_accounts"`
	Confidence           string                  `json:"confidence"`
	LimitingFactor       string                  `json:"limiting_factor"`
	AvgRequestDurationMs int                     `json:"avg_request_duration_ms"`
	DegradedAtC1         bool                    `json:"degraded_at_c1,omitempty"`
	Levels               []ConcurrencyLevelStats `json:"levels,omitempty"`
}

// ConcurrencyRecommendation is the full API response for Create/Edit Account prefill.
type ConcurrencyRecommendation struct {
	Bucket                 ConcurrencyBucket `json:"bucket"`
	RecommendedConcurrency int               `json:"recommended_concurrency"`
	BucketRecommended      int               `json:"bucket_recommended"`
	ProxyCoupledCap        *int              `json:"proxy_coupled_cap,omitempty"`
	CStarEmpirical         *int              `json:"c_star_empirical,omitempty"`
	CPrior                 int               `json:"c_prior"`
	CHardMax               int               `json:"c_hard_max"`
	SafetyFactor           float64           `json:"safety_factor"`
	Confidence             string            `json:"confidence"`
	LimitingFactor         string            `json:"limiting_factor"`
	EffectiveSamples       float64           `json:"effective_samples"`
	DistinctAccounts       int               `json:"distinct_accounts"`
	ProxyOversubscribed    bool              `json:"proxy_oversubscribed"`
	Rationale              string            `json:"rationale"`
}

// NormalizeAccountPlanTier canonicalizes plan/tier metadata across platforms.
func NormalizeAccountPlanTier(platform, accountType string, credentials, extra map[string]any) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	t := strings.ToLower(strings.TrimSpace(accountType))
	isOAuth := t == AccountTypeOAuth || t == AccountTypeSetupToken

	first := func(vals ...string) string {
		for _, v := range vals {
			s := strings.ToLower(strings.TrimSpace(v))
			if s != "" {
				return s
			}
		}
		return ""
	}
	getStr := func(m map[string]any, key string) string {
		if m == nil {
			return ""
		}
		s, _ := m[key].(string)
		return strings.TrimSpace(s)
	}

	var raw string
	switch p {
	case PlatformAnthropic:
		if isOAuth {
			raw = first(getStr(credentials, "rate_limit_tier"), getStr(extra, "rate_limit_tier"), getStr(credentials, "subscription_type"), getStr(extra, "claude_plan_tier"), getStr(extra, "subscription_tier"))
			switch {
			case strings.Contains(raw, "20x"):
				return "max_20x"
			case strings.Contains(raw, "5x"):
				return "max_5x"
			case strings.Contains(raw, "enterprise"):
				return "enterprise"
			case strings.Contains(raw, "team"):
				return "team"
			case strings.Contains(raw, "pro"):
				return "pro"
			}
		} else {
			raw = first(getStr(extra, "api_tier"), getStr(credentials, "tier"))
		}
	case PlatformOpenAI:
		if isOAuth {
			raw = first(getStr(credentials, "chatgpt_plan_type"), getStr(credentials, "plan_type"), getStr(extra, "chatgpt_plan_type"), getStr(extra, "subscription_tier"))
			switch raw {
			case "free", "plus", "team", "pro", "enterprise", "edu":
				return raw
			}
		} else {
			raw = first(getStr(extra, "api_tier"), getStr(credentials, "tier"))
		}
	case PlatformGemini:
		raw = first(getStr(credentials, "tier_id"), getStr(extra, "tier_id"))
		switch raw {
		case "google_one_free", "free":
			return "free"
		case "google_ai_pro", "ai_pro":
			return "ai_pro"
		case "google_ai_ultra", "ai_ultra":
			return "ai_ultra"
		case "gcp_standard":
			return "gcp_standard"
		case "aistudio_free":
			return "aistudio_free"
		case "paid":
			return "paid"
		}
	case PlatformAntigravity:
		raw = first(getStr(credentials, "plan_type"), getStr(extra, "plan_type"))
		switch raw {
		case "free", "pro", "ultra":
			return raw
		}
	case PlatformGrok:
		if isOAuth {
			raw = first(getStr(credentials, "plan_type"), getStr(extra, "subscription_tier"))
			switch {
			case strings.Contains(raw, "heavy"):
				return "supergrok_heavy"
			case strings.Contains(raw, "super"):
				return "supergrok"
			case raw == "free":
				return "free"
			}
		}
	case PlatformKimi, PlatformZhipu, "deepseek", PlatformMiniMax, PlatformOpenCodeGo, "opencode":
		raw = first(getStr(credentials, "account_mode"), getStr(extra, "account_mode"))
		switch raw {
		case "coding", "payg":
			return raw
		}
	default:
		raw = first(getStr(extra, "api_tier"), getStr(credentials, "tier"), getStr(credentials, "plan_type"))
	}

	if raw != "" {
		return raw
	}
	if isOAuth {
		return "unknown"
	}
	return "default"
}

// ColdStartConcurrencyPrior returns the conservative anti-ban cold-start prior for a bucket.
func ColdStartConcurrencyPrior(platform, accountType, planTier string) ConcurrencyPriorSpec {
	p := strings.ToLower(strings.TrimSpace(platform))
	t := strings.ToLower(strings.TrimSpace(accountType))
	tier := strings.ToLower(strings.TrimSpace(planTier))
	isOAuth := t == AccountTypeOAuth || t == AccountTypeSetupToken

	switch p {
	case PlatformAnthropic:
		if isOAuth {
			switch tier {
			case "max_20x":
				return ConcurrencyPriorSpec{Prior: 5, HardMax: 8, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			case "team", "enterprise":
				return ConcurrencyPriorSpec{Prior: 4, HardMax: 8, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			case "max_5x":
				return ConcurrencyPriorSpec{Prior: 3, HardMax: 6, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			default: // pro / unknown
				return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			}
		}
		switch tier {
		case "tier_3", "tier_4", "custom":
			return ConcurrencyPriorSpec{Prior: 10, HardMax: 30, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
		case "tier_1", "tier_2":
			return ConcurrencyPriorSpec{Prior: 5, HardMax: 15, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
		default:
			return ConcurrencyPriorSpec{Prior: 8, HardMax: 20, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
		}
	case PlatformOpenAI:
		if isOAuth {
			switch tier {
			case "pro", "enterprise":
				return ConcurrencyPriorSpec{Prior: 4, HardMax: 8, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			case "team", "edu":
				return ConcurrencyPriorSpec{Prior: 3, HardMax: 6, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			case "plus":
				return ConcurrencyPriorSpec{Prior: 2, HardMax: 5, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			default: // free / unknown
				return ConcurrencyPriorSpec{Prior: 1, HardMax: 2, SafetyFactor: 0.70, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			}
		}
		return ConcurrencyPriorSpec{Prior: 8, HardMax: 30, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
	case PlatformGemini:
		if isOAuth {
			switch tier {
			case "ai_ultra":
				return ConcurrencyPriorSpec{Prior: 4, HardMax: 8, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
			case "ai_pro", "gcp_standard":
				return ConcurrencyPriorSpec{Prior: 3, HardMax: 6, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
			default:
				return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
			}
		}
		if tier == "aistudio_free" {
			return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.75, Max429Rate: 0.025, Max403Rate: 0.005, Max529Rate: 0.030}
		}
		return ConcurrencyPriorSpec{Prior: 8, HardMax: 25, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
	case PlatformAntigravity:
		switch tier {
		case "ultra":
			return ConcurrencyPriorSpec{Prior: 4, HardMax: 8, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
		case "pro":
			return ConcurrencyPriorSpec{Prior: 3, HardMax: 6, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
		default:
			return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
		}
	case PlatformGrok:
		if isOAuth {
			switch tier {
			case "supergrok", "supergrok_heavy":
				return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.65, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			default:
				return ConcurrencyPriorSpec{Prior: 1, HardMax: 2, SafetyFactor: 0.65, Max429Rate: 0.015, Max403Rate: 0.0015, Max529Rate: 0.020}
			}
		}
		return ConcurrencyPriorSpec{Prior: 8, HardMax: 25, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
	case PlatformKimi, PlatformZhipu, "deepseek", PlatformMiniMax, PlatformOpenCodeGo, "opencode":
		if tier == "coding" {
			return ConcurrencyPriorSpec{Prior: 3, HardMax: 8, SafetyFactor: 0.80, Max429Rate: 0.025, Max403Rate: 0.005, Max529Rate: 0.030}
		}
		return ConcurrencyPriorSpec{Prior: 8, HardMax: 25, SafetyFactor: 0.80, Max429Rate: 0.025, Max403Rate: 0.005, Max529Rate: 0.030}
	default:
		if isOAuth {
			return ConcurrencyPriorSpec{Prior: 2, HardMax: 4, SafetyFactor: 0.70, Max429Rate: 0.020, Max403Rate: 0.0020, Max529Rate: 0.025}
		}
		return ConcurrencyPriorSpec{Prior: 8, HardMax: 20, SafetyFactor: 0.80, Max429Rate: 0.030, Max403Rate: 0.005, Max529Rate: 0.030}
	}
}

// WilsonUCB95 computes the empirical-Bayes Beta-smoothed 95% Wilson upper confidence bound.
func WilsonUCB95(weightedErrors, effectiveSamples, riskThreshold float64) float64 {
	if effectiveSamples <= 0 {
		return 1.0
	}
	alpha0 := 0.5 * riskThreshold * berthConcurrencyPriorPseudocount
	n := effectiveSamples + berthConcurrencyPriorPseudocount
	pHat := (weightedErrors + alpha0) / n
	if pHat < 0 {
		pHat = 0
	}
	if pHat > 1 {
		pHat = 1
	}
	z := berthConcurrencyWilsonZ95
	z2 := z * z
	denom := 1.0 + z2/n
	center := pHat + z2/(2.0*n)
	rad := z * math.Sqrt((pHat*(1.0-pHat))/n+z2/(4.0*n*n))
	ucb := (center + rad) / denom
	if ucb > 1.0 {
		return 1.0
	}
	return ucb
}

type levelAccum struct {
	sumW           float64
	sumW2          float64
	weighted429    float64
	weighted403    float64
	weighted529    float64
	maxAccounts    int
	ttftWeightSum  float64
	ttftP50Sum     float64
	ttftP90Sum     float64
	durWeightSum   float64
	durMsSum       float64
	pelicanTotal   int
	pelicanFailed  int
}

// EvaluateBucketTelemetry runs the 14-day exponentially decayed 4-gate stability evaluation.
func EvaluateBucketTelemetry(bucket ConcurrencyBucket, prior ConcurrencyPriorSpec, rows []ConcurrencyHourlyRow, now time.Time) ConcurrencyEvaluation {
	eval := ConcurrencyEvaluation{
		Bucket:               bucket,
		Recommended:          maxInt(1, prior.Prior),
		CPrior:               maxInt(1, prior.Prior),
		CHardMax:             maxInt(1, prior.HardMax),
		SafetyFactor:         prior.SafetyFactor,
		Confidence:           "cold_start",
		LimitingFactor:       "prior",
		AvgRequestDurationMs: int(berthConcurrencyDefaultDurSec * 1000),
	}
	if len(rows) == 0 {
		return eval
	}

	byLevel := make(map[int]*levelAccum)
	var globalDurWeight, globalDurSum float64
	cutoff := now.Add(-time.Duration(berthConcurrencyWindowDays) * 24 * time.Hour)

	for _, row := range rows {
		if row.ConcurrencyLevel < 1 || row.TotalRequests <= 0 {
			continue
		}
		if row.BucketHour.Before(cutoff) {
			continue
		}
		ageDays := now.Sub(row.BucketHour).Hours() / 24.0
		if ageDays < 0 {
			ageDays = 0
		}
		w := math.Pow(2.0, -ageDays/berthConcurrencyHalfLifeDays)
		acc := byLevel[row.ConcurrencyLevel]
		if acc == nil {
			acc = &levelAccum{}
			byLevel[row.ConcurrencyLevel] = acc
		}
		n := float64(row.TotalRequests)
		acc.sumW += n * w
		acc.sumW2 += n * w * w
		acc.weighted429 += float64(row.Err429Count) * w
		acc.weighted403 += float64(row.Err403Count) * w
		acc.weighted529 += float64(row.Err529Count) * w
		if row.DistinctAccounts > acc.maxAccounts {
			acc.maxAccounts = row.DistinctAccounts
		}
		if row.TTFTSampleCount > 0 && row.TTFTRatioP50 != nil {
			tw := float64(row.TTFTSampleCount) * w
			acc.ttftWeightSum += tw
			acc.ttftP50Sum += (*row.TTFTRatioP50) * tw
			if row.TTFTRatioP90 != nil {
				acc.ttftP90Sum += (*row.TTFTRatioP90) * tw
			} else {
				acc.ttftP90Sum += (*row.TTFTRatioP50) * tw
			}
		}
		if row.AvgDurationMs != nil && *row.AvgDurationMs > 0 {
			dw := n * w
			acc.durWeightSum += dw
			acc.durMsSum += (*row.AvgDurationMs) * dw
			globalDurWeight += dw
			globalDurSum += (*row.AvgDurationMs) * dw
		}
		acc.pelicanTotal += row.PelicanTotal
		acc.pelicanFailed += row.PelicanFailed
	}

	if globalDurWeight > 0 {
		eval.AvgRequestDurationMs = maxInt(1000, int(math.Round(globalDurSum/globalDurWeight)))
	}

	if len(byLevel) == 0 {
		return eval
	}

	levels := make([]int, 0, len(byLevel))
	for c := range byLevel {
		if c <= prior.HardMax {
			levels = append(levels, c)
		}
	}
	sort.Ints(levels)
	if len(levels) == 0 {
		return eval
	}

	// Baseline Pelican fail rate at c=1 (0 if unavailable).
	p1PelicanRate := 0.0
	if c1 := byLevel[1]; c1 != nil && c1.pelicanTotal > 0 {
		p1PelicanRate = float64(c1.pelicanFailed) / float64(c1.pelicanTotal)
	}

	statsByLevel := make(map[int]ConcurrencyLevelStats, len(levels))
	eval.Levels = make([]ConcurrencyLevelStats, 0, len(levels))
	var totalEffSamples float64
	maxDistinct := 0

	for _, c := range levels {
		acc := byLevel[c]
		neff := 0.0
		if acc.sumW2 > 0 {
			neff = (acc.sumW * acc.sumW) / acc.sumW2
		}
		totalEffSamples += neff
		if acc.maxAccounts > maxDistinct {
			maxDistinct = acc.maxAccounts
		}
		// Scale weighted error counts onto Kish effective sample size n = neff.
		scale := 0.0
		if acc.sumW > 0 {
			scale = neff / acc.sumW
		}
		k429 := acc.weighted429 * scale
		k403 := acc.weighted403 * scale
		k529 := acc.weighted529 * scale

		ucb429 := WilsonUCB95(k429, neff, prior.Max429Rate)
		ucb403 := WilsonUCB95(k403, neff, prior.Max403Rate)
		ucb529 := WilsonUCB95(k529, neff, prior.Max529Rate)

		// When zero errors of a class were observed (k == 0), a small-sample Wilson UCB
		// can exceed a tiny threshold like Max403Rate=0.0020 even on a completely clean level.
		// Gate 2 only flags an error class if errors were actually observed AND UCB exceeds the cap.
		fail429 := k429 > 0 && ucb429 > prior.Max429Rate
		fail403 := k403 > 0 && ucb403 > prior.Max403Rate
		fail529 := k529 > 0 && ucb529 > prior.Max529Rate

		gate1 := neff >= berthConcurrencyMinEffSamples && acc.maxAccounts >= berthConcurrencyMinAccounts
		gate2 := !fail429 && !fail403 && !fail529

		ttftP50, ttftP90 := 1.0, 1.0
		gate3 := true
		if acc.ttftWeightSum > 0 {
			ttftP50 = acc.ttftP50Sum / acc.ttftWeightSum
			ttftP90 = acc.ttftP90Sum / acc.ttftWeightSum
			gate3 = ttftP50 <= berthConcurrencyTTFTMedianLimit && ttftP90 <= berthConcurrencyTTFTP90Limit
		}

		// Cumulative Pelican checks at concurrency >= c.
		pelTotal, pelFailed := 0, 0
		for lvl, a := range byLevel {
			if lvl >= c {
				pelTotal += a.pelicanTotal
				pelFailed += a.pelicanFailed
			}
		}
		gate4 := true
		pelUCB := 0.0
		if pelTotal >= berthConcurrencyPelicanMinN {
			pelUCB = WilsonUCB95(float64(pelFailed), float64(pelTotal), berthConcurrencyPelicanUCBLimit)
			pelRate := float64(pelFailed) / float64(pelTotal)
			gate4 = pelFailed == 0 || (pelUCB <= berthConcurrencyPelicanUCBLimit && pelRate <= p1PelicanRate+berthConcurrencyPelicanDeltaMax)
		}

		failReason := ""
		switch {
		case !gate2:
			if fail403 {
				failReason = "403_rate"
			} else if fail429 {
				failReason = "429_rate"
			} else {
				failReason = "529_rate"
			}
		case !gate3:
			failReason = "ttft_knee"
		case !gate4:
			failReason = "pelican"
		case !gate1:
			failReason = "min_samples"
		}

		st := ConcurrencyLevelStats{
			ConcurrencyLevel: c,
			EffectiveSamples: neff,
			DistinctAccounts: acc.maxAccounts,
			UCB429:           ucb429,
			UCB403:           ucb403,
			UCB529:           ucb529,
			TTFTRatioP50:     ttftP50,
			TTFTRatioP90:     ttftP90,
			PelicanSamples:   pelTotal,
			PelicanUCB:       pelUCB,
			Gate1MinEvidence: gate1,
			Gate2RiskRates:   gate2,
			Gate3TTFTKnee:    gate3,
			Gate4Pelican:     gate4,
			Passed:           gate1 && gate2 && gate3 && gate4,
			FailReason:       failReason,
		}
		statsByLevel[c] = st
		eval.Levels = append(eval.Levels, st)
	}

	eval.EffectiveSamples = totalEffSamples
	eval.DistinctAccounts = maxDistinct

	// Check c=1 degradation signal.
	if st1, ok := statsByLevel[1]; ok && st1.EffectiveSamples >= berthConcurrencyFastDownSamples && (!st1.Gate2RiskRates || !st1.Gate4Pelican) {
		eval.DegradedAtC1 = true
		cStar := 1
		eval.CStarEmpirical = &cStar
		eval.Recommended = 1
		eval.Confidence = confidenceFromSamples(st1.EffectiveSamples)
		eval.LimitingFactor = st1.FailReason
		return eval
	}

	// Fast-down guardrail: if empirical telemetry actively fails Gate 2/3/4 at c <= prior
	// with N_eff >= 100, immediately cap downward without waiting for N_0=500.
	fastDownCap := prior.HardMax
	fastDownReason := ""
	for c := 1; c <= prior.Prior; c++ {
		st, ok := statsByLevel[c]
		if !ok {
			continue
		}
		if st.EffectiveSamples >= berthConcurrencyFastDownSamples && (!st.Gate2RiskRates || !st.Gate3TTFTKnee || !st.Gate4Pelican) {
			fastDownCap = maxInt(1, c-1)
			fastDownReason = st.FailReason
			break
		}
	}
	if fastDownReason != "" {
		cStar := fastDownCap
		eval.CStarEmpirical = &cStar
		eval.Recommended = clampInt(fastDownCap, 1, prior.HardMax)
		eval.Confidence = confidenceFromSamples(totalEffSamples)
		eval.LimitingFactor = fastDownReason
		return eval
	}

	// Walk contiguous stable frontier starting from c=2 up to HardMax.
	cStar := 0
	limitingFactor := "min_samples"
	if st1, ok := statsByLevel[1]; ok && st1.Gate1MinEvidence && st1.Gate2RiskRates && st1.Gate4Pelican {
		cStar = 1
	}
	for c := 2; c <= prior.HardMax; c++ {
		st, ok := statsByLevel[c]
		if !ok {
			limitingFactor = "min_samples"
			break
		}
		if !st.Passed {
			limitingFactor = st.FailReason
			break
		}
		cStar = c
	}

	// Minimum evidence gate: never promote above cold-start prior without passing Gate 1.
	if cStar == 0 {
		eval.Confidence = "cold_start"
		eval.LimitingFactor = "min_samples"
		eval.Recommended = clampInt(prior.Prior, 1, prior.HardMax)
		return eval
	}

	if cStar == prior.HardMax {
		limitingFactor = "hard_max"
	}

	eval.CStarEmpirical = &cStar
	cSafe := maxInt(1, int(math.Floor(prior.SafetyFactor*float64(cStar))))
	cStarSamples := statsByLevel[cStar].EffectiveSamples
	wCred := cStarSamples / (cStarSamples + berthConcurrencyCredibilityN0)
	blended := int(math.Floor(wCred*float64(cSafe) + (1.0-wCred)*float64(prior.Prior) + 0.5))
	eval.Recommended = clampInt(blended, 1, prior.HardMax)
	eval.Confidence = confidenceFromSamples(cStarSamples)
	eval.LimitingFactor = limitingFactor
	return eval
}

func confidenceFromSamples(neff float64) string {
	switch {
	case neff >= 1000:
		return "high"
	case neff >= 300:
		return "medium"
	case neff >= berthConcurrencyFastDownSamples:
		return "low"
	default:
		return "cold_start"
	}
}

// ApplyProxyCapacityCoupling couples a bucket concurrency recommendation with
// the bound landing proxy's max_concurrency and max_rpm across active accounts.
func ApplyProxyCapacityCoupling(
	rec *ConcurrencyRecommendation,
	proxyMaxConcurrency int,
	proxyMaxRPM int,
	activeAccounts int,
	avgDurationSec float64,
) {
	if rec == nil {
		return
	}
	if activeAccounts < 1 {
		activeAccounts = 1
	}
	if avgDurationSec <= 0 {
		avgDurationSec = berthConcurrencyDefaultDurSec
	}

	coupled := rec.BucketRecommended
	limitedBy := ""
	hasCap := false

	if proxyMaxConcurrency > 0 {
		hasCap = true
		if activeAccounts > proxyMaxConcurrency {
			rec.ProxyOversubscribed = true
		}
		proxyConcCap := maxInt(1, proxyMaxConcurrency/activeAccounts)
		if proxyConcCap < coupled {
			coupled = proxyConcCap
			limitedBy = "proxy_max_concurrency"
		}
	}

	if proxyMaxRPM > 0 {
		hasCap = true
		rpmPerAcct := float64(proxyMaxRPM) / float64(activeAccounts)
		proxyRPMCap := maxInt(1, int(math.Floor(0.85*(rpmPerAcct/60.0)*avgDurationSec)))
		if proxyRPMCap < coupled {
			coupled = proxyRPMCap
			limitedBy = "proxy_max_rpm"
		}
	}

	if hasCap {
		capVal := coupled
		rec.ProxyCoupledCap = &capVal
	}
	rec.RecommendedConcurrency = maxInt(1, coupled)
	if limitedBy != "" {
		rec.LimitingFactor = limitedBy
	}
}

// BerthConcurrencyAdvisor computes and serves adaptive concurrency defaults.
type BerthConcurrencyAdvisor struct {
	db     *sql.DB
	stopCh chan struct{}
	once   sync.Once
}

func NewBerthConcurrencyAdvisor(db *sql.DB) *BerthConcurrencyAdvisor {
	return &BerthConcurrencyAdvisor{
		db:     db,
		stopCh: make(chan struct{}),
	}
}

func (a *BerthConcurrencyAdvisor) Start(ctx context.Context) {
	if a == nil || a.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-a.stopCh:
				return
			case <-ticker.C:
				now := time.Now().UTC()
				if err := a.RollupHourlyWindow(ctx, now.Add(-2*time.Hour), now); err != nil {
					slog.Warn("berth_concurrency_rollup_failed", "error", err)
					continue
				}
				if err := a.RecomputeAllRecommendations(ctx, now); err != nil {
					slog.Warn("berth_concurrency_recompute_failed", "error", err)
				}
			}
		}
	}()
}

func (a *BerthConcurrencyAdvisor) Stop() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		if a.stopCh != nil {
			close(a.stopCh)
		}
	})
}

// RecommendForAccount resolves the recommended concurrency for a given bucket and optional proxy.
func (a *BerthConcurrencyAdvisor) RecommendForAccount(
	ctx context.Context,
	platform, accountType, planTier string,
	proxyID *int64,
) *ConcurrencyRecommendation {
	p := strings.ToLower(strings.TrimSpace(platform))
	t := strings.ToLower(strings.TrimSpace(accountType))
	tier := strings.ToLower(strings.TrimSpace(planTier))
	if tier == "" {
		if t == AccountTypeOAuth || t == AccountTypeSetupToken {
			tier = "unknown"
		} else {
			tier = "default"
		}
	}

	prior := ColdStartConcurrencyPrior(p, t, tier)
	rec := &ConcurrencyRecommendation{
		Bucket:                 ConcurrencyBucket{Platform: p, AccountType: t, PlanTier: tier},
		RecommendedConcurrency: maxInt(1, prior.Prior),
		BucketRecommended:      maxInt(1, prior.Prior),
		CPrior:                 maxInt(1, prior.Prior),
		CHardMax:               maxInt(1, prior.HardMax),
		SafetyFactor:           prior.SafetyFactor,
		Confidence:             "cold_start",
		LimitingFactor:         "prior",
	}

	avgDurSec := berthConcurrencyDefaultDurSec
	if a != nil && a.db != nil {
		if snap, ok := a.loadRecommendationRow(ctx, p, t, tier); ok {
			rec.BucketRecommended = maxInt(1, snap.Recommended)
			rec.RecommendedConcurrency = rec.BucketRecommended
			rec.CStarEmpirical = snap.CStarEmpirical
			rec.EffectiveSamples = snap.EffectiveSamples
			rec.DistinctAccounts = snap.DistinctAccounts
			rec.Confidence = snap.Confidence
			rec.LimitingFactor = snap.LimitingFactor
			if snap.AvgRequestDurationMs > 0 {
				avgDurSec = float64(snap.AvgRequestDurationMs) / 1000.0
			}
		}
		if proxyID != nil && *proxyID > 0 {
			var maxConc, maxRPM, activeCount int
			err := a.db.QueryRowContext(ctx, `
				SELECT p.max_concurrency, p.max_rpm,
				       GREATEST(1, (SELECT COUNT(*) FROM accounts a WHERE a.proxy_id = p.id AND a.deleted_at IS NULL AND a.status = 'active'))::int
				FROM proxies p
				WHERE p.id = $1 AND p.deleted_at IS NULL
			`, *proxyID).Scan(&maxConc, &maxRPM, &activeCount)
			if err == nil {
				// Include the account being created/bound as +1 if none currently active.
				ApplyProxyCapacityCoupling(rec, maxConc, maxRPM, activeCount, avgDurSec)
			}
		}
	}

	rec.Rationale = buildConcurrencyRationale(rec, proxyID)
	return rec
}

func (a *BerthConcurrencyAdvisor) loadRecommendationRow(ctx context.Context, platform, accountType, planTier string) (*ConcurrencyEvaluation, bool) {
	if a == nil || a.db == nil {
		return nil, false
	}
	for _, candidateTier := range []string{planTier, "*"} {
		var eval ConcurrencyEvaluation
		var cStar sql.NullInt32
		err := a.db.QueryRowContext(ctx, `
			SELECT recommended_concurrency, c_star_empirical, c_prior, c_hard_max,
			       safety_factor, effective_samples, distinct_accounts,
			       confidence, limiting_factor, avg_request_duration_ms
			FROM berth_concurrency_recommendations
			WHERE platform = $1 AND account_type = $2 AND plan_tier = $3
		`, platform, accountType, candidateTier).Scan(
			&eval.Recommended, &cStar, &eval.CPrior, &eval.CHardMax,
			&eval.SafetyFactor, &eval.EffectiveSamples, &eval.DistinctAccounts,
			&eval.Confidence, &eval.LimitingFactor, &eval.AvgRequestDurationMs,
		)
		if err == nil {
			if cStar.Valid {
				v := int(cStar.Int32)
				eval.CStarEmpirical = &v
			}
			return &eval, true
		}
	}
	return nil, false
}

// RollupHourlyWindow aggregates usage_logs, ops_error_logs, and pelican_tests
// into berth_concurrency_bucket_hourly for [from, to).
func (a *BerthConcurrencyAdvisor) RollupHourlyWindow(ctx context.Context, from, to time.Time) error {
	if a == nil || a.db == nil {
		return nil
	}
	_, err := a.db.ExecContext(ctx, berthConcurrencyHourlyRollupSQL, from.UTC(), to.UTC())
	return err
}

// RecomputeAllRecommendations reads the trailing 14 days of hourly rows and
// upserts berth_concurrency_recommendations for each observed bucket.
func (a *BerthConcurrencyAdvisor) RecomputeAllRecommendations(ctx context.Context, now time.Time) error {
	if a == nil || a.db == nil {
		return nil
	}
	since := now.UTC().Add(-time.Duration(berthConcurrencyWindowDays) * 24 * time.Hour)
	rows, err := a.db.QueryContext(ctx, `
		SELECT bucket_hour, platform, account_type, plan_tier, concurrency_level,
		       total_requests, distinct_accounts, err_429_count, err_403_count,
		       err_529_count, err_5xx_count, stream_disconnects,
		       ttft_sample_count, ttft_ratio_p50, ttft_ratio_p90, avg_duration_ms,
		       pelican_total, pelican_failed
		FROM berth_concurrency_bucket_hourly
		WHERE bucket_hour >= $1
	`, since)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	byBucket := make(map[ConcurrencyBucket][]ConcurrencyHourlyRow)
	byParent := make(map[ConcurrencyBucket][]ConcurrencyHourlyRow)
	for rows.Next() {
		var r ConcurrencyHourlyRow
		var p50, p90, dur sql.NullFloat64
		if err := rows.Scan(
			&r.BucketHour, &r.Platform, &r.AccountType, &r.PlanTier, &r.ConcurrencyLevel,
			&r.TotalRequests, &r.DistinctAccounts, &r.Err429Count, &r.Err403Count,
			&r.Err529Count, &r.Err5xxCount, &r.StreamDisconnects,
			&r.TTFTSampleCount, &p50, &p90, &dur,
			&r.PelicanTotal, &r.PelicanFailed,
		); err != nil {
			return err
		}
		if p50.Valid {
			v := p50.Float64
			r.TTFTRatioP50 = &v
		}
		if p90.Valid {
			v := p90.Float64
			r.TTFTRatioP90 = &v
		}
		if dur.Valid {
			v := dur.Float64
			r.AvgDurationMs = &v
		}
		b := ConcurrencyBucket{Platform: r.Platform, AccountType: r.AccountType, PlanTier: r.PlanTier}
		byBucket[b] = append(byBucket[b], r)
		parent := ConcurrencyBucket{Platform: r.Platform, AccountType: r.AccountType, PlanTier: "*"}
		byParent[parent] = append(byParent[parent], r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	upsert := func(b ConcurrencyBucket, bucketRows []ConcurrencyHourlyRow) error {
		prior := ColdStartConcurrencyPrior(b.Platform, b.AccountType, b.PlanTier)
		eval := EvaluateBucketTelemetry(b, prior, bucketRows, now.UTC())
		rationaleBytes, _ := json.Marshal(eval)
		var cStar any
		if eval.CStarEmpirical != nil {
			cStar = *eval.CStarEmpirical
		}
		_, execErr := a.db.ExecContext(ctx, `
			INSERT INTO berth_concurrency_recommendations (
				platform, account_type, plan_tier, recommended_concurrency,
				c_star_empirical, c_prior, c_hard_max, safety_factor,
				effective_samples, distinct_accounts, confidence, limiting_factor,
				avg_request_duration_ms, rationale_json, window_days, computed_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (platform, account_type, plan_tier) DO UPDATE SET
				recommended_concurrency = EXCLUDED.recommended_concurrency,
				c_star_empirical = EXCLUDED.c_star_empirical,
				c_prior = EXCLUDED.c_prior,
				c_hard_max = EXCLUDED.c_hard_max,
				safety_factor = EXCLUDED.safety_factor,
				effective_samples = EXCLUDED.effective_samples,
				distinct_accounts = EXCLUDED.distinct_accounts,
				confidence = EXCLUDED.confidence,
				limiting_factor = EXCLUDED.limiting_factor,
				avg_request_duration_ms = EXCLUDED.avg_request_duration_ms,
				rationale_json = EXCLUDED.rationale_json,
				window_days = EXCLUDED.window_days,
				computed_at = EXCLUDED.computed_at
		`,
			b.Platform, b.AccountType, b.PlanTier, eval.Recommended,
			cStar, eval.CPrior, eval.CHardMax, eval.SafetyFactor,
			eval.EffectiveSamples, eval.DistinctAccounts, eval.Confidence, eval.LimitingFactor,
			eval.AvgRequestDurationMs, string(rationaleBytes), berthConcurrencyWindowDays, now.UTC(),
		)
		return execErr
	}

	for b, bucketRows := range byBucket {
		if err := upsert(b, bucketRows); err != nil {
			return err
		}
	}
	for b, bucketRows := range byParent {
		if err := upsert(b, bucketRows); err != nil {
			return err
		}
	}
	return nil
}

func buildConcurrencyRationale(rec *ConcurrencyRecommendation, proxyID *int64) string {
	if rec == nil {
		return ""
	}
	base := fmt.Sprintf("Bucket %s/%s/%s cold-start prior=%d (hard max=%d, safety=%.2f)",
		rec.Bucket.Platform, rec.Bucket.AccountType, rec.Bucket.PlanTier,
		rec.CPrior, rec.CHardMax, rec.SafetyFactor)
	if rec.CStarEmpirical != nil {
		base = fmt.Sprintf("14d telemetry across %d %s/%s/%s accounts (n_eff=%.0f) supports c*=%d -> bucket recommended=%d (limiting=%s)",
			rec.DistinctAccounts, rec.Bucket.Platform, rec.Bucket.AccountType, rec.Bucket.PlanTier,
			rec.EffectiveSamples, *rec.CStarEmpirical, rec.BucketRecommended, rec.LimitingFactor)
	}
	if rec.ProxyCoupledCap != nil && proxyID != nil && *proxyID > 0 {
		if rec.ProxyOversubscribed {
			base += fmt.Sprintf("; WARNING: landing proxy #%d is oversubscribed, capped to %d", *proxyID, *rec.ProxyCoupledCap)
		} else if *rec.ProxyCoupledCap < rec.BucketRecommended {
			base += fmt.Sprintf("; capped to %d by landing proxy #%d capacity", *rec.ProxyCoupledCap, *proxyID)
		}
	}
	return base
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

const berthConcurrencyHourlyRollupSQL = `
WITH account_buckets AS (
    SELECT
        a.id AS account_id,
        LOWER(a.platform) AS platform,
        LOWER(a.type) AS account_type,
        COALESCE(
            NULLIF(LOWER(TRIM(
                CASE
                    WHEN a.platform = 'anthropic' AND a.type IN ('oauth', 'setup-token') THEN
                        COALESCE(a.credentials->>'rate_limit_tier', a.extra->>'claude_plan_tier', a.extra->>'subscription_tier')
                    WHEN a.platform IN ('openai', 'antigravity', 'grok') AND a.type IN ('oauth', 'setup-token') THEN
                        COALESCE(a.credentials->>'plan_type', a.extra->>'subscription_tier')
                    WHEN a.platform = 'gemini' THEN
                        a.credentials->>'tier_id'
                    WHEN a.platform IN ('kimi', 'zhipu', 'deepseek', 'minimax', 'opencode', 'opencode_go') THEN
                        a.credentials->>'account_mode'
                    ELSE
                        COALESCE(a.extra->>'api_tier', a.credentials->>'tier')
                END
            )), ''),
            CASE WHEN a.type IN ('oauth', 'setup-token') THEN 'unknown' ELSE 'default' END
        ) AS plan_tier
    FROM accounts a
    WHERE a.deleted_at IS NULL
),
raw_events AS (
    SELECT
        u.account_id,
        u.created_at AS end_ts,
        u.created_at - make_interval(secs => GREATEST(COALESCE(u.duration_ms, 1000), 100) / 1000.0) AS start_ts,
        u.account_concurrency_at_start AS exact_conc,
        COALESCE(NULLIF(u.upstream_model, ''), u.model) AS model_key,
        FLOOR(LN(GREATEST(512, COALESCE(u.input_tokens, 0) + COALESCE(u.cache_creation_tokens, 0))) / LN(2))::INT AS tok_bucket,
        u.first_token_ms,
        u.duration_ms,
        0 AS is_429, 0 AS is_403, 0 AS is_529, 0 AS is_5xx, 0 AS is_disconnect
    FROM usage_logs u
    WHERE u.created_at >= $1 AND u.created_at < $2
    UNION ALL
    SELECT
        e.account_id,
        e.created_at AS end_ts,
        e.created_at - make_interval(secs => GREATEST(COALESCE(e.duration_ms, 500), 100) / 1000.0) AS start_ts,
        e.account_concurrency_at_start AS exact_conc,
        COALESCE(e.model, '') AS model_key,
        0 AS tok_bucket,
        e.time_to_first_token_ms AS first_token_ms,
        e.duration_ms,
        CASE WHEN COALESCE(e.upstream_status_code, e.status_code) = 429 THEN 1 ELSE 0 END,
        CASE WHEN COALESCE(e.upstream_status_code, e.status_code) = 403 THEN 1 ELSE 0 END,
        CASE WHEN COALESCE(e.upstream_status_code, e.status_code) = 529 THEN 1 ELSE 0 END,
        CASE WHEN COALESCE(e.upstream_status_code, e.status_code) >= 500 AND COALESCE(e.upstream_status_code, e.status_code) <> 529 THEN 1 ELSE 0 END,
        CASE WHEN e.error_type ILIKE '%disconnect%' OR e.error_type ILIKE '%eof%' THEN 1 ELSE 0 END
    FROM ops_error_logs e
    WHERE e.created_at >= $1 AND e.created_at < $2
      AND e.account_id IS NOT NULL
      AND e.is_business_limited = FALSE
      AND e.error_phase IN ('upstream', 'forward', 'stream')
),
sweep_points AS (
    SELECT account_id, start_ts AS ts, +1 AS delta FROM raw_events WHERE exact_conc IS NULL
    UNION ALL
    SELECT account_id, end_ts   AS ts, -1 AS delta FROM raw_events WHERE exact_conc IS NULL
),
sweep_running AS (
    SELECT
        account_id,
        ts,
        SUM(delta) OVER (PARTITION BY account_id ORDER BY ts, delta DESC ROWS UNBOUNDED PRECEDING) AS active_conc
    FROM sweep_points
),
events_with_conc AS (
    SELECT
        r.*,
        ab.platform,
        ab.account_type,
        ab.plan_tier,
        GREATEST(1, LEAST(50, COALESCE(
            r.exact_conc,
            (SELECT sr.active_conc FROM sweep_running sr
             WHERE sr.account_id = r.account_id AND sr.ts <= r.start_ts
             ORDER BY sr.ts DESC LIMIT 1),
            1
        )))::SMALLINT AS c_obs
    FROM raw_events r
    JOIN account_buckets ab ON ab.account_id = r.account_id
),
ttft_baseline AS (
    SELECT
        platform, account_type, plan_tier, model_key, tok_bucket,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY first_token_ms) AS base_ttft_p50
    FROM events_with_conc
    WHERE c_obs = 1 AND first_token_ms > 0 AND is_429 = 0 AND is_403 = 0 AND is_529 = 0 AND is_5xx = 0
    GROUP BY 1, 2, 3, 4, 5
    HAVING COUNT(*) >= 10
),
pelican_with_peak AS (
    SELECT
        date_trunc('hour', p.created_at) AS bucket_hour,
        ab.platform, ab.account_type, ab.plan_tier,
        GREATEST(1, COALESCE((
            SELECT MAX(ec.c_obs) FROM events_with_conc ec
            WHERE ec.account_id = p.account_id
              AND ec.end_ts BETWEEN p.created_at - INTERVAL '60 minutes' AND p.created_at
        ), 1))::SMALLINT AS c_obs,
        COUNT(*) AS pelican_total,
        COUNT(*) FILTER (WHERE p.status <> 'success') AS pelican_failed
    FROM pelican_tests p
    JOIN account_buckets ab ON ab.account_id = p.account_id
    WHERE p.created_at >= $1 AND p.created_at < $2
      AND p.status <> 'running'
    GROUP BY 1, 2, 3, 4, 5
)
INSERT INTO berth_concurrency_bucket_hourly (
    bucket_hour, platform, account_type, plan_tier, concurrency_level,
    total_requests, distinct_accounts, err_429_count, err_403_count, err_529_count,
    err_5xx_count, stream_disconnects, ttft_sample_count, ttft_ratio_p50, ttft_ratio_p90,
    avg_duration_ms, pelican_total, pelican_failed, updated_at
)
SELECT
    date_trunc('hour', e.end_ts) AS bucket_hour,
    e.platform, e.account_type, e.plan_tier, e.c_obs,
    COUNT(*)::INT AS total_requests,
    COUNT(DISTINCT e.account_id)::INT AS distinct_accounts,
    SUM(e.is_429)::INT, SUM(e.is_403)::INT, SUM(e.is_529)::INT, SUM(e.is_5xx)::INT, SUM(e.is_disconnect)::INT,
    COUNT(*) FILTER (WHERE e.first_token_ms > 0 AND b.base_ttft_p50 > 0)::INT,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY e.first_token_ms / NULLIF(b.base_ttft_p50, 0))
        FILTER (WHERE e.first_token_ms > 0 AND b.base_ttft_p50 > 0),
    PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY e.first_token_ms / NULLIF(b.base_ttft_p50, 0))
        FILTER (WHERE e.first_token_ms > 0 AND b.base_ttft_p50 > 0),
    AVG(e.duration_ms) FILTER (WHERE e.duration_ms > 0),
    COALESCE(MAX(pw.pelican_total), 0)::INT,
    COALESCE(MAX(pw.pelican_failed), 0)::INT,
    NOW()
FROM events_with_conc e
LEFT JOIN ttft_baseline b
    ON b.platform = e.platform AND b.account_type = e.account_type
   AND b.plan_tier = e.plan_tier AND b.model_key = e.model_key AND b.tok_bucket = e.tok_bucket
LEFT JOIN pelican_with_peak pw
    ON pw.bucket_hour = date_trunc('hour', e.end_ts)
   AND pw.platform = e.platform AND pw.account_type = e.account_type
   AND pw.plan_tier = e.plan_tier AND pw.c_obs = e.c_obs
GROUP BY 1, 2, 3, 4, 5
ON CONFLICT (bucket_hour, platform, account_type, plan_tier, concurrency_level)
DO UPDATE SET
    total_requests = EXCLUDED.total_requests,
    distinct_accounts = EXCLUDED.distinct_accounts,
    err_429_count = EXCLUDED.err_429_count,
    err_403_count = EXCLUDED.err_403_count,
    err_529_count = EXCLUDED.err_529_count,
    err_5xx_count = EXCLUDED.err_5xx_count,
    stream_disconnects = EXCLUDED.stream_disconnects,
    ttft_sample_count = EXCLUDED.ttft_sample_count,
    ttft_ratio_p50 = EXCLUDED.ttft_ratio_p50,
    ttft_ratio_p90 = EXCLUDED.ttft_ratio_p90,
    avg_duration_ms = EXCLUDED.avg_duration_ms,
    pelican_total = EXCLUDED.pelican_total,
    pelican_failed = EXCLUDED.pelican_failed,
    updated_at = NOW();
`
