//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAccountPlanTier(t *testing.T) {
	require.Equal(t, "max_20x", NormalizeAccountPlanTier(PlatformAnthropic, AccountTypeOAuth, nil, map[string]any{"rate_limit_tier": "default_claude_max_20x"}))
	require.Equal(t, "max_5x", NormalizeAccountPlanTier(PlatformAnthropic, AccountTypeOAuth, nil, map[string]any{"rate_limit_tier": "default_claude_max_5x"}))
	require.Equal(t, "pro", NormalizeAccountPlanTier(PlatformAnthropic, AccountTypeOAuth, map[string]any{"subscription_type": "claude_pro"}, nil))
	require.Equal(t, "team", NormalizeAccountPlanTier(PlatformOpenAI, AccountTypeOAuth, map[string]any{"chatgpt_plan_type": "team"}, nil))
	require.Equal(t, "plus", NormalizeAccountPlanTier(PlatformOpenAI, AccountTypeOAuth, map[string]any{"plan_type": "plus"}, nil))
	require.Equal(t, "free", NormalizeAccountPlanTier(PlatformGrok, AccountTypeOAuth, map[string]any{"plan_type": "free"}, nil))
	require.Equal(t, "supergrok", NormalizeAccountPlanTier(PlatformGrok, AccountTypeOAuth, map[string]any{"plan_type": "SuperGrok"}, nil))
	require.Equal(t, "coding", NormalizeAccountPlanTier(PlatformKimi, AccountTypeAPIKey, map[string]any{"account_mode": "coding"}, nil))
	require.Equal(t, "default", NormalizeAccountPlanTier(PlatformAnthropic, AccountTypeAPIKey, nil, nil))
}

func TestColdStartConcurrencyPrior(t *testing.T) {
	require.Equal(t, 3, ColdStartConcurrencyPrior(PlatformAnthropic, AccountTypeOAuth, "max_5x").Prior)
	require.Equal(t, 5, ColdStartConcurrencyPrior(PlatformAnthropic, AccountTypeOAuth, "max_20x").Prior)
	require.Equal(t, 2, ColdStartConcurrencyPrior(PlatformAnthropic, AccountTypeOAuth, "pro").Prior)
	require.Equal(t, 3, ColdStartConcurrencyPrior(PlatformOpenAI, AccountTypeOAuth, "team").Prior)
	require.Equal(t, 2, ColdStartConcurrencyPrior(PlatformOpenAI, AccountTypeOAuth, "plus").Prior)
	require.Equal(t, 1, ColdStartConcurrencyPrior(PlatformGrok, AccountTypeOAuth, "free").Prior)
	require.Equal(t, 1, ColdStartConcurrencyPrior(PlatformGrok, AccountTypeOAuth, "unknown").Prior)
	require.GreaterOrEqual(t, ColdStartConcurrencyPrior(PlatformAnthropic, AccountTypeAPIKey, "default").Prior, 8)
	require.GreaterOrEqual(t, ColdStartConcurrencyPrior(PlatformOpenAI, AccountTypeAPIKey, "default").Prior, 8)
}

func TestWilsonUCB95_Properties(t *testing.T) {
	smallSample := WilsonUCB95(0, 10, 0.02)
	largeSample := WilsonUCB95(0, 500, 0.02)
	require.Greater(t, smallSample, largeSample, "more clean samples must shrink upper confidence bound")
	require.Greater(t, WilsonUCB95(20, 100, 0.02), 0.15)
}

func TestEvaluateBucketTelemetry_ColdStartAndMinSampleGate(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	bucket := ConcurrencyBucket{Platform: PlatformAnthropic, AccountType: AccountTypeOAuth, PlanTier: "max_5x"}
	prior := ColdStartConcurrencyPrior(bucket.Platform, bucket.AccountType, bucket.PlanTier)

	// Empty rows -> cold_start with prior.
	emptyRes := EvaluateBucketTelemetry(bucket, prior, nil, now)
	require.Equal(t, "cold_start", emptyRes.Confidence)
	require.Equal(t, 3, emptyRes.Recommended)
	require.Equal(t, "prior", emptyRes.LimitingFactor)

	// Below minimum sample gate (only 40 clean requests at concurrency=6 across 2 accounts):
	// MUST NOT promote above c_prior=3!
	fewRows := []ConcurrencyHourlyRow{
		{
			BucketHour:       now.Add(-1 * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 6,
			TotalRequests:    40,
			DistinctAccounts: 2,
			TTFTSampleCount:  40,
			TTFTRatioP50:     floatPtr(1.02),
			TTFTRatioP90:     floatPtr(1.05),
		},
	}
	gatedRes := EvaluateBucketTelemetry(bucket, prior, fewRows, now)
	require.LessOrEqual(t, gatedRes.Recommended, 3, "min sample gate must prevent premature promotion above cold-start prior")
}

func TestEvaluateBucketTelemetry_FastDownGuardrail(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	bucket := ConcurrencyBucket{Platform: PlatformAnthropic, AccountType: AccountTypeOAuth, PlanTier: "max_5x"}
	prior := ColdStartConcurrencyPrior(bucket.Platform, bucket.AccountType, bucket.PlanTier)

	// Heavy 429 burst at concurrency=3 (>=100 fast-down samples) must reduce below prior (3 -> <=2).
	rows := []ConcurrencyHourlyRow{
		{
			BucketHour:       now.Add(-1 * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 1,
			TotalRequests:    250,
			DistinctAccounts: 4,
			TTFTSampleCount:  250,
			TTFTRatioP50:     floatPtr(1.02),
			TTFTRatioP90:     floatPtr(1.05),
		},
		{
			BucketHour:       now.Add(-1 * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 3,
			TotalRequests:    120,
			DistinctAccounts: 3,
			Err429Count:      50,
			TTFTSampleCount:  70,
			TTFTRatioP50:     floatPtr(1.05),
			TTFTRatioP90:     floatPtr(1.10),
		},
	}
	res := EvaluateBucketTelemetry(bucket, prior, rows, now)
	require.Less(t, res.Recommended, 3, "fast-down guardrail must reduce below prior when 429 rate breaches threshold")
	require.Equal(t, "429_rate", res.LimitingFactor)
}

func TestEvaluateBucketTelemetry_EmpiricalPromotionAndTTFTKnee(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	// Use anthropic/apikey/tier_1 (Prior=5, HardMax=15, SafetyFactor=0.80):
	// Contiguous levels 2..10 clean (>=1000 requests each across 5 accounts), level 11 trips TTFT knee (p90=2.20 > 1.65)
	// -> c_star = 10, safety factor 0.80 -> floor(10 * 0.80) = 8 > prior(5), limiting_factor = "ttft_knee".
	bucket := ConcurrencyBucket{Platform: PlatformAnthropic, AccountType: AccountTypeAPIKey, PlanTier: "tier_1"}
	prior := ColdStartConcurrencyPrior(bucket.Platform, bucket.AccountType, bucket.PlanTier)

	var rows []ConcurrencyHourlyRow
	for _, level := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10} {
		for h := 1; h <= 6; h++ {
			rows = append(rows, ConcurrencyHourlyRow{
				BucketHour:       now.Add(-time.Duration(h) * time.Hour),
				Platform:         bucket.Platform,
				AccountType:      bucket.AccountType,
				PlanTier:         bucket.PlanTier,
				ConcurrencyLevel: level,
				TotalRequests:    200,
				DistinctAccounts: 5,
				TTFTSampleCount:  200,
				TTFTRatioP50:     floatPtr(1.05),
				TTFTRatioP90:     floatPtr(1.15),
			})
		}
	}
	for h := 1; h <= 6; h++ {
		rows = append(rows, ConcurrencyHourlyRow{
			BucketHour:       now.Add(-time.Duration(h) * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 11,
			TotalRequests:    200,
			DistinctAccounts: 5,
			TTFTSampleCount:  200,
			TTFTRatioP50:     floatPtr(1.60),
			TTFTRatioP90:     floatPtr(2.20),
		})
	}

	res := EvaluateBucketTelemetry(bucket, prior, rows, now)
	require.NotNil(t, res.CStarEmpirical)
	require.Equal(t, 10, *res.CStarEmpirical)
	// cSafe = floor(10 * 0.80) = 8; empirical-Bayes shrinkage with N0=500 at n_eff~=1200 blends prior(5) and cSafe(8) -> 7.
	require.Equal(t, 7, res.Recommended)
	require.Greater(t, res.Recommended, prior.Prior)
	require.Equal(t, "ttft_knee", res.LimitingFactor)
	require.Contains(t, []string{"high", "medium"}, res.Confidence)
}

func TestEvaluateBucketTelemetry_PelicanGate(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	bucket := ConcurrencyBucket{Platform: PlatformAnthropic, AccountType: AccountTypeOAuth, PlanTier: "max_20x"}
	prior := ColdStartConcurrencyPrior(bucket.Platform, bucket.AccountType, bucket.PlanTier)

	rows := []ConcurrencyHourlyRow{
		{
			BucketHour:       now.Add(-1 * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 3,
			TotalRequests:    500,
			DistinctAccounts: 5,
			TTFTSampleCount:  500,
			TTFTRatioP50:     floatPtr(1.05),
			TTFTRatioP90:     floatPtr(1.10),
			PelicanTotal:     40,
			PelicanFailed:    0,
		},
		{
			BucketHour:       now.Add(-1 * time.Hour),
			Platform:         bucket.Platform,
			AccountType:      bucket.AccountType,
			PlanTier:         bucket.PlanTier,
			ConcurrencyLevel: 5,
			TotalRequests:    500,
			DistinctAccounts: 5,
			TTFTSampleCount:  500,
			TTFTRatioP50:     floatPtr(1.05),
			TTFTRatioP90:     floatPtr(1.10),
			PelicanTotal:     40,
			PelicanFailed:    12, // 30% Pelican failure -> trips Pelican degradation gate!
		},
	}
	res := EvaluateBucketTelemetry(bucket, prior, rows, now)
	require.Equal(t, "pelican", res.LimitingFactor)
	require.Less(t, res.Recommended, 5)
}

func TestApplyProxyCapacityCoupling(t *testing.T) {
	// Proxy MaxConcurrency=6, 3 active accounts -> floor(6/3)=2; caps 5 down to 2.
	rec := &ConcurrencyRecommendation{BucketRecommended: 5, RecommendedConcurrency: 5}
	ApplyProxyCapacityCoupling(rec, 6, 0, 3, 18.0)
	require.Equal(t, 2, rec.RecommendedConcurrency)
	require.NotNil(t, rec.ProxyCoupledCap)
	require.Equal(t, 2, *rec.ProxyCoupledCap)
	require.False(t, rec.ProxyOversubscribed)
	require.Equal(t, "proxy_max_concurrency", rec.LimitingFactor)

	// Oversubscribed proxy: MaxConcurrency=2, 6 active accounts -> floor(2/6)=0 -> clamp 1 + ProxyOversubscribed=true.
	recOver := &ConcurrencyRecommendation{BucketRecommended: 3, RecommendedConcurrency: 3}
	ApplyProxyCapacityCoupling(recOver, 2, 0, 6, 18.0)
	require.Equal(t, 1, recOver.RecommendedConcurrency)
	require.True(t, recOver.ProxyOversubscribed)

	// Unlimited proxy (0, 0) -> uncapped.
	recUnlim := &ConcurrencyRecommendation{BucketRecommended: 4, RecommendedConcurrency: 4}
	ApplyProxyCapacityCoupling(recUnlim, 0, 0, 10, 18.0)
	require.Equal(t, 4, recUnlim.RecommendedConcurrency)
	require.Nil(t, recUnlim.ProxyCoupledCap)
	require.False(t, recUnlim.ProxyOversubscribed)
}

func TestBerthConcurrencyAdvisor_RecommendForAccountWithSQLMock(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	advisor := NewBerthConcurrencyAdvisor(db)
	proxyID := int64(42)

	mock.ExpectQuery(`FROM berth_concurrency_recommendations`).
		WithArgs(PlatformAnthropic, AccountTypeOAuth, "max_20x").
		WillReturnRows(sqlmock.NewRows([]string{
			"recommended_concurrency", "c_star_empirical", "c_prior", "c_hard_max",
			"safety_factor", "effective_samples", "distinct_accounts", "confidence",
			"limiting_factor", "avg_request_duration_ms",
		}).AddRow(6, 9, 5, 10, 0.70, 500.0, 6, "high", "429_rate", 15000))

	mock.ExpectQuery(`SELECT p\.max_concurrency, p\.max_rpm`).
		WithArgs(proxyID).
		WillReturnRows(sqlmock.NewRows([]string{"max_concurrency", "max_rpm", "active_count"}).AddRow(6, 0, 3))

	rec := advisor.RecommendForAccount(context.Background(), PlatformAnthropic, AccountTypeOAuth, "max_20x", &proxyID)
	require.NotNil(t, rec)
	require.Equal(t, 2, rec.RecommendedConcurrency, "proxy cap floor(6/3)=2 must constrain bucket recommendation 6")
	require.NotNil(t, rec.ProxyCoupledCap)
	require.Equal(t, 2, *rec.ProxyCoupledCap)
	require.False(t, rec.ProxyOversubscribed)
	require.Equal(t, "high", rec.Confidence)
	require.NoError(t, mock.ExpectationsWereMet())
}
