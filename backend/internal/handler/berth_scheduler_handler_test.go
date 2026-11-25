//go:build unit

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	middleware2 "github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

type stubTempUnscheduler struct{ calls int }

func (s *stubTempUnscheduler) TempUnscheduleRetryableError(_ context.Context, _ int64, _ *service.UpstreamFailoverError) {
	s.calls++
}

func TestBerthConcurrencyHandler_ColdStartAndProxyRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("cold_start_prior_returned_for_user", func(t *testing.T) {
		advisor := service.NewBerthConcurrencyAdvisor(nil)
		h := NewBerthConcurrencyHandler(advisor, nil)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/berth/pool/accounts/recommended-concurrency?platform=anthropic&type=oauth&plan_tier=max_5x", nil)
		c.Set(string(middleware2.ContextKeyUserRole), service.RoleUser)
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 7})

		h.GetRecommendedConcurrency(c)
		require.Equal(t, http.StatusOK, rec.Code)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		data := payload["data"].(map[string]any)
		require.Equal(t, float64(3), data["recommended_concurrency"])
		require.Equal(t, "cold_start", data["confidence"])
	})

	t.Run("non_admin_foreign_proxy_rejected_403", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		stewards := service.NewStewardStore(db)
		advisor := service.NewBerthConcurrencyAdvisor(nil)
		h := NewBerthConcurrencyHandler(advisor, stewards)

		// CanUseProxy checks owned proxy then active rental -> both return false
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(7), int64(999)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs(int64(7), int64(999)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/berth/pool/accounts/recommended-concurrency?platform=anthropic&type=oauth&proxy_id=999", nil)
		c.Set(string(middleware2.ContextKeyUserRole), service.RoleUser)
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 7})

		h.GetRecommendedConcurrency(c)
		require.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("missing_role_fails_closed_403", func(t *testing.T) {
		advisor := service.NewBerthConcurrencyAdvisor(nil)
		h := NewBerthConcurrencyHandler(advisor, nil)

		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/berth/pool/accounts/recommended-concurrency?platform=openai&type=oauth&proxy_id=5", nil)

		h.GetRecommendedConcurrency(c)
		require.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestWriteCageRebindRequiredResponse_PreCommitVsPostCommit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rebindErr := &service.ErrCageRebindRequired{
		Reason:              "cage_rebind_required",
		Message:             "all accounts in America/Denver exhausted",
		CurrentCohortTZ:     "America/Denver",
		RecommendedCohortTZ: "America/Chicago",
		AvailableCohorts: []service.CohortAvailability{
			{Timezone: "America/Chicago", CountryCode: "US", AvailableCount: 3},
		},
		RetryAfterSeconds: 5,
	}

	t.Run("pre_commit_emits_http_409_with_headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

		fallbackCalled := false
		writeCageRebindRequiredResponse(c, rebindErr, false, func(*gin.Context, int, string, string, bool) {
			fallbackCalled = true
		})
		require.False(t, fallbackCalled)
		require.Equal(t, http.StatusConflict, rec.Code)
		require.Equal(t, "cage_rebind_required", rec.Header().Get(service.HeaderBerthFailoverReason))
		require.Equal(t, "America/Denver", rec.Header().Get(service.HeaderBerthSessionCohortTZ))
		require.Equal(t, "America/Chicago", rec.Header().Get(service.HeaderBerthRecommendedCohortTZ))
		require.Equal(t, "America/Chicago:3", rec.Header().Get(service.HeaderBerthAvailableCohorts))
		require.Equal(t, "5", rec.Header().Get("Retry-After"))
	})

	t.Run("post_commit_never_emits_http_409", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		c.Writer.WriteHeader(http.StatusOK)

		fallbackCalled := false
		var fallbackErrType string
		writeCageRebindRequiredResponse(c, rebindErr, true, func(_ *gin.Context, _ int, errType, _ string, started bool) {
			fallbackCalled = true
			fallbackErrType = errType
			require.True(t, started)
		})
		require.True(t, fallbackCalled)
		require.Equal(t, "cage_rebind_required", fallbackErrType)
		require.Equal(t, http.StatusOK, rec.Code, "committed stream must never overwrite status with 409")
	})
}

func TestFailoverState_BlastRadius403CapAndZeroSameAccountRetry(t *testing.T) {
	guard := service.NewBerthBlastRadiusGuard()
	fs := NewFailoverState(10, true)
	fs.OperationID = "op-403-test"
	fs.SessionHash = "sess-403-test"
	fs.BlastRadius = guard
	fs.DisableJitter = true

	unsched := &stubTempUnscheduler{}
	err403 := &service.UpstreamFailoverError{
		StatusCode:             http.StatusForbidden,
		RetryableOnSameAccount: true, // even if caller sets true, 403 MUST do 0 same-account retries!
	}

	// Account 1 fails with 403 -> NO same-account retry, switches immediately to Account 2.
	act1 := fs.HandleFailoverError(context.Background(), unsched, 1, service.PlatformAnthropic, 3, err403)
	require.Equal(t, FailoverContinue, act1)
	require.Equal(t, 0, fs.SameAccountRetryCount[1], "403 must never perform same-account retry")
	require.Equal(t, 1, fs.SwitchCount)
	require.False(t, fs.SessionToxic)

	// Account 2 fails with 403 -> hits max 2 distinct accounts cap -> exhausted + SessionToxic=true!
	act2 := fs.HandleFailoverError(context.Background(), unsched, 2, service.PlatformAnthropic, 3, err403)
	require.Equal(t, FailoverExhausted, act2)
	require.True(t, fs.SessionToxic)
	require.Equal(t, 1, fs.SwitchCount)
}
