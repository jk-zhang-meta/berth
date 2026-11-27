//go:build unit

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/usagestats"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

type countingTodayStatsUsageRepo struct {
	service.UsageLogRepository
	calls atomic.Int64
	reqs  atomic.Int64
}

func (r *countingTodayStatsUsageRepo) GetAccountTodayStats(_ context.Context, _ int64) (*usagestats.AccountStats, error) {
	r.calls.Add(1)
	return &usagestats.AccountStats{Requests: r.reqs.Load()}, nil
}

func (r *countingTodayStatsUsageRepo) GetAccountWindowStats(_ context.Context, _ int64, _ time.Time) (*usagestats.AccountStats, error) {
	r.calls.Add(1)
	return &usagestats.AccountStats{Requests: r.reqs.Load()}, nil
}

func (r *countingTodayStatsUsageRepo) GetAccountWindowStatsBatch(_ context.Context, ids []int64, _ time.Time) (map[int64]*usagestats.AccountStats, error) {
	r.calls.Add(1)
	out := make(map[int64]*usagestats.AccountStats, len(ids))
	for _, id := range ids {
		out[id] = &usagestats.AccountStats{Requests: r.reqs.Load()}
	}
	return out, nil
}

func TestGetBatchTodayStats_ForceAndInvalidationBypassStaleCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	InvalidateAccountTodayStatsCache()

	repo := &countingTodayStatsUsageRepo{}
	repo.reqs.Store(1)
	usageSvc := service.NewAccountUsageService(nil, repo, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := NewAccountHandler(nil, nil, nil, nil, nil, nil, nil, usageSvc, nil, nil, nil, nil, nil, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUserRole), service.RoleAdmin)
		c.Next()
	})
	r.POST("/api/v1/admin/accounts/today-stats/batch", h.GetBatchTodayStats)

	post := func(body string) (int, string, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/today-stats/batch", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return w.Code, w.Header().Get("X-Snapshot-Cache"), resp
	}

	// 1st call populates cache with requests=1
	code, cacheHdr, _ := post(`{"account_ids":[23]}`)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "miss", cacheHdr)
	require.Equal(t, int64(1), repo.calls.Load())

	// Underlying count increases to 5; force:true MUST bypass cache and return 5 immediately.
	repo.reqs.Store(5)
	code, cacheHdr, resp := post(`{"account_ids":[23],"force":true}`)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "miss", cacheHdr)
	require.Equal(t, int64(2), repo.calls.Load())
	data := resp["data"].(map[string]any)["stats"].(map[string]any)["23"].(map[string]any)
	require.Equal(t, float64(5), data["requests"])

	// InvalidateAccountTodayStatsCache() must clear cache so even non-forced call refreshes.
	repo.reqs.Store(9)
	InvalidateAccountTodayStatsCache()
	code, cacheHdr, resp = post(`{"account_ids":[23]}`)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "miss", cacheHdr)
	require.Equal(t, int64(3), repo.calls.Load())
	data = resp["data"].(map[string]any)["stats"].(map[string]any)["23"].(map[string]any)
	require.Equal(t, float64(9), data["requests"])
}
