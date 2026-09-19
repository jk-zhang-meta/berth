package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceUnsupportedModesStopBeforeUpstream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &OpenAIGatewayHandler{}
	for _, tc := range []struct {
		name, platform string
		run            func(*gin.Context)
	}{
		{"live", service.PlatformOpenAI, h.Live}, {"sideband", service.PlatformOpenAI, h.LiveSideband},
		{"grok realtime", service.PlatformGrok, h.GrokRealtime},
		{"grok video create", service.PlatformGrok, h.GrokVideoGeneration},
		{"grok video edit", service.PlatformGrok, h.GrokVideoEdit},
		{"grok video extend", service.PlatformGrok, h.GrokVideoExtension},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(r)
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			c.Request.Header.Set("Upgrade", "websocket")
			c.Request.Header.Set("Connection", "Upgrade")
			key := &service.APIKey{ID: 1, UserID: 2, Group: &service.Group{Platform: tc.platform, AllowLive: true}, MarketplaceUsage: &service.MarketplaceUsageSnapshot{}}
			c.Set(string(middleware.ContextKeyAPIKey), key)
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 2})
			tc.run(c)
			require.Equal(t, http.StatusForbidden, r.Code, "nil upstream dependencies must not be reached")
		})
	}
}

func TestMarketplaceBatchOwnerAndCrossGroupFallback(t *testing.T) {
	groupID := int64(1)
	key := &service.APIKey{ID: 1, UserID: 2, GroupID: &groupID, Group: &service.Group{ID: 1, Platform: service.PlatformOpenAI, AllowLive: true}}
	require.True(t, liveEnabledForAPIKey(key))
	require.NotNil(t, cloneAPIKeyWithGroup(key, &service.Group{ID: 2}))
	key.MarketplaceUsage = &service.MarketplaceUsageSnapshot{GroupID: 1}
	require.False(t, liveEnabledForAPIKey(key))
	require.Nil(t, cloneAPIKeyWithGroup(key, &service.Group{ID: 2}))
	require.Same(t, key.MarketplaceUsage, cloneAPIKeyWithGroup(key, &service.Group{ID: 1}).MarketplaceUsage)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(string(middleware.ContextKeyAPIKey), key)
	owner, ok := batchImageOwnerFromContext(c)
	require.True(t, ok)
	require.True(t, owner.MarketplaceUsage)
	s := &service.BatchImagePublicService{}
	_, err := s.Submit(context.Background(), owner, service.BatchImageSubmitRequest{}, "")
	require.ErrorIs(t, err, service.ErrBatchImageGroupDisabled)
	_, err = s.ListModels(context.Background(), owner)
	require.ErrorIs(t, err, service.ErrBatchImageGroupDisabled)
}
