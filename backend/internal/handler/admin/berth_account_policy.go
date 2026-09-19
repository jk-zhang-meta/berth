package admin

import (
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

// Account handlers are shared by the authenticated user and administrator routes.
func isAccountUser(c *gin.Context) bool {
	role, ok := middleware.GetUserRoleFromContext(c)
	return ok && role != service.RoleAdmin
}

func privateAccountOwner(c *gin.Context) int64 {
	if !isAccountUser(c) {
		return 0
	}
	if subject, ok := middleware.GetAuthSubjectFromContext(c); ok {
		return subject.UserID
	}
	return 0
}

func allowAccountProxy(c *gin.Context, store *service.StewardStore, proxyID *int64) bool {
	if proxyID == nil || *proxyID == 0 {
		return true
	}
	if *proxyID < 0 {
		response.BadRequest(c, "Invalid proxy ID")
		return false
	}
	if !isAccountUser(c) {
		if store != nil && !store.HasVerifiedProxyExit(c.Request.Context(), *proxyID) {
			response.BadRequest(c, "proxy exit IP and timezone must be verified before binding")
			return false
		}
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || store == nil || !store.CanUseProxy(c.Request.Context(), *proxyID, subject.UserID) {
		response.Forbidden(c, "not your proxy")
		return false
	}
	return true
}

func accountCreatePolicy(c *gin.Context, input *service.CreateAccountInput) *service.CreateAccountInput {
	if isAccountUser(c) {
		if subject, ok := middleware.GetAuthSubjectFromContext(c); ok {
			input.PrivateOwnerUserID = subject.UserID
		}
		input.GroupIDs = nil
		input.Priority = 0
		input.RateMultiplier = nil
		input.SkipDefaultGroupBind = true
	}
	return input
}

type accountImportCaller struct {
	userID     int64
	restricted bool
}

func (h *AntigravityOAuthHandler) SetStewards(store *service.StewardStore) { h.stewards = store }
func (h *GeminiOAuthHandler) SetStewards(store *service.StewardStore)      { h.stewards = store }
func (h *OAuthHandler) SetStewards(store *service.StewardStore)            { h.stewards = store }
