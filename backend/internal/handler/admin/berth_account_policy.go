package admin

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/adminaccess"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
)

// Account and proxy handlers are shared by authenticated user and administrator
// routes. Every helper below is strictly fail-closed: missing role context,
// invalid auth subject, or a nil StewardStore always denies non-admin callers.

func isAdminCaller(c *gin.Context) bool {
	if c == nil {
		return false
	}
	role, ok := middleware.GetUserRoleFromContext(c)
	if ok && role == service.RoleAdmin {
		return true
	}
	if c.Request != nil && adminaccess.FromContext(c.Request.Context()) != nil {
		return true
	}
	return false
}

func isAccountUser(c *gin.Context) bool {
	return !isAdminCaller(c)
}

func requireAdmin(c *gin.Context) bool {
	if isAdminCaller(c) {
		return true
	}
	response.Forbidden(c, "admin only")
	return false
}

func requireStewardAccount(c *gin.Context, store *service.StewardStore, accountID int64) bool {
	if isAdminCaller(c) {
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil || !store.OwnsAccount(c.Request.Context(), accountID, subject.UserID) {
		response.Forbidden(c, "not your account")
		return false
	}
	return true
}

func requireStewardAccounts(c *gin.Context, store *service.StewardStore, accountIDs []int64) bool {
	if isAdminCaller(c) {
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil {
		response.Forbidden(c, "forbidden")
		return false
	}
	for _, id := range accountIDs {
		if !store.OwnsAccount(c.Request.Context(), id, subject.UserID) {
			response.Forbidden(c, "not your account")
			return false
		}
	}
	return true
}

func requireStewardProxy(c *gin.Context, store *service.StewardStore, proxyID int64) bool {
	if isAdminCaller(c) {
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil || !store.OwnsProxy(c.Request.Context(), proxyID, subject.UserID) {
		response.Forbidden(c, "not your proxy")
		return false
	}
	return true
}

func requireStewardProxies(c *gin.Context, store *service.StewardStore, proxyIDs []int64) bool {
	if isAdminCaller(c) {
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil {
		response.Forbidden(c, "forbidden")
		return false
	}
	for _, id := range proxyIDs {
		if !store.OwnsProxy(c.Request.Context(), id, subject.UserID) {
			response.Forbidden(c, "not your proxy")
			return false
		}
	}
	return true
}

func privateAccountOwner(c *gin.Context) int64 {
	if !isAccountUser(c) {
		return 0
	}
	if subject, ok := middleware.GetAuthSubjectFromContext(c); ok && subject.UserID > 0 {
		return subject.UserID
	}
	return 0
}

func allowAccountProxyRequired(c *gin.Context, store *service.StewardStore, proxyID *int64, requireNonEmpty bool) bool {
	if proxyID == nil || *proxyID == 0 {
		if requireNonEmpty {
			response.ErrorFrom(c, service.ErrProxyRequired)
			return false
		}
		return true
	}
	if *proxyID < 0 {
		response.BadRequest(c, "Invalid proxy ID")
		return false
	}
	if isAdminCaller(c) {
		if store != nil && !store.HasVerifiedProxyExit(c.Request.Context(), *proxyID) {
			response.BadRequest(c, "proxy exit IP and timezone must be verified before binding")
			return false
		}
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil || !store.CanUseProxy(c.Request.Context(), *proxyID, subject.UserID) {
		response.Forbidden(c, "not your proxy or proxy exit not verified")
		return false
	}
	return true
}

func allowAccountProxy(c *gin.Context, store *service.StewardStore, proxyID *int64) bool {
	return allowAccountProxyRequired(c, store, proxyID, isAccountUser(c))
}

// allowOwnedBackupProxy verifies a backup proxy binding. Non-admin callers may
// only select a verified proxy they directly own (never a rented proxy clone).
func allowOwnedBackupProxy(c *gin.Context, store *service.StewardStore, backupProxyID *int64) bool {
	if backupProxyID == nil || *backupProxyID == 0 {
		return true
	}
	if *backupProxyID < 0 {
		response.BadRequest(c, "Invalid proxy ID")
		return false
	}
	if isAdminCaller(c) {
		if store != nil && !store.HasVerifiedProxyExit(c.Request.Context(), *backupProxyID) {
			response.BadRequest(c, "proxy exit IP and timezone must be verified before binding")
			return false
		}
		return true
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil {
		response.Forbidden(c, "not your proxy")
		return false
	}
	if !store.HasVerifiedProxyExit(c.Request.Context(), *backupProxyID) || !store.OwnsProxy(c.Request.Context(), *backupProxyID, subject.UserID) {
		response.Forbidden(c, "backup proxy must be an owned verified proxy")
		return false
	}
	return true
}

func stripAdminExtraKeys(extra map[string]any) {
	if extra == nil {
		return
	}
	for k := range extra {
		if strings.HasPrefix(k, "upstream_billing_") {
			delete(extra, k)
		}
	}
	for _, k := range []string{
		"window_cost_limit",
		"window_cost_sticky_reserve",
		"max_sessions",
		"session_idle_timeout_minutes",
		"base_rpm",
		"rpm_strategy",
		"rpm_sticky_buffer",
		"user_msg_queue_mode",
		"quota_limit",
		"quota_daily_limit",
		"quota_weekly_limit",
	} {
		delete(extra, k)
	}
}

func accountCreatePolicy(c *gin.Context, input *service.CreateAccountInput) *service.CreateAccountInput {
	if input == nil {
		return nil
	}
	if !isAdminCaller(c) {
		if subject, ok := middleware.GetAuthSubjectFromContext(c); ok && subject.UserID > 0 {
			input.PrivateOwnerUserID = subject.UserID
		}
		input.GroupIDs = nil
		input.Priority = 0
		input.RateMultiplier = nil
		input.LoadFactor = nil
		input.ProbeEnabled = nil
		input.GroupSyncEnabled = nil
		input.SkipDefaultGroupBind = true
		stripAdminExtraKeys(input.Extra)
	}
	return input
}

func accountUpdatePolicy(c *gin.Context, input *service.UpdateAccountInput) *service.UpdateAccountInput {
	if input == nil {
		return nil
	}
	if !isAdminCaller(c) {
		input.GroupIDs = nil
		input.Priority = nil
		input.RateMultiplier = nil
		input.LoadFactor = nil
		input.ProbeEnabled = nil
		input.GroupSyncEnabled = nil
		input.RateSyncEnabled = nil
		stripAdminExtraKeys(input.Extra)
	}
	return input
}

func rejectInvalidOptionalConcurrency(c *gin.Context, concurrency *int) bool {
	if concurrency == nil {
		return true
	}
	if err := service.ValidateAccountConcurrency(*concurrency); err != nil {
		response.ErrorFrom(c, err)
		return false
	}
	return true
}

func requireValidNonAdminSubject(c *gin.Context, store *service.StewardStore) (int64, bool) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 || store == nil {
		response.Forbidden(c, "forbidden")
		return 0, false
	}
	return subject.UserID, true
}

var _ = infraerrors.BadRequest

type accountImportCaller struct {
	userID     int64
	restricted bool
}

func (h *AntigravityOAuthHandler) SetStewards(store *service.StewardStore) { h.stewards = store }
func (h *GeminiOAuthHandler) SetStewards(store *service.StewardStore)      { h.stewards = store }
func (h *OAuthHandler) SetStewards(store *service.StewardStore)            { h.stewards = store }
func (h *CNProviderHandler) SetStewards(store *service.StewardStore)       { h.stewards = store }
