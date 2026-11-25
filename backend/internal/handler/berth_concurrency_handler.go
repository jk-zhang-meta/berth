package handler

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	middleware2 "github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
)

// BerthConcurrencyHandler serves adaptive concurrency recommendations for Create/Edit Account UX.
type BerthConcurrencyHandler struct {
	advisor  *service.BerthConcurrencyAdvisor
	stewards *service.StewardStore
}

func NewBerthConcurrencyHandler(advisor *service.BerthConcurrencyAdvisor, stewards *service.StewardStore) *BerthConcurrencyHandler {
	return &BerthConcurrencyHandler{
		advisor:  advisor,
		stewards: stewards,
	}
}

// GetRecommendedConcurrency returns adaptive concurrency recommendations coupled with proxy capacity.
// GET /recommended-concurrency?platform=...&type=...&plan_tier=...&proxy_id=...
func (h *BerthConcurrencyHandler) GetRecommendedConcurrency(c *gin.Context) {
	role, roleOK := middleware2.GetUserRoleFromContext(c)
	isAdmin := roleOK && role == service.RoleAdmin
	if !isAdmin {
		subject, ok := middleware2.GetAuthSubjectFromContext(c)
		if !ok || subject.UserID <= 0 {
			response.Forbidden(c, "forbidden")
			return
		}
	}

	platform := strings.ToLower(strings.TrimSpace(c.Query("platform")))
	accountType := strings.ToLower(strings.TrimSpace(c.Query("type")))
	planTier := strings.ToLower(strings.TrimSpace(c.Query("plan_tier")))
	if platform == "" || accountType == "" {
		response.BadRequest(c, "platform and type query parameters are required")
		return
	}

	var proxyID *int64
	if rawProxy := strings.TrimSpace(c.Query("proxy_id")); rawProxy != "" {
		parsed, err := strconv.ParseInt(rawProxy, 10, 64)
		if err != nil || parsed <= 0 {
			response.BadRequest(c, "invalid proxy_id")
			return
		}
		if !isAdmin {
			subject, _ := middleware2.GetAuthSubjectFromContext(c)
			if h.stewards == nil || !h.stewards.CanUseProxy(c.Request.Context(), parsed, subject.UserID) {
				response.Forbidden(c, "not your proxy or proxy exit not verified")
				return
			}
		}
		proxyID = &parsed
	}

	advisor := h.advisor
	if advisor == nil {
		advisor = service.NewBerthConcurrencyAdvisor(nil)
	}
	rec := advisor.RecommendForAccount(c.Request.Context(), platform, accountType, planTier, proxyID)
	response.Success(c, rec)
}
