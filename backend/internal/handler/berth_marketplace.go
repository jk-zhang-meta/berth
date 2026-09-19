package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

type MarketplaceHandler struct {
	market  *service.MarketplaceService
	db      *sql.DB
	billing *service.BillingCacheService
	keys    *service.APIKeyService
	enabled bool
}

func NewMarketplaceHandler(market *service.MarketplaceService, db *sql.DB, billing *service.BillingCacheService, keys *service.APIKeyService, enabled bool) *MarketplaceHandler {
	return &MarketplaceHandler{market: market, db: db, billing: billing, keys: keys, enabled: enabled}
}

func (h *MarketplaceHandler) caller(c *gin.Context) (int64, bool, bool) {
	u, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return 0, false, false
	}
	if !h.enabled {
		response.BadRequest(c, "租赁市场需要标准运行模式")
		return 0, false, false
	}
	role, _ := middleware.GetUserRoleFromContext(c)
	return u.UserID, role == service.RoleAdmin, true
}

func marketError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrMarketplaceForbidden):
		response.Forbidden(c, "无权操作此资源")
	case errors.Is(err, service.ErrMarketplaceNotFound):
		response.Error(c, 404, "资源不存在")
	case errors.Is(err, service.ErrMarketplaceConflict):
		response.Error(c, 409, "资源状态已变化或可租份数不足，请刷新后重试")
	case errors.Is(err, service.ErrMarketplaceInvalid):
		response.BadRequest(c, "请检查租期、价格、份数和资源选择")
	case errors.Is(err, service.ErrMarketplaceInsufficientBalance):
		response.Error(c, http.StatusPaymentRequired, "余额不足")
	default:
		response.Error(c, 500, "租赁服务暂不可用，请稍后重试")
	}
}

func (h *MarketplaceHandler) List(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	items, err := h.market.List(c.Request.Context(), u, a, c.DefaultQuery("scope", "market"))
	if err != nil {
		marketError(c, err)
		return
	}
	if items == nil {
		items = []service.MarketplaceListing{}
	}
	response.Success(c, gin.H{"items": items})
}
func (h *MarketplaceHandler) GetSettings(c *gin.Context) {
	if _, _, ok := h.caller(c); !ok {
		return
	}
	settings, err := h.market.GetCommissionSettings(c.Request.Context())
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, settings)
}

func (h *MarketplaceHandler) UpdateSettings(c *gin.Context) {
	_, admin, ok := h.caller(c)
	if !ok {
		return
	}
	if !admin {
		response.Forbidden(c, "仅管理员可修改平台抽成")
		return
	}
	var input service.MarketplaceCommissionSettings
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	settings, err := h.market.UpdateCommissionSettings(c.Request.Context(), input)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, settings)
}
func (h *MarketplaceHandler) Publish(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	var input service.MarketplacePublishInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	item, err := h.market.Publish(c.Request.Context(), u, a, input)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, item)
}
func (h *MarketplaceHandler) Orders(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	items, err := h.market.Orders(c.Request.Context(), u, a)
	if err != nil {
		marketError(c, err)
		return
	}
	if items == nil {
		items = []service.MarketplaceOrder{}
	}
	response.Success(c, gin.H{"items": items})
}
func (h *MarketplaceHandler) Resources(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	items, err := h.market.ResourceOptions(c.Request.Context(), u, a)
	if err != nil {
		marketError(c, err)
		return
	}
	accounts, proxies := []service.MarketplaceResourceOption{}, []service.MarketplaceResourceOption{}
	for _, item := range items {
		if item.ResourceType == "account" {
			accounts = append(accounts, item)
		} else {
			proxies = append(proxies, item)
		}
	}
	response.Success(c, gin.H{"accounts": accounts, "proxies": proxies})
}
func (h *MarketplaceHandler) Checkout(c *gin.Context) {
	u, _, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	var input struct {
		Key string `json:"idempotency_key"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	item, err := h.market.Checkout(c.Request.Context(), u, id, input.Key)
	if err != nil {
		marketError(c, err)
		return
	}
	h.invalidate(c, u)
	response.Success(c, item)
}
func (h *MarketplaceHandler) UpdateListing(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	if input.Status == "inactive" {
		input.Status = "paused"
	}
	item, err := h.market.SetListingStatus(c.Request.Context(), u, a, id, input.Status)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, item)
}
func (h *MarketplaceHandler) Terminate(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	item, err := h.market.Terminate(c.Request.Context(), u, a, id)
	if err != nil {
		marketError(c, err)
		return
	}
	h.invalidate(c, item.BuyerID)
	h.invalidate(c, item.SellerID)
	response.Success(c, item)
}
func (h *MarketplaceHandler) invalidate(c *gin.Context, userID int64) {
	if h.billing != nil {
		_ = h.billing.InvalidateUserBalance(c.Request.Context(), userID)
	}
	if h.keys != nil {
		h.keys.InvalidateAuthCacheByUserID(c.Request.Context(), userID)
	}
}

// ServiceDetails exposes only the resources behind the caller's rental, never
// the internal account DTO or provider credentials.
func (h *MarketplaceHandler) ServiceDetails(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	orders, err := h.market.Orders(c.Request.Context(), u, a)
	if err != nil {
		marketError(c, err)
		return
	}
	var order *service.MarketplaceOrder
	for i := range orders {
		if orders[i].ID == id {
			order = &orders[i]
			break
		}
	}
	if order == nil {
		response.Error(c, 404, "租赁订单不存在")
		return
	}
	var groupID int64
	// The order's group is resolved through the immutable listing resource,
	// avoiding assumptions about the optional group_id representation in DTOs.
	err = h.db.QueryRowContext(c.Request.Context(), `SELECT COALESCE(group_id,0) FROM berth_marketplace_orders WHERE id=$1`, id).Scan(&groupID)
	if err != nil {
		marketError(c, err)
		return
	}
	accounts := []gin.H{}
	reports := []gin.H{}
	groupName, platform := "", ""
	if groupID > 0 {
		managed, allowed, e := h.market.GroupAccess(c.Request.Context(), u, groupID)
		if e != nil {
			marketError(c, e)
			return
		}
		if managed && !allowed && !a {
			response.Forbidden(c, "租赁授权已结束")
			return
		}
		err = h.db.QueryRowContext(c.Request.Context(), `SELECT name,platform FROM groups WHERE id=$1 AND deleted_at IS NULL`, groupID).Scan(&groupName, &platform)
		if err != nil {
			marketError(c, err)
			return
		}
		rows, e := h.db.QueryContext(c.Request.Context(), `SELECT a.id,a.status,(SELECT ROUND(AVG(first_token_ms))::bigint FROM usage_logs WHERE account_id=a.id AND created_at>=date_trunc('day',now())),(SELECT ROUND(AVG(duration_ms))::bigint FROM usage_logs WHERE account_id=a.id AND created_at>=date_trunc('day',now())) FROM accounts a JOIN account_groups ag ON ag.account_id=a.id WHERE ag.group_id=$1 AND a.deleted_at IS NULL ORDER BY a.id`, groupID)
		if e != nil {
			marketError(c, e)
			return
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var accountID int64
			var status string
			var first, total sql.NullInt64
			if e = rows.Scan(&accountID, &status, &first, &total); e != nil {
				marketError(c, e)
				return
			}
			account := gin.H{"id": "resource-" + strconv.Itoa(len(accounts)+1), "name": "账号 " + strconv.Itoa(len(accounts)+1), "status": status}
			if first.Valid {
				account["first_token_ms"] = first.Int64
			}
			if total.Valid {
				account["duration_ms"] = total.Int64
			}
			accounts = append(accounts, account)
		}
		if e = rows.Err(); e != nil {
			marketError(c, e)
			return
		}
		_ = rows.Close()
		// Only summary fields are shared. Raw prompts, generated HTML, internal
		// provider errors and account identifiers remain private.
		tests, e := h.db.QueryContext(c.Request.Context(), `SELECT kind,status,latency_ms,created_at FROM (
		 SELECT '连通性测试' AS kind,r.status,r.latency_ms,r.created_at FROM scheduled_test_results r JOIN scheduled_test_plans p ON p.id=r.plan_id JOIN account_groups ag ON ag.account_id=p.account_id WHERE ag.group_id=$1
		 UNION ALL SELECT '鹈鹕测智' AS kind,t.status,t.duration_ms AS latency_ms,t.created_at FROM pelican_tests t JOIN account_groups ag ON ag.account_id=t.account_id WHERE ag.group_id=$1
		) results ORDER BY created_at DESC LIMIT 20`, groupID)
		if e != nil {
			marketError(c, e)
			return
		}
		defer func() { _ = tests.Close() }()
		for tests.Next() {
			var kind, status string
			var latency sql.NullInt64
			var created any
			if e = tests.Scan(&kind, &status, &latency, &created); e != nil {
				marketError(c, e)
				return
			}
			item := gin.H{"kind": kind, "status": status, "created_at": created}
			if latency.Valid {
				item["latency_ms"] = latency.Int64
			}
			reports = append(reports, item)
		}
		if e = tests.Err(); e != nil {
			marketError(c, e)
			return
		}
	}
	response.Success(c, gin.H{"group_id": groupID, "group_name": groupName, "platform": platform, "accounts": accounts, "test_reports": reports})
}
