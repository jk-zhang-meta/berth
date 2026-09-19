package handler

import (
	"strconv"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	middleware2 "github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *UsageHandler) ListMyAccounts(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil || h.stewards == nil {
		response.Success(c, gin.H{"items": []any{}})
		return
	}
	ids := h.stewards.ListAccountIDs(c.Request.Context(), subject.UserID)
	accounts, err := h.adminService.GetAccountsByIDs(c.Request.Context(), ids)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": accounts})
}

func (h *UsageHandler) CreateMyAccount(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil || h.stewards == nil {
		response.BadRequest(c, "accounts unavailable")
		return
	}
	var body service.CreateAccountInput
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	body.SkipMixedChannelCheck = true
	account, err := h.adminService.CreateAccount(c.Request.Context(), &body)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	_ = h.stewards.ClaimAccount(c.Request.Context(), account.ID, subject.UserID)
	response.Success(c, account)
}

func (h *UsageHandler) ListMyProxies(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil || h.stewards == nil {
		response.Success(c, gin.H{"items": []any{}})
		return
	}
	ids := h.stewards.ListProxyIDs(c.Request.Context(), subject.UserID)
	proxies, err := h.adminService.GetProxiesByIDs(c.Request.Context(), ids)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": proxies})
}

func (h *UsageHandler) CreateMyProxy(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil || h.stewards == nil {
		response.BadRequest(c, "proxies unavailable")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	proxy, err := h.adminService.CreateProxy(c.Request.Context(), &service.CreateProxyInput{
		Name:     strings.TrimSpace(body.Name),
		Protocol: strings.ToLower(strings.TrimSpace(body.Protocol)),
		Host:     strings.TrimSpace(body.Host),
		Port:     body.Port,
		Username: body.Username,
		Password: body.Password,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	_ = h.stewards.ClaimProxy(c.Request.Context(), proxy.ID, subject.UserID)
	response.Success(c, proxy)
}

func parseIDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid id")
		return 0, false
	}
	return id, true
}
