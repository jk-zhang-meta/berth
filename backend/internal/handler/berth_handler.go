package handler

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

type BerthAccount struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	ProxyID    *int64 `json:"proxy_id,omitempty"`
	Listed     bool   `json:"listed"`
	RentalID   int64  `json:"rental_id,omitempty"`
	HasSecret  bool   `json:"has_secret"`
	Borrowed   bool   `json:"borrowed"`
}

type BerthProxy struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
}

func (h *UsageHandler) SetAdmin(admin service.AdminService) {
	if h == nil {
		return
	}
	h.adminService = admin
}

func (h *UsageHandler) ListBerthAccounts(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil {
		response.Success(c, gin.H{"items": []BerthAccount{}})
		return
	}
	ownedIDs := h.usageService.StewardAccountIDs(c.Request.Context(), subject.UserID)
	listed := h.usageService.ListedAccountMap(c.Request.Context(), subject.UserID)
	borrowedIDs := h.usageService.BorrowedAccountIDs(c.Request.Context(), subject.UserID)
	idSet := append([]int64{}, ownedIDs...)
	idSet = append(idSet, borrowedIDs...)
	accounts, err := h.adminService.GetAccountsByIDs(c.Request.Context(), uniqueIDs(idSet))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	owned := map[int64]struct{}{}
	for _, id := range ownedIDs {
		owned[id] = struct{}{}
	}
	items := make([]BerthAccount, 0, len(accounts))
	for _, account := range accounts {
		if account == nil {
			continue
		}
		_, isOwned := owned[account.ID]
		rentalID := listed[account.ID]
		items = append(items, BerthAccount{
			ID:        account.ID,
			Name:      account.Name,
			Platform:  account.Platform,
			Type:      account.Type,
			Status:    account.Status,
			ProxyID:   account.ProxyID,
			Listed:    rentalID > 0,
			RentalID:  rentalID,
			HasSecret: isOwned && len(account.Credentials) > 0,
			Borrowed:  !isOwned,
		})
	}
	response.Success(c, gin.H{"items": items})
}

func (h *UsageHandler) CreateBerthAccount(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil {
		response.BadRequest(c, "accounts unavailable")
		return
	}
	var body struct {
		Name        string         `json:"name"`
		Platform    string         `json:"platform"`
		Type        string         `json:"type"`
		Credentials map[string]any `json:"credentials"`
		ProxyID     *int64         `json:"proxy_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Platform = strings.ToLower(strings.TrimSpace(body.Platform))
	body.Type = strings.ToLower(strings.TrimSpace(body.Type))
	if body.Name == "" || body.Platform == "" {
		response.BadRequest(c, "name and platform are required")
		return
	}
	if body.Type == "" {
		body.Type = "oauth"
	}
	if body.Type == "api_key" {
		body.Type = "apikey"
	}
	if body.Credentials == nil {
		body.Credentials = map[string]any{}
	}
	if body.ProxyID != nil && *body.ProxyID > 0 && !h.usageService.OwnsProxy(c.Request.Context(), *body.ProxyID, subject.UserID) {
		response.BadRequest(c, "not your proxy")
		return
	}
	account, err := h.adminService.CreateAccount(c.Request.Context(), &service.CreateAccountInput{
		Name:                  body.Name,
		Platform:              body.Platform,
		Type:                  body.Type,
		Credentials:           body.Credentials,
		ProxyID:               body.ProxyID,
		SkipMixedChannelCheck: true,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := h.usageService.ClaimAccount(c.Request.Context(), account.ID, subject.UserID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, BerthAccount{
		ID:        account.ID,
		Name:      account.Name,
		Platform:  account.Platform,
		Type:      account.Type,
		Status:    account.Status,
		ProxyID:   account.ProxyID,
		HasSecret: true,
	})
}

func (h *UsageHandler) ListBerthProxies(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil {
		response.Success(c, gin.H{"items": []BerthProxy{}})
		return
	}
	ids := h.usageService.StewardProxyIDs(c.Request.Context(), subject.UserID)
	items := make([]BerthProxy, 0, len(ids))
	for _, id := range ids {
		proxy, err := h.adminService.GetProxy(c.Request.Context(), id)
		if err != nil || proxy == nil {
			continue
		}
		items = append(items, BerthProxy{
			ID:       proxy.ID,
			Name:     proxy.Name,
			Protocol: proxy.Protocol,
			Host:     proxy.Host,
			Port:     proxy.Port,
			Status:   proxy.Status,
		})
	}
	response.Success(c, gin.H{"items": items})
}

func (h *UsageHandler) CreateBerthProxy(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	if h.adminService == nil {
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
	body.Name = strings.TrimSpace(body.Name)
	body.Protocol = strings.ToLower(strings.TrimSpace(body.Protocol))
	body.Host = strings.TrimSpace(body.Host)
	if body.Name == "" || body.Host == "" || body.Port <= 0 {
		response.BadRequest(c, "name, host and port are required")
		return
	}
	if body.Protocol == "" {
		body.Protocol = "http"
	}
	proxy, err := h.adminService.CreateProxy(c.Request.Context(), &service.CreateProxyInput{
		Name:     body.Name,
		Protocol: body.Protocol,
		Host:     body.Host,
		Port:     body.Port,
		Username: body.Username,
		Password: body.Password,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := h.usageService.ClaimProxy(c.Request.Context(), proxy.ID, subject.UserID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, BerthProxy{
		ID:       proxy.ID,
		Name:     proxy.Name,
		Protocol: proxy.Protocol,
		Host:     proxy.Host,
		Port:     proxy.Port,
		Status:   proxy.Status,
	})
}

func uniqueIDs(ids []int64) []int64 {
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
