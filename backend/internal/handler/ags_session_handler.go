package handler

import (
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	middleware2 "github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

func agsRequestOwner(c *gin.Context) (*service.APIKey, bool) {
	key, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok || key == nil || key.UserID <= 0 {
		response.Unauthorized(c, "Authentication required")
		return nil, false
	}
	return key, true
}

func parseAgentReportTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-0700", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return &parsed
		}
	}
	return nil
}

func (h *UsageHandler) AGSPing(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	accounts, err := h.usageService.ListAGSPoolAccounts(c.Request.Context(), key.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"accounts": len(accounts)})
}

func (h *UsageHandler) AGSAccounts(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	accounts, err := h.usageService.ListAGSPoolAccounts(c.Request.Context(), key.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"accounts": accounts})
}

func (h *UsageHandler) AGSSessions(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	items, err := h.usageService.ListWorkSessions(c.Request.Context(), key.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, item := range items {
		if item.Status != "live" || item.DeviceID == "" {
			continue
		}
		out = append(out, gin.H{
			"device_id":   item.DeviceID,
			"ags_id":      item.AgsID,
			"cwd":         item.CWD,
			"host":        item.Host,
			"description": item.Description,
			"started_at":  item.StartedAt.Format(time.RFC3339),
			"status":      item.Status,
		})
	}
	response.Success(c, gin.H{"sessions": out})
}

func (h *UsageHandler) AGSReportSession(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	var body struct {
		DeviceID    string   `json:"device_id"`
		AgsID       string   `json:"ags_id"`
		Agent       string   `json:"agent"`
		CWD         string   `json:"cwd"`
		Host        string   `json:"host"`
		StartedAt   string   `json:"started_at"`
		Description string   `json:"description"`
		Accounts    []string `json:"accounts"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	if body.Agent == "" {
		body.Agent = "codex"
	}
	item, err := h.usageService.ReportAgentSession(c.Request.Context(), key.UserID, key.ID, service.AgentSessionReport{
		DeviceID:    body.DeviceID,
		AgsID:       body.AgsID,
		Agent:       body.Agent,
		CWD:         body.CWD,
		Host:        body.Host,
		Description: body.Description,
		StartedAt:   parseAgentReportTime(body.StartedAt),
		Status:      "live",
		Accounts:    body.Accounts,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, item)
}

func (h *UsageHandler) AGSDescribeSession(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	var body struct {
		DeviceID    string `json:"device_id"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	if err := h.usageService.UpdateAgentSessionDescription(c.Request.Context(), key.UserID, body.DeviceID, body.Description); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"ok": true})
}

func (h *UsageHandler) AGSEndSession(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	var body struct {
		DeviceID string `json:"device_id"`
		EndedAt  string `json:"ended_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	endedAt := time.Now()
	if parsed := parseAgentReportTime(body.EndedAt); parsed != nil {
		endedAt = *parsed
	}
	if err := h.usageService.EndAgentSession(c.Request.Context(), key.UserID, body.DeviceID, endedAt); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"ok": true})
}

func (h *UsageHandler) AGSResolveAccounts(c *gin.Context) {
	key, ok := agsRequestOwner(c)
	if !ok {
		return
	}
	var body struct {
		WantAccount string `json:"want_account"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	names := strings.FieldsFunc(body.WantAccount, func(r rune) bool { return r == ',' || r == '，' })
	states := h.usageService.ResolveAGSPoolAccounts(c.Request.Context(), key.UserID, names)
	wanted := make([]gin.H, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name != "" {
			wanted = append(wanted, gin.H{"name": name, "state": states[name]})
		}
	}
	response.Success(c, gin.H{"wanted": wanted})
}
