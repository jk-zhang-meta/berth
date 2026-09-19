package handler

import (
	"strconv"

	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	middleware2 "github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *UsageHandler) ListSessions(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	items, err := h.usageService.ListWorkSessions(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if items == nil {
		items = []service.WorkSession{}
	}
	response.Success(c, gin.H{"items": items})
}

func (h *UsageHandler) ListSessionAccounts(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	accounts, err := h.usageService.ListAGSPoolAccounts(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	type accountOption struct {
		ID          int64   `json:"id"`
		Name        string  `json:"name"`
		Platform    string  `json:"platform"`
		Headroom    float64 `json:"headroom"`
		Schedulable bool    `json:"schedulable"`
	}
	items := make([]accountOption, 0, len(accounts))
	for _, account := range accounts {
		items = append(items, accountOption{
			ID: account.ID, Name: account.Email, Platform: account.Plan,
			Headroom: account.Headroom, Schedulable: account.Schedulable,
		})
	}
	response.Success(c, gin.H{"items": items})
}

func (h *UsageHandler) PatchSession(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid session id")
		return
	}
	var body struct {
		Title             *string `json:"title"`
		Description       *string `json:"description"`
		Importance        *int    `json:"importance"`
		AssignedAccountID *int64  `json:"assigned_account_id"`
		ClearAssignment   bool    `json:"clear_assignment"`
		Status            *string `json:"status"`
		CWD               *string `json:"cwd"`
		AgsID             *string `json:"ags_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	err = h.usageService.PatchWorkSession(c.Request.Context(), id, subject.UserID, service.WorkSessionPatch{
		Title: body.Title, Description: body.Description, Importance: body.Importance,
		AssignedAccountID: body.AssignedAccountID, ClearAssignment: body.ClearAssignment,
		Status: body.Status, CWD: body.CWD, AgsID: body.AgsID,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"ok": true})
}

func (h *UsageHandler) ReplaceSessionQueue(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid session id")
		return
	}
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	if err := h.usageService.ReplaceWorkSessionQueue(c.Request.Context(), id, subject.UserID, body.AccountIDs); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"ok": true})
}

func (h *UsageHandler) ListSessionRequests(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid session id")
		return
	}
	items, err := h.usageService.ListWorkSessionRequests(c.Request.Context(), id, subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if items == nil {
		items = []service.WorkSessionRequest{}
	}
	response.Success(c, gin.H{"items": items})
}
