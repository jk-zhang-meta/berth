package handler

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
)

// Dead unwired user-pool CRUD bypasses (ListMyAccounts/CreateMyAccount/ListMyProxies/CreateMyProxy)
// were removed in Berth v2 Track B; user account/proxy operations go through the hardened
// fail-closed admin handlers mounted on authenticated user routes.

func parseIDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid id")
		return 0, false
	}
	return id, true
}
