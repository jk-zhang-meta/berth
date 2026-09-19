package handler

import (
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// Usage amounts are USD, separate from the integer-cent rental ledger.
type marketplaceRevenue struct {
	GrossAmount     float64 `json:"gross_amount"`
	AvailableIncome float64 `json:"available_income"`
	PendingIncome   float64 `json:"pending_income"`
	PlatformAmount  float64 `json:"platform_amount"`
}

func (h *MarketplaceHandler) Revenue(c *gin.Context) {
	userID, admin, ok := h.caller(c)
	if !ok {
		return
	}
	query := `SELECT COALESCE(SUM(gross_amount),0),COALESCE(SUM(seller_paid_amount),0),COALESCE(SUM(seller_amount-seller_paid_amount),0),COALESCE(SUM(platform_amount),0) FROM berth_marketplace_usage_revenue`
	var args []any
	if !admin {
		query += " WHERE seller_id=$1"
		args = append(args, userID)
	}
	var result marketplaceRevenue
	if err := h.db.QueryRowContext(c.Request.Context(), query, args...).Scan(&result.GrossAmount, &result.AvailableIncome, &result.PendingIncome, &result.PlatformAmount); err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, result)
}
