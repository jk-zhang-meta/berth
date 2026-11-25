package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/service"
)

type marketplaceCheckoutPaymentBody struct {
	IdempotencyKey    string `json:"idempotency_key" binding:"required"`
	PaymentType       string `json:"payment_type" binding:"required"`
	ReturnURL         string `json:"return_url"`
	OpenID            string `json:"openid"`
	WechatResumeToken string `json:"wechat_resume_token"`
	PaymentSource     string `json:"payment_source"`
	IsMobile          *bool  `json:"is_mobile,omitempty"`
}

// DeclineListing allows a targeted buyer to decline an active private offer.
// POST /api/v1/marketplace/listings/:id/decline
func (h *MarketplaceHandler) DeclineListing(c *gin.Context) {
	u, _, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	item, err := h.market.DeclineListing(c.Request.Context(), u, id)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, item)
}

// OrderUsage returns the paginated append-only quota usage audit trail for a rental order.
// GET /api/v1/marketplace/orders/:id/usage
func (h *MarketplaceHandler) OrderUsage(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	id, ok := parseIDParam(c)
	if !ok {
		return
	}
	page, pageSize := response.ParsePagination(c)
	result, err := h.market.ListOrderUsage(c.Request.Context(), u, a, id, page, pageSize)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, result)
}

// CheckoutPayment initiates a linked built-in payment order covering a buyer's
// balance shortfall, or completes checkout immediately if balance is now sufficient.
// POST /api/v1/marketplace/listings/:id/checkout-payment
func (h *MarketplaceHandler) CheckoutPayment(c *gin.Context) {
	u, _, ok := h.caller(c)
	if !ok {
		return
	}
	if h.payment == nil {
		marketError(c, service.ErrMarketplacePaymentUnavailable)
		return
	}
	listingID, ok := parseIDParam(c)
	if !ok {
		return
	}
	var body marketplaceCheckoutPaymentBody
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid request body")
		return
	}
	mobile := isMobile(c)
	if body.IsMobile != nil {
		mobile = *body.IsMobile
	}
	res, err := h.payment.CreateCheckoutPaymentIntent(c.Request.Context(), u, listingID, service.MarketplaceCheckoutPaymentRequest{
		IdempotencyKey:    body.IdempotencyKey,
		PaymentType:       body.PaymentType,
		ReturnURL:         body.ReturnURL,
		OpenID:            body.OpenID,
		WechatResumeToken: body.WechatResumeToken,
		ClientIP:          c.ClientIP(),
		IsMobile:          mobile,
		IsWeChatBrowser:   isWeChatBrowser(c),
		SrcHost:           c.Request.Host,
		SrcURL:            c.Request.Referer(),
		PaymentSource:     body.PaymentSource,
		Locale:            c.GetHeader("Accept-Language"),
	})
	if err != nil {
		marketError(c, err)
		return
	}
	if res.Mode == service.MarketplaceCheckoutPaymentModeBalanceCompleted {
		h.invalidate(c, u)
	}
	response.Success(c, res)
}

// GetPaymentIntent performs a strictly read-only status lookup of a marketplace
// checkout payment intent. Never triggers upstream provider verification or writes.
// GET /api/v1/marketplace/payment-intents/:id
func (h *MarketplaceHandler) GetPaymentIntent(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	if h.payment == nil {
		marketError(c, service.ErrMarketplacePaymentUnavailable)
		return
	}
	intentID, ok := parseIDParam(c)
	if !ok {
		return
	}
	view, err := h.payment.GetPaymentIntent(c.Request.Context(), u, a, intentID)
	if err != nil {
		marketError(c, err)
		return
	}
	response.Success(c, view)
}

// VerifyPaymentIntent explicitly triggers upstream payment verification via
// PaymentService.VerifyOrderByOutTradeNo and completes Phase 2 if paid.
// POST /api/v1/marketplace/payment-intents/:id/verify
func (h *MarketplaceHandler) VerifyPaymentIntent(c *gin.Context) {
	u, a, ok := h.caller(c)
	if !ok {
		return
	}
	if h.payment == nil {
		marketError(c, service.ErrMarketplacePaymentUnavailable)
		return
	}
	intentID, ok := parseIDParam(c)
	if !ok {
		return
	}
	view, err := h.payment.VerifyPaymentIntent(c.Request.Context(), u, a, intentID)
	if err != nil {
		marketError(c, err)
		return
	}
	if view.Status == service.MarketplacePaymentIntentStatusCompleted {
		h.invalidate(c, view.BuyerID)
	}
	response.Success(c, view)
}
