package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/service"
)

// attachBerthSchedulerContext extracts Cage Cohort headers + WorkSession cohort metadata
// and estimated cacheable prefix tokens onto the request context.
func attachBerthSchedulerContext(c *gin.Context, bodyBytes int) {
	if c == nil || c.Request == nil {
		return
	}
	ctx := c.Request.Context()
	if bodyBytes > 0 {
		tokens := service.EstimatePrefixTokens(bodyBytes)
		if tokens < 1 {
			tokens = 1
		}
		ctx = service.WithRequestPrefixTokens(ctx, tokens)
	}
	pref := service.WorkSessionPrefFromContext(ctx)
	if cohortReq := service.ExtractCageCohortRequest(c.Request.Header, pref); cohortReq != nil {
		ctx = service.WithCageCohortRequest(ctx, cohortReq)
	}
	c.Request = c.Request.WithContext(ctx)
}

// writeCageRebindRequiredResponse handles *service.ErrCageRebindRequired safely:
//   - Pre-commit (!streamStarted && !c.Writer.Written()): emits HTTP 409 Conflict with
//     machine-readable cohort headers and JSON payload (Codex Blocker #3.2).
//   - Post-commit (streamStarted || c.Writer.Written()): NEVER writes HTTP 409; delegates
//     to streaming-aware error emission so committed SSE/WS streams stay well-formed.
func writeCageRebindRequiredResponse(
	c *gin.Context,
	rebindErr *service.ErrCageRebindRequired,
	streamStarted bool,
	streamingFallback func(c *gin.Context, statusCode int, errType, message string, streamStarted bool),
) {
	if c == nil || rebindErr == nil {
		return
	}
	if streamStarted || (c.Writer != nil && c.Writer.Written()) {
		if streamingFallback != nil {
			streamingFallback(c, http.StatusConflict, "cage_rebind_required", rebindErr.Error(), true)
		}
		return
	}
	c.Header(service.HeaderBerthFailoverReason, "cage_rebind_required")
	if rebindErr.CurrentCohortTZ != "" {
		c.Header(service.HeaderBerthSessionCohortTZ, rebindErr.CurrentCohortTZ)
	}
	if rebindErr.RecommendedCohortTZ != "" {
		c.Header(service.HeaderBerthRecommendedCohortTZ, rebindErr.RecommendedCohortTZ)
	}
	if avail := rebindErr.FormatAvailableCohortsHeader(); avail != "" {
		c.Header(service.HeaderBerthAvailableCohorts, avail)
	}
	retryAfter := rebindErr.RetryAfterSeconds
	if retryAfter <= 0 {
		retryAfter = 5
	}
	c.Header("Retry-After", strconv.Itoa(retryAfter))
	c.JSON(http.StatusConflict, rebindErr)
}

// applyBerthSelectionHeaders writes handover observability headers (pre-commit) and
// persists the selected account's egress cohort on the active WorkSession.
func applyBerthSelectionHeaders(c *gin.Context, gw *service.GatewayService, selection *service.AccountSelectionResult) {
	if c == nil || selection == nil || selection.Account == nil {
		return
	}
	if selection.HandoverCohortTZ != "" && (c.Writer == nil || !c.Writer.Written()) {
		c.Header(service.HeaderBerthCageHandoverTZ, selection.HandoverCohortTZ)
	}
	if gw != nil {
		cohort := service.AccountCohort(selection.Account)
		if cohort.IsSet() {
			gw.BindWorkSessionCohort(c.Request.Context(), cohort, selection.HandoverCohortTZ != "")
		}
	}
}

// resolveBerthOperationID returns X-Berth-Operation-ID if sent by AGS/client,
// falling back to X-Request-ID so cross-hop retries share the same 403 blast-radius bucket.
func resolveBerthOperationID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if op := strings.TrimSpace(c.GetHeader(service.HeaderBerthOperationID)); op != "" {
		return op
	}
	if reqID := strings.TrimSpace(c.GetHeader("X-Request-ID")); reqID != "" {
		return reqID
	}
	if v, ok := c.Get("request_id"); ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// configureBerthFailoverState attaches operation ID, session hash, and the global
// 403 blast-radius guard onto a FailoverState.
func configureBerthFailoverState(c *gin.Context, fs *FailoverState, sessionKey string) {
	if fs == nil {
		return
	}
	fs.OperationID = resolveBerthOperationID(c)
	fs.SessionHash = sessionKey
	fs.BlastRadius = service.DefaultBlastRadiusGuard()
}

// markSessionToxicHeader emits X-Berth-Circuit-Open: session_toxic pre-commit when
// failover terminated due to the 403/5xx session toxicity circuit breaker.
func markSessionToxicHeader(c *gin.Context, sessionToxic bool, streamStarted bool) {
	if !sessionToxic || c == nil || streamStarted || (c.Writer != nil && c.Writer.Written()) {
		return
	}
	c.Header(service.HeaderBerthCircuitOpen, "session_toxic")
}
