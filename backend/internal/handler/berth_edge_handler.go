package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
)

const contextKeyEdgeNodeID = "berth_edge_node_id"

// BerthEdgeHandler serves AGS v2 lease negotiation, Edge internal control-plane
// endpoints, Admin network topology & landing grant APIs, and User landing grant views.
type BerthEdgeHandler struct {
	zones  *service.BerthZoneService
	grants *service.BerthLandingGrantService
	leases *service.BerthEdgeLeaseService
}

// NewBerthEdgeHandler constructs a BerthEdgeHandler.
func NewBerthEdgeHandler(
	zones *service.BerthZoneService,
	grants *service.BerthLandingGrantService,
	leases *service.BerthEdgeLeaseService,
) *BerthEdgeHandler {
	return &BerthEdgeHandler{
		zones:  zones,
		grants: grants,
		leases: leases,
	}
}

// RegisterRoutes mounts all Berth v2 Track D routes cleanly onto r using the
// provided user, admin, and edge authentication middleware hooks.
func (h *BerthEdgeHandler) RegisterRoutes(r gin.IRouter, userAuth, adminAuth, edgeAuth gin.HandlerFunc) {
	if edgeAuth == nil && h.zones != nil {
		edgeAuth = EdgeNodeAuthMiddleware(h.zones)
	}

	// AGS v2 & User endpoints
	userGroup := r.Group("/api/v1")
	if userAuth != nil {
		userGroup.Use(userAuth)
	}
	userGroup.POST("/ags/leases", h.MintLease)
	userGroup.POST("/ags/leases/:id/renew", h.RenewLease)
	userGroup.DELETE("/ags/leases/:id", h.RevokeLease)
	userGroup.GET("/user/landing-nodes", h.ListAvailableLandingNodes)
	userGroup.GET("/user/landing-grants", h.ListUserLandingGrants)
	userGroup.POST("/user/landing-grants/apply", h.ApplyUserLandingGrant)
	userGroup.DELETE("/user/landing-grants/:id", h.CancelUserLandingGrantApplication)

	// Edge Internal control-plane endpoints
	edgeGroup := r.Group("/api/v1/internal/edge")
	if edgeAuth != nil {
		edgeGroup.Use(edgeAuth)
	}
	edgeGroup.POST("/heartbeat", h.EdgeHeartbeat)
	edgeGroup.POST("/grant-slice", h.EdgeGrantSlice)
	edgeGroup.POST("/usage-outbox", h.EdgeUsageOutbox)
	edgeGroup.POST("/failover", h.EdgeFailover)
	edgeGroup.GET("/oauth-tasks", h.EdgeListOAuthTasks)
	edgeGroup.POST("/oauth-tasks/:id/complete", h.EdgeCompleteOAuthTask)
	edgeGroup.GET("/binary/:os/:arch", h.EdgeDownloadBinary)

	// Admin Topology & Landing Grants endpoints
	adminGroup := r.Group("/api/v1/admin/network")
	if adminAuth != nil {
		adminGroup.Use(adminAuth)
	}
	adminGroup.GET("/zones", h.AdminListZones)
	adminGroup.POST("/zones", h.AdminCreateZone)
	adminGroup.GET("/nodes", h.AdminListNodes)
	adminGroup.POST("/nodes", h.AdminCreateNode)
	adminGroup.PUT("/nodes/:id", h.AdminUpdateNode)
	adminGroup.GET("/links", h.AdminListLinks)
	adminGroup.POST("/links", h.AdminCreateLink)
	adminGroup.DELETE("/links/:id", h.AdminDeleteLink)
	adminGroup.GET("/edge-releases", h.AdminListEdgeReleases)
	adminGroup.GET("/grants", h.AdminListGrants)
	adminGroup.POST("/grants", h.AdminCreateGrant)
	adminGroup.POST("/grants/:id/approve", h.AdminApproveGrant)
	adminGroup.POST("/grants/:id/reject", h.AdminRejectGrant)
	adminGroup.DELETE("/grants/:id", h.AdminRevokeGrant)
}

// EdgeNodeAuthMiddleware authenticates berth-edge internal requests via Ed25519
// signed headers (X-Berth-Node-ID, X-Berth-Timestamp, X-Berth-Signature).
func EdgeNodeAuthMiddleware(zones *service.BerthZoneService) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeIDStr := strings.TrimSpace(c.GetHeader(edgeproto.HeaderNodeID))
		tsStr := strings.TrimSpace(c.GetHeader(edgeproto.HeaderNodeTimestamp))
		sig := strings.TrimSpace(c.GetHeader(edgeproto.HeaderNodeSignature))
		nodeID, err := strconv.ParseInt(nodeIDStr, 10, 64)
		if err != nil || nodeID <= 0 || tsStr == "" || sig == "" {
			response.Unauthorized(c, "Edge node authentication headers required")
			c.Abort()
			return
		}
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			response.Unauthorized(c, "Invalid edge node timestamp")
			c.Abort()
			return
		}
		pub, err := zones.LookupNodePubKey(c.Request.Context(), nodeID)
		if err != nil {
			response.Unauthorized(c, "Unknown or suspended edge node")
			c.Abort()
			return
		}
		var body []byte
		if c.Request.Body != nil {
			body, err = io.ReadAll(io.LimitReader(c.Request.Body, 4*1024*1024))
			if err != nil {
				response.BadRequest(c, "Failed to read request body")
				c.Abort()
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		if err := edgeproto.VerifyNodeRequest(pub, nodeID, c.Request.Method, c.Request.URL.Path, ts, body, sig, time.Now()); err != nil {
			response.Unauthorized(c, "Invalid edge node request signature")
			c.Abort()
			return
		}
		c.Set(contextKeyEdgeNodeID, nodeID)
		c.Next()
	}
}

func edgeCallerIdentity(c *gin.Context) (userID int64, apiKeyID int64, isAdmin bool, ok bool) {
	if key, hasKey := middleware.GetAPIKeyFromContext(c); hasKey && key != nil && key.UserID > 0 {
		role, _ := middleware.GetUserRoleFromContext(c)
		return key.UserID, key.ID, role == service.RoleAdmin, true
	}
	if sub, hasSub := middleware.GetAuthSubjectFromContext(c); hasSub && sub.UserID > 0 {
		role, _ := middleware.GetUserRoleFromContext(c)
		return sub.UserID, 0, role == service.RoleAdmin, true
	}
	response.Unauthorized(c, "Authentication required")
	return 0, 0, false, false
}

func requireEdgeAdmin(c *gin.Context) (int64, bool) {
	sub, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || sub.UserID <= 0 {
		response.Unauthorized(c, "Admin authentication required")
		return 0, false
	}
	role, hasRole := middleware.GetUserRoleFromContext(c)
	if !hasRole || role != service.RoleAdmin {
		response.Forbidden(c, "Admin access required")
		return 0, false
	}
	return sub.UserID, true
}

func getAuthenticatedEdgeNodeID(c *gin.Context) (int64, bool) {
	v, ok := c.Get(contextKeyEdgeNodeID)
	if ok {
		if id, ok := v.(int64); ok && id > 0 {
			return id, true
		}
	}
	// Fallback header when custom edgeAuth middleware authenticated mTLS and set header.
	if raw := strings.TrimSpace(c.GetHeader(edgeproto.HeaderNodeID)); raw != "" {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil && id > 0 {
			return id, true
		}
	}
	response.Unauthorized(c, "Edge node identity missing")
	return 0, false
}

func parsePathInt64(c *gin.Context, param string) (int64, bool) {
	id, err := strconv.ParseInt(c.Param(param), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid numeric identifier")
		return 0, false
	}
	return id, true
}

// ---------- AGS v2 & User Handlers ----------

type mintLeaseHTTPBody struct {
	WorkSessionID     json.RawMessage `json:"work_session_id"`
	Agent             string          `json:"agent"`
	Platform          string          `json:"platform"`
	AccountID         int64           `json:"account_id"`
	AccountPreference []string        `json:"account_preference"`
	CageID            int64           `json:"cage_id"`
	CageEpoch         int64           `json:"cage_epoch"`
	GrantID           int64           `json:"grant_id"`
	LandingNodeID     int64           `json:"landing_node_id"`
	PreferredZoneSlug string          `json:"preferred_zone_slug"`
	ZonePreference    string          `json:"zone_preference"`
	CohortHint        string          `json:"cohort_hint"`
	PeerCountryCode   string          `json:"peer_country_code"`
	DNSHintDomain     string          `json:"dns_hint_domain"`
	DefaultRouteVPN   bool            `json:"default_route_vpn"`
	LastCleanZoneSlug string          `json:"last_clean_zone_slug"`
	CohortTimezone    string          `json:"cohort_timezone"`
	CohortCountryCode string          `json:"cohort_country_code"`
	CohortLocale      string          `json:"cohort_locale"`
}

func parseFlexibleInt64(raw json.RawMessage) int64 {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return n
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		if n, err := strconv.ParseInt(str, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func (h *BerthEdgeHandler) MintLease(c *gin.Context) {
	userID, apiKeyID, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	var rawBody mintLeaseHTTPBody
	if err := c.ShouldBindJSON(&rawBody); err != nil {
		response.BadRequest(c, "Invalid lease request body")
		return
	}
	req := service.MintLeaseInput{
		UserID:            userID,
		APIKeyID:          apiKeyID,
		WorkSessionID:     parseFlexibleInt64(rawBody.WorkSessionID),
		Agent:             rawBody.Agent,
		Platform:          rawBody.Platform,
		AccountID:         rawBody.AccountID,
		AccountPreference: rawBody.AccountPreference,
		CageID:            rawBody.CageID,
		CageEpoch:         rawBody.CageEpoch,
		GrantID:           rawBody.GrantID,
		LandingNodeID:     rawBody.LandingNodeID,
		PreferredZoneSlug: rawBody.PreferredZoneSlug,
		ZonePreference:    rawBody.ZonePreference,
		CohortHint:        rawBody.CohortHint,
		PeerCountryCode:   rawBody.PeerCountryCode,
		DNSHintDomain:     rawBody.DNSHintDomain,
		DefaultRouteVPN:   rawBody.DefaultRouteVPN,
		LastCleanZoneSlug: rawBody.LastCleanZoneSlug,
		CohortTimezone:    rawBody.CohortTimezone,
		CohortCountryCode: rawBody.CohortCountryCode,
		CohortLocale:      rawBody.CohortLocale,
	}

	resp, err := h.leases.MintLease(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, resp)
}

func (h *BerthEdgeHandler) RenewLease(c *gin.Context) {
	userID, _, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	leaseID := strings.TrimSpace(c.Param("id"))
	if leaseID == "" {
		response.BadRequest(c, "Missing lease ID")
		return
	}
	resp, err := h.leases.RenewLease(c.Request.Context(), userID, leaseID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, resp)
}

func (h *BerthEdgeHandler) RevokeLease(c *gin.Context) {
	userID, _, isAdmin, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	leaseID := strings.TrimSpace(c.Param("id"))
	if leaseID == "" {
		response.BadRequest(c, "Missing lease ID")
		return
	}
	revSeq, err := h.leases.RevokeLease(c.Request.Context(), userID, isAdmin, leaseID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"lease_id": leaseID, "revoked": true, "rev_seq": revSeq})
}

func (h *BerthEdgeHandler) ListAvailableLandingNodes(c *gin.Context) {
	userID, _, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	items, err := h.grants.ListAvailableLandingNodes(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) ListUserLandingGrants(c *gin.Context) {
	userID, _, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	items, err := h.grants.ListUserGrants(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) ApplyUserLandingGrant(c *gin.Context) {
	userID, _, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	var in service.ApplyLandingGrantInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, "Invalid landing grant application body")
		return
	}
	in.GranteeUserID = userID
	created, err := h.grants.ApplyForLandingNode(c.Request.Context(), in)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Created(c, created)
}

func (h *BerthEdgeHandler) CancelUserLandingGrantApplication(c *gin.Context) {
	userID, _, _, ok := edgeCallerIdentity(c)
	if !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	if err := h.grants.CancelPendingApplication(c.Request.Context(), id, userID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"cancelled": true, "id": id})
}

// ---------- Edge Internal Control-Plane Handlers ----------

func (h *BerthEdgeHandler) EdgeHeartbeat(c *gin.Context) {
	nodeID, ok := getAuthenticatedEdgeNodeID(c)
	if !ok {
		return
	}
	var upd service.EdgeHeartbeatUpdate
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&upd); err != nil {
			response.BadRequest(c, "Invalid heartbeat payload")
			return
		}
	}
	now := time.Now()
	node, err := h.zones.RecordHeartbeat(c.Request.Context(), nodeID, upd, now)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	snap, err := h.leases.BuildRevocationSnapshot(c.Request.Context(), now)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	osName, archName := service.ParseEdgeArchPair(upd.AgentArch)
	edgeRelease, _, _ := service.LookupEdgeRelease(service.ResolveEdgeReleaseDir(), osName, archName)
	payload := gin.H{
		"node":                node,
		"revocation_snapshot": snap,
		"central_pubkey":      h.leases.PublicKeyBase64(),
	}
	if edgeRelease != nil {
		payload["edge_release"] = edgeRelease
	}
	response.Success(c, payload)
}

func (h *BerthEdgeHandler) EdgeDownloadBinary(c *gin.Context) {
	if _, ok := getAuthenticatedEdgeNodeID(c); !ok {
		return
	}
	goos := c.Param("os")
	goarch := c.Param("arch")
	rel, binPath, err := service.LookupEdgeRelease(service.ResolveEdgeReleaseDir(), goos, goarch)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if rel == nil || binPath == "" {
		response.NotFound(c, "No staged berth-edge binary for platform")
		return
	}
	c.Header("X-Berth-Edge-Version", rel.Version)
	c.Header("X-Berth-Edge-SHA256", rel.SHA256)
	c.Header("Content-Type", "application/octet-stream")
	c.File(binPath)
}

func (h *BerthEdgeHandler) AdminListEdgeReleases(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	items := service.ListEdgeReleases(service.ResolveEdgeReleaseDir())
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) EdgeGrantSlice(c *gin.Context) {
	nodeID, ok := getAuthenticatedEdgeNodeID(c)
	if !ok {
		return
	}
	var body struct {
		GrantID        int64 `json:"grant_id"`
		RequestedBytes int64 `json:"requested_bytes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid grant slice request")
		return
	}
	res, err := h.grants.ReserveGrantByteSlice(c.Request.Context(), body.GrantID, nodeID, body.RequestedBytes, time.Now())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, res)
}

func (h *BerthEdgeHandler) EdgeUsageOutbox(c *gin.Context) {
	nodeID, ok := getAuthenticatedEdgeNodeID(c)
	if !ok {
		return
	}
	var body struct {
		Receipts []edgeproto.UsageReceipt `json:"receipts"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid outbox batch")
		return
	}
	acked, err := h.leases.IngestUsageOutbox(c.Request.Context(), nodeID, body.Receipts)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"acked_receipt_ids": acked})
}

func (h *BerthEdgeHandler) EdgeFailover(c *gin.Context) {
	if _, ok := getAuthenticatedEdgeNodeID(c); !ok {
		return
	}
	var req service.EdgeFailoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid failover request")
		return
	}
	resp, err := h.leases.CoordinateFailover(c.Request.Context(), req)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if resp.Action == "cage_rebind_required" {
		c.Header(edgeproto.HeaderAction, "cage_rebind_required")
		c.JSON(http.StatusConflict, gin.H{
			"code":    http.StatusConflict,
			"message": resp.Message,
			"reason":  "cage_rebind_required",
			"data":    resp,
		})
		return
	}
	response.Success(c, resp)
}

func (h *BerthEdgeHandler) EdgeListOAuthTasks(c *gin.Context) {
	nodeID, ok := getAuthenticatedEdgeNodeID(c)
	if !ok {
		return
	}
	tasks := h.leases.ListPendingOAuthTasks(nodeID)
	response.Success(c, gin.H{"tasks": tasks})
}

func (h *BerthEdgeHandler) EdgeCompleteOAuthTask(c *gin.Context) {
	nodeID, ok := getAuthenticatedEdgeNodeID(c)
	if !ok {
		return
	}
	taskID := strings.TrimSpace(c.Param("id"))
	var body struct {
		StatusCode int    `json:"status_code"`
		RespBody   string `json:"resp_body"`
		Error      string `json:"error"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Invalid task completion body")
		return
	}
	task, err := h.leases.CompleteOAuthTask(nodeID, taskID, body.StatusCode, body.RespBody, body.Error)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, task)
}

// ---------- Admin Topology & Landing Grants Handlers ----------

func (h *BerthEdgeHandler) AdminListZones(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	items, err := h.zones.ListZones(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) AdminCreateZone(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	var z service.NetworkZone
	if err := c.ShouldBindJSON(&z); err != nil {
		response.BadRequest(c, "Invalid zone body")
		return
	}
	created, err := h.zones.CreateZone(c.Request.Context(), z)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Created(c, created)
}

func (h *BerthEdgeHandler) AdminListNodes(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	items, err := h.zones.ListNodes(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) AdminCreateNode(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	var n service.EdgeNode
	if err := c.ShouldBindJSON(&n); err != nil {
		response.BadRequest(c, "Invalid edge node body")
		return
	}
	created, err := h.zones.CreateNode(c.Request.Context(), n)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Created(c, created)
}

func (h *BerthEdgeHandler) AdminUpdateNode(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	var n service.EdgeNode
	if err := c.ShouldBindJSON(&n); err != nil {
		response.BadRequest(c, "Invalid edge node body")
		return
	}
	n.ID = id
	updated, err := h.zones.UpdateNode(c.Request.Context(), n)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, updated)
}

func (h *BerthEdgeHandler) AdminListLinks(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	items, err := h.zones.ListLinks(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) AdminCreateLink(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	var l service.ServerLink
	if err := c.ShouldBindJSON(&l); err != nil {
		response.BadRequest(c, "Invalid server link body")
		return
	}
	created, err := h.zones.CreateLink(c.Request.Context(), l)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Created(c, created)
}

func (h *BerthEdgeHandler) AdminDeleteLink(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	if err := h.zones.DeleteLink(c.Request.Context(), id); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true, "id": id})
}

func (h *BerthEdgeHandler) AdminListGrants(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	items, err := h.grants.ListAdminGrants(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items})
}

func (h *BerthEdgeHandler) AdminCreateGrant(c *gin.Context) {
	adminID, ok := requireEdgeAdmin(c)
	if !ok {
		return
	}
	var in service.CreateLandingGrantInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, "Invalid landing grant body")
		return
	}
	in.GrantedByAdminID = adminID
	created, err := h.grants.CreateGrant(c.Request.Context(), in)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Created(c, created)
}

func (h *BerthEdgeHandler) AdminApproveGrant(c *gin.Context) {
	adminID, ok := requireEdgeAdmin(c)
	if !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	var in service.ApproveLandingGrantInput
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&in); err != nil {
			response.BadRequest(c, "Invalid approval body")
			return
		}
	}
	in.GrantID = id
	in.AdminID = adminID
	approved, err := h.grants.ApproveGrant(c.Request.Context(), in)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, approved)
}

func (h *BerthEdgeHandler) AdminRejectGrant(c *gin.Context) {
	adminID, ok := requireEdgeAdmin(c)
	if !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	var body struct {
		ReviewNote string `json:"review_note"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			response.BadRequest(c, "Invalid rejection body")
			return
		}
	}
	rejected, err := h.grants.RejectGrant(c.Request.Context(), id, adminID, body.ReviewNote)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, rejected)
}

func (h *BerthEdgeHandler) AdminRevokeGrant(c *gin.Context) {
	if _, ok := requireEdgeAdmin(c); !ok {
		return
	}
	id, ok := parsePathInt64(c, "id")
	if !ok {
		return
	}
	reason := strings.TrimSpace(c.Query("reason"))
	revSeq, err := h.grants.RevokeGrant(c.Request.Context(), id, reason)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"revoked": true, "id": id, "rev_seq": revSeq})
}
