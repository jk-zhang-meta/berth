package handler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestBerthLandingGrantApprovalLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	centralPub, centralPriv, centralKid, err := service.LoadOrGenerateEdgeSigningKey("", "")
	require.NoError(t, err)
	nodePub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	zoneStore := service.NewMemoryZoneStore(true)
	revSeq := int64(1)
	grantStore := service.NewMemoryLandingGrantStore(zoneStore, &revSeq)
	leaseStore := service.NewMemoryEdgeLeaseStore(&revSeq)

	zoneSvc := service.NewBerthZoneServiceWithStore(zoneStore)
	grantSvc := service.NewBerthLandingGrantServiceWithStore(grantStore)
	leaseSvc := service.NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, centralPub, centralPriv, centralKid)

	zones, err := zoneSvc.ListZones(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, zones)

	// Seed landing node (with private exit_ip that must NEVER leak to user catalog).
	node, err := zoneSvc.CreateNode(t.Context(), service.EdgeNode{
		Name:            "houston-vm100",
		ZoneID:          zones[0].ID,
		Roles:           []string{service.EdgeRoleLanding},
		ExitIP:          "68.77.201.111",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Chicago",
		ExitLocale:      "en_US.UTF-8",
		PubkeyEd25519:   base64.RawURLEncoding.EncodeToString(nodePub),
		Status:          service.EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	r := gin.New()
	h := NewBerthEdgeHandler(zoneSvc, grantSvc, leaseSvc)
	authMiddleware := func(c *gin.Context) {
		switch c.GetHeader("X-Test-Role") {
		case "admin":
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 1})
			c.Set(string(middleware.ContextKeyUserRole), service.RoleAdmin)
		case "user":
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 42})
			c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)
		default:
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
	h.RegisterRoutes(r, authMiddleware, authMiddleware, nil)

	doReq := func(role, method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			require.NoError(t, json.NewEncoder(&buf).Encode(body))
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		if role != "" {
			req.Header.Set("X-Test-Role", role)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// 1. User lists available landing nodes -> redacted (no exit_ip!), has_active=false, has_pending=false.
	w := doReq("user", http.MethodGet, "/api/v1/user/landing-nodes", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "68.77.201.111")
	var catalogEnv struct {
		Data struct {
			Items []service.AvailableLandingNode `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &catalogEnv))
	require.Len(t, catalogEnv.Data.Items, 1)
	require.Equal(t, "houston-vm100", catalogEnv.Data.Items[0].Name)
	require.False(t, catalogEnv.Data.Items[0].HasActiveGrant)
	require.False(t, catalogEnv.Data.Items[0].HasPendingRequest)

	// 2. User applies for houston-vm100 -> 201 pending.
	w = doReq("user", http.MethodPost, "/api/v1/user/landing-grants/apply", map[string]any{
		"node_id":        node.ID,
		"request_reason": "Need US Chicago residential IP for Codex",
		"max_accounts":   2,
	})
	require.Equal(t, http.StatusCreated, w.Code)
	var grantEnv struct {
		Data service.LandingNodeGrant `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))
	require.Equal(t, service.GrantStatusPending, grantEnv.Data.Status)
	require.Nil(t, grantEnv.Data.ProxyID)
	app1ID := grantEnv.Data.ID

	// 3. Duplicate pending application rejected with 409 Conflict.
	w = doReq("user", http.MethodPost, "/api/v1/user/landing-grants/apply", map[string]any{
		"node_id":        node.ID,
		"request_reason": "Duplicate",
	})
	require.Equal(t, http.StatusConflict, w.Code)

	// 4. User cancels pending application -> 200.
	w = doReq("user", http.MethodDelete, fmt.Sprintf("/api/v1/user/landing-grants/%d", app1ID), nil)
	require.Equal(t, http.StatusOK, w.Code)

	// 5. User re-applies -> Admin rejects with review_note -> status=rejected!
	w = doReq("user", http.MethodPost, "/api/v1/user/landing-grants/apply", map[string]any{
		"node_id":        node.ID,
		"request_reason": "Second attempt",
	})
	require.Equal(t, http.StatusCreated, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))
	app2ID := grantEnv.Data.ID

	// Normal user CANNOT approve/reject!
	w = doReq("user", http.MethodPost, fmt.Sprintf("/api/v1/admin/network/grants/%d/reject", app2ID), map[string]any{"review_note": "hijack"})
	require.Equal(t, http.StatusForbidden, w.Code)

	w = doReq("admin", http.MethodPost, fmt.Sprintf("/api/v1/admin/network/grants/%d/reject", app2ID), map[string]any{"review_note": "Please specify project"})
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))
	require.Equal(t, service.GrantStatusRejected, grantEnv.Data.Status)
	require.Equal(t, "Please specify project", grantEnv.Data.ReviewNote)
	require.NotNil(t, grantEnv.Data.ReviewedAt)

	// 6. User re-applies with full details -> Admin approves with custom quota -> status=active + proxy materialized!
	w = doReq("user", http.MethodPost, "/api/v1/user/landing-grants/apply", map[string]any{
		"node_id":        node.ID,
		"request_reason": "AgentOps production Codex workspace",
		"max_accounts":   3,
	})
	require.Equal(t, http.StatusCreated, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))
	app3ID := grantEnv.Data.ID

	w = doReq("admin", http.MethodPost, fmt.Sprintf("/api/v1/admin/network/grants/%d/approve", app3ID), map[string]any{
		"max_bytes":       104857600,
		"max_accounts":    4,
		"max_rpm":         60,
		"max_concurrency": 5,
		"review_note":     "Approved for production use",
	})
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))
	require.Equal(t, service.GrantStatusActive, grantEnv.Data.Status)
	require.NotNil(t, grantEnv.Data.ProxyID)
	require.Equal(t, int64(104857600), grantEnv.Data.MaxBytes)
	require.Equal(t, 4, grantEnv.Data.MaxAccounts)
	require.Equal(t, "Approved for production use", grantEnv.Data.ReviewNote)

	// 7. Re-approving an already-active grant fails cleanly (400).
	w = doReq("admin", http.MethodPost, fmt.Sprintf("/api/v1/admin/network/grants/%d/approve", app3ID), map[string]any{})
	require.Equal(t, http.StatusBadRequest, w.Code)

	// 8. User catalog now reflects has_active_grant=true, has_pending_request=false!
	w = doReq("user", http.MethodGet, "/api/v1/user/landing-nodes", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &catalogEnv))
	require.True(t, catalogEnv.Data.Items[0].HasActiveGrant)
	require.False(t, catalogEnv.Data.Items[0].HasPendingRequest)
}
