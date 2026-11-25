package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestBerthEdgeHandler_RoutesAuthAndContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	centralPub, centralPriv, centralKid, err := service.LoadOrGenerateEdgeSigningKey("", "")
	require.NoError(t, err)
	nodePub, nodePriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := service.NewMemoryZoneStore(true)
	zoneSvc := service.NewBerthZoneServiceWithStore(zoneStore)
	grantStore := service.NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := service.NewBerthLandingGrantServiceWithStore(grantStore)
	leaseStore := service.NewMemoryEdgeLeaseStore(&revSeq)
	leaseSvc := service.NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, centralPub, centralPriv, centralKid)

	h := NewBerthEdgeHandler(zoneSvc, grantSvc, leaseSvc)
	router := gin.New()

	// Auth middlewares driven by test headers.
	userAuth := func(c *gin.Context) {
		if uidStr := c.GetHeader("X-Test-User-ID"); uidStr != "" {
			uid, _ := strconv.ParseInt(uidStr, 10, 64)
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: uid})
			c.Set(string(middleware.ContextKeyUserRole), c.GetHeader("X-Test-Role"))
		}
		c.Next()
	}
	adminAuth := userAuth
	h.RegisterRoutes(router, userAuth, adminAuth, nil) // nil edgeAuth exercises built-in EdgeNodeAuthMiddleware!

	doReq := func(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
		var rdr *bytes.Reader
		if body != nil {
			b, err := json.Marshal(body)
			require.NoError(t, err)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	adminHeaders := map[string]string{"X-Test-User-ID": "1", "X-Test-Role": service.RoleAdmin}
	userHeaders := map[string]string{"X-Test-User-ID": "42", "X-Test-Role": service.RoleUser}

	// Non-admin MUST receive 403 on admin topology routes!
	w := doReq(http.MethodGet, "/api/v1/admin/network/zones", nil, userHeaders)
	require.Equal(t, http.StatusForbidden, w.Code)

	// Admin lists seeded zones.
	w = doReq(http.MethodGet, "/api/v1/admin/network/zones", nil, adminHeaders)
	require.Equal(t, http.StatusOK, w.Code)

	// Admin creates relay + landing nodes with registered Ed25519 pubkey.
	zones, err := zoneSvc.ListZones(context.Background())
	require.NoError(t, err)
	cnZoneID := zones[1].ID
	overseasZoneID := zones[2].ID

	w = doReq(http.MethodPost, "/api/v1/admin/network/nodes", map[string]any{
		"name":           "cn-relay-1",
		"zone_id":        cnZoneID,
		"roles":          []string{service.EdgeRoleIngressRelay},
		"tunnel_addr":    "10.0.0.1:9443",
		"status":         service.EdgeNodeStatusActive,
		"pubkey_ed25519": base64.RawURLEncoding.EncodeToString(nodePub),
	}, adminHeaders)
	require.Equal(t, http.StatusCreated, w.Code)
	var relayEnv struct {
		Data service.EdgeNode `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &relayEnv))

	w = doReq(http.MethodPost, "/api/v1/admin/network/nodes", map[string]any{
		"name":              "jp-landing-1",
		"zone_id":           overseasZoneID,
		"roles":             []string{service.EdgeRoleLanding},
		"tunnel_addr":       "10.0.0.2:9443",
		"status":            service.EdgeNodeStatusActive,
		"exit_country_code": "JP",
		"exit_timezone":     "Asia/Tokyo",
		"exit_locale":       "ja_JP.UTF-8",
		"max_bytes_month":   100000,
		"pubkey_ed25519":    base64.RawURLEncoding.EncodeToString(nodePub),
	}, adminHeaders)
	require.Equal(t, http.StatusCreated, w.Code)
	var landEnv struct {
		Data service.EdgeNode `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &landEnv))

	// Admin links cn-relay-1 -> jp-landing-1.
	w = doReq(http.MethodPost, "/api/v1/admin/network/links", map[string]any{
		"src_node_id": relayEnv.Data.ID,
		"dst_node_id": landEnv.Data.ID,
		"direction":   service.LinkDirectionOneWay,
		"link_class":  service.LinkClassIPLC,
		"weight":      10,
		"rtt_ms":      25,
		"enabled":     true,
	}, adminHeaders)
	require.Equal(t, http.StatusCreated, w.Code)

	// Admin grants jp-landing-1 to user 42.
	w = doReq(http.MethodPost, "/api/v1/admin/network/grants", map[string]any{
		"node_id":         landEnv.Data.ID,
		"grantee_user_id": 42,
		"max_bytes":       50000,
		"max_accounts":    2,
	}, adminHeaders)
	require.Equal(t, http.StatusCreated, w.Code)
	var grantEnv struct {
		Data service.LandingNodeGrant `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grantEnv))

	// User 42 sees their own landing grants.
	w = doReq(http.MethodGet, "/api/v1/user/landing-grants", nil, userHeaders)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"remaining_bytes":50000`)

	// User 42 mints an AGS v2 lease.
	w = doReq(http.MethodPost, "/api/v1/ags/leases", map[string]any{
		"work_session_id":   10,
		"platform":          "openai",
		"account_id":        501,
		"cage_id":           88,
		"cage_epoch":        1,
		"grant_id":          grantEnv.Data.ID,
		"landing_node_id":   landEnv.Data.ID,
		"peer_country_code": "CN",
	}, userHeaders)
	require.Equal(t, http.StatusOK, w.Code)
	var leaseEnv struct {
		Data service.MintedLeaseResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &leaseEnv))
	require.NotEmpty(t, leaseEnv.Data.Token)

	// Helper for Ed25519-signed Edge internal calls.
	doEdgeReq := func(nodeID int64, method, path string, body any) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			var err error
			raw, err = json.Marshal(body)
			require.NoError(t, err)
		}
		ts := time.Now().Unix()
		sig, err := edgeproto.SignNodeRequest(nodePriv, nodeID, method, path, ts, raw)
		require.NoError(t, err)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(edgeproto.HeaderNodeID, strconv.FormatInt(nodeID, 10))
		req.Header.Set(edgeproto.HeaderNodeTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(edgeproto.HeaderNodeSignature, sig)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Unauthenticated internal heartbeat MUST return 401.
	w = doReq(http.MethodPost, "/api/v1/internal/edge/heartbeat", map[string]any{"status": "active"}, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// Signed heartbeat returns fresh signed RevocationSnapshot!
	w = doEdgeReq(landEnv.Data.ID, http.MethodPost, "/api/v1/internal/edge/heartbeat", map[string]any{"status": "active"})
	require.Equal(t, http.StatusOK, w.Code)
	var hbEnv struct {
		Data struct {
			RevocationSnapshot edgeproto.RevocationSnapshot `json:"revocation_snapshot"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &hbEnv))
	require.NoError(t, edgeproto.VerifyRevocationSnapshot(centralPub, &hbEnv.Data.RevocationSnapshot, time.Now()))

	// Signed grant-slice reserves bytes atomically!
	w = doEdgeReq(landEnv.Data.ID, http.MethodPost, "/api/v1/internal/edge/grant-slice", map[string]any{
		"grant_id":        grantEnv.Data.ID,
		"requested_bytes": 10000,
	})
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"granted_bytes":10000`)

	// Signed failover with cross-cohort candidate returns HTTP 409 cage_rebind_required!
	w = doEdgeReq(relayEnv.Data.ID, http.MethodPost, "/api/v1/internal/edge/failover", service.EdgeFailoverRequest{
		LeaseID:         leaseEnv.Data.LeaseID,
		FailedAccountID: 501,
		StatusCode:      429,
		Candidates: []service.FailoverCandidate{
			{AccountID: 900, LandingNodeID: landEnv.Data.ID, CohortTimezone: "America/Chicago", CohortCountryCode: "US"},
		},
	})
	require.Equal(t, http.StatusConflict, w.Code)
	require.Equal(t, "cage_rebind_required", w.Header().Get(edgeproto.HeaderAction))

	// Signed usage-outbox ACKs receipts idempotently!
	w = doEdgeReq(landEnv.Data.ID, http.MethodPost, "/api/v1/internal/edge/usage-outbox", map[string]any{
		"receipts": []edgeproto.UsageReceipt{{
			ReceiptID: "r-100", NodeID: landEnv.Data.ID, GrantID: grantEnv.Data.ID, TotalBytes: 2500, RequestCount: 1, StatusCode: 200,
		}},
	})
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"r-100"`)

	// User revokes lease -> DELETE /api/v1/ags/leases/:id.
	w = doReq(http.MethodDelete, "/api/v1/ags/leases/"+leaseEnv.Data.LeaseID, nil, userHeaders)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"revoked":true`)
}
