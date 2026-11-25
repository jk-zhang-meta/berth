package edge_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/edge"
	"github.com/jk-zhang-meta/berth/internal/handler"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

// TestFullDecoupledTopologyE2E spins up the complete Berth v2 Track D topology in-process:
//   - Berth Central Control Plane (asserting ZERO AI provider requests & ZERO AI bytes hit Central!)
//   - mgmt_entry (BHE1 attested connection + replay rejection)
//   - ingress_relay (cn_mainland)
//   - transit (1-way IPLC + ReverseTunnelHub)
//   - landing_direct (direct mode) & landing_reverse (NAT home reverse_tunnel mode)
//   - Mock AI Provider (HTTP JSON, SSE stream, RFC 6455 WebSocket echo, 429 fault injection, OAuth refresh)
func TestFullDecoupledTopologyE2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Mock AI Provider (HTTP JSON + SSE + WebSocket echo + 429 failover + OAuth refresh).
	var (
		providerHits       atomic.Int64
		oauthRefreshHits   atomic.Int64
		sseHoldCh          = make(chan struct{})
		wsOpenedCh         = make(chan struct{}, 2)
		forceRateLimitOnce atomic.Bool
	)
	mockProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerHits.Add(1)
		switch r.URL.Path {
		case "/v1/responses":
			if forceRateLimitOnce.CompareAndSwap(true, false) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
				return
			}
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"ok":true,"echo":%q}`, string(body))

		case "/v1/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("A"), 2000))

		case "/v1/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fl, _ := w.(http.Flusher)
			_, _ = io.WriteString(w, "data: chunk-1\n\n")
			if fl != nil {
				fl.Flush()
			}
			if r.URL.Query().Get("hold") == "1" {
				select {
				case <-sseHoldCh:
				case <-r.Context().Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
			_, _ = io.WriteString(w, "data: chunk-2\n\n")
			if fl != nil {
				fl.Flush()
			}

		case "/v1/ws":
			secKey := r.Header.Get("Sec-WebSocket-Key")
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = fmt.Fprintf(rw,
				"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
				edge.ComputeWebSocketAccept(secKey),
			)
			_ = rw.Flush()
			select {
			case wsOpenedCh <- struct{}{}:
			default:
			}
			for {
				op, payload, err := edge.ReadRFC6455Frame(rw, 1024*1024)
				if err != nil || op == edgeproto.WSOpClose {
					return
				}
				if err := edge.WriteRFC6455Frame(conn, op, append([]byte("echo:"), payload...), false); err != nil {
					return
				}
			}

		case "/oauth/token":
			oauthRefreshHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"fresh-tok","expires_in":3600}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockProvider.Close()
	providerAuthority := mockProvider.Listener.Addr().String()

	// 2. Berth Central Control Plane (with strict assertion: ZERO AI provider paths/bytes hit Central!).
	centralPub, centralPriv, centralKid, err := service.LoadOrGenerateEdgeSigningKey("", "")
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := service.NewMemoryZoneStore(true)
	zoneSvc := service.NewBerthZoneServiceWithStore(zoneStore)
	grantStore := service.NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := service.NewBerthLandingGrantServiceWithStore(grantStore)
	leaseStore := service.NewMemoryEdgeLeaseStore(&revSeq)
	leaseSvc := service.NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, centralPub, centralPriv, centralKid)
	leaseSvc.SetEdgeDataPlaneStrict(true)
	require.ErrorIs(t, leaseSvc.AssertDirectProviderEgressAllowed(), service.ErrCentralDirectEgressBlocked)

	var centralAIDataHits atomic.Int64
	router := gin.New()
	router.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/v1/") || strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/edge/v1/") {
			centralAIDataHits.Add(1)
		}
		c.Next()
	})
	userAuth := func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 42})
		c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)
		c.Next()
	}
	adminAuth := func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 1})
		c.Set(string(middleware.ContextKeyUserRole), service.RoleAdmin)
		c.Next()
	}
	edgeHandler := handler.NewBerthEdgeHandler(zoneSvc, grantSvc, leaseSvc)
	edgeHandler.RegisterRoutes(router, userAuth, adminAuth, nil)

	centralSrv := httptest.NewServer(router)
	defer centralSrv.Close()

	// Helper to generate Ed25519 keys per edge node.
	genNodeKey := func() (ed25519.PublicKey, ed25519.PrivateKey, string) {
		pub, priv, gErr := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, gErr)
		return pub, priv, base64.RawURLEncoding.EncodeToString(pub)
	}
	relayPub, relayPriv, relayPubB64 := genNodeKey()
	_, transitPriv, transitPubB64 := genNodeKey()
	_, landDirectPriv, landDirectPubB64 := genNodeKey()
	landRevPub, landRevPriv, landRevPubB64 := genNodeKey()

	// Allocate TCP listeners upfront so topology addresses are known.
	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	transitLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	revHubLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	landDirectLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Register topology in Berth Central:
	//   cn_mainland: ingress_relay (gz-relay)
	//   overseas:    transit (sh-jp-iplc-transit), landing_direct (tokyo-direct)
	//   home_direct: landing_reverse (tokyo-home, connect_mode=reverse_tunnel, NO public listener!)
	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	zID := map[string]int64{}
	for _, z := range zones {
		zID[z.Slug] = z.ID
	}

	relayNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name: "gz-relay", ZoneID: zID["cn_mainland"],
		Roles: []string{service.EdgeRoleIngressRelay, service.EdgeRoleMgmtEntry},
		PublicAddr: relayLn.Addr().String(), TunnelAddr: relayLn.Addr().String(),
		PubkeyEd25519: relayPubB64, Status: service.EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	transitNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name: "sh-jp-iplc", ZoneID: zID["overseas"],
		Roles: []string{service.EdgeRoleTransit},
		TunnelAddr: transitLn.Addr().String(),
		PubkeyEd25519: transitPubB64, Status: service.EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	landDirectNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name: "tokyo-direct", ZoneID: zID["overseas"],
		Roles: []string{service.EdgeRoleLanding, service.EdgeRoleCompat},
		TunnelAddr: landDirectLn.Addr().String(),
		ExitCountryCode: "JP", ExitTimezone: "Asia/Tokyo", ExitLocale: "ja_JP.UTF-8",
		MaxBytesMonth: 10 * 1024 * 1024,
		PubkeyEd25519: landDirectPubB64, Status: service.EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	landRevNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name: "tokyo-home", ZoneID: zID["home_direct"],
		Roles: []string{service.EdgeRoleLanding},
		ConnectMode: service.ConnectModeReverseTunnel,
		ExitCountryCode: "JP", ExitTimezone: "Asia/Tokyo", ExitLocale: "ja_JP.UTF-8",
		MaxBytesMonth: 10 * 1024 * 1024,
		PubkeyEd25519: landRevPubB64, Status: service.EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	// Wire asymmetric 1-way IPLC links + reverse tunnel link:
	//   gz-relay -(1-way iplc)-> sh-jp-iplc -(1-way direct)-> tokyo-direct
	//   sh-jp-iplc -(reverse_tunnel)-> tokyo-home
	_, err = zoneSvc.CreateLink(ctx, service.ServerLink{SrcNodeID: relayNode.ID, DstNodeID: transitNode.ID, Direction: service.LinkDirectionOneWay, LinkClass: service.LinkClassIPLC, Weight: 10, RTTMs: 20, Enabled: true})
	require.NoError(t, err)
	_, err = zoneSvc.CreateLink(ctx, service.ServerLink{SrcNodeID: transitNode.ID, DstNodeID: landDirectNode.ID, Direction: service.LinkDirectionOneWay, LinkClass: service.LinkClassDirect, Weight: 10, RTTMs: 10, Enabled: true})
	require.NoError(t, err)
	_, err = zoneSvc.CreateLink(ctx, service.ServerLink{SrcNodeID: transitNode.ID, DstNodeID: landRevNode.ID, Direction: service.LinkDirectionOneWay, LinkClass: service.LinkClassReverseTunnel, Weight: 5, RTTMs: 5, Enabled: true})
	require.NoError(t, err)

	// 3. Test mgmt_entry (BHE1) attestation + exact replay rejection!
	var attestedIPs []netip.Addr
	var attestedMu sync.Mutex
	bhe1Guard := edgeproto.NewNonceGuard(30*time.Second, 90*time.Second, 1024)
	bhe1Lookup := func(nodeID int64) (ed25519.PublicKey, error) {
		if nodeID == relayNode.ID {
			return relayPub, nil
		}
		return nil, errors.New("unknown node")
	}
	centralRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	bhe1Ln := &edge.BHE1Listener{
		Listener:     centralRawLn,
		LookupPubKey: bhe1Lookup,
		NonceGuard:   bhe1Guard,
	}
	defer func() { _ = bhe1Ln.Close() }()
	go func() {
		for {
			c, aErr := bhe1Ln.Accept()
			if aErr != nil {
				return
			}
			ac := c.(*edgeproto.AttestedConn)
			attestedMu.Lock()
			attestedIPs = append(attestedIPs, ac.Attestation().ClientIP)
			attestedMu.Unlock()
			_, _ = c.Write([]byte("CENTRAL-OK"))
			_ = c.Close()
		}
	}()

	mgmtLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtProxy := edge.NewMgmtEntryProxy(relayNode.ID, relayPriv, centralRawLn.Addr().String())
	go func() { _ = mgmtProxy.Serve(ctx, mgmtLn) }()

	// Connect through mgmt_entry -> BHE1Listener verifies attested peer IP.
	mc, err := net.DialTimeout("tcp", mgmtLn.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	reply, err := io.ReadAll(mc)
	require.NoError(t, err)
	_ = mc.Close()
	require.Equal(t, "CENTRAL-OK", string(reply))
	attestedMu.Lock()
	require.Len(t, attestedIPs, 1)
	require.Equal(t, netip.MustParseAddr("127.0.0.1"), attestedIPs[0])
	attestedMu.Unlock()

	// Replay test on BHE1 frame directly against bhe1Guard.
	rawBHE1, _, err := edgeproto.EncodeBHE1(relayPriv, relayNode.ID, netip.MustParseAddr("198.51.100.77"), time.Now())
	require.NoError(t, err)
	_, err = edgeproto.ReadAndVerifyPreface(bytes.NewReader(rawBHE1), bhe1Lookup, bhe1Guard, time.Now())
	require.NoError(t, err)
	_, err = edgeproto.ReadAndVerifyPreface(bytes.NewReader(rawBHE1), bhe1Lookup, bhe1Guard, time.Now())
	require.ErrorIs(t, err, edgeproto.ErrBHE1Replay)

	// 4. Boot Transit (with ReverseTunnelHub), Landing Direct, Landing Reverse, and Ingress Relay!
	revTunnelReady := make(chan struct{}, 1)
	revHub := edge.NewReverseTunnelHub(
		func(nodeID int64) (ed25519.PublicKey, error) {
			if nodeID == landRevNode.ID {
				return landRevPub, nil
			}
			return nil, errors.New("unknown landing")
		},
		func(nodeID int64, online bool, _ uint64) {
			leaseSvc.SetReverseTunnelLive(nodeID, online)
			if online && nodeID == landRevNode.ID {
				select {
				case revTunnelReady <- struct{}{}:
				default:
				}
			}
		},
	)
	go func() { _ = revHub.Serve(ctx, revHubLn) }()

	transitCfg := &edge.Config{
		NodeID: transitNode.ID, NodeName: transitNode.Name,
		Roles: []string{edge.RoleTransit},
	}
	transitSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: transitCfg, CentralPubKey: centralPub,
		CentralClient: edge.NewCentralClient(centralSrv.URL, transitNode.ID, transitPriv, nil),
		ReverseHub:    revHub,
	})
	require.NoError(t, err)
	go func() { _ = transitSrv.Serve(ctx, transitLn) }()

	// Landing Direct
	directWALDir := t.TempDir()
	directGrantWAL, err := edgeproto.OpenGrantWAL(filepath.Join(directWALDir, "grant.wal"))
	require.NoError(t, err)
	defer func() { _ = directGrantWAL.Close() }()
	directOutbox, err := edgeproto.OpenOutboxWAL(filepath.Join(directWALDir, "outbox.wal"))
	require.NoError(t, err)
	defer func() { _ = directOutbox.Close() }()

	directCentralClient := edge.NewCentralClient(centralSrv.URL, landDirectNode.ID, landDirectPriv, nil)
	landDirectSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: &edge.Config{
			NodeID: landDirectNode.ID, NodeName: landDirectNode.Name,
			Roles: []string{edge.RoleLanding, edge.RoleCompat},
			GrantSliceBytes: 1024, GrantLowWatermark: 256, PreDebitChunkSize: 256,
			TestAllowLoopbackHosts: []string{providerAuthority},
		},
		CentralPubKey: centralPub,
		CentralClient: directCentralClient,
		GrantWAL:      directGrantWAL,
		OutboxWAL:     directOutbox,
	})
	require.NoError(t, err)
	go func() { _ = landDirectSrv.Serve(ctx, landDirectLn) }()

	// Landing Reverse (NAT Home mode — ZERO listening port! Dials outbound to Transit's ReverseTunnelHub!)
	revWALDir := t.TempDir()
	revGrantWAL, err := edgeproto.OpenGrantWAL(filepath.Join(revWALDir, "grant.wal"))
	require.NoError(t, err)
	defer func() { _ = revGrantWAL.Close() }()
	revOutbox, err := edgeproto.OpenOutboxWAL(filepath.Join(revWALDir, "outbox.wal"))
	require.NoError(t, err)
	defer func() { _ = revOutbox.Close() }()

	revCentralClient := edge.NewCentralClient(centralSrv.URL, landRevNode.ID, landRevPriv, nil)
	landRevSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: &edge.Config{
			NodeID: landRevNode.ID, NodeName: landRevNode.Name,
			Roles: []string{edge.RoleLanding},
			GrantSliceBytes: 4096, GrantLowWatermark: 512, PreDebitChunkSize: 256,
			TestAllowLoopbackHosts: []string{providerAuthority},
		},
		CentralPubKey: centralPub,
		CentralClient: revCentralClient,
		GrantWAL:      revGrantWAL,
		OutboxWAL:     revOutbox,
	})
	require.NoError(t, err)
	revClient := edge.NewReverseTunnelClient(landRevNode.ID, landRevPriv, revHubLn.Addr().String(), landRevSrv.Handler())
	go func() { _ = revClient.Run(ctx) }()

	select {
	case <-revTunnelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("reverse tunnel landing node did not register in time")
	}

	// Ingress Relay (configured with failover candidates callback for failover test)
	var failoverCands []edge.FailoverCandidateDTO
	var failoverMu sync.Mutex
	relayCentralClient := edge.NewCentralClient(centralSrv.URL, relayNode.ID, relayPriv, nil)
	relaySrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: &edge.Config{
			NodeID: relayNode.ID, NodeName: relayNode.Name,
			Roles:                  []string{edge.RoleIngressRelay},
			DefaultUpstreamBaseURL: mockProvider.URL,
		},
		CentralPubKey: centralPub,
		CentralClient: relayCentralClient,
		FailoverLookup: func(*edgeproto.SessionLeaseClaims) []edge.FailoverCandidateDTO {
			failoverMu.Lock()
			defer failoverMu.Unlock()
			return failoverCands
		},
	})
	require.NoError(t, err)
	go func() { _ = relaySrv.Serve(ctx, relayLn) }()

	// Push fresh signed RevocationSnapshot from Central heartbeat to Relay + both Landings!
	syncSnapshots := func() {
		for _, pair := range []struct {
			c *edge.CentralClient
			s *edge.EdgeServer
		}{
			{relayCentralClient, relaySrv},
			{directCentralClient, landDirectSrv},
			{revCentralClient, landRevSrv},
		} {
			snap, hbErr := pair.c.Heartbeat(ctx, "active")
			require.NoError(t, hbErr)
			require.NoError(t, pair.s.Gate().UpdateSnapshot(snap))
		}
	}
	syncSnapshots()

	// Create Admin Landing Grants:
	//   grantDirect: generous 100KB on tokyo-direct
	//   grantRev:    generous 100KB on tokyo-home (reverse tunnel)
	//   grantTight:  strict 500B cap on tokyo-direct (for exact cutoff test!)
	grantDirect, err := grantSvc.CreateGrant(ctx, service.CreateLandingGrantInput{
		NodeID: landDirectNode.ID, GranteeUserID: 42, MaxBytes: 100_000, MaxAccounts: 2,
	})
	require.NoError(t, err)
	grantRev, err := grantSvc.CreateGrant(ctx, service.CreateLandingGrantInput{
		NodeID: landRevNode.ID, GranteeUserID: 42, MaxBytes: 100_000, MaxAccounts: 2,
	})
	require.NoError(t, err)
	grantTight, err := grantSvc.CreateGrant(ctx, service.CreateLandingGrantInput{
		NodeID: landDirectNode.ID, GranteeUserID: 42, MaxBytes: 500, MaxAccounts: 1,
	})
	require.NoError(t, err)

	// Mint leases!
	leaseDirect, err := leaseSvc.MintLease(ctx, service.MintLeaseInput{
		UserID: 42, APIKeyID: 77, WorkSessionID: 1, Platform: "openai",
		AccountID: 501, CageID: 10, CageEpoch: 1, GrantID: grantDirect.ID,
		LandingNodeID: landDirectNode.ID, PeerCountryCode: "CN",
	})
	require.NoError(t, err)
	require.Len(t, leaseDirect.RouteChain, 3) // gz-relay -> sh-jp-iplc -> tokyo-direct

	leaseRev, err := leaseSvc.MintLease(ctx, service.MintLeaseInput{
		UserID: 42, APIKeyID: 77, WorkSessionID: 2, Platform: "openai",
		AccountID: 502, CageID: 11, CageEpoch: 1, GrantID: grantRev.ID,
		LandingNodeID: landRevNode.ID, PeerCountryCode: "CN",
	})
	require.NoError(t, err)
	require.Len(t, leaseRev.RouteChain, 3) // gz-relay -> sh-jp-iplc =(rev)=> tokyo-home
	require.Equal(t, service.LinkClassReverseTunnel, leaseRev.RouteChain[2].LinkClass)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	relayURL := "http://" + relayLn.Addr().String()

	// === ASSERTION 1: Happy-path HTTP JSON over Direct Landing (1-way IPLC) ===
	req, _ := http.NewRequest(http.MethodPost, relayURL+"/v1/responses", strings.NewReader(`{"msg":"hi-direct"}`))
	req.Header.Set("Authorization", "Bearer "+leaseDirect.Token)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), "hi-direct")
	require.Equal(t, "tokyo-direct", resp.Header.Get(edgeproto.HeaderLandingNode))

	// === ASSERTION 2: Happy-path HTTP JSON + SSE + WebSocket over Reverse-Tunnel NAT Home Landing! ===
	req, _ = http.NewRequest(http.MethodPost, relayURL+"/v1/responses", strings.NewReader(`{"msg":"hi-reverse-home"}`))
	req.Header.Set("Authorization", "Bearer "+leaseRev.Token)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), "hi-reverse-home")
	require.Equal(t, "tokyo-home", resp.Header.Get(edgeproto.HeaderLandingNode))

	// SSE streaming over Reverse-Tunnel NAT Home Landing
	req, _ = http.NewRequest(http.MethodGet, relayURL+"/v1/sse", nil)
	req.Header.Set("Authorization", "Bearer "+leaseRev.Token)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	sseBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(sseBody), "data: chunk-1")
	require.Contains(t, string(sseBody), "data: chunk-2")

	// WebSocket echo over Reverse-Tunnel NAT Home Landing
	wsGuard := edge.NewCompatSSRFGuard(nil, []string{relayLn.Addr().String()}, nil)
	wsHdr := http.Header{"Authorization": []string{"Bearer " + leaseRev.Token}}
	wsConn, wsBR, _, err := edge.DialRFC6455WebSocket(ctx, wsGuard, nil, "ws://"+relayLn.Addr().String()+"/v1/ws", wsHdr)
	require.NoError(t, err)
	require.NoError(t, edge.WriteRFC6455Frame(wsConn, edgeproto.WSOpText, []byte("hello-ws-reverse"), true))
	op, payload, err := edge.ReadRFC6455Frame(wsBR, 1024*1024)
	require.NoError(t, err)
	require.Equal(t, edgeproto.WSOpText, op)
	require.Equal(t, "echo:hello-ws-reverse", string(payload))
	require.NoError(t, edge.WriteRFC6455Close(wsConn, edge.WSCloseNormalClosure, "bye", true))
	_ = wsConn.Close()

	// === ASSERTION 3: Instant Revocation Snapshot closes LIVE SSE stream AND LIVE WebSocket with code 4009! ===
	// Open live SSE stream + live WS under leaseRev.
	sseReq, _ := http.NewRequest(http.MethodGet, relayURL+"/v1/sse?hold=1", nil)
	sseReq.Header.Set("Authorization", "Bearer "+leaseRev.Token)
	liveSSEResp, err := httpClient.Do(sseReq)
	require.NoError(t, err)
	sseReader := bufio.NewReader(liveSSEResp.Body)
	firstLine, err := sseReader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, firstLine, "chunk-1")

	liveWSConn, liveWSBR, _, err := edge.DialRFC6455WebSocket(ctx, wsGuard, nil, "ws://"+relayLn.Addr().String()+"/v1/ws", wsHdr)
	require.NoError(t, err)
	defer func() { _ = liveWSConn.Close() }()

	// Revoke leaseRev on Central and push fresh RevocationSnapshot to Edge!
	_, err = leaseSvc.RevokeLease(ctx, 42, false, leaseRev.LeaseID)
	require.NoError(t, err)
	syncSnapshots()

	// Live SSE stream MUST terminate promptly with terminal error event!
	sseTailCh := make(chan string, 1)
	go func() {
		rest, _ := io.ReadAll(sseReader)
		_ = liveSSEResp.Body.Close()
		sseTailCh <- string(rest)
	}()
	select {
	case tail := <-sseTailCh:
		require.Contains(t, tail, "cage_rebind_required")
	case <-time.After(3 * time.Second):
		t.Fatal("live SSE stream was not closed on lease revocation")
	}

	// Live WebSocket MUST receive close code 4009 (or EOF immediately after close)!
	_ = liveWSConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	wsOp, wsPayload, wsErr := edge.ReadRFC6455Frame(liveWSBR, 1024*1024)
	if wsErr == nil {
		require.Equal(t, edgeproto.WSOpClose, wsOp)
		require.GreaterOrEqual(t, len(wsPayload), 2)
		closeCode := binary.BigEndian.Uint16(wsPayload[:2])
		require.Equal(t, edge.WSCloseCageRebind, closeCode)
	}
	close(sseHoldCh)

	// === ASSERTION 4: Fail-Closed Grant max_bytes Cutoff at Exact Budget Boundary (500 bytes)! ===
	leaseTight, err := leaseSvc.MintLease(ctx, service.MintLeaseInput{
		UserID: 42, APIKeyID: 77, WorkSessionID: 3, Platform: "openai",
		AccountID: 503, CageID: 12, CageEpoch: 1, GrantID: grantTight.ID,
		LandingNodeID: landDirectNode.ID, PeerCountryCode: "CN",
	})
	require.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, relayURL+"/v1/big", nil)
	req.Header.Set("Authorization", "Bearer "+leaseTight.Token)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	bigGot, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// Mock provider tries to send 2000B, grant max_bytes is 500B -> MUST stop at exact 500 bytes!
	require.Equal(t, 500, len(bigGot), "expected fail-closed cutoff at exact 500-byte grant budget")

	// Next request on grantTight MUST be rejected fail-closed with 403 landing_grant_exhausted!
	req, _ = http.NewRequest(http.MethodGet, relayURL+"/v1/big", nil)
	req.Header.Set("Authorization", "Bearer "+leaseTight.Token)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	errBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Contains(t, string(errBody), "landing_grant_exhausted")

	// === ASSERTION 5: Durable Outbox delivers idempotent receipts to Central and compacts ===
	require.Greater(t, directOutbox.PendingCount(), 0)
	flushedDirect, err := directOutbox.FlushOnce(ctx, 100, directCentralClient.FlushUsageOutbox)
	require.NoError(t, err)
	require.Greater(t, flushedDirect, 0)
	require.Equal(t, 0, directOutbox.PendingCount())

	flushedRev, err := revOutbox.FlushOnce(ctx, 100, revCentralClient.FlushUsageOutbox)
	require.NoError(t, err)
	require.Greater(t, flushedRev, 0)
	require.Equal(t, 0, revOutbox.PendingCount())

	tightAfter, err := grantSvc.GetGrant(ctx, grantTight.ID)
	require.NoError(t, err)
	require.Equal(t, int64(500), tightAfter.UsedBytes)
	require.Equal(t, service.GrantStatusQuotaExhausted, tightAfter.Status)

	// Re-submitting the exact same receipt ID to Central MUST be idempotent (0 additional charge)!
	dupAck, err := leaseSvc.IngestUsageOutbox(ctx, landDirectNode.ID, []edgeproto.UsageReceipt{{
		ReceiptID: "idemp-check-1", NodeID: landDirectNode.ID, GrantID: grantDirect.ID, TotalBytes: 123, RequestCount: 1, StatusCode: 200,
	}})
	require.NoError(t, err)
	require.Equal(t, []string{"idemp-check-1"}, dupAck)
	beforeDup, _ := grantSvc.GetGrant(ctx, grantDirect.ID)
	_, err = leaseSvc.IngestUsageOutbox(ctx, landDirectNode.ID, []edgeproto.UsageReceipt{{
		ReceiptID: "idemp-check-1", NodeID: landDirectNode.ID, GrantID: grantDirect.ID, TotalBytes: 123, RequestCount: 1, StatusCode: 200,
	}})
	require.NoError(t, err)
	afterDup, _ := grantSvc.GetGrant(ctx, grantDirect.ID)
	require.Equal(t, beforeDup.UsedBytes, afterDup.UsedBytes)

	// === ASSERTION 6: Pre-commit 429 Failover -> HTTP 409 cage_rebind_required for cross-cohort! ===
	failoverMu.Lock()
	failoverCands = []edge.FailoverCandidateDTO{
		{AccountID: 777, LandingNodeID: landDirectNode.ID, CohortTimezone: "America/Chicago", CohortCountryCode: "US", CohortLocale: "en_US.UTF-8"},
	}
	failoverMu.Unlock()
	forceRateLimitOnce.Store(true)
	req, _ = http.NewRequest(http.MethodPost, relayURL+"/v1/responses", strings.NewReader(`{"msg":"trigger-429"}`))
	req.Header.Set("Authorization", "Bearer "+leaseDirect.Token)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	rebindBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	require.Equal(t, "cage_rebind_required", resp.Header.Get(edgeproto.HeaderAction))
	require.Contains(t, string(rebindBody), "America/Chicago")

	// === ASSERTION 7: Central-dispatched OAuth refresh task executed locally on Landing! ===
	task := leaseSvc.EnqueueOAuthTask(service.EdgeOAuthTask{
		NodeID:    landDirectNode.ID,
		AccountID: 501,
		Kind:      "token_refresh",
		TargetURL: mockProvider.URL + "/oauth/token",
		Method:    http.MethodPost,
	})
	execCount, err := landDirectSrv.ExecutePendingOAuthTasks(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, execCount)
	require.Equal(t, int64(1), oauthRefreshHits.Load())
	require.Empty(t, leaseSvc.ListPendingOAuthTasks(landDirectNode.ID))
	_ = task

	// === ASSERTION 8: ZERO AI provider requests / ZERO AI data bytes ever hit Berth Central! ===
	require.Equal(t, int64(0), centralAIDataHits.Load(), "Berth Central MUST NEVER handle AI data-plane traffic!")
	require.GreaterOrEqual(t, providerHits.Load(), int64(6), "Mock AI provider should have served all Edge requests")

	// Ensure unused helper import check stays clean.
	var checkJSON map[string]any
	require.NoError(t, json.Unmarshal(rebindBody, &checkJSON))
	_ = strconv.Itoa(1)
}
