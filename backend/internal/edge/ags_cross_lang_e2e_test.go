package edge_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/edge"
	"github.com/jk-zhang-meta/berth/internal/handler"
	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
)

// TestCrossLanguage_BerthCentral_Edge_Cage_AGS_v2_E2E verifies the complete
// end-to-end decoupled production architecture across BOTH Go (Berth Central +
// berth-edge Relay/Transit/Reverse-Tunnel Landing + Account Cage uTLS/httpwire)
// and the compiled Rust `ags` v2 binary launching fake stock `codex` and `claude`
// CLIs (covering JSON + SSE streaming, Cage TZ/LANG alignment, proxy stripping,
// 0 AI bytes on Central, prompt-cache byte invariance, and grant byte metering).
func TestCrossLanguage_BerthCentral_Edge_Cage_AGS_v2_E2E(t *testing.T) {
	agsBin := strings.TrimSpace(os.Getenv("BERTH_E2E_AGS_BIN"))
	if agsBin == "" {
		candidate := "/root/.agent-work/runtime/berth-v2/ags-work/target/release/ags"
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			agsBin = candidate
		}
	}
	if agsBin == "" {
		t.Skip("BERTH_E2E_AGS_BIN not set and local release binary not found")
	}

	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Mock AI Provider HTTPS server echoing exact path, headers, and prompt prefix SHA-256.
	var providerReqCount atomic.Int64
	var seenMu sync.Mutex
	seenPrefixHashes := make([]string, 0, 8)
	leakedBerthHeaders := make([]string, 0)
	seenAuthHeaders := make([]string, 0, 8)

	mockProvider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerReqCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:8])

		seenMu.Lock()
		seenPrefixHashes = append(seenPrefixHashes, hash)
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-berth-") {
				leakedBerthHeaders = append(leakedBerthHeaders, k)
			}
		}
		seenAuthHeaders = append(seenAuthHeaders, r.Header.Get("Authorization"))
		seenMu.Unlock()

		if strings.HasPrefix(r.URL.Path, "/v1/messages") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fl, _ := w.(http.Flusher)
			_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: {\"prefix_hash\":%q}\n\n", hash)
			if fl != nil {
				fl.Flush()
			}
			_, _ = fmt.Fprintf(w, "event: message_stop\ndata: {\"ok\":true}\n\n")
			if fl != nil {
				fl.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"path":        r.URL.Path,
			"prefix_hash": hash,
		})
	}))
	defer mockProvider.Close()

	providerURLParsed, err := url.Parse(mockProvider.URL)
	if err != nil {
		t.Fatalf("parse mock provider url: %v", err)
	}
	providerAuthority := providerURLParsed.Host

	// 2. Local HTTP CONNECT proxy standing in for dedicated residential landing exit.
	var proxyConnectCount atomic.Int64
	connectProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		proxyConnectCount.Add(1)
		targetConn, dErr := net.DialTimeout("tcp4", r.Host, 5*time.Second)
		if dErr != nil {
			http.Error(w, dErr.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = targetConn.Close()
			return
		}
		clientConn, _, hErr := hj.Hijack()
		if hErr != nil {
			_ = targetConn.Close()
			return
		}
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { defer clientConn.Close(); defer targetConn.Close(); _, _ = io.Copy(targetConn, clientConn) }()
		go func() { defer clientConn.Close(); defer targetConn.Close(); _, _ = io.Copy(clientConn, targetConn) }()
	}))
	defer connectProxy.Close()

	// 3. Berth Central (Control Plane ONLY — asserts ZERO AI data traffic hits Central!).
	centralPub, centralPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen central key: %v", err)
	}
	genKey := func() (ed25519.PublicKey, ed25519.PrivateKey, string) {
		pub, priv, gErr := ed25519.GenerateKey(rand.Reader)
		if gErr != nil {
			t.Fatalf("gen key: %v", gErr)
		}
		return pub, priv, base64.RawURLEncoding.EncodeToString(pub)
	}
	_, ingressPriv, ingressPubB64 := genKey()
	_, transitPriv, transitPubB64 := genKey()
	landingPub, landingPriv, landingPubB64 := genKey()

	var revSeq int64 = 1
	zoneStore := service.NewMemoryZoneStore(true)
	zoneSvc := service.NewBerthZoneServiceWithStore(zoneStore)
	grantStore := service.NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := service.NewBerthLandingGrantServiceWithStore(grantStore)
	leaseStore := service.NewMemoryEdgeLeaseStore(&revSeq)
	leaseSvc := service.NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, centralPub, centralPriv, "")
	leaseSvc.SetEdgeDataPlaneStrict(true)
	leaseSvc.SetSnapshotTTL(60 * time.Second)
	leaseSvc.SetLeaseTTL(5 * time.Minute)
	edgeHandler := handler.NewBerthEdgeHandler(zoneSvc, grantSvc, leaseSvc)

	ingressLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ingress: %v", err)
	}
	transitLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen transit: %v", err)
	}
	revHubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen rev hub: %v", err)
	}

	zones, _ := zoneSvc.ListZones(ctx)
	zID := map[string]int64{}
	for _, z := range zones {
		zID[z.Slug] = z.ID
	}

	ingressNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name:          "po0-gz-e2e",
		ZoneID:        zID["cn_mainland"],
		Roles:         []string{service.EdgeRoleIngressRelay},
		PublicAddr:    "http://" + ingressLn.Addr().String(),
		TunnelAddr:    ingressLn.Addr().String(),
		ConnectMode:   service.ConnectModeDirect,
		PubkeyEd25519: ingressPubB64,
		Status:        service.EdgeNodeStatusActive,
	})
	if err != nil {
		t.Fatalf("create ingress node: %v", err)
	}
	transitNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name:          "sh-jp-iplc-e2e",
		ZoneID:        zID["overseas"],
		Roles:         []string{service.EdgeRoleTransit},
		TunnelAddr:    transitLn.Addr().String(),
		ConnectMode:   service.ConnectModeDirect,
		PubkeyEd25519: transitPubB64,
		Status:        service.EdgeNodeStatusActive,
	})
	if err != nil {
		t.Fatalf("create transit node: %v", err)
	}
	landingNode, err := zoneSvc.CreateNode(ctx, service.EdgeNode{
		Name:            "home-la-nat-e2e",
		ZoneID:          zID["home_direct"],
		Roles:           []string{service.EdgeRoleLanding},
		ConnectMode:     service.ConnectModeReverseTunnel,
		ExitIP:          "203.0.113.88",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Los_Angeles",
		ExitLocale:      "en_US.UTF-8",
		ExitASNClass:    "residential_isp",
		PubkeyEd25519:   landingPubB64,
		Status:          service.EdgeNodeStatusActive,
		MaxBytesMonth:   100 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create landing node: %v", err)
	}

	// Asymmetric 1-way IPLC link + outbound NAT reverse tunnel link!
	if _, err := zoneSvc.CreateLink(ctx, service.ServerLink{
		SrcNodeID: ingressNode.ID, DstNodeID: transitNode.ID,
		Direction: service.LinkDirectionOneWay, LinkClass: service.LinkClassIPLC,
		Weight: 10, RTTMs: 18, Enabled: true,
	}); err != nil {
		t.Fatalf("create iplc link: %v", err)
	}
	if _, err := zoneSvc.CreateLink(ctx, service.ServerLink{
		SrcNodeID: transitNode.ID, DstNodeID: landingNode.ID,
		Direction: service.LinkDirectionOneWay, LinkClass: service.LinkClassReverseTunnel,
		Weight: 15, RTTMs: 35, Enabled: true,
	}); err != nil {
		t.Fatalf("create rev link: %v", err)
	}

	expAt := time.Now().Add(2 * time.Hour)
	grant, err := grantSvc.CreateGrant(ctx, service.CreateLandingGrantInput{
		NodeID:           landingNode.ID,
		GranteeUserID:    101,
		GrantedByAdminID: 1,
		ExpiresAt:        &expAt,
		MaxBytes:         10 * 1024 * 1024,
		MaxAccounts:      2,
		MaxRPM:           60,
		MaxConcurrency:   4,
		Notes:            "E2E cross-lang test grant",
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}

	var centralAIDataRequests atomic.Int64
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/v1/responses") ||
			strings.HasPrefix(c.Request.URL.Path, "/v1/messages") ||
			strings.HasPrefix(c.Request.URL.Path, "/v1/chat") {
			centralAIDataRequests.Add(1)
		}
		c.Next()
	})
	userAuth := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer sk-e2e-test" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
			return
		}
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 101, Concurrency: 4})
		c.Set(string(middleware.ContextKeyUserRole), service.RoleUser)
		c.Next()
	}
	// Register Edge internal + admin + renew/revoke routes, plus AGS v2 agent-aware POST /api/v1/ags/leases.
	router.POST("/api/v1/ags/leases", userAuth, func(c *gin.Context) {
		var raw map[string]any
		if err := c.ShouldBindJSON(&raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		agentName, _ := raw["agent"].(string)
		platform := "openai"
		switch strings.ToLower(strings.TrimSpace(agentName)) {
		case "claude":
			platform = "anthropic"
		case "agy":
			platform = "gemini"
		case "grok":
			platform = "grok"
		}
		prefZone, _ := raw["zone_preference"].(string)
		if prefZone == "" || prefZone == "auto" {
			prefZone = "cn_mainland"
		}
		resp, err := leaseSvc.MintLease(c.Request.Context(), service.MintLeaseInput{
			UserID:            101,
			APIKeyID:          501,
			WorkSessionID:     9001,
			Platform:          platform,
			AccountID:         42,
			CageID:            77,
			CageEpoch:         1,
			GrantID:           grant.ID,
			LandingNodeID:     landingNode.ID,
			PreferredZoneSlug: prefZone,
		})
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": 0, "message": "success", "data": resp})
	})
	router.POST("/api/v1/ags/leases/:id/renew", userAuth, edgeHandler.RenewLease)
	router.DELETE("/api/v1/ags/leases/:id", userAuth, edgeHandler.RevokeLease)
	edgeGroup := router.Group("/api/v1/internal/edge", handler.EdgeNodeAuthMiddleware(zoneSvc))
	edgeGroup.POST("/heartbeat", edgeHandler.EdgeHeartbeat)
	edgeGroup.POST("/grant-slice", edgeHandler.EdgeGrantSlice)
	edgeGroup.POST("/usage-outbox", edgeHandler.EdgeUsageOutbox)
	edgeGroup.POST("/failover", edgeHandler.EdgeFailover)
	centralServer := httptest.NewServer(router)
	defer centralServer.Close()

	// 4. Start Transit + ReverseTunnelHub, NAT Home Landing (wired with Track A CageUpstreamExecutor!), and Ingress Relay.
	revReady := make(chan struct{}, 1)
	revHub := edge.NewReverseTunnelHub(
		func(nodeID int64) (ed25519.PublicKey, error) {
			if nodeID == landingNode.ID {
				return landingPub, nil
			}
			return nil, fmt.Errorf("unknown node %d", nodeID)
		},
		func(nodeID int64, online bool, _ uint64) {
			leaseSvc.SetReverseTunnelLive(nodeID, online)
			if online && nodeID == landingNode.ID {
				select {
				case revReady <- struct{}{}:
				default:
				}
			}
		},
	)
	go func() { _ = revHub.Serve(ctx, revHubLn) }()

	transitCentral := edge.NewCentralClient(centralServer.URL, transitNode.ID, transitPriv, nil)
	transitSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config:        &edge.Config{NodeID: transitNode.ID, NodeName: transitNode.Name, Roles: []string{edge.RoleTransit}},
		CentralPubKey: centralPub,
		CentralClient: transitCentral,
		ReverseHub:    revHub,
	})
	if err != nil {
		t.Fatalf("new transit server: %v", err)
	}
	go func() { _ = transitSrv.Serve(ctx, transitLn) }()

	// Landing node with Track A CageUpstreamExecutor (pinned uTLS + httpwire + fail-closed CageGate + CONNECT proxy)!
	walDir := t.TempDir()
	grantWAL, err := edgeproto.OpenGrantWAL(filepath.Join(walDir, "grant.wal"))
	if err != nil {
		t.Fatalf("open grant wal: %v", err)
	}
	defer func() { _ = grantWAL.Close() }()
	outboxWAL, err := edgeproto.OpenOutboxWAL(filepath.Join(walDir, "outbox.wal"))
	if err != nil {
		t.Fatalf("open outbox wal: %v", err)
	}
	defer func() { _ = outboxWAL.Close() }()

	roots := x509.NewCertPool()
	roots.AddCert(mockProvider.Certificate())
	cagePool := cage.NewCageTransportPool()
	cageGate := cage.NewCageGate(77, cage.WithEvictionCallback(cagePool.EvictCage))
	cageGate.Open(5 * time.Minute)
	cageExec := edge.NewCageUpstreamExecutor(cagePool, func(_ context.Context, _ *edgeproto.SessionLeaseClaims) (*edge.CageBinding, error) {
		return &edge.CageBinding{
			CageID:            77,
			ProxyURL:          connectProxy.URL,
			Plane:             cage.PlaneInference,
			ProfilePreset:     cage.PresetClaudeNode24Inference,
			DNSMode:           cage.DNSModeProxyDoHIPv4Only,
			AllowTestLoopback: true,
			RootCAs:           roots,
			Gate:              cageGate,
		}, nil
	}, nil, nil)

	landingCentral := edge.NewCentralClient(centralServer.URL, landingNode.ID, landingPriv, nil)
	landingSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: &edge.Config{
			NodeID:                 landingNode.ID,
			NodeName:               landingNode.Name,
			Roles:                  []string{edge.RoleLanding},
			GrantSliceBytes:        256 * 1024,
			GrantLowWatermark:      32 * 1024,
			PreDebitChunkSize:      4096,
			TestAllowLoopbackHosts: []string{providerAuthority},
		},
		CentralPubKey: centralPub,
		CentralClient: landingCentral,
		GrantWAL:      grantWAL,
		OutboxWAL:     outboxWAL,
		Upstream:      cageExec,
	})
	if err != nil {
		t.Fatalf("new landing server: %v", err)
	}

	revClient := edge.NewReverseTunnelClient(landingNode.ID, landingPriv, revHubLn.Addr().String(), landingSrv.Handler())
	go func() { _ = revClient.Run(ctx) }()
	select {
	case <-revReady:
	case <-time.After(5 * time.Second):
		t.Fatalf("reverse tunnel did not register in time")
	}

	ingressCentral := edge.NewCentralClient(centralServer.URL, ingressNode.ID, ingressPriv, nil)
	ingressSrv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config: &edge.Config{
			NodeID:                 ingressNode.ID,
			NodeName:               ingressNode.Name,
			Roles:                  []string{edge.RoleIngressRelay},
			DefaultUpstreamBaseURL: mockProvider.URL,
		},
		CentralPubKey: centralPub,
		CentralClient: ingressCentral,
	})
	if err != nil {
		t.Fatalf("new ingress server: %v", err)
	}
	go func() { _ = ingressSrv.Serve(ctx, ingressLn) }()

	// Sync signed RevocationSnapshots onto Ingress and Landing.
	snap1, err := ingressCentral.Heartbeat(ctx, "")
	if err != nil {
		t.Fatalf("ingress heartbeat: %v", err)
	}
	if err := ingressSrv.Gate().UpdateSnapshot(snap1); err != nil {
		t.Fatalf("ingress update snapshot: %v", err)
	}
	snap2, err := landingCentral.Heartbeat(ctx, "")
	if err != nil {
		t.Fatalf("landing heartbeat: %v", err)
	}
	if err := landingSrv.Gate().UpdateSnapshot(snap2); err != nil {
		t.Fatalf("landing update snapshot: %v", err)
	}

	// 5. Configure REAL compiled Rust `ags` v2 binary!
	agsHome := t.TempDir()
	agsEnv := append(os.Environ(),
		"HOME="+agsHome,
		"XDG_CONFIG_HOME="+filepath.Join(agsHome, "config"),
		"XDG_STATE_HOME="+filepath.Join(agsHome, "state"),
		"HTTP_PROXY=http://127.0.0.1:9", // Hostile ambient proxy — AGS MUST scrub this!
		"HTTPS_PROXY=http://127.0.0.1:9",
	)

	initCmd := exec.Command(agsBin, "berth", "init",
		"--url", centralServer.URL,
		"--key", "sk-e2e-test",
		"--zone", "cn_mainland",
		"--isolation", "tz-overlay",
		"--allow-insecure-http-for-tests",
	)
	initCmd.Env = agsEnv
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("ags berth init failed: %v\n%s", err, string(out))
	}

	// 6. Create fake stock `codex` and `claude` binaries routed through AGS v2 loopback shim -> Edge -> Cage -> Mock AI Provider!
	fakeBinDir := filepath.Join(agsHome, "bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	reportPath := filepath.Join(agsHome, "cli-report.txt")

	fakeCodex := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
{
  echo "AGENT=codex"
  echo "TZ=${TZ:-}"
  echo "LANG=${LANG:-}"
  echo "LC_ALL=${LC_ALL:-}"
  echo "HTTP_PROXY=${HTTP_PROXY:-}"
  echo "OPENAI_BASE_URL=${OPENAI_BASE_URL:-}"
  echo "TOKEN_PREFIX=${OPENAI_API_KEY:0:9}"
} > %q
curl -fsS -X POST "${OPENAI_BASE_URL}/responses" \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-6.2-sol","input":"deterministic prompt prefix"}' >> %q
echo "" >> %q
curl -fsS -X POST "${OPENAI_BASE_URL}/responses" \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-6.2-sol","input":"deterministic prompt prefix"}' >> %q
echo "" >> %q
`, reportPath, reportPath, reportPath, reportPath, reportPath)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "codex"), []byte(fakeCodex), 0o755); err != nil {
		t.Fatalf("write fake codex: %v", err)
	}

	fakeClaude := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
{
  echo "AGENT=claude"
  echo "TZ=${TZ:-}"
  echo "LANG=${LANG:-}"
  echo "ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL:-}"
  echo "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}"
} > %q
curl -fsS -N -X POST "${ANTHROPIC_BASE_URL}/v1/messages" \
  -H "Authorization: Bearer ${ANTHROPIC_AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-5-2","system":"byte-stable-prefix","messages":[{"role":"user","content":"hi"}]}' >> %q
`, reportPath+".claude", reportPath+".claude")
	if err := os.WriteFile(filepath.Join(fakeBinDir, "claude"), []byte(fakeClaude), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}

	launchEnv := append(agsEnv, "PATH="+fakeBinDir+":"+os.Getenv("PATH"))

	codexCmd := exec.Command(agsBin, "berth", "launch", "--agent", "codex", "--isolation", "tz-overlay")
	codexCmd.Env = launchEnv
	if out, err := codexCmd.CombinedOutput(); err != nil {
		t.Fatalf("ags berth launch codex failed: %v\n%s", err, string(out))
	}

	claudeCmd := exec.Command(agsBin, "berth", "launch", "--agent", "claude", "--isolation", "tz-overlay")
	claudeCmd.Env = launchEnv
	if out, err := claudeCmd.CombinedOutput(); err != nil {
		t.Fatalf("ags berth launch claude failed: %v\n%s", err, string(out))
	}

	// Flush Landing outbox receipts to Berth Central!
	if _, err := landingSrv.Outbox().FlushOnce(ctx, 100, landingCentral.FlushUsageOutbox); err != nil {
		t.Fatalf("flush landing outbox: %v", err)
	}

	// 7. Strict invariant assertions:
	codexReport, _ := os.ReadFile(reportPath)
	claudeReport, _ := os.ReadFile(reportPath + ".claude")
	t.Logf("Codex CLI Report:\n%s", string(codexReport))
	t.Logf("Claude CLI Report:\n%s", string(claudeReport))

	for _, want := range []string{
		"TZ=America/Los_Angeles",
		"LANG=en_US.UTF-8",
		"HTTP_PROXY=\n",
		"TOKEN_PREFIX=ags-shim-",
		`"path":"/v1/responses"`,
	} {
		if !strings.Contains(string(codexReport), want) {
			t.Fatalf("codex report missing %q:\n%s", want, string(codexReport))
		}
	}
	for _, want := range []string{
		"TZ=America/Los_Angeles",
		"ANTHROPIC_API_KEY=\n",
		"event: content_block_delta",
		"event: message_stop",
	} {
		if !strings.Contains(string(claudeReport), want) {
			t.Fatalf("claude report missing %q:\n%s", want, string(claudeReport))
		}
	}

	if got := centralAIDataRequests.Load(); got != 0 {
		t.Fatalf("INVARIANT VIOLATION: %d AI requests hit Berth Central (expected 0!)", got)
	}
	if got := providerReqCount.Load(); got != 3 {
		t.Fatalf("expected 3 AI requests at Mock Provider, got %d", got)
	}
	if got := proxyConnectCount.Load(); got < 1 {
		t.Fatalf("expected requests to traverse Landing Cage CONNECT proxy, got %d connects", got)
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seenPrefixHashes) < 3 || seenPrefixHashes[0] != seenPrefixHashes[1] {
		t.Fatalf("prompt prefix hash drifted across identical turns: %v", seenPrefixHashes)
	}
	// Stealth invariant: ZERO internal X-Berth-* headers and ZERO ephemeral ags-shim-* tokens leak to upstream AI provider!
	if len(leakedBerthHeaders) != 0 {
		t.Fatalf("STEALTH VIOLATION: internal X-Berth-* headers leaked to upstream provider: %v", leakedBerthHeaders)
	}
	for _, auth := range seenAuthHeaders {
		if strings.Contains(auth, "ags-shim-") {
			t.Fatalf("ephemeral shim token leaked to upstream provider: %q", auth)
		}
	}

	updatedGrant, err := grantSvc.GetGrant(ctx, grant.ID)
	if err != nil {
		t.Fatalf("get updated grant: %v", err)
	}
	if updatedGrant.UsedBytes <= 0 {
		t.Fatalf("expected non-zero settled grant used_bytes after outbox flush, got %d", updatedGrant.UsedBytes)
	}
	t.Logf("CROSS-LANG E2E PASSED: CentralAIReqs=%d ProviderReqs=%d CageProxyConnects=%d PrefixHash=%s GrantUsedBytes=%d",
		centralAIDataRequests.Load(), providerReqCount.Load(), proxyConnectCount.Load(), seenPrefixHashes[0], updatedGrant.UsedBytes)
}
