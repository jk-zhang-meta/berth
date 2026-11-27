package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/antigravity"
	"github.com/jk-zhang-meta/berth/internal/pkg/httpclient"
)

func TestParseEdgeInternalNodeName(t *testing.T) {
	if name, ok := ParseEdgeInternalNodeName("https://legend-sg.edge.internal:443"); !ok || name != "legend-sg" {
		t.Fatalf("expected legend-sg, got %q (%v)", name, ok)
	}
	if name, ok := ParseEdgeInternalNodeName("http://houston-vm100.edge.internal"); !ok || name != "houston-vm100" {
		t.Fatalf("expected houston-vm100, got %q (%v)", name, ok)
	}
	if _, ok := ParseEdgeInternalNodeName("socks5://1.2.3.4:1080"); ok {
		t.Fatalf("external socks5 proxy must not match edge.internal")
	}
	if _, ok := ParseEdgeInternalNodeName(""); ok {
		t.Fatalf("empty proxy must not match")
	}
}

func TestEdgeLandingRoundTripperAtomicClaimHeadersAndPurge(t *testing.T) {
	zoneStore := NewMemoryZoneStore(false)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	ctx := context.Background()
	z, err := zoneSvc.CreateZone(ctx, NetworkZone{Slug: "sg", DisplayName: "SG"})
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	node, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:        "legend-sg",
		ZoneID:      z.ID,
		Roles:       []string{EdgeRoleLanding},
		ConnectMode: ConnectModeReverseTunnel,
		Status:      EdgeNodeStatusActive,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(NewMemoryEdgeLeaseStore(nil), zoneSvc, nil, pub, priv, "k1")
	RegisterDefaultEdgeLeaseService(leaseSvc)
	defer RegisterDefaultEdgeLeaseService(nil)

	// Simulate legend-sg berth-edge long-polling and completing the OAuth task.
	go func() {
		tasks := leaseSvc.WaitPendingOAuthTasks(ctx, node.ID, 5*time.Second)
		if len(tasks) != 1 {
			return
		}
		// Second immediate poll MUST return 0 tasks (atomic single-claim prevents duplicate POST!).
		if dup := leaseSvc.ListPendingOAuthTasks(node.ID); len(dup) != 0 {
			t.Errorf("expected atomic single-claim, got %d duplicate tasks", len(dup))
		}
		body := []byte(`{"access_token":"tok_sg_ok","token_type":"Bearer","expires_in":3600}`)
		_, _ = leaseSvc.CompleteOAuthTaskFull(
			node.ID,
			tasks[0].TaskID,
			tasks[0].ClaimID,
			302,
			"",
			base64.StdEncoding.EncodeToString(body),
			map[string][]string{
				"Content-Type": {"application/json"},
				"Location":     {"https://accounts.x.ai/done"},
				"Set-Cookie":   {"sso=abc123; Path=/", "csrf=xyz; Path=/"},
			},
			"",
		)
		// Second completion attempt MUST be idempotent and NOT overwrite first success!
		_, _ = leaseSvc.CompleteOAuthTaskFull(node.ID, tasks[0].TaskID, tasks[0].ClaimID, 500, "", "", nil, "late duplicate error")
	}()

	rt := NewEdgeLandingRoundTripperForAccount("https://legend-sg.edge.internal:443", 42)
	if rt == nil {
		t.Fatalf("expected edge landing RoundTripper")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://platform.claude.com/v1/oauth/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 302 {
		t.Fatalf("expected 302 (no internal redirect following), got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://accounts.x.ai/done" {
		t.Fatalf("expected Location preserved, got %q", loc)
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 || !strings.HasPrefix(cookies[0], "sso=abc123") {
		t.Fatalf("expected multi-valued Set-Cookie preserved, got %v", cookies)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "tok_sg_ok") {
		t.Fatalf("unexpected body: %s", string(body))
	}

	// Verify secrets/tasks are purged from Central memory after consumption.
	leaseSvc.mu.RLock()
	remainingTasks := len(leaseSvc.oauthTaskIndex)
	leaseSvc.mu.RUnlock()
	if remainingTasks != 0 {
		t.Fatalf("expected consumed OAuth task purged from memory, found %d", remainingTasks)
	}

	// ProbeEdgeLandingNode must fail closed when heartbeat is nil or exit IP is empty.
	if _, _, err := ProbeEdgeLandingNode(ctx, "legend-sg"); err == nil {
		t.Fatalf("expected ProbeEdgeLandingNode to fail when heartbeat/exit IP missing")
	}

	// Populate fresh heartbeat + exit IP and answer live health_probe task.
	node.ExitIP = "217.116.175.208"
	node.ExitCountryCode = "SG"
	node.ExitTimezone = "Asia/Singapore"
	_, _ = zoneSvc.UpdateNode(ctx, *node)
	_, err = zoneSvc.RecordHeartbeat(ctx, node.ID, EdgeHeartbeatUpdate{Status: EdgeNodeStatusActive}, time.Now())
	if err != nil {
		t.Fatalf("RecordHeartbeat failed: %v", err)
	}

	go func() {
		tasks := leaseSvc.WaitPendingOAuthTasks(ctx, node.ID, 5*time.Second)
		if len(tasks) != 1 || tasks[0].Kind != "health_probe" {
			return
		}
		_, _ = leaseSvc.CompleteOAuthTaskFull(node.ID, tasks[0].TaskID, tasks[0].ClaimID, 200, "ok", "", nil, "")
	}()

	exitInfo, latencyMs, err := ProbeEdgeLandingNode(ctx, "legend-sg")
	if err != nil {
		t.Fatalf("ProbeEdgeLandingNode failed: %v", err)
	}
	if exitInfo.IP != "217.116.175.208" || exitInfo.CountryCode != "SG" || latencyMs < 1 {
		t.Fatalf("unexpected probe exitInfo=%+v latencyMs=%d", exitInfo, latencyMs)
	}

	// Verify httpclient.GetClient routes *.edge.internal via Landing node (skipping Central DNS).
	go func() {
		tasks := leaseSvc.WaitPendingOAuthTasks(ctx, node.ID, 5*time.Second)
		if len(tasks) != 1 || tasks[0].TargetURL != "https://cloudresourcemanager.googleapis.com/v1/projects" {
			return
		}
		respJSON := `{"projects":[{"projectId":"demo-proj","lifecycleState":"ACTIVE"}]}`
		_, _ = leaseSvc.CompleteOAuthTaskFull(
			node.ID, tasks[0].TaskID, tasks[0].ClaimID, 200, "",
			base64.StdEncoding.EncodeToString([]byte(respJSON)),
			map[string][]string{"Content-Type": {"application/json"}}, "",
		)
	}()
	hc, err := httpclient.GetClient(httpclient.Options{
		ProxyURL:           "https://legend-sg.edge.internal:443",
		Timeout:            10 * time.Second,
		ValidateResolvedIP: true,
	})
	if err != nil {
		t.Fatalf("httpclient.GetClient edge.internal failed: %v", err)
	}
	crmReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudresourcemanager.googleapis.com/v1/projects", nil)
	crmResp, err := hc.Do(crmReq)
	if err != nil {
		t.Fatalf("httpclient edge.internal Do failed: %v", err)
	}
	crmBody, _ := io.ReadAll(crmResp.Body)
	_ = crmResp.Body.Close()
	if crmResp.StatusCode != 200 || !strings.Contains(string(crmBody), "demo-proj") {
		t.Fatalf("unexpected crm response status=%d body=%s", crmResp.StatusCode, string(crmBody))
	}

	// Verify antigravity.NewClient routes *.edge.internal via Landing node.
	go func() {
		tasks := leaseSvc.WaitPendingOAuthTasks(ctx, node.ID, 5*time.Second)
		if len(tasks) != 1 || tasks[0].TargetURL != antigravity.TokenURL {
			return
		}
		tokJSON := `{"access_token":"ag_tok","refresh_token":"ag_rt","expires_in":3600,"token_type":"Bearer"}`
		_, _ = leaseSvc.CompleteOAuthTaskFull(
			node.ID, tasks[0].TaskID, tasks[0].ClaimID, 200, "",
			base64.StdEncoding.EncodeToString([]byte(tokJSON)),
			map[string][]string{"Content-Type": {"application/json"}}, "",
		)
	}()
	agClient, err := antigravity.NewClient("https://legend-sg.edge.internal:443")
	if err != nil {
		t.Fatalf("antigravity.NewClient edge.internal failed: %v", err)
	}
	tokResp, err := agClient.ExchangeCode(ctx, "auth-code", "pkce-verifier")
	if err != nil {
		t.Fatalf("antigravity.ExchangeCode via edge.internal failed: %v", err)
	}
	if tokResp.AccessToken != "ag_tok" || tokResp.RefreshToken != "ag_rt" {
		t.Fatalf("unexpected antigravity token resp: %+v", tokResp)
	}
}
