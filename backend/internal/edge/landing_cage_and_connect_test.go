package edge

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

func TestLandingCageExecutor_PinnedUTLSPresetsPSKIsolationAndEpochEviction(t *testing.T) {
	if got := SelectLandingPreset("anthropic", "/v1/messages"); got != cage.PresetClaudeNode24Inference {
		t.Fatalf("expected claude inference preset, got %q", got)
	}
	if got := SelectLandingPreset("anthropic", "/v1/messages/count_tokens"); got != cage.PresetClaudeNode24CountTokens {
		t.Fatalf("expected count_tokens preset, got %q", got)
	}
	if got := SelectLandingPreset("anthropic", "/v1/oauth/token"); got != cage.PresetClaudeNode24OAuth {
		t.Fatalf("expected oauth preset, got %q", got)
	}
	if got := SelectLandingPreset("openai", "/v1/responses"); got != cage.PresetCodexChromePinned {
		t.Fatalf("expected codex chrome preset, got %q", got)
	}
	if got := AcceptLanguageForLocale("ja_JP.UTF-8"); got != "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7" {
		t.Fatalf("unexpected Accept-Language for ja_JP: %q", got)
	}
	if got := AcceptLanguageForLocale("en_US.UTF-8"); got != "en-US,en;q=0.9" {
		t.Fatalf("unexpected Accept-Language for en_US: %q", got)
	}

	// Real local TLS server verifying uTLS handshake, ALPN, and Accept-Language alignment!
	var gotAcceptLang string
	var gotProto string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptLang = r.Header.Get("Accept-Language")
		gotProto = r.Proto
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())

	guard := NewCompatSSRFGuard(nil, []string{u.Host}, nil)
	exec := NewLandingCageExecutor(guard, &tls.Config{RootCAs: certPool})

	// Account 101 (Anthropic -> HTTP/1.1 pinned uTLS + httpwire)
	lease1 := &edgeproto.SessionLeaseClaims{
		AccountID:    101,
		CageEpoch:    1,
		Platform:     "anthropic",
		CohortLocale: "en_US.UTF-8",
	}
	req1, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	resp1, err := exec.DoHTTP(context.Background(), req1, lease1)
	if err != nil {
		t.Fatalf("DoHTTP anthropic uTLS failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	if gotProto != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1 for claude_node24_inference, got %q", gotProto)
	}
	if gotAcceptLang != "en-US,en;q=0.9" {
		t.Fatalf("expected aligned Accept-Language, got %q", gotAcceptLang)
	}

	// Account 202 gets its OWN distinct TLS PSK cache (never shared with Account 101!).
	lease2 := &edgeproto.SessionLeaseClaims{
		AccountID:    202,
		CageEpoch:    1,
		Platform:     "openai",
		CohortLocale: "ja_JP.UTF-8",
	}
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses", strings.NewReader(`{}`))
	resp2, err := exec.DoHTTP(context.Background(), req2, lease2)
	if err != nil {
		t.Fatalf("DoHTTP openai uTLS failed: %v", err)
	}
	_ = resp2.Body.Close()

	cache1 := exec.SessionCacheForAccount(101)
	cache2 := exec.SessionCacheForAccount(202)
	if cache1 == nil || cache2 == nil || cache1 == cache2 {
		t.Fatalf("expected distinct non-nil TLS PSK session caches per account")
	}

	// Bumping CageEpoch on Account 101 MUST atomically evict & rotate its TLS PSK cache!
	lease1Epoch2 := *lease1
	lease1Epoch2.CageEpoch = 2
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	resp3, err := exec.DoHTTP(context.Background(), req3, &lease1Epoch2)
	if err != nil {
		t.Fatalf("DoHTTP epoch2 failed: %v", err)
	}
	_ = resp3.Body.Close()
	cache1After := exec.SessionCacheForAccount(101)
	if cache1After == nil || cache1After == cache1 {
		t.Fatalf("expected TLS PSK cache rotation on CageEpoch bump")
	}
}

func TestEdgeServer_TransparentConnectTunnelMultiHopSSRFAndMetering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	// Local TCP echo server acting as an arbitrary remote target (e.g. statsig / github / ipify).
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, aErr := echoLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().String()

	// Blocked private target (NOT in testAllowLoopback) to verify fail-closed SSRF guard!
	blockedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blocked: %v", err)
	}
	defer func() { _ = blockedLn.Close() }()
	blockedAddr := blockedLn.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Landing node (node 2) and Ingress Relay node (node 1).
	landLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	ingLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer func() { _ = landLn.Close(); _ = ingLn.Close() }()

	outbox, err := edgeproto.OpenOutboxWAL(t.TempDir() + "/outbox.wal")
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	defer func() { _ = outbox.Close() }()

	landSrv, err := NewEdgeServer(EdgeServerOptions{
		Config: &Config{
			NodeID:                 2,
			NodeName:               "houston-vm100",
			Roles:                  []string{RoleLanding},
			TestAllowLoopbackHosts: []string{echoAddr}, // ONLY echoAddr allowed; blockedAddr MUST be rejected!
		},
		CentralPubKey: pub,
		OutboxWAL:     outbox,
	})
	if err != nil {
		t.Fatalf("new landing: %v", err)
	}
	ingSrv, err := NewEdgeServer(EdgeServerOptions{
		Config: &Config{
			NodeID:   1,
			NodeName: "po0-gz",
			Roles:    []string{RoleIngressRelay, RoleTransit},
		},
		CentralPubKey: pub,
	})
	if err != nil {
		t.Fatalf("new ingress: %v", err)
	}

	now := time.Now()
	snap := edgeproto.RevocationSnapshot{
		Seq:        1,
		IssuedAt:   now.Unix(),
		ValidUntil: now.Add(5 * time.Minute).Unix(),
	}
	if err := edgeproto.SignRevocationSnapshot(priv, "k1", &snap); err != nil {
		t.Fatalf("sign snap: %v", err)
	}
	_ = landSrv.Gate().UpdateSnapshot(&snap)
	_ = ingSrv.Gate().UpdateSnapshot(&snap)

	go func() { _ = landSrv.Serve(ctx, landLn) }()
	go func() { _ = ingSrv.Serve(ctx, ingLn) }()

	claims := edgeproto.SessionLeaseClaims{
		LeaseID:       "lease-connect-1",
		JTI:           "jti-connect-1",
		UserID:        1,
		AccountID:     55,
		LandingNodeID: 2,
		Platform:      "anthropic",
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(10 * time.Minute).Unix(),
		RouteChain: []edgeproto.RouteHop{
			{NodeID: 1, NodeName: "po0-gz", Role: RoleIngressRelay, Addr: ingLn.Addr().String(), LinkClass: "direct"},
			{NodeID: 2, NodeName: "houston-vm100", Role: RoleLanding, Addr: landLn.Addr().String(), LinkClass: "direct"},
		},
	}
	leaseTok, err := edgeproto.SignLease(priv, "k1", claims)
	if err != nil {
		t.Fatalf("sign lease: %v", err)
	}

	// 1. Valid CONNECT through Ingress -> Landing -> echoAddr succeeds end-to-end!
	conn, err := net.DialTimeout("tcp4", ingLn.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial ingress: %v", err)
	}
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n", echoAddr, echoAddr, edgeproto.HeaderLease, leaseTok)
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 Connection Established, got %q err=%v", statusLine, err)
	}
	for {
		line, lErr := br.ReadString('\n')
		if lErr != nil || line == "\r\n" {
			break
		}
	}
	payload := "hello-through-berth-connect-tunnel\n"
	_, _ = io.WriteString(conn, payload)
	echoed, err := br.ReadString('\n')
	if err != nil || echoed != payload {
		t.Fatalf("expected echoed %q, got %q err=%v", payload, echoed, err)
	}
	_ = conn.Close()

	// Wait briefly for receipt persistence on Landing outbox.
	time.Sleep(100 * time.Millisecond)
	pending := outbox.Pending()
	if len(pending) == 0 || pending[0].IngressBytes < int64(len(payload)) || pending[0].EgressBytes < int64(len(payload)) {
		t.Fatalf("expected metered CONNECT usage receipt in outbox, got %+v", pending)
	}

	// 2. Private/SSRF targets (blockedAddr, 169.254.169.254:80, 10.0.0.1:443, smtp:25) MUST return 403!
	for _, badTarget := range []string{blockedAddr, "169.254.169.254:80", "10.0.0.1:443", "1.1.1.1:25", "internal.local:443"} {
		c2, dErr := net.DialTimeout("tcp4", ingLn.Addr().String(), 3*time.Second)
		if dErr != nil {
			t.Fatalf("dial ingress for ssrf test: %v", dErr)
		}
		_, _ = fmt.Fprintf(c2, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n", badTarget, badTarget, edgeproto.HeaderLease, leaseTok)
		r2 := bufio.NewReader(c2)
		line2, _ := r2.ReadString('\n')
		_ = c2.Close()
		if !strings.Contains(line2, "403") {
			t.Fatalf("expected 403 SSRF block for %s, got %q", badTarget, line2)
		}
	}
}
