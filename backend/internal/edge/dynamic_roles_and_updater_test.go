package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

func TestEdgeServer_ApplyRuntimeRolesHotToggle(t *testing.T) {
	srv, err := NewEdgeServer(EdgeServerOptions{
		Config: &Config{
			NodeID:   7,
			NodeName: "hyonix-sg",
			Roles:    []string{RoleIngressRelay, RoleTransit},
		},
	})
	if err != nil {
		t.Fatalf("new edge server: %v", err)
	}
	if srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role initially disabled")
	}
	if !srv.HasRole(RoleTransit) {
		t.Fatalf("expected transit role initially enabled")
	}

	// Hot-enable landing role (as pushed from Central heartbeat after Admin toggles Landing).
	if !srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit, RoleLanding}) {
		t.Fatalf("expected ApplyRuntimeRoles to report change")
	}
	if !srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role hot-enabled")
	}

	// Identical role set is a no-op.
	if srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit, RoleLanding}) {
		t.Fatalf("expected identical role set to return changed=false")
	}

	// Hot-disable landing role.
	if !srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit}) {
		t.Fatalf("expected landing removal to report change")
	}
	if srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role hot-disabled")
	}
}

func TestSelfUpdater_SHA256VerifiedAtomicSwapAndMismatchReject(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "berth-edge")
	initialPayload := []byte("berth-edge-v1-binary")
	if err := os.WriteFile(exePath, initialPayload, 0o755); err != nil {
		t.Fatalf("write initial exe: %v", err)
	}
	initSum, err := ComputeFileSHA256(exePath)
	if err != nil {
		t.Fatalf("compute initial sha: %v", err)
	}

	updater := NewSelfUpdater(exePath, initSum)
	updater.verifyCommand = func(_ context.Context, _ string) error { return nil }

	// 1. Mismatched SHA-256 MUST fail closed and leave original binary untouched!
	badPayload := []byte("corrupted-payload")
	applied := false
	updated, err := updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, dst io.Writer) error {
			_, werr := dst.Write(badPayload)
			return werr
		},
		func() { applied = true },
	)
	if err == nil || updated || applied {
		t.Fatalf("expected sha mismatch rejection, got updated=%v applied=%v err=%v", updated, applied, err)
	}
	cur, _ := os.ReadFile(exePath)
	if string(cur) != string(initialPayload) {
		t.Fatalf("original binary was modified on mismatch!")
	}

	// 2. Exact matching SHA-256 MUST atomically swap binary and invoke onApplied!
	newPayload := []byte("berth-edge-v2-binary-verified")
	sumBytes := sha256.Sum256(newPayload)
	newSum := hex.EncodeToString(sumBytes[:])
	updated, err = updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       newSum,
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, dst io.Writer) error {
			_, werr := dst.Write(newPayload)
			return werr
		},
		func() { applied = true },
	)
	if err != nil || !updated || !applied {
		t.Fatalf("expected verified swap to succeed, got updated=%v applied=%v err=%v", updated, applied, err)
	}
	cur, _ = os.ReadFile(exePath)
	if string(cur) != string(newPayload) {
		t.Fatalf("expected swapped binary content, got %q", string(cur))
	}

	// 3. Re-invoking with the same SHA-256 is an immediate no-op!
	applied = false
	updated, err = updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       newSum,
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, _ io.Writer) error {
			t.Fatalf("download should not be called when already up-to-date")
			return nil
		},
		func() { applied = true },
	)
	if err != nil || updated || applied {
		t.Fatalf("expected no-op when already on target sha, got updated=%v applied=%v err=%v", updated, applied, err)
	}
}

type captureUpstreamExecutor struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (c *captureUpstreamExecutor) DoHTTP(_ context.Context, req *http.Request, _ *edgeproto.SessionLeaseClaims) (*http.Response, error) {
	return c.fn(req)
}

func (c *captureUpstreamExecutor) DialWebSocket(_ context.Context, _ string, _ http.Header, _ *edgeproto.SessionLeaseClaims) (net.Conn, *bufio.Reader, *http.Response, error) {
	return nil, nil, nil, io.EOF
}

func TestEdgeServer_LandingCredentialInjectionRewriteAnd401Eviction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	now := time.Now()
	claims := edgeproto.SessionLeaseClaims{
		LeaseID:       "lease-cred-1",
		JTI:           "jti-cred-1",
		UserID:        1,
		AccountID:     88,
		LandingNodeID: 9,
		Platform:      "openai",
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(10 * time.Minute).Unix(),
		RouteChain: []edgeproto.RouteHop{
			{NodeID: 9, NodeName: "la-land", Role: RoleLanding, Addr: "127.0.0.1:1"},
		},
	}
	token, err := edgeproto.SignLease(priv, "k1", claims)
	if err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	snap := edgeproto.RevocationSnapshot{
		Seq:        1,
		IssuedAt:   now.Unix(),
		ValidUntil: now.Add(5 * time.Minute).Unix(),
	}
	if err := edgeproto.SignRevocationSnapshot(priv, "k1", &snap); err != nil {
		t.Fatalf("sign snap: %v", err)
	}

	var fetchCount atomic.Int32
	var forceUpstream401 atomic.Bool
	var forceForbidden atomic.Bool
	var lastURL string
	var lastAuth string
	var lastAccountHdr string
	var lastBeta string

	exec := &captureUpstreamExecutor{
		fn: func(req *http.Request) (*http.Response, error) {
			lastURL = req.URL.String()
			lastAuth = req.Header.Get("Authorization")
			lastAccountHdr = req.Header.Get("Chatgpt-Account-Id")
			lastBeta = req.Header.Get("anthropic-beta")
			status := http.StatusOK
			if forceUpstream401.Load() {
				status = http.StatusUnauthorized
			}
			return &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		},
	}

	srv, err := NewEdgeServer(EdgeServerOptions{
		Config: &Config{
			NodeID:   9,
			NodeName: "la-land",
			Roles:    []string{RoleLanding},
		},
		CentralPubKey: pub,
		Upstream:      exec,
		CredentialFetcher: func(_ context.Context, leaseID string, accountID int64) (*UpstreamCredentialDTO, error) {
			if forceForbidden.Load() {
				return nil, ErrUpstreamCredentialForbidden
			}
			n := fetchCount.Add(1)
			return &UpstreamCredentialDTO{
				AccountID:   accountID,
				Platform:    "openai",
				AccountType: "oauth",
				BaseURL:     "https://chatgpt.com/backend-api/codex",
				Headers: map[string]string{
					"Authorization":      "Bearer tok-v" + string(rune('0'+n)),
					"Chatgpt-Account-Id": "acct-99",
					"anthropic-beta":     "oauth-2025-04-20",
				},
				ExpiresAtUnix: time.Now().Add(60 * time.Second).Unix(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("new edge server: %v", err)
	}
	if err := srv.Gate().UpdateSnapshot(&snap); err != nil {
		t.Fatalf("update snapshot: %v", err)
	}

	routeHdr, _ := edgeproto.EncodeRouteHeader(claims.RouteChain)
	doReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, edgeproto.TunnelExecutePath, bytes.NewBufferString(`{"model":"gpt-5"}`))
		req.Header.Set(edgeproto.HeaderRoute, routeHdr)
		req.Header.Set(edgeproto.HeaderHopIndex, "0")
		req.Header.Set(edgeproto.HeaderLease, token)
		req.Header.Set(edgeproto.HeaderUpstreamMethod, http.MethodPost)
		req.Header.Set(edgeproto.HeaderUpstreamURL, "https://api.openai.com/v1/responses?stream=true")
		req.Header.Set("Authorization", "Bearer client-lease-should-be-stripped")
		req.Header.Set("anthropic-beta", "claude-code-20250219")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// 1. First request fetches credential, rewrites URL to codex backend, merges anthropic-beta, injects auth!
	rec1 := doReq()
	if rec1.Code != http.StatusOK {
		t.Fatalf("req1 status=%d body=%s", rec1.Code, rec1.Body.String())
	}
	if lastURL != "https://chatgpt.com/backend-api/codex/responses?stream=true" {
		t.Fatalf("unexpected rewritten URL: %q", lastURL)
	}
	if lastAuth != "Bearer tok-v1" || lastAccountHdr != "acct-99" {
		t.Fatalf("unexpected auth headers: auth=%q acct=%q", lastAuth, lastAccountHdr)
	}
	if lastBeta != "claude-code-20250219,oauth-2025-04-20" {
		t.Fatalf("expected merged anthropic-beta, got %q", lastBeta)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("expected 1 credential fetch, got %d", fetchCount.Load())
	}

	// 2. Second request hits RAM cache (still fetchCount == 1), then upstream 401 evicts cache!
	forceUpstream401.Store(true)
	rec2 := doReq()
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 passthrough, got %d", rec2.Code)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("expected RAM cache hit before 401 eviction, got %d fetches", fetchCount.Load())
	}

	// 3. Third request MUST re-fetch fresh token after 401 eviction!
	forceUpstream401.Store(false)
	rec3 := doReq()
	if rec3.Code != http.StatusOK {
		t.Fatalf("req3 status=%d", rec3.Code)
	}
	if fetchCount.Load() != 2 || lastAuth != "Bearer tok-v2" {
		t.Fatalf("expected re-fetch tok-v2 after 401 eviction, got count=%d auth=%q", fetchCount.Load(), lastAuth)
	}

	// 4. Evict & force forbidden -> MUST fail closed with 403 without calling upstream!
	srv.evictUpstreamCredential(claims.LeaseID, claims.AccountID)
	forceForbidden.Store(true)
	rec4 := doReq()
	if rec4.Code != http.StatusForbidden {
		t.Fatalf("expected 403 fail-closed when credential forbidden, got %d", rec4.Code)
	}
}
