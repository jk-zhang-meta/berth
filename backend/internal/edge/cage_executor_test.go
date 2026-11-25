package edge

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

func TestCageUpstreamExecutor_RoutesThroughCageAndFailsClosedOnEpochBump(t *testing.T) {
	// 1. Mock upstream HTTPS provider echoing request path & headers.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
	}))
	defer upstream.Close()

	// 2. Local HTTP CONNECT proxy standing in for dedicated landing egress.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		targetConn, err := net.DialTimeout("tcp4", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = targetConn.Close()
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			_ = targetConn.Close()
			return
		}
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { defer clientConn.Close(); defer targetConn.Close(); _, _ = io.Copy(targetConn, clientConn) }()
		go func() { defer clientConn.Close(); defer targetConn.Close(); _, _ = io.Copy(clientConn, targetConn) }()
	}))
	defer proxy.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	pool := cage.NewCageTransportPool()
	gate := cage.NewCageGate(77, cage.WithEvictionCallback(pool.EvictCage))
	gate.Open(60 * time.Second)
	initialEpoch := gate.Snapshot().Epoch

	exec := NewCageUpstreamExecutor(pool, func(_ context.Context, _ *edgeproto.SessionLeaseClaims) (*CageBinding, error) {
		return &CageBinding{
			CageID:            77,
			ProxyURL:          proxy.URL,
			Plane:             cage.PlaneInference,
			ProfilePreset:     cage.PresetClaudeNode24Inference,
			DNSMode:           cage.DNSModeProxyDoHIPv4Only,
			AllowTestLoopback: true,
			RootCAs:           roots,
			Gate:              gate,
		}, nil
	}, nil, nil)

	lease := &edgeproto.SessionLeaseClaims{
		LeaseID:   "lease-cage-bridge",
		Platform:  "anthropic",
		CageID:    77,
		CageEpoch: initialEpoch,
	}

	// Happy path through pinned uTLS + httpwire + CONNECT proxy.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/v1/messages", strings.NewReader(`{"model":"claude-5"}`))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	resp, err := exec.DoHTTP(context.Background(), req, lease)
	if err != nil {
		t.Fatalf("DoHTTP through cage failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "/v1/messages") {
		t.Fatalf("unexpected response: %d %s", resp.StatusCode, string(body))
	}

	// Epoch bump MUST immediately reject the stale lease fail-closed.
	gate.BumpEpoch("exit_ip_drift")
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/v1/messages", strings.NewReader(`{}`))
	if _, err := exec.DoHTTP(context.Background(), req2, lease); !errors.Is(err, cage.ErrGateEpochMismatch) {
		t.Fatalf("expected ErrGateEpochMismatch after epoch bump, got %v", err)
	}
}
