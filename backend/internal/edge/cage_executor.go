package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

// CageBinding configures how a specific Account Cage executes upstream provider
// requests inside a Landing or Compat berth-edge node using Track A's fail-closed
// CageGate + CageDialer + pinned uTLS + httpwire transport pool.
type CageBinding struct {
	CageID             int64
	ProxyURL           string // Required: zero direct fallback (ErrDirectEgressForbidden if empty)
	Plane              string // cage.PlaneInference | cage.PlaneOAuth | cage.PlaneUnified
	ProfilePreset      string // e.g. cage.PresetClaudeNode24Inference, cage.PresetCodexChromePinned
	DNSMode            string // cage.DNSModeProxyDoHIPv4Only | cage.DNSModeSOCKS5hRemote
	DoHEndpoints       []string
	AllowedAuthorities []string
	AllowTestLoopback  bool
	RootCAs            *x509.CertPool
	ProxyTLSConfig     *tls.Config
	Gate               *cage.CageGate
}

// CageBindingResolver resolves the active CageBinding for an admitted SessionLease.
type CageBindingResolver func(ctx context.Context, lease *edgeproto.SessionLeaseClaims) (*CageBinding, error)

// CageUpstreamExecutor bridges Track A's internal/pkg/cage (fail-closed CageGate,
// epoch-fenced sockets, pinned uTLS, per-cage PSK cache, httpwire ordering, and
// zero-direct proxy dialing) directly into Track D's berth-edge UpstreamExecutor seam.
type CageUpstreamExecutor struct {
	pool     *cage.CageTransportPool
	resolver CageBindingResolver
	wsGuard  *CompatSSRFGuard
	wsTLS    *tls.Config

	mu      sync.Mutex
	dialers map[string]*cage.CageDialer
}

// NewCageUpstreamExecutor constructs a CageUpstreamExecutor backed by a shared CageTransportPool.
func NewCageUpstreamExecutor(
	pool *cage.CageTransportPool,
	resolver CageBindingResolver,
	wsGuard *CompatSSRFGuard,
	wsTLS *tls.Config,
) *CageUpstreamExecutor {
	if pool == nil {
		pool = cage.NewCageTransportPool()
	}
	if wsGuard == nil {
		wsGuard = NewCompatSSRFGuard(nil, nil, nil)
	}
	return &CageUpstreamExecutor{
		pool:     pool,
		resolver: resolver,
		wsGuard:  wsGuard,
		wsTLS:    wsTLS,
		dialers:  make(map[string]*cage.CageDialer),
	}
}

// EvictCage immediately bumps/evicts all pooled transports and TLS PSK session caches for cageID.
func (e *CageUpstreamExecutor) EvictCage(cageID int64, newEpoch int64, reason string) {
	e.pool.EvictCage(cageID, newEpoch, reason)
}

func (e *CageUpstreamExecutor) resolveRoundTripper(ctx context.Context, lease *edgeproto.SessionLeaseClaims) (*cage.CageRoundTripper, *CageBinding, error) {
	if lease == nil {
		return nil, nil, errors.New("edge cage executor: lease is required")
	}
	if e.resolver == nil {
		return nil, nil, errors.New("edge cage executor: binding resolver is not configured")
	}
	binding, err := e.resolver(ctx, lease)
	if err != nil {
		return nil, nil, err
	}
	if binding == nil || binding.Gate == nil {
		return nil, nil, cage.ErrCageClosed
	}

	// Enforce lease CageEpoch monotonicity against live CageGate epoch.
	snap := binding.Gate.Snapshot()
	if lease.CageEpoch > 0 && snap.Epoch > lease.CageEpoch {
		return nil, nil, cage.ErrGateEpochMismatch
	}

	preset := binding.ProfilePreset
	if preset == "" {
		switch lease.Platform {
		case "anthropic", "claude":
			preset = cage.PresetClaudeNode24Inference
		default:
			preset = cage.PresetCodexChromePinned
		}
	}
	profile, err := cage.ProfileForPreset(preset)
	if err != nil {
		return nil, nil, err
	}

	dialerKey := fmt.Sprintf("%d|%d|%s|%s", binding.CageID, snap.Epoch, binding.ProxyURL, binding.DNSMode)
	e.mu.Lock()
	dialer, ok := e.dialers[dialerKey]
	if !ok {
		d, dErr := cage.NewCageDialer(cage.DialerConfig{
			ProxyURL:           binding.ProxyURL,
			Gate:               binding.Gate,
			DNSMode:            binding.DNSMode,
			DoHEndpoints:       binding.DoHEndpoints,
			ProxyTLSConfig:     binding.ProxyTLSConfig,
			AllowedAuthorities: binding.AllowedAuthorities,
			AllowTestLoopback:  binding.AllowTestLoopback,
			DialTimeout:        15 * time.Second,
			KeepAlive:          30 * time.Second,
		})
		if dErr != nil {
			e.mu.Unlock()
			return nil, nil, dErr
		}
		e.dialers[dialerKey] = d
		dialer = d
	}
	e.mu.Unlock()

	rt, err := e.pool.GetOrCreate(cage.TransportConfig{
		CageID:   binding.CageID,
		Plane:    binding.Plane,
		ProxyURL: binding.ProxyURL,
		Profile:  profile,
		Dialer:   dialer,
		RootCAs:  binding.RootCAs,
	})
	if err != nil {
		return nil, nil, err
	}
	return rt, binding, nil
}

// DoHTTP executes an admitted upstream HTTP/SSE request strictly through the account's CageRoundTripper.
func (e *CageUpstreamExecutor) DoHTTP(ctx context.Context, req *http.Request, lease *edgeproto.SessionLeaseClaims) (*http.Response, error) {
	rt, _, err := e.resolveRoundTripper(ctx, lease)
	if err != nil {
		return nil, err
	}
	outReq := req.Clone(ctx)
	outReq.RequestURI = ""
	if lease.CohortLocale != "" && outReq.Header.Get("Accept-Language") == "" {
		outReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	return rt.RoundTrip(outReq)
}

// DialWebSocket opens an upstream RFC 6455 WebSocket strictly after verifying the account's CageGate state and epoch.
func (e *CageUpstreamExecutor) DialWebSocket(ctx context.Context, targetURL string, headers http.Header, lease *edgeproto.SessionLeaseClaims) (net.Conn, *bufio.Reader, *http.Response, error) {
	if _, binding, err := e.resolveRoundTripper(ctx, lease); err != nil {
		return nil, nil, nil, err
	} else if binding.Gate.Snapshot().State != cage.GateOpen {
		return nil, nil, nil, cage.ErrCageClosed
	}
	return DialRFC6455WebSocket(ctx, e.wsGuard, e.wsTLS, targetURL, headers)
}
