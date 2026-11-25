package cage

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/httpwire"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const defaultPerCageSessionCacheCap = 16

// TransportPoolKey uniquely identifies a pooled CageRoundTripper.
// Includes cage_id, gate_epoch, plane, profile_hash, and proxy_url so stale
// transports can never be reused across epoch bumps or profile mutations.
type TransportPoolKey struct {
	CageID      int64
	GateEpoch   int64
	Plane       string
	ProfileHash string
	ProxyURL    string
}

func (k TransportPoolKey) String() string {
	return fmt.Sprintf("%d|%d|%s|%s|%s", k.CageID, k.GateEpoch, k.Plane, k.ProfileHash, k.ProxyURL)
}

// TransportConfig specifies parameters to acquire/build a CageRoundTripper.
type TransportConfig struct {
	CageID              int64
	Plane               string
	ProxyURL            string
	Profile             *TLSProfileSpec
	Dialer              *CageDialer
	RootCAs             *x509.CertPool // Optional custom RootCAs (used in local TLS tests)
	InsecureSkipVerify  bool           // Strictly for controlled test servers if needed
	ResponseHeaderLimit time.Duration  // Optional ResponseHeaderTimeout
}

// CageTransportPool caches CageRoundTrippers keyed by
// (cage_id, gate_epoch, plane, profile_hash, proxy_url) alongside isolated
// per-cage utls.ClientSessionCaches (capacity 16).
//
// Wire pool.EvictCage into CageGate.SetEvictionCallback so epoch bumps atomically
// evict both pooled transports AND the cage's TLS PSK session cache together.
type CageTransportPool struct {
	mu           sync.Mutex
	transports   map[TransportPoolKey]*CageRoundTripper
	sessionCache map[int64]utls.ClientSessionCache
}

// NewCageTransportPool creates an empty CageTransportPool.
func NewCageTransportPool() *CageTransportPool {
	return &CageTransportPool{
		transports:   make(map[TransportPoolKey]*CageRoundTripper),
		sessionCache: make(map[int64]utls.ClientSessionCache),
	}
}

// GetOrCreate returns a pooled CageRoundTripper matching the composite key
// (cage_id, gate_epoch, plane, profile_hash, proxy_url).
func (p *CageTransportPool) GetOrCreate(cfg TransportConfig) (*CageRoundTripper, error) {
	if cfg.Dialer == nil || cfg.Dialer.Gate() == nil {
		return nil, ErrCageClosed
	}
	if cfg.Profile == nil {
		return nil, errors.New("cage: TLSProfileSpec is required")
	}
	if strings.TrimSpace(cfg.ProxyURL) == "" {
		return nil, ErrDirectEgressForbidden
	}

	snap := cfg.Dialer.Gate().Snapshot()
	plane := strings.TrimSpace(cfg.Plane)
	if plane == "" {
		plane = cfg.Profile.Plane
	}
	key := TransportPoolKey{
		CageID:      cfg.CageID,
		GateEpoch:   snap.Epoch,
		Plane:       plane,
		ProfileHash: cfg.Profile.ProfileHash(),
		ProxyURL:    strings.TrimSpace(cfg.ProxyURL),
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.transports[key]; ok {
		return existing, nil
	}

	sessCache, ok := p.sessionCache[cfg.CageID]
	if !ok {
		sessCache = utls.NewLRUClientSessionCache(defaultPerCageSessionCacheCap)
		p.sessionCache[cfg.CageID] = sessCache
	}

	rt := newCageRoundTripper(cfg, key, sessCache)
	p.transports[key] = rt
	return rt, nil
}

// EvictCage clears ALL pooled transports for cageID (closing idle HTTP/1.1 and
// HTTP/2 connections) AND resets the cage's isolated TLS ClientSessionCache
// in one atomic critical section.
func (p *CageTransportPool) EvictCage(cageID int64, _ int64, _ string) {
	p.mu.Lock()
	var evicted []*CageRoundTripper
	for k, rt := range p.transports {
		if k.CageID == cageID {
			evicted = append(evicted, rt)
			delete(p.transports, k)
		}
	}
	delete(p.sessionCache, cageID)
	p.mu.Unlock()

	for _, rt := range evicted {
		rt.CloseIdleConnections()
		if rt.dialer != nil {
			rt.dialer.ClearDNSCache()
		}
	}
}

// SessionCacheForCage returns the current per-cage TLS ClientSessionCache (nil if evicted/absent).
// Intended for inspection and verification in tests.
func (p *CageTransportPool) SessionCacheForCage(cageID int64) utls.ClientSessionCache {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessionCache[cageID]
}

// Size returns the number of pooled transport entries currently held.
func (p *CageTransportPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.transports)
}

// CageRoundTripper executes HTTP/HTTPS requests over CageDialer using pinned
// uTLS specs, ALPN-following H2/H1.1 dispatch, and httpwire ordered framing.
type CageRoundTripper struct {
	key          TransportPoolKey
	profile      *TLSProfileSpec
	dialer       *CageDialer
	sessionCache utls.ClientSessionCache
	rootCAs      *x509.CertPool
	insecureSkip bool
	headerOrder  []string

	h1Transport *http.Transport
	h2Transport *http2.Transport

	h2Mu    sync.Mutex
	h2Conns map[string]*http2.ClientConn
}

func newCageRoundTripper(cfg TransportConfig, key TransportPoolKey, sessCache utls.ClientSessionCache) *CageRoundTripper {
	headerOrder := httpwire.PresetHeaderOrder(cfg.Profile.HeaderOrderPreset)
	rt := &CageRoundTripper{
		key:          key,
		profile:      cfg.Profile,
		dialer:       cfg.Dialer,
		sessionCache: sessCache,
		rootCAs:      cfg.RootCAs,
		insecureSkip: cfg.InsecureSkipVerify,
		headerOrder:  headerOrder,
		h2Transport:  &http2.Transport{},
		h2Conns:      make(map[string]*http2.ClientConn),
	}

	rt.h1Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := rt.dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return httpwire.NewOrderedRequestConn(conn, rt.headerOrder), nil
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			uConn, err := rt.dialUTLS(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return httpwire.NewOrderedRequestConn(uConn, rt.headerOrder), nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderLimit,
	}
	return rt
}

// Key returns the composite pool key for this CageRoundTripper.
func (rt *CageRoundTripper) Key() TransportPoolKey {
	return rt.key
}

// RoundTrip dispatches req over the cage's proxy-fenced uTLS transport.
// For ALPNModeFollowNegotiated HTTPS requests, it inspects NegotiatedProtocol
// after uTLS handshake and dispatches "h2" via http2.ClientConn or HTTP/1.1 via
// httpwire.OrderedRequestConn.
func (rt *CageRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("cage: nil request or URL")
	}

	// Non-HTTPS or HTTP/1.1-only presets go directly through the pooled H1 transport
	// (which uses uTLS + httpwire.OrderedRequestConn for HTTPS).
	if !strings.EqualFold(req.URL.Scheme, "https") || rt.profile.ALPNMode != ALPNModeFollowNegotiated {
		return rt.h1Transport.RoundTrip(req)
	}

	addr := authorityWithDefaultPort(req.URL.Host, "443")

	// Fast path: reuse an active pooled HTTP/2 client connection if available.
	if cc := rt.getUsableH2Conn(addr); cc != nil {
		return cc.RoundTrip(req)
	}

	// Dial via CageDialer + pinned uTLS and inspect negotiated ALPN.
	uConn, err := rt.dialUTLS(req.Context(), "tcp4", addr)
	if err != nil {
		return nil, err
	}

	alpn := uConn.ConnectionState().NegotiatedProtocol
	if alpn == "h2" {
		cc, err := rt.h2Transport.NewClientConn(uConn)
		if err != nil {
			_ = uConn.Close()
			return nil, fmt.Errorf("cage: create http2 client conn: %w", err)
		}
		rt.storeH2Conn(addr, cc)
		return cc.RoundTrip(req)
	}

	// Negotiated http/1.1 or empty ALPN: wrap with httpwire ordered framing and execute once.
	ordered := httpwire.NewOrderedRequestConn(uConn, rt.headerOrder)
	var once sync.Once
	singleH1 := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, dialAddr string) (net.Conn, error) {
			var conn net.Conn
			once.Do(func() {
				conn = ordered
			})
			if conn != nil {
				return conn, nil
			}
			nextUConn, dialErr := rt.dialUTLS(ctx, network, dialAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			return httpwire.NewOrderedRequestConn(nextUConn, rt.headerOrder), nil
		},
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: rt.h1Transport.ResponseHeaderTimeout,
	}
	return singleH1.RoundTrip(req)
}

// CloseIdleConnections closes all idle HTTP/1.1 and cached HTTP/2 connections.
func (rt *CageRoundTripper) CloseIdleConnections() {
	if rt.h1Transport != nil {
		rt.h1Transport.CloseIdleConnections()
	}
	rt.h2Mu.Lock()
	conns := make([]*http2.ClientConn, 0, len(rt.h2Conns))
	for k, cc := range rt.h2Conns {
		conns = append(conns, cc)
		delete(rt.h2Conns, k)
	}
	rt.h2Mu.Unlock()

	for _, cc := range conns {
		_ = cc.Close()
	}
}

func (rt *CageRoundTripper) dialUTLS(ctx context.Context, network, addr string) (*utls.UConn, error) {
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}

	spec, err := BuildClientHelloSpec(rt.profile.Preset)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	tlsCfg := &utls.Config{
		ServerName:                         host,
		RootCAs:                            rt.rootCAs,
		InsecureSkipVerify:                 rt.insecureSkip,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
	if rt.profile.EnablePSKCache && rt.sessionCache != nil {
		tlsCfg.ClientSessionCache = rt.sessionCache
	}

	uConn := utls.UClient(rawConn, tlsCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("cage: apply uTLS preset %q: %w", rt.profile.Preset, err)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("cage: uTLS handshake (%s): %w", rt.profile.Preset, err)
	}
	return uConn, nil
}

func (rt *CageRoundTripper) getUsableH2Conn(addr string) *http2.ClientConn {
	rt.h2Mu.Lock()
	defer rt.h2Mu.Unlock()
	cc, ok := rt.h2Conns[addr]
	if !ok {
		return nil
	}
	if !cc.CanTakeNewRequest() {
		delete(rt.h2Conns, addr)
		return nil
	}
	return cc
}

func (rt *CageRoundTripper) storeH2Conn(addr string, cc *http2.ClientConn) {
	rt.h2Mu.Lock()
	if prev, ok := rt.h2Conns[addr]; ok && prev != cc {
		_ = prev.Close()
	}
	rt.h2Conns[addr] = cc
	rt.h2Mu.Unlock()
}

func authorityWithDefaultPort(hostPort, defaultPort string) string {
	if _, _, err := net.SplitHostPort(hostPort); err == nil {
		return hostPort
	}
	return net.JoinHostPort(hostPort, defaultPort)
}
