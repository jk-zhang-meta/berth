// Package cage implements Berth v2's lightweight protocol-level Account Cage
// primitives (fail-closed CageGate with epoch socket fencing, proxy-only
// RFC 8484 IPv4-only DoH, zero-direct proxy dialer with HTTPS TLS-before-CONNECT
// and context-aware SOCKS5h, pinned uTLS profiles, and ALPN-following pooled
// transport with httpwire header ordering).
//
// This package is compiled into BOTH `berth` and `berth-edge`.
package cage

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GateState models the 4-state fail-closed egress gate lifecycle.
type GateState uint8

const (
	GateClosed GateState = iota
	GateChecking
	GateOpen
	GateQuarantined
)

func (s GateState) String() string {
	switch s {
	case GateClosed:
		return "closed"
	case GateChecking:
		return "checking"
	case GateOpen:
		return "open"
	case GateQuarantined:
		return "quarantined"
	default:
		return "unknown"
	}
}

const (
	// DefaultGateLease is the fail-closed lease duration once a cage gate opens.
	DefaultGateLease = 90 * time.Second
	// SyntheticProbeAddr is the Claude-Cage synthetic probe target allowed while GateChecking.
	SyntheticProbeAddr = "198.18.0.254:80"
)

var (
	ErrCageClosed            = errors.New("cage: gate is closed")
	ErrCageQuarantined       = errors.New("cage: gate is quarantined")
	ErrGateEpochMismatch     = errors.New("cage: gate epoch mismatch; connection revoked")
	ErrProbeOnly             = errors.New("cage: gate is checking; only probe targets allowed")
	ErrDirectEgressForbidden = errors.New("cage: direct egress is forbidden; proxy_url is required")
	ErrProxyUnavailable      = errors.New("cage: proxy unavailable or unsupported")
	ErrProtocolBlocked       = errors.New("cage: network protocol blocked; only IPv4 TCP is allowed")
	ErrIPv6Blocked           = errors.New("cage: IPv6 egress is blocked")
	ErrUDPBlocked            = errors.New("cage: UDP egress is blocked")
	ErrPrivateIPBlocked      = errors.New("cage: non-public IPv4 destination is blocked")
	ErrBlockedDomain         = errors.New("cage: local/internal domain is blocked")
	ErrAuthorityNotAllowed   = errors.New("cage: target authority is not in allowlist")
	ErrDoHRedirectBlocked    = errors.New("cage: DoH HTTP redirects are forbidden")
)

// GateEvictionFunc is called whenever a gate epoch bumps or the gate closes/quarantines,
// allowing the transport pool and per-cage TLS ClientSessionCache to evict together.
type GateEvictionFunc func(cageID int64, newEpoch int64, reason string)

// GateSnapshot is a point-in-time read-only view of a CageGate.
type GateSnapshot struct {
	CageID         int64
	State          GateState
	Epoch          int64
	LeaseExpiresAt time.Time
	ActiveConns    int
	LastReason     string
}

// CageGate enforces fail-closed egress admission and epoch-fenced socket revocation.
type CageGate struct {
	cageID int64

	mu             sync.Mutex
	state          GateState
	epoch          int64
	leaseExpiresAt time.Time
	lastReason     string
	probeAllowlist map[string]struct{}
	activeConns    map[*gateConn]struct{}
	onEvict        GateEvictionFunc
	nowFn          func() time.Time
}

// GateOption configures a CageGate.
type GateOption func(*CageGate)

// WithClock overrides the clock used by CageGate (intended for deterministic tests).
func WithClock(nowFn func() time.Time) GateOption {
	return func(g *CageGate) {
		if nowFn != nil {
			g.nowFn = nowFn
		}
	}
}

// WithEvictionCallback registers the callback invoked whenever gate epoch bumps.
func WithEvictionCallback(fn GateEvictionFunc) GateOption {
	return func(g *CageGate) {
		g.onEvict = fn
	}
}

// WithProbeAllowlist registers additional targets permitted while in GateChecking state.
func WithProbeAllowlist(addrs ...string) GateOption {
	return func(g *CageGate) {
		for _, a := range addrs {
			if norm := normalizeGateTarget(a); norm != "" {
				g.probeAllowlist[norm] = struct{}{}
			}
		}
	}
}

// NewCageGate constructs a fail-closed CageGate starting in GateClosed at epoch 1.
func NewCageGate(cageID int64, opts ...GateOption) *CageGate {
	g := &CageGate{
		cageID: cageID,
		state:  GateClosed,
		epoch:  1,
		probeAllowlist: map[string]struct{}{
			SyntheticProbeAddr:      {},
			"ipwho.is:443":          {},
			"api.ip.sb:443":         {},
			"1.1.1.1:443":           {},
			"dns.google:443":        {},
			"cloudflare-dns.com:443": {},
		},
		activeConns: make(map[*gateConn]struct{}),
		nowFn:       time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
}

func (g *CageGate) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

// SetEvictionCallback updates the eviction hook triggered on every epoch bump.
func (g *CageGate) SetEvictionCallback(fn GateEvictionFunc) {
	g.mu.Lock()
	g.onEvict = fn
	g.mu.Unlock()
}

// AddProbeAllowed adds one or more host:port targets permitted during GateChecking.
func (g *CageGate) AddProbeAllowed(addrs ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range addrs {
		if norm := normalizeGateTarget(a); norm != "" {
			g.probeAllowlist[norm] = struct{}{}
		}
	}
}

// Snapshot returns a consistent snapshot of the gate's state.
func (g *CageGate) Snapshot() GateSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return GateSnapshot{
		CageID:         g.cageID,
		State:          g.state,
		Epoch:          g.epoch,
		LeaseExpiresAt: g.leaseExpiresAt,
		ActiveConns:    len(g.activeConns),
		LastReason:     g.lastReason,
	}
}

// BeginChecking transitions a non-quarantined gate into GateChecking so health/exit
// probes can run over the probe allowlist. Returns ErrCageQuarantined if quarantined.
func (g *CageGate) BeginChecking(extraProbeAddrs ...string) (int64, error) {
	g.mu.Lock()
	if g.state == GateQuarantined {
		g.mu.Unlock()
		return g.epoch, ErrCageQuarantined
	}
	for _, a := range extraProbeAddrs {
		if norm := normalizeGateTarget(a); norm != "" {
			g.probeAllowlist[norm] = struct{}{}
		}
	}
	g.state = GateChecking
	epoch := g.epoch
	g.mu.Unlock()
	return epoch, nil
}

// ReanchorAndCheck clears quarantine as part of an explicit operator re-anchor flow,
// bumps epoch (killing any remaining sockets and evicting pools/TLS cache), and
// enters GateChecking so the new exit can be verified before opening.
func (g *CageGate) ReanchorAndCheck(reason string, extraProbeAddrs ...string) int64 {
	g.mu.Lock()
	for _, a := range extraProbeAddrs {
		if norm := normalizeGateTarget(a); norm != "" {
			g.probeAllowlist[norm] = struct{}{}
		}
	}
	g.state = GateChecking
	g.leaseExpiresAt = time.Time{}
	conns, newEpoch, evict := g.bumpEpochLocked(reason)
	g.mu.Unlock()

	g.revokeDetached(conns, newEpoch, reason, evict)
	return newEpoch
}

// Open transitions the gate to GateOpen with the requested lease (defaults to 90s).
// Refuses to open directly from GateQuarantined (must re-anchor first).
func (g *CageGate) Open(lease time.Duration) (int64, error) {
	if lease <= 0 {
		lease = DefaultGateLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == GateQuarantined {
		return g.epoch, ErrCageQuarantined
	}
	g.state = GateOpen
	g.leaseExpiresAt = g.now().Add(lease)
	g.lastReason = ""
	return g.epoch, nil
}

// RenewLease extends the active lease when the gate is currently open and unexpired.
func (g *CageGate) RenewLease(lease time.Duration) error {
	if lease <= 0 {
		lease = DefaultGateLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == GateQuarantined {
		return ErrCageQuarantined
	}
	if g.state != GateOpen || g.now().After(g.leaseExpiresAt) {
		return ErrCageClosed
	}
	g.leaseExpiresAt = g.now().Add(lease)
	return nil
}

// CloseGate transitions the gate to GateClosed, bumps epoch, kills all live
// sockets, and invokes the eviction callback.
func (g *CageGate) CloseGate(reason string) int64 {
	g.mu.Lock()
	g.state = GateClosed
	g.leaseExpiresAt = time.Time{}
	conns, newEpoch, evict := g.bumpEpochLocked(reason)
	g.mu.Unlock()

	g.revokeDetached(conns, newEpoch, reason, evict)
	return newEpoch
}

// Quarantine transitions the gate to GateQuarantined, bumps epoch, kills all live
// sockets, and invokes the eviction callback.
func (g *CageGate) Quarantine(reason string) int64 {
	g.mu.Lock()
	g.state = GateQuarantined
	g.leaseExpiresAt = time.Time{}
	conns, newEpoch, evict := g.bumpEpochLocked(reason)
	g.mu.Unlock()

	g.revokeDetached(conns, newEpoch, reason, evict)
	return newEpoch
}

// BumpEpoch atomically increments gate_epoch, revokes and closes all active
// gateConns, and invokes the eviction callback to clear transport pools AND
// per-cage tls.ClientSessionCache together.
func (g *CageGate) BumpEpoch(reason string) int64 {
	g.mu.Lock()
	conns, newEpoch, evict := g.bumpEpochLocked(reason)
	g.mu.Unlock()

	g.revokeDetached(conns, newEpoch, reason, evict)
	return newEpoch
}

func (g *CageGate) bumpEpochLocked(reason string) ([]*gateConn, int64, GateEvictionFunc) {
	g.epoch++
	g.lastReason = reason
	conns := make([]*gateConn, 0, len(g.activeConns))
	for c := range g.activeConns {
		conns = append(conns, c)
	}
	clear(g.activeConns)
	return conns, g.epoch, g.onEvict
}

func (g *CageGate) revokeDetached(conns []*gateConn, newEpoch int64, reason string, evict GateEvictionFunc) {
	if evict != nil {
		evict(g.cageID, newEpoch, reason)
	}
	for _, c := range conns {
		c.revoke()
	}
}

// CheckDialAllowed verifies whether an outbound dial to targetAddr is permitted
// right now and returns the epoch that MUST be passed to RegisterConn after dial.
func (g *CageGate) CheckDialAllowed(targetAddr string) (epoch int64, isProbe bool, err error) {
	g.mu.Lock()
	switch g.state {
	case GateQuarantined:
		g.mu.Unlock()
		return 0, false, ErrCageQuarantined

	case GateClosed:
		g.mu.Unlock()
		return 0, false, ErrCageClosed

	case GateChecking:
		if g.isProbeAllowedLocked(targetAddr) {
			ep := g.epoch
			g.mu.Unlock()
			return ep, true, nil
		}
		g.mu.Unlock()
		return 0, false, ErrProbeOnly

	case GateOpen:
		if g.leaseExpiresAt.IsZero() || g.now().After(g.leaseExpiresAt) {
			g.state = GateClosed
			g.leaseExpiresAt = time.Time{}
			conns, newEpoch, evict := g.bumpEpochLocked("lease_expired")
			g.mu.Unlock()
			g.revokeDetached(conns, newEpoch, "lease_expired", evict)
			return 0, false, ErrCageClosed
		}
		ep := g.epoch
		g.mu.Unlock()
		return ep, false, nil

	default:
		g.mu.Unlock()
		return 0, false, ErrCageClosed
	}
}

// RegisterConn atomically validates under the gate mutex that the gate is still
// eligible (state == GateOpen && currentEpoch == epoch && unexpired for normal
// traffic, or GateChecking/GateOpen && currentEpoch == epoch for probe traffic).
//
// Codex Review Blocker Gate: If the gate closed, quarantined, expired, or bumped
// epoch while the dial was in flight, RegisterConn immediately closes conn and
// returns ErrGateEpochMismatch / ErrCageClosed / ErrCageQuarantined.
func (g *CageGate) RegisterConn(epoch int64, conn net.Conn, isProbe bool) (net.Conn, error) {
	if conn == nil {
		return nil, ErrCageClosed
	}

	g.mu.Lock()
	if g.state == GateQuarantined {
		g.mu.Unlock()
		_ = conn.Close()
		return nil, ErrCageQuarantined
	}
	if g.epoch != epoch {
		g.mu.Unlock()
		_ = conn.Close()
		return nil, ErrGateEpochMismatch
	}
	if isProbe {
		if g.state != GateChecking && g.state != GateOpen {
			g.mu.Unlock()
			_ = conn.Close()
			return nil, ErrCageClosed
		}
	} else {
		if g.state != GateOpen {
			g.mu.Unlock()
			_ = conn.Close()
			return nil, ErrCageClosed
		}
		if g.leaseExpiresAt.IsZero() || g.now().After(g.leaseExpiresAt) {
			g.state = GateClosed
			g.leaseExpiresAt = time.Time{}
			conns, newEpoch, evict := g.bumpEpochLocked("lease_expired")
			g.mu.Unlock()
			_ = conn.Close()
			g.revokeDetached(conns, newEpoch, "lease_expired", evict)
			return nil, ErrCageClosed
		}
	}

	gc := &gateConn{
		Conn:  conn,
		gate:  g,
		epoch: epoch,
	}
	g.activeConns[gc] = struct{}{}
	g.mu.Unlock()
	return gc, nil
}

func (g *CageGate) unregisterConn(gc *gateConn) {
	g.mu.Lock()
	delete(g.activeConns, gc)
	g.mu.Unlock()
}

func (g *CageGate) isProbeAllowedLocked(targetAddr string) bool {
	norm := normalizeGateTarget(targetAddr)
	if norm == "" {
		return false
	}
	if _, ok := g.probeAllowlist[norm]; ok {
		return true
	}
	return false
}

func normalizeGateTarget(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(strings.TrimSuffix(host, "."), port)
}

type gateConn struct {
	net.Conn
	gate    *CageGate
	epoch   int64
	revoked atomic.Bool
	closed  atomic.Bool
}

func (c *gateConn) Read(b []byte) (int, error) {
	if c.revoked.Load() {
		return 0, ErrGateEpochMismatch
	}
	return c.Conn.Read(b)
}

func (c *gateConn) Write(b []byte) (int, error) {
	if c.revoked.Load() {
		return 0, ErrGateEpochMismatch
	}
	return c.Conn.Write(b)
}

func (c *gateConn) revoke() {
	c.revoked.Store(true)
	_ = c.Conn.SetDeadline(time.Now())
	if c.closed.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
	}
}

func (c *gateConn) Close() error {
	if c.gate != nil {
		c.gate.unregisterConn(c)
	}
	if c.closed.CompareAndSwap(false, true) {
		return c.Conn.Close()
	}
	return nil
}
