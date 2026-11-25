package cage

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DNSModeProxyDoHIPv4Only = "proxy_doh_ipv4_only"
	DNSModeSOCKS5hRemote    = "socks5h_remote"

	defaultDialTimeout = 15 * time.Second
	defaultKeepAlive   = 30 * time.Second
)

// DialerConfig configures the zero-direct fail-closed proxy dialer.
type DialerConfig struct {
	// ProxyURL MUST be a valid http://, https://, socks5://, or socks5h:// URL.
	// Empty ProxyURL ALWAYS fails closed with ErrDirectEgressForbidden.
	ProxyURL string
	// Gate MUST be non-nil; every dial is admitted and epoch-fenced through Gate.
	Gate *CageGate
	// DNSMode controls name resolution ("proxy_doh_ipv4_only" or "socks5h_remote").
	DNSMode string
	// DoHEndpoints optionally overrides the RFC 8484 DoH endpoints for proxy_doh_ipv4_only.
	DoHEndpoints []string
	// DoHTLSConfig optionally overrides TLS verification for DoH requests (tests).
	DoHTLSConfig *tls.Config
	// ProxyTLSConfig optionally overrides outer TLS config when connecting to an https:// proxy.
	ProxyTLSConfig *tls.Config
	// AllowedAuthorities enforces Compat anti-SSRF allowlist (e.g. "api.anthropic.com:443", "*.openai.com:443").
	// When non-empty, dials to any authority/port not matching an entry fail closed with ErrAuthorityNotAllowed.
	AllowedAuthorities []string
	// AllowTestLoopback permits 127.0.0.1 targets/proxies strictly for unit & E2E tests.
	AllowTestLoopback bool
	// DialTimeout bounds TCP + proxy handshake timeout. Defaults to 15s.
	DialTimeout time.Duration
	// KeepAlive sets TCP keepalive on proxy sockets. Defaults to 30s.
	KeepAlive time.Duration
}

// CageDialer enforces zero-direct, IPv4-only TCP egress strictly through an
// account cage's bound proxy with CageGate epoch fencing and optional anti-SSRF
// authority allowlist + proxy-only DoH resolution.
type CageDialer struct {
	proxyURL           *url.URL
	proxyScheme        string
	proxyAddr          string
	gate               *CageGate
	dnsMode            string
	doh                *DoHResolver
	proxyTLSConfig     *tls.Config
	allowedAuthorities []authorityRule
	allowTestLoopback  bool
	dialTimeout        time.Duration
	keepAlive          time.Duration
}

type authorityRule struct {
	wildcard bool
	host     string // lowercase hostname or suffix without leading "*."
	port     string
}

// NewCageDialer builds a fail-closed CageDialer. It NEVER permits direct egress.
func NewCageDialer(cfg DialerConfig) (*CageDialer, error) {
	if cfg.Gate == nil {
		return nil, ErrCageClosed
	}
	rawProxy := strings.TrimSpace(cfg.ProxyURL)
	if rawProxy == "" {
		return nil, ErrDirectEgressForbidden
	}
	parsed, err := url.Parse(rawProxy)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("%w: invalid proxy URL", ErrProxyUnavailable)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrProxyUnavailable, scheme)
	}

	proxyAddr := parsed.Host
	if parsed.Port() == "" {
		switch scheme {
		case "http":
			proxyAddr = net.JoinHostPort(parsed.Hostname(), "80")
		case "https":
			proxyAddr = net.JoinHostPort(parsed.Hostname(), "443")
		case "socks5", "socks5h":
			proxyAddr = net.JoinHostPort(parsed.Hostname(), "1080")
		}
	}

	dnsMode := strings.TrimSpace(cfg.DNSMode)
	if dnsMode == "" {
		if scheme == "socks5h" {
			dnsMode = DNSModeSOCKS5hRemote
		} else {
			dnsMode = DNSModeProxyDoHIPv4Only
		}
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	keepAlive := cfg.KeepAlive
	if keepAlive <= 0 {
		keepAlive = defaultKeepAlive
	}

	rules, err := parseAuthorityRules(cfg.AllowedAuthorities)
	if err != nil {
		return nil, err
	}

	d := &CageDialer{
		proxyURL:           parsed,
		proxyScheme:        scheme,
		proxyAddr:          proxyAddr,
		gate:               cfg.Gate,
		dnsMode:            dnsMode,
		proxyTLSConfig:     cfg.ProxyTLSConfig,
		allowedAuthorities: rules,
		allowTestLoopback:  cfg.AllowTestLoopback,
		dialTimeout:        dialTimeout,
		keepAlive:          keepAlive,
	}

	if dnsMode == DNSModeProxyDoHIPv4Only {
		doh, err := NewDoHResolver(DoHConfig{
			Endpoints:         cfg.DoHEndpoints,
			ProxyDialContext:  d.dialProxyForDoH,
			TLSConfig:         cfg.DoHTLSConfig,
			Timeout:           dialTimeout,
			AllowTestLoopback: cfg.AllowTestLoopback,
		})
		if err != nil {
			return nil, err
		}
		d.doh = doh
	}

	return d, nil
}

// Gate returns the CageGate bound to this dialer.
func (d *CageDialer) Gate() *CageGate {
	return d.gate
}

// ClearDNSCache drops any cached DoH records.
func (d *CageDialer) ClearDNSCache() {
	if d != nil && d.doh != nil {
		d.doh.ClearCache()
	}
}

// DialContext establishes an IPv4-only TCP tunnel to addr strictly through the
// bound proxy, guarded by CageGate epoch fencing and anti-SSRF policy.
func (d *CageDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := validateIPv4TCPNetwork(network); err != nil {
		return nil, err
	}
	host, port, err := splitAndValidateAddr(addr)
	if err != nil {
		return nil, err
	}

	// Gate admission check before any network activity.
	epoch, isProbe, err := d.gate.CheckDialAllowed(net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	// Authority allowlist check (skip for explicit synthetic probe during GateChecking).
	if !isProbe && len(d.allowedAuthorities) > 0 && !d.authorityAllowed(host, port) {
		return nil, fmt.Errorf("%w: %s:%s", ErrAuthorityNotAllowed, host, port)
	}

	// Validate destination host / IPv4 before tunneling.
	dialAddr, err := d.resolveAndValidateTarget(ctx, host, port, isProbe)
	if err != nil {
		return nil, err
	}

	conn, err := d.dialViaProxy(ctx, dialAddr)
	if err != nil {
		return nil, err
	}

	// Codex Review Blocker: register and validate state+epoch UNDER LOCK; closes stale dials immediately.
	return d.gate.RegisterConn(epoch, conn, isProbe)
}

// dialProxyForDoH dials DoH endpoints strictly through the cage proxy (never direct).
func (d *CageDialer) dialProxyForDoH(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := validateIPv4TCPNetwork(network); err != nil {
		return nil, err
	}
	host, port, err := splitAndValidateAddr(addr)
	if err != nil {
		return nil, err
	}
	epoch, isProbe, err := d.gate.CheckDialAllowed(net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if ipAddr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if err := ValidateTargetIP(ipAddr, d.allowTestLoopback); err != nil {
			return nil, err
		}
	} else if isBlockedLocalDomain(host) {
		return nil, ErrBlockedDomain
	}
	conn, err := d.dialViaProxy(ctx, net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return d.gate.RegisterConn(epoch, conn, isProbe)
}

func (d *CageDialer) resolveAndValidateTarget(ctx context.Context, host, port string, isProbe bool) (string, error) {
	// Allow Claude-Cage synthetic probe address during GateChecking.
	if isProbe && net.JoinHostPort(host, port) == SyntheticProbeAddr {
		return SyntheticProbeAddr, nil
	}
	if isBlockedLocalDomain(host) {
		return "", ErrBlockedDomain
	}

	// IP literal check (blocks IPv6 and RFC1918/loopback/link-local).
	if ipAddr, err := netip.ParseAddr(host); err == nil {
		if err := ValidateTargetIP(ipAddr, d.allowTestLoopback); err != nil {
			return "", err
		}
		return net.JoinHostPort(ipAddr.Unmap().String(), port), nil
	}

	// Hostname resolution path:
	// - proxy_doh_ipv4_only: resolve public IPv4 via proxy-only DoH and dial the validated IPv4
	//   while callers preserve original hostname for TLS SNI & cert verification.
	// - socks5h_remote: forward hostname directly inside SOCKS5 ATYP=DOMAIN (remote DNS on proxy).
	if d.dnsMode == DNSModeProxyDoHIPv4Only && d.doh != nil {
		ips, err := d.doh.LookupIPv4(ctx, host)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", ErrPrivateIPBlocked
		}
		return net.JoinHostPort(ips[0].String(), port), nil
	}
	return net.JoinHostPort(host, port), nil
}

func (d *CageDialer) dialViaProxy(ctx context.Context, targetAddr string) (net.Conn, error) {
	dialCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		dialCtx, cancel = context.WithTimeout(ctx, d.dialTimeout)
		defer cancel()
	}

	switch d.proxyScheme {
	case "http":
		return d.dialHTTPProxy(dialCtx, targetAddr, false)
	case "https":
		return d.dialHTTPProxy(dialCtx, targetAddr, true)
	case "socks5", "socks5h":
		return d.dialSOCKS5Proxy(dialCtx, targetAddr)
	default:
		return nil, fmt.Errorf("%w: unsupported proxy scheme %q", ErrProxyUnavailable, d.proxyScheme)
	}
}

func (d *CageDialer) dialProxyTCP(ctx context.Context) (net.Conn, error) {
	nd := &net.Dialer{
		Timeout:   d.dialTimeout,
		KeepAlive: d.keepAlive,
	}
	conn, err := nd.DialContext(ctx, "tcp4", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProxyUnavailable, err)
	}
	return conn, nil
}

func (d *CageDialer) dialHTTPProxy(ctx context.Context, targetAddr string, useTLS bool) (net.Conn, error) {
	conn, err := d.dialProxyTCP(ctx)
	if err != nil {
		return nil, err
	}

	if useTLS {
		// Perform real TLS handshake to the HTTPS proxy BEFORE sending CONNECT.
		tlsCfg := &tls.Config{
			ServerName: d.proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		}
		if d.proxyTLSConfig != nil {
			tlsCfg = d.proxyTLSConfig.Clone()
			if tlsCfg.ServerName == "" {
				tlsCfg.ServerName = d.proxyURL.Hostname()
			}
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: https proxy TLS handshake failed: %v", ErrProxyUnavailable, err)
		}
		conn = tlsConn
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer func() {
		if stopCancel() {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	if d.proxyURL.User != nil {
		user := d.proxyURL.User.Username()
		pass, _ := d.proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: write CONNECT failed: %v", ErrProxyUnavailable, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: read CONNECT response failed: %v", ErrProxyUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: proxy CONNECT rejected with %s", ErrProxyUnavailable, resp.Status)
	}

	// Preserve any bytes buffered ahead by bufio.Reader (unlikely for CONNECT, but safe).
	if br.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, br: br}
	}
	return conn, nil
}

// dialSOCKS5Proxy implements a context-aware RFC 1928 / RFC 1929 SOCKS5 client
// over IPv4 TCP with 30s keepalive, honoring ctx deadlines and cancellations.
func (d *CageDialer) dialSOCKS5Proxy(ctx context.Context, targetAddr string) (net.Conn, error) {
	conn, err := d.dialProxyTCP(ctx)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer func() {
		if stopCancel() {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	hasAuth := d.proxyURL.User != nil
	var greeting []byte
	if hasAuth {
		greeting = []byte{0x05, 0x02, 0x00, 0x02} // VER=5, NO_AUTH or USER/PASS
	} else {
		greeting = []byte{0x05, 0x01, 0x00} // VER=5, NO_AUTH
	}
	if _, err := conn.Write(greeting); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 greeting write: %v", ErrProxyUnavailable, err)
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 greeting read: %v", ErrProxyUnavailable, err)
	}
	if methodResp[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: invalid socks5 version %d", ErrProxyUnavailable, methodResp[0])
	}
	switch methodResp[1] {
	case 0x00:
		// No authentication required.
	case 0x02:
		if !hasAuth {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 proxy requires authentication", ErrProxyUnavailable)
		}
		user := d.proxyURL.User.Username()
		pass, _ := d.proxyURL.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 credentials too long", ErrProxyUnavailable)
		}
		authReq := make([]byte, 0, 3+len(user)+len(pass))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 auth write: %v", ErrProxyUnavailable, err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 auth read: %v", ErrProxyUnavailable, err)
		}
		if authResp[1] != 0x00 {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 authentication rejected", ErrProxyUnavailable)
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 unsupported auth method %d", ErrProxyUnavailable, methodResp[1])
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("cage: invalid target port %q", portStr)
	}

	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00) // VER=5, CMD=CONNECT, RSV=0
	if ipAddr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !ipAddr.Unmap().Is4() {
			_ = conn.Close()
			return nil, ErrIPv6Blocked
		}
		v4 := ipAddr.Unmap().As4()
		req = append(req, 0x01) // ATYP=IPv4
		req = append(req, v4[:]...)
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, errors.New("cage: socks5 domain too long")
		}
		req = append(req, 0x03, byte(len(host))) // ATYP=DOMAIN (remote DNS on socks5h)
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	req = append(req, portBytes[:]...)

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 connect write: %v", ErrProxyUnavailable, err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 connect read: %v", ErrProxyUnavailable, err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 connect rejected (rep=%d)", ErrProxyUnavailable, hdr[1])
	}

	// Drain BND.ADDR + BND.PORT
	var drainLen int
	switch hdr[3] {
	case 0x01:
		drainLen = 4 + 2
	case 0x04:
		drainLen = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socks5 bind domain len: %v", ErrProxyUnavailable, err)
		}
		drainLen = int(l[0]) + 2
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 unknown bind atyp %d", ErrProxyUnavailable, hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(drainLen)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: socks5 bind addr drain: %v", ErrProxyUnavailable, err)
	}

	return conn, nil
}

func validateIPv4TCPNetwork(network string) error {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4":
		return nil
	case "tcp6":
		return ErrIPv6Blocked
	case "udp", "udp4", "udp6":
		return ErrUDPBlocked
	default:
		return fmt.Errorf("%w: %q", ErrProtocolBlocked, network)
	}
}

func splitAndValidateAddr(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", "", fmt.Errorf("cage: invalid target address %q: %w", addr, err)
	}
	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return "", "", fmt.Errorf("cage: empty host or port in %q", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return "", "", fmt.Errorf("cage: invalid port %q", port)
	}
	return host, port, nil
}

func parseAuthorityRules(raw []string) ([]authorityRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	rules := make([]authorityRule, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, fmt.Errorf("cage: invalid allowed authority %q (must be host:port): %w", entry, err)
		}
		host = strings.TrimSuffix(strings.TrimSpace(host), ".")
		if strings.HasPrefix(host, "*.") {
			suffix := strings.TrimPrefix(host, "*.")
			if suffix == "" {
				return nil, fmt.Errorf("cage: invalid wildcard authority %q", entry)
			}
			rules = append(rules, authorityRule{wildcard: true, host: suffix, port: port})
		} else {
			rules = append(rules, authorityRule{wildcard: false, host: host, port: port})
		}
	}
	return rules, nil
}

func (d *CageDialer) authorityAllowed(host, port string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, rule := range d.allowedAuthorities {
		if rule.port != port {
			continue
		}
		if rule.wildcard {
			if strings.HasSuffix(h, "."+rule.host) {
				return true
			}
		} else if h == rule.host {
			return true
		}
	}
	return false
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}
