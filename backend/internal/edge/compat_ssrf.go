package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrSSRFSchemeBlocked     = errors.New("edge: blocked non-https upstream scheme")
	ErrSSRFAuthorityBlocked  = errors.New("edge: upstream authority or port not in allowlist")
	ErrSSRFPrivateIPBlocked  = errors.New("edge: resolved upstream IP is not a public IPv4 address")
	ErrSSRFUserInfoBlocked   = errors.New("edge: upstream URL must not contain userinfo")
	ErrSSRFRedirectLimit     = errors.New("edge: too many upstream redirects")
	ErrSSRFNoPublicIPv4Found = errors.New("edge: no public IPv4 address resolved for upstream host")
)

// DefaultAllowedProviderAuthorities lists official AI provider HTTPS authorities.
var DefaultAllowedProviderAuthorities = []string{
	"api.openai.com:443",
	"chatgpt.com:443",
	"auth.openai.com:443",
	"api.anthropic.com:443",
	"console.anthropic.com:443",
	"generativelanguage.googleapis.com:443",
	"cloudcode-pa.googleapis.com:443",
	"oauth2.googleapis.com:443",
	"api.x.ai:443",
	"accounts.x.ai:443",
}

// IPResolver resolves a hostname into IP addresses (injectable for DoH/proxy resolver or tests).
type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

var reservedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "This" network
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT RFC6598
	netip.MustParsePrefix("127.0.0.0/8"),     // Loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // Link-local / Cloud IMDS
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF Protocol Assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // Multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved / Broadcast
}

// IsPublicIPv4 returns true iff addr is a strictly routable global unicast IPv4 address
// (blocking IPv6, RFC1918, loopback, link-local/IMDS, CGNAT, multicast, and reserved ranges).
func IsPublicIPv4(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		// Reject IPv6/mapped IPv6 strictly when IPv4-only policy is active.
		return false
	}
	if !addr.Is4() {
		return false
	}
	for _, pfx := range reservedIPv4Prefixes {
		if pfx.Contains(addr) {
			return false
		}
	}
	return true
}

// CompatSSRFGuard enforces Codex Blocker #1.6:
//   - Strict provider authority & port allowlist (plus explicit opt-in test allowlist)
//   - Resolves & validates public IPv4 (blocking RFC1918, loopback, link-local, IPv6)
//   - Dials the validated IPv4 directly while preserving TLS SNI & X.509 cert verification
//   - Revalidates every HTTP redirect & discovered OAuth endpoint
type CompatSSRFGuard struct {
	allowedAuthorities map[string]struct{}
	testAllowLoopback  map[string]struct{}
	resolver           IPResolver
	dialTimeout        time.Duration
}

// NewCompatSSRFGuard creates a fail-closed CompatSSRFGuard.
// testAllowLoopback MUST be empty in production; only tests explicitly pass loopback host:port entries.
func NewCompatSSRFGuard(extraAuthorities, testAllowLoopback []string, resolver IPResolver) *CompatSSRFGuard {
	allowed := make(map[string]struct{}, len(DefaultAllowedProviderAuthorities)+len(extraAuthorities))
	for _, a := range DefaultAllowedProviderAuthorities {
		allowed[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	for _, a := range extraAuthorities {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			if !strings.Contains(a, ":") {
				a += ":443"
			}
			allowed[a] = struct{}{}
		}
	}
	testAllowed := make(map[string]struct{}, len(testAllowLoopback))
	for _, a := range testAllowLoopback {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			testAllowed[a] = struct{}{}
		}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &CompatSSRFGuard{
		allowedAuthorities: allowed,
		testAllowLoopback:  testAllowed,
		resolver:           resolver,
		dialTimeout:        15 * time.Second,
	}
}

func (g *CompatSSRFGuard) isTestAllowed(authority string) bool {
	_, ok := g.testAllowLoopback[strings.ToLower(authority)]
	return ok
}

// ValidateURL validates scheme, authority/port allowlist, and forbids userinfo.
func (g *CompatSSRFGuard) ValidateURL(rawURL string) (host, port string, isTest bool, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false, fmt.Errorf("%w: %v", ErrSSRFAuthorityBlocked, err)
	}
	if u.User != nil {
		return "", "", false, ErrSSRFUserInfoBlocked
	}
	scheme := strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		}
	}
	authority := net.JoinHostPort(host, port)

	if g.isTestAllowed(authority) {
		if scheme != "https" && scheme != "http" && scheme != "wss" && scheme != "ws" {
			return "", "", false, ErrSSRFSchemeBlocked
		}
		return host, port, true, nil
	}

	if scheme != "https" && scheme != "wss" {
		return "", "", false, fmt.Errorf("%w: %s", ErrSSRFSchemeBlocked, scheme)
	}
	if _, ok := g.allowedAuthorities[authority]; !ok {
		return "", "", false, fmt.Errorf("%w: %s", ErrSSRFAuthorityBlocked, authority)
	}
	return host, port, false, nil
}

// ValidateOAuthDiscoveryURL revalidates a discovered OAuth endpoint against the SSRF allowlist.
func (g *CompatSSRFGuard) ValidateOAuthDiscoveryURL(rawURL string) error {
	_, _, _, err := g.ValidateURL(rawURL)
	return err
}

// ResolveAndValidateIPv4 resolves host via the guard's resolver and returns the first
// strictly validated public IPv4 address (or loopback IPv4 ONLY for explicitly test-allowlisted authorities).
func (g *CompatSSRFGuard) ResolveAndValidateIPv4(ctx context.Context, host, port string) (netip.Addr, error) {
	authority := strings.ToLower(net.JoinHostPort(host, port))
	testOK := g.isTestAllowed(authority)
	if !testOK {
		if _, ok := g.allowedAuthorities[authority]; !ok {
			return netip.Addr{}, fmt.Errorf("%w: %s", ErrSSRFAuthorityBlocked, authority)
		}
	}

	// If host is already an IP literal, validate it directly.
	if literal, err := netip.ParseAddr(host); err == nil {
		if testOK && literal.Is4() && literal.IsLoopback() {
			return literal, nil
		}
		if IsPublicIPv4(literal) {
			return literal, nil
		}
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrSSRFPrivateIPBlocked, literal)
	}

	ips, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	sawPrivateOrV6 := false
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		if ip.IP.To4() != nil {
			addr = addr.Unmap()
		}
		if testOK && addr.Is4() && addr.IsLoopback() {
			return addr, nil
		}
		if IsPublicIPv4(addr) {
			return addr, nil
		}
		sawPrivateOrV6 = true
	}
	if sawPrivateOrV6 {
		return netip.Addr{}, fmt.Errorf("%w: host=%s", ErrSSRFPrivateIPBlocked, host)
	}
	return netip.Addr{}, fmt.Errorf("%w: host=%s", ErrSSRFNoPublicIPv4Found, host)
}

// DialValidatedTCP resolves & validates host:port and dials the validated IPv4 directly
// (tcp4) so no second DNS resolution or IPv6 fallback can occur.
func (g *CompatSSRFGuard) DialValidatedTCP(ctx context.Context, addr string) (net.Conn, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrSSRFAuthorityBlocked, err)
	}
	ip, err := g.ResolveAndValidateIPv4(ctx, host, port)
	if err != nil {
		return nil, "", err
	}
	dialer := &net.Dialer{Timeout: g.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, "", err
	}
	return conn, host, nil
}

// isBlockedLocalDomain returns true for hostnames that should never be dialed by
// a generic Landing egress CONNECT tunnel.
func isBlockedLocalDomain(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" || h == "localhost" || !strings.Contains(h, ".") {
		return true
	}
	for _, suf := range []string{".localhost", ".local", ".internal", ".lan", ".home.arpa", ".localdomain"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// DialValidatedPublicTCP resolves host:port strictly on the Landing node and dials a
// validated public IPv4 address for lease-authorized CONNECT proxy tunneling.
// Blocks private/loopback/CGNAT/IMDS/IPv6 addresses, local domains, and SMTP port 25.
func (g *CompatSSRFGuard) DialValidatedPublicTCP(ctx context.Context, addr string) (net.Conn, string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid connect target %q", ErrSSRFAuthorityBlocked, addr)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	portNum, pErr := strconv.Atoi(portStr)
	if pErr != nil || portNum <= 0 || portNum > 65535 || portNum == 25 {
		return nil, "", fmt.Errorf("%w: blocked connect port %q", ErrSSRFAuthorityBlocked, portStr)
	}
	authority := net.JoinHostPort(host, portStr)
	testOK := g.isTestAllowed(authority)

	var targetIP netip.Addr
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		if testOK && literal.Is4() && literal.IsLoopback() {
			targetIP = literal
		} else if IsPublicIPv4(literal) {
			targetIP = literal
		} else {
			return nil, "", fmt.Errorf("%w: %s", ErrSSRFPrivateIPBlocked, literal)
		}
	} else {
		if !testOK && isBlockedLocalDomain(host) {
			return nil, "", fmt.Errorf("%w: local domain %s", ErrSSRFAuthorityBlocked, host)
		}
		ips, lErr := g.resolver.LookupIPAddr(ctx, host)
		if lErr != nil {
			return nil, "", lErr
		}
		sawPrivateOrV6 := false
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				continue
			}
			if ip.IP.To4() != nil {
				a = a.Unmap()
			}
			if testOK && a.Is4() && a.IsLoopback() {
				targetIP = a
				break
			}
			if IsPublicIPv4(a) {
				targetIP = a
				break
			}
			sawPrivateOrV6 = true
		}
		if !targetIP.IsValid() {
			if sawPrivateOrV6 {
				return nil, "", fmt.Errorf("%w: host=%s", ErrSSRFPrivateIPBlocked, host)
			}
			return nil, "", fmt.Errorf("%w: host=%s", ErrSSRFNoPublicIPv4Found, host)
		}
	}

	dialer := &net.Dialer{Timeout: g.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(targetIP.String(), portStr))
	if err != nil {
		return nil, "", err
	}
	return conn, host, nil
}

// DialValidatedTLS dials the validated IPv4 address directly while preserving TLS SNI
// and full X.509 certificate verification against the original provider hostname.
func (g *CompatSSRFGuard) DialValidatedTLS(ctx context.Context, addr string, baseTLS *tls.Config) (net.Conn, error) {
	rawConn, origHost, err := g.DialValidatedTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	var cfg *tls.Config
	if baseTLS != nil {
		cfg = baseTLS.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// Preserve original provider hostname for SNI and X.509 hostname verification!
	cfg.ServerName = origHost
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// NewSafeHTTPClient builds a fail-closed *http.Client that enforces authority allowlisting,
// single-resolve public IPv4 dialing, preserved TLS SNI verification, and redirect revalidation.
func (g *CompatSSRFGuard) NewSafeHTTPClient(baseTLS *tls.Config) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, _, err := g.DialValidatedTCP(ctx, addr)
			return conn, err
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.DialValidatedTLS(ctx, addr, baseTLS)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return ErrSSRFRedirectLimit
			}
			_, _, _, err := g.ValidateURL(req.URL.String())
			return err
		},
	}
}
