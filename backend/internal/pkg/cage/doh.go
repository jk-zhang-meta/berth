package cage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultDoHEndpoint uses Cloudflare's IPv4 DoH endpoint so resolving the DoH
	// endpoint itself never requires host DNS.
	DefaultDoHEndpoint = "https://1.1.1.1/dns-query"

	dnsTypeA     = 1
	dnsClassIN   = 1
	maxDoHResp   = 64 * 1024
	defaultDoTTL = 60 * time.Second
)

// DoHConfig configures the proxy-only RFC 8484 IPv4-only DoH resolver.
type DoHConfig struct {
	// Endpoints is the prioritized list of RFC 8484 DoH endpoints.
	// Defaults to []string{DefaultDoHEndpoint}.
	Endpoints []string
	// ProxyDialContext MUST dial via the cage's proxy (never direct!).
	ProxyDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLSConfig optionally overrides TLS verification (used in unit/E2E mock DoH tests).
	TLSConfig *tls.Config
	// Timeout bounds each DoH HTTP POST. Defaults to 8s.
	Timeout time.Duration
	// AllowTestLoopback permits 127.0.0.1 answers strictly for local unit/E2E tests.
	AllowTestLoopback bool
}

type dohCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// DoHResolver resolves hostnames to public IPv4 A records exclusively via
// RFC 8484 DNS-over-HTTPS over the cage proxy. AAAA lookups always return empty.
type DoHResolver struct {
	endpoints         []string
	client            *http.Client
	allowTestLoopback bool

	mu    sync.RWMutex
	cache map[string]dohCacheEntry
}

// NewDoHResolver creates a proxy-only RFC 8484 IPv4-only DoH resolver.
func NewDoHResolver(cfg DoHConfig) (*DoHResolver, error) {
	if cfg.ProxyDialContext == nil {
		return nil, ErrDirectEgressForbidden
	}
	endpoints := cfg.Endpoints
	if len(endpoints) == 0 {
		endpoints = []string{DefaultDoHEndpoint}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	tr := &http.Transport{
		DialContext:         cfg.ProxyDialContext,
		TLSClientConfig:     cfg.TLSConfig,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrDoHRedirectBlocked
		},
	}
	return &DoHResolver{
		endpoints:         append([]string(nil), endpoints...),
		client:            client,
		allowTestLoopback: cfg.AllowTestLoopback,
		cache:             make(map[string]dohCacheEntry),
	}, nil
}

// LookupAAAA always returns an empty slice to guarantee IPv4-only egress consistency.
func (r *DoHResolver) LookupAAAA(_ context.Context, host string) ([]net.IP, error) {
	if isBlockedLocalDomain(host) {
		return nil, ErrBlockedDomain
	}
	return nil, nil
}

// LookupIPv4 resolves host to validated public IPv4 addresses via RFC 8484 DoH.
func (r *DoHResolver) LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	clean := normalizeHostForDNS(host)
	if clean == "" {
		return nil, ErrBlockedDomain
	}
	if isBlockedLocalDomain(clean) {
		return nil, ErrBlockedDomain
	}

	// Literal IP fast path (enforces IPv4 + public IPv4 validation).
	if addr, err := netip.ParseAddr(clean); err == nil {
		if err := ValidateTargetIP(addr, r.allowTestLoopback); err != nil {
			return nil, err
		}
		v4 := addr.Unmap().As4()
		return []net.IP{net.IPv4(v4[0], v4[1], v4[2], v4[3])}, nil
	}

	r.mu.RLock()
	if entry, ok := r.cache[clean]; ok && time.Now().Before(entry.expiresAt) && len(entry.ips) > 0 {
		out := make([]net.IP, len(entry.ips))
		for i, ip := range entry.ips {
			out[i] = append(net.IP(nil), ip...)
		}
		r.mu.RUnlock()
		return out, nil
	}
	r.mu.RUnlock()

	query, txID, err := buildDNSQueryA(clean)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, endpoint := range r.endpoints {
		ips, minTTL, err := r.queryEndpoint(ctx, endpoint, query, txID)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrDoHRedirectBlocked) {
				return nil, err
			}
			continue
		}
		valid := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				continue
			}
			if err := ValidateTargetIP(addr, r.allowTestLoopback); err != nil {
				continue
			}
			valid = append(valid, ip.To4())
		}
		if len(valid) == 0 {
			lastErr = ErrPrivateIPBlocked
			continue
		}

		ttl := minTTL
		if ttl <= 0 {
			ttl = defaultDoTTL
		}
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
		r.mu.Lock()
		r.cache[clean] = dohCacheEntry{
			ips:       valid,
			expiresAt: time.Now().Add(ttl),
		}
		r.mu.Unlock()

		out := make([]net.IP, len(valid))
		for i, ip := range valid {
			out[i] = append(net.IP(nil), ip...)
		}
		return out, nil
	}

	if lastErr == nil {
		lastErr = errors.New("cage: DoH lookup returned no public IPv4 records")
	}
	return nil, lastErr
}

// ClearCache drops cached DNS entries (called on cage epoch eviction).
func (r *DoHResolver) ClearCache() {
	r.mu.Lock()
	clear(r.cache)
	r.mu.Unlock()
}

func (r *DoHResolver) queryEndpoint(ctx context.Context, endpoint string, query []byte, txID uint16) ([]net.IP, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("cage: DoH endpoint %s returned status %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResp+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxDoHResp {
		return nil, 0, errors.New("cage: DoH response exceeds size limit")
	}
	return parseDNSResponseA(body, txID)
}

func normalizeHostForDNS(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	return h
}

func isBlockedLocalDomain(host string) bool {
	h := normalizeHostForDNS(host)
	if h == "" {
		return true
	}
	if h == "localhost" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// ValidateTargetIP enforces IPv4-only public egress (rejecting IPv6, RFC1918,
// loopback, link-local, CGNAT, multicast, unspecified, and reserved ranges).
// When allowTestLoopback is true, IPv4 loopback (127.0.0.0/8) is allowed strictly for tests.
func ValidateTargetIP(addr netip.Addr, allowTestLoopback bool) error {
	if !addr.IsValid() {
		return ErrPrivateIPBlocked
	}
	if addr.Is6() && !addr.Is4In6() {
		return ErrIPv6Blocked
	}
	v4 := addr.Unmap()
	if !v4.Is4() {
		return ErrIPv6Blocked
	}
	if v4.IsLoopback() {
		if allowTestLoopback {
			return nil
		}
		return ErrPrivateIPBlocked
	}
	if !IsPublicIPv4(v4) {
		return ErrPrivateIPBlocked
	}
	return nil
}

// IsPublicIPv4 returns true iff addr is a globally routable public IPv4 address.
func IsPublicIPv4(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	b := addr.As4()
	switch {
	case b[0] == 0: // 0.0.0.0/8
		return false
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // 100.64.0.0/10 CGNAT
		return false
	case b[0] == 192 && b[1] == 0 && b[2] == 0: // 192.0.0.0/24 IETF protocol assignments
		return false
	case b[0] == 192 && b[1] == 0 && b[2] == 2: // 192.0.2.0/24 TEST-NET-1
		return false
	case b[0] == 198 && (b[1] == 18 || b[1] == 19): // 198.18.0.0/15 benchmark (except synthetic probe checked separately)
		return false
	case b[0] == 198 && b[1] == 51 && b[2] == 100: // 198.51.100.0/24 TEST-NET-2
		return false
	case b[0] == 203 && b[1] == 0 && b[2] == 113: // 203.0.113.0/24 TEST-NET-3
		return false
	case b[0] >= 240: // 240.0.0.0/4 reserved + broadcast
		return false
	}
	return true
}

// buildDNSQueryA encodes a minimal RFC 1035 DNS query for QTYPE=A, QCLASS=IN.
func buildDNSQueryA(name string) ([]byte, uint16, error) {
	labels := strings.Split(name, ".")
	var txBytes [2]byte
	if _, err := rand.Read(txBytes[:]); err != nil {
		return nil, 0, err
	}
	txID := binary.BigEndian.Uint16(txBytes[:])

	var buf bytes.Buffer
	// 12-byte DNS header: ID, Flags (RD=1 -> 0x0100), QDCOUNT=1, AN/NS/AR=0
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txID)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)
	buf.Write(header)

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("cage: invalid DNS label in %q", name)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // root terminator

	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], dnsTypeA)
	binary.BigEndian.PutUint16(qTail[2:4], dnsClassIN)
	buf.Write(qTail[:])
	return buf.Bytes(), txID, nil
}

// parseDNSResponseA extracts IPv4 A records and minimum TTL from an RFC 1035 response.
func parseDNSResponseA(msg []byte, expectedTxID uint16) ([]net.IP, time.Duration, error) {
	if len(msg) < 12 {
		return nil, 0, errors.New("cage: truncated DNS response header")
	}
	respID := binary.BigEndian.Uint16(msg[0:2])
	if respID != 0 && respID != expectedTxID {
		return nil, 0, errors.New("cage: DNS transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := flags & 0x000f
	if rcode != 0 {
		return nil, 0, fmt.Errorf("cage: DNS query failed with rcode %d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	for i := 0; i < qdCount; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, 0, err
		}
		if next+4 > len(msg) {
			return nil, 0, errors.New("cage: truncated DNS question")
		}
		off = next + 4
	}

	var ips []net.IP
	var minTTL time.Duration
	for i := 0; i < anCount; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, 0, err
		}
		if next+10 > len(msg) {
			return nil, 0, errors.New("cage: truncated DNS answer record")
		}
		rtype := binary.BigEndian.Uint16(msg[next : next+2])
		rclass := binary.BigEndian.Uint16(msg[next+2 : next+4])
		ttlSec := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(msg) {
			return nil, 0, errors.New("cage: truncated DNS rdata")
		}
		if rtype == dnsTypeA && rclass == dnsClassIN && rdLen == 4 {
			ip := net.IPv4(msg[rdataStart], msg[rdataStart+1], msg[rdataStart+2], msg[rdataStart+3])
			ips = append(ips, ip)
			ttl := time.Duration(ttlSec) * time.Second
			if minTTL == 0 || (ttl > 0 && ttl < minTTL) {
				minTTL = ttl
			}
		}
		off = rdataStart + rdLen
	}
	return ips, minTTL, nil
}

func skipDNSName(msg []byte, off int) (int, error) {
	jumps := 0
	for {
		if off >= len(msg) {
			return 0, errors.New("cage: DNS name out of bounds")
		}
		b := msg[off]
		if b == 0 {
			return off + 1, nil
		}
		if b&0xc0 == 0xc0 {
			if off+2 > len(msg) {
				return 0, errors.New("cage: truncated DNS compression pointer")
			}
			return off + 2, nil
		}
		if b&0xc0 != 0 {
			return 0, errors.New("cage: invalid DNS label flags")
		}
		off += 1 + int(b)
		jumps++
		if jumps > 128 {
			return 0, errors.New("cage: DNS name exceeds label limit")
		}
	}
}
