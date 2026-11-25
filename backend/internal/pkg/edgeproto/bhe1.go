package edgeproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	BHE1Magic   = "BHE1"
	BHE1Version = uint8(1)

	bhe1FixedPrefixLen = 4 + 1 + 1 // magic + version + ip_len
	bhe1FixedSuffixLen = 8 + 8 + 16 + ed25519.SignatureSize

	DefaultMaxClockSkew = 30 * time.Second
	DefaultNonceTTL     = 90 * time.Second
	DefaultMaxNonces    = 100_000
)

var (
	ErrBHE1InvalidFrame  = errors.New("edgeproto: invalid BHE1 attestation frame")
	ErrBHE1ClockSkew     = errors.New("edgeproto: BHE1 timestamp skew exceeds limit")
	ErrBHE1Replay        = errors.New("edgeproto: BHE1 nonce replay detected")
	ErrBHE1BadSignature  = errors.New("edgeproto: BHE1 Ed25519 signature invalid")
	ErrBHE1UnknownNode   = errors.New("edgeproto: BHE1 entry node unknown")
	ErrBHE1InvalidPeerIP = errors.New("edgeproto: unable to extract socket peer IP")
)

// BHE1Attestation represents a verified fixed-length management-entry attestation frame.
type BHE1Attestation struct {
	Version       uint8
	ClientIP      netip.Addr
	EntryNodeID   int64
	TimestampUnix int64
	Nonce         [16]byte
	Signature     [ed25519.SignatureSize]byte
}

type nonceKey struct {
	scopeID int64
	nonce   [16]byte
}

// NonceGuard provides bounded-memory, TTL-enforced anti-replay and clock-skew
// protection for BHE1 management-entry and BRT1 reverse-tunnel frames.
type NonceGuard struct {
	mu         sync.Mutex
	maxSkew    time.Duration
	ttl        time.Duration
	maxEntries int
	seen       map[nonceKey]int64 // value: expiry unix seconds
}

// NewNonceGuard returns a NonceGuard with bounded capacity and skew enforcement.
func NewNonceGuard(maxSkew, ttl time.Duration, maxEntries int) *NonceGuard {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxClockSkew
	}
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	if ttl < maxSkew*2 {
		ttl = maxSkew * 2
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxNonces
	}
	return &NonceGuard{
		maxSkew:    maxSkew,
		ttl:        ttl,
		maxEntries: maxEntries,
		seen:       make(map[nonceKey]int64, 256),
	}
}

// CheckAndRecord rejects timestamps skewed beyond maxSkew or duplicate nonces within TTL.
func (g *NonceGuard) CheckAndRecord(scopeID int64, nonce [16]byte, tsUnix int64, now time.Time) error {
	if g == nil {
		return nil
	}
	nowUnix := now.Unix()
	skew := nowUnix - tsUnix
	if skew < 0 {
		skew = -skew
	}
	if time.Duration(skew)*time.Second > g.maxSkew {
		return fmt.Errorf("%w: skew=%ds max=%s", ErrBHE1ClockSkew, skew, g.maxSkew)
	}

	key := nonceKey{scopeID: scopeID, nonce: nonce}
	g.mu.Lock()
	defer g.mu.Unlock()

	if exp, exists := g.seen[key]; exists && exp > nowUnix {
		return ErrBHE1Replay
	}

	// Evict expired entries lazily when map grows large.
	if len(g.seen) >= g.maxEntries {
		for k, exp := range g.seen {
			if exp <= nowUnix {
				delete(g.seen, k)
			}
		}
		// If still full, evict oldest entries until under cap.
		if len(g.seen) >= g.maxEntries {
			for k := range g.seen {
				delete(g.seen, k)
				if len(g.seen) < g.maxEntries {
					break
				}
			}
		}
	}

	g.seen[key] = nowUnix + int64(g.ttl.Seconds())
	return nil
}

// ExtractClientIP extracts the canonical netip.Addr strictly from a socket's RemoteAddr.
func ExtractClientIP(remoteAddr net.Addr) (netip.Addr, error) {
	if remoteAddr == nil {
		return netip.Addr{}, ErrBHE1InvalidPeerIP
	}
	switch a := remoteAddr.(type) {
	case *net.TCPAddr:
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			return addr.Unmap(), nil
		}
	case *net.UDPAddr:
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			return addr.Unmap(), nil
		}
	default:
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			host = remoteAddr.String()
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap(), nil
		}
	}
	return netip.Addr{}, ErrBHE1InvalidPeerIP
}

// EncodeBHE1 creates and signs a fixed-length binary BHE1 attestation frame:
// magic="BHE1"(4B) || version=1(1B) || ip_len(1B: 4|16) || client_ip(ip_len) ||
// entry_node_id(8B BE) || timestamp_unix(8B BE) || nonce(16B) || ed25519_sig(64B).
func EncodeBHE1(priv ed25519.PrivateKey, entryNodeID int64, clientIP netip.Addr, now time.Time) ([]byte, *BHE1Attestation, error) {
	if len(priv) != ed25519.PrivateKeySize || entryNodeID <= 0 || !clientIP.IsValid() {
		return nil, nil, ErrBHE1InvalidFrame
	}
	clientIP = clientIP.Unmap()
	ipBytes := clientIP.AsSlice()
	if len(ipBytes) != 4 && len(ipBytes) != 16 {
		return nil, nil, ErrBHE1InvalidFrame
	}

	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, err
	}

	return encodeBHE1WithNonce(priv, entryNodeID, clientIP, now.Unix(), nonce)
}

func encodeBHE1WithNonce(priv ed25519.PrivateKey, entryNodeID int64, clientIP netip.Addr, tsUnix int64, nonce [16]byte) ([]byte, *BHE1Attestation, error) {
	ipBytes := clientIP.Unmap().AsSlice()
	totalLen := bhe1FixedPrefixLen + len(ipBytes) + bhe1FixedSuffixLen
	buf := make([]byte, totalLen)

	copy(buf[0:4], BHE1Magic)
	buf[4] = BHE1Version
	buf[5] = byte(len(ipBytes))
	off := 6
	copy(buf[off:off+len(ipBytes)], ipBytes)
	off += len(ipBytes)
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(entryNodeID))
	off += 8
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(tsUnix))
	off += 8
	copy(buf[off:off+16], nonce[:])
	signedLen := off + 16

	sig := ed25519.Sign(priv, buf[:signedLen])
	copy(buf[signedLen:], sig)

	att := &BHE1Attestation{
		Version:       BHE1Version,
		ClientIP:      clientIP.Unmap(),
		EntryNodeID:   entryNodeID,
		TimestampUnix: tsUnix,
		Nonce:         nonce,
	}
	copy(att.Signature[:], sig)
	return buf, att, nil
}

// ReadAndVerifyPreface reads an exact length-bounded BHE1 frame from r, verifies
// the entry node's Ed25519 signature, checks timestamp skew, and records nonce anti-replay.
func ReadAndVerifyPreface(
	r io.Reader,
	lookupPubKey func(nodeID int64) (ed25519.PublicKey, error),
	guard *NonceGuard,
	now time.Time,
) (*BHE1Attestation, error) {
	if r == nil || lookupPubKey == nil {
		return nil, ErrBHE1InvalidFrame
	}
	var prefix [bhe1FixedPrefixLen]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBHE1InvalidFrame, err)
	}
	if string(prefix[0:4]) != BHE1Magic {
		return nil, fmt.Errorf("%w: bad magic", ErrBHE1InvalidFrame)
	}
	if prefix[4] != BHE1Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrBHE1InvalidFrame, prefix[4])
	}
	ipLen := int(prefix[5])
	if ipLen != 4 && ipLen != 16 {
		return nil, fmt.Errorf("%w: invalid ip_len %d", ErrBHE1InvalidFrame, ipLen)
	}

	restLen := ipLen + bhe1FixedSuffixLen
	full := make([]byte, bhe1FixedPrefixLen+restLen)
	copy(full[:bhe1FixedPrefixLen], prefix[:])
	if _, err := io.ReadFull(r, full[bhe1FixedPrefixLen:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBHE1InvalidFrame, err)
	}

	off := bhe1FixedPrefixLen
	ipAddr, ok := netip.AddrFromSlice(full[off : off+ipLen])
	if !ok {
		return nil, ErrBHE1InvalidFrame
	}
	ipAddr = ipAddr.Unmap()
	off += ipLen

	entryNodeID := int64(binary.BigEndian.Uint64(full[off : off+8]))
	off += 8
	if entryNodeID <= 0 {
		return nil, fmt.Errorf("%w: non-positive entry_node_id", ErrBHE1InvalidFrame)
	}
	tsUnix := int64(binary.BigEndian.Uint64(full[off : off+8]))
	off += 8

	var nonce [16]byte
	copy(nonce[:], full[off:off+16])
	signedLen := off + 16
	sigBytes := full[signedLen:]

	// Verify entry node key and signature FIRST before polluting nonce cache with forged frames.
	pub, err := lookupPubKey(entryNodeID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: node %d", ErrBHE1UnknownNode, entryNodeID)
	}
	if !ed25519.Verify(pub, full[:signedLen], sigBytes) {
		return nil, ErrBHE1BadSignature
	}

	if err := guard.CheckAndRecord(entryNodeID, nonce, tsUnix, now); err != nil {
		return nil, err
	}

	att := &BHE1Attestation{
		Version:       prefix[4],
		ClientIP:      ipAddr,
		EntryNodeID:   entryNodeID,
		TimestampUnix: tsUnix,
		Nonce:         nonce,
	}
	copy(att.Signature[:], sigBytes)
	return att, nil
}

// AttestedConn wraps a net.Conn alongside its verified BHE1 attestation.
type AttestedConn struct {
	net.Conn
	att *BHE1Attestation
}

// Attestation returns the verified BHE1 attestation bound to this connection.
func (c *AttestedConn) Attestation() *BHE1Attestation {
	return c.att
}

// WrapConn writes a signed BHE1 preface attesting clientIP onto an outbound
// management connection to Berth Central and returns an AttestedConn wrapper.
func WrapConn(conn net.Conn, priv ed25519.PrivateKey, entryNodeID int64, clientIP netip.Addr, now time.Time) (*AttestedConn, error) {
	if conn == nil {
		return nil, ErrBHE1InvalidFrame
	}
	frame, att, err := EncodeBHE1(priv, entryNodeID, clientIP, now)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	return &AttestedConn{Conn: conn, att: att}, nil
}

// AcceptAttestedConn reads and verifies the BHE1 preface on an accepted Central
// connection and returns an AttestedConn ready for normal TLS/HTTP handling.
func AcceptAttestedConn(
	conn net.Conn,
	lookupPubKey func(nodeID int64) (ed25519.PublicKey, error),
	guard *NonceGuard,
	prefaceTimeout time.Duration,
	now time.Time,
) (*AttestedConn, error) {
	if conn == nil {
		return nil, ErrBHE1InvalidFrame
	}
	if prefaceTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(prefaceTimeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	att, err := ReadAndVerifyPreface(conn, lookupPubKey, guard, now)
	if err != nil {
		return nil, err
	}
	return &AttestedConn{Conn: conn, att: att}, nil
}
