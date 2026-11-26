package edgeproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	// Tunnel HTTP headers (berth-tunnel/v1 over single HTTP/2 mux).
	HeaderRoute          = "X-Berth-Route"
	HeaderHopIndex       = "X-Berth-Hop-Index"
	HeaderLease          = "X-Berth-Lease"
	HeaderRequestID      = "X-Berth-Request-ID"
	HeaderOperationID    = "X-Berth-Operation-ID"
	HeaderUpstreamMethod = "X-Berth-Upstream-Method"
	HeaderUpstreamURL    = "X-Berth-Upstream-URL"
	HeaderConnectTarget  = "X-Berth-Connect-Target"
	HeaderAccountID      = "X-Berth-Account-ID"
	HeaderLandingNode    = "X-Berth-Landing-Node"
	HeaderCageCohort     = "X-Berth-Cage-Cohort"
	HeaderAction         = "X-Berth-Action"
	HeaderSwitchReason   = "X-Berth-Switch-Reason"
	HeaderNodeID         = "X-Berth-Node-ID"
	HeaderNodeTimestamp  = "X-Berth-Timestamp"
	HeaderNodeSignature  = "X-Berth-Signature"

	TunnelExecutePath  = "/edge/v1/execute"
	TunnelWSBridgePath = "/edge/v1/ws-bridge"
	TunnelConnectPath  = "/edge/v1/connect"

	// Reverse-tunnel registration frame ("BRT1").
	BRT1Magic    = "BRT1"
	BRT1Version  = uint8(1)
	brt1FrameLen = 4 + 1 + 8 + 8 + 8 + 16 + ed25519.SignatureSize // 109 bytes

	// WebSocket-over-H2 frame opcodes.
	WSOpText   byte = 0x1
	WSOpBinary byte = 0x2
	WSOpClose  byte = 0x8
	WSOpPing   byte = 0x9
	WSOpPong   byte = 0xA

	DefaultMaxWSFrameBytes = 16 * 1024 * 1024
)

var (
	ErrStaleGeneration          = errors.New("edgeproto: reverse tunnel generation is stale")
	ErrReverseTunnelUnavailable = errors.New("edgeproto: reverse tunnel unavailable for node")
	ErrBRT1InvalidFrame         = errors.New("edgeproto: invalid BRT1 reverse-tunnel frame")
	ErrBRT1BadSignature         = errors.New("edgeproto: invalid BRT1 signature")
	ErrWSFrameTooLarge          = errors.New("edgeproto: ws-over-h2 frame exceeds max size")
)

// EncodeRouteHeader serializes a route chain into a base64url header value.
func EncodeRouteHeader(hops []RouteHop) (string, error) {
	raw, err := json.Marshal(hops)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeRouteHeader deserializes a base64url X-Berth-Route header value.
func DecodeRouteHeader(val string) ([]RouteHop, error) {
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return nil, err
	}
	var hops []RouteHop
	if err := json.Unmarshal(raw, &hops); err != nil {
		return nil, err
	}
	return hops, nil
}

// WriteWSFrame writes a single length-prefixed WebSocket-over-H2 frame: [1B op][4B BE len][payload].
func WriteWSFrame(w io.Writer, op byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = op
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	return nil
}

// ReadWSFrame reads a single length-prefixed WebSocket-over-H2 frame bounded by maxBytes.
func ReadWSFrame(r io.Reader, maxBytes int) (byte, []byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxWSFrameBytes
	}
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	op := hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if n > maxBytes {
		return 0, nil, fmt.Errorf("%w: %d > %d", ErrWSFrameTooLarge, n, maxBytes)
	}
	if n == 0 {
		return op, nil, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return op, payload, nil
}

// ReverseTunnelReg represents a verified BRT1 reverse-tunnel registration handshake.
type ReverseTunnelReg struct {
	NodeID        int64
	Generation    uint64
	TimestampUnix int64
	Nonce         [16]byte
}

// WriteReverseTunnelReg writes a signed 109-byte BRT1 registration frame onto conn.
func WriteReverseTunnelReg(w io.Writer, priv ed25519.PrivateKey, nodeID int64, generation uint64, now time.Time) error {
	if len(priv) != ed25519.PrivateKeySize || nodeID <= 0 || generation == 0 {
		return ErrBRT1InvalidFrame
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	var buf [brt1FrameLen]byte
	copy(buf[0:4], BRT1Magic)
	buf[4] = BRT1Version
	binary.BigEndian.PutUint64(buf[5:13], uint64(nodeID))
	binary.BigEndian.PutUint64(buf[13:21], generation)
	binary.BigEndian.PutUint64(buf[21:29], uint64(now.Unix()))
	copy(buf[29:45], nonce[:])
	sig := ed25519.Sign(priv, buf[:45])
	copy(buf[45:], sig)
	_, err := w.Write(buf[:])
	return err
}

// ReadAndVerifyReverseTunnelReg reads and verifies a 109-byte BRT1 reverse-tunnel frame.
func ReadAndVerifyReverseTunnelReg(
	r io.Reader,
	lookupPubKey func(nodeID int64) (ed25519.PublicKey, error),
	guard *NonceGuard,
	now time.Time,
) (*ReverseTunnelReg, error) {
	if r == nil || lookupPubKey == nil {
		return nil, ErrBRT1InvalidFrame
	}
	var buf [brt1FrameLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBRT1InvalidFrame, err)
	}
	if string(buf[0:4]) != BRT1Magic || buf[4] != BRT1Version {
		return nil, ErrBRT1InvalidFrame
	}
	nodeID := int64(binary.BigEndian.Uint64(buf[5:13]))
	generation := binary.BigEndian.Uint64(buf[13:21])
	tsUnix := int64(binary.BigEndian.Uint64(buf[21:29]))
	if nodeID <= 0 || generation == 0 {
		return nil, ErrBRT1InvalidFrame
	}
	var nonce [16]byte
	copy(nonce[:], buf[29:45])

	pub, err := lookupPubKey(nodeID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: unknown node %d", ErrBRT1BadSignature, nodeID)
	}
	if !ed25519.Verify(pub, buf[:45], buf[45:]) {
		return nil, ErrBRT1BadSignature
	}
	if err := guard.CheckAndRecord(nodeID, nonce, tsUnix, now); err != nil {
		return nil, err
	}
	return &ReverseTunnelReg{
		NodeID:        nodeID,
		Generation:    generation,
		TimestampUnix: tsUnix,
		Nonce:         nonce,
	}, nil
}

type reverseTunnelEntry struct {
	nodeID     int64
	generation uint64
	conn       net.Conn
	h2cc       *http2.ClientConn
	useHTTPS   bool
	done       chan struct{}
	closeOnce  sync.Once
}

func (e *reverseTunnelEntry) close() {
	e.closeOnce.Do(func() {
		if e.h2cc != nil {
			_ = e.h2cc.Close()
		}
		if e.conn != nil {
			_ = e.conn.Close()
		}
		close(e.done)
	})
}

// ReverseTunnelRegistry manages generation-fenced single-H2-mux reverse tunnels
// from NAT/home Landing nodes (Codex Blocker #1.4 & #7.1).
type ReverseTunnelRegistry struct {
	mu      sync.RWMutex
	tunnels map[int64]*reverseTunnelEntry
	h2Tr    *http2.Transport
	onChange func(nodeID int64, online bool, generation uint64)
}

// NewReverseTunnelRegistry initializes a single-H2-mux ReverseTunnelRegistry.
func NewReverseTunnelRegistry(onChange func(nodeID int64, online bool, generation uint64)) *ReverseTunnelRegistry {
	return &ReverseTunnelRegistry{
		tunnels:  make(map[int64]*reverseTunnelEntry),
		h2Tr:     &http2.Transport{AllowHTTP: true},
		onChange: onChange,
	}
}

// RegisterReverseTunnel atomically installs a reverse tunnel connection for nodeID
// fenced strictly by a monotonic generation counter:
//   - Any registration with generation <= current active generation is rejected (ErrStaleGeneration).
//   - Any older registration for nodeID is immediately evicted and closed.
//   - When the underlying H2 connection dies, the route is automatically withdrawn.
func (r *ReverseTunnelRegistry) RegisterReverseTunnel(nodeID int64, generation uint64, conn net.Conn) (<-chan struct{}, error) {
	if nodeID <= 0 || generation == 0 || conn == nil {
		return nil, ErrBRT1InvalidFrame
	}

	h2cc, err := r.h2Tr.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("edgeproto: create reverse h2 client conn: %w", err)
	}
	_, isTLS := conn.(*tls.Conn)

	entry := &reverseTunnelEntry{
		nodeID:     nodeID,
		generation: generation,
		conn:       conn,
		h2cc:       h2cc,
		useHTTPS:   isTLS,
		done:       make(chan struct{}),
	}

	var evicted *reverseTunnelEntry
	r.mu.Lock()
	if cur, exists := r.tunnels[nodeID]; exists {
		if generation <= cur.generation {
			r.mu.Unlock()
			entry.close()
			return nil, fmt.Errorf("%w: got %d <= active %d", ErrStaleGeneration, generation, cur.generation)
		}
		evicted = cur
	}
	r.tunnels[nodeID] = entry
	r.mu.Unlock()

	if evicted != nil {
		evicted.close()
	}
	if r.onChange != nil {
		r.onChange(nodeID, true, generation)
	}

	// Monitor H2 connection health and withdraw the route immediately upon disconnect.
	go r.watchEntry(entry)

	return entry.done, nil
}

func (r *ReverseTunnelRegistry) watchEntry(entry *reverseTunnelEntry) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-entry.done:
			return
		case <-ticker.C:
			if entry.h2cc.State().Closed {
				r.Unregister(entry.nodeID, entry.generation)
				return
			}
		}
	}
}

// Unregister withdraws nodeID's route if and only if the currently registered generation matches.
func (r *ReverseTunnelRegistry) Unregister(nodeID int64, generation uint64) {
	var removed *reverseTunnelEntry
	r.mu.Lock()
	if cur, exists := r.tunnels[nodeID]; exists && cur.generation == generation {
		delete(r.tunnels, nodeID)
		removed = cur
	}
	r.mu.Unlock()
	if removed != nil {
		removed.close()
		if r.onChange != nil {
			r.onChange(nodeID, false, generation)
		}
	}
}

// OnlineNodeIDs returns a sorted slice of landing node IDs with a live, non-closed reverse tunnel.
func (r *ReverseTunnelRegistry) OnlineNodeIDs() []int64 {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]int64, 0, len(r.tunnels))
	for id, entry := range r.tunnels {
		if entry != nil && entry.h2cc != nil && !entry.h2cc.State().Closed {
			out = append(out, id)
		}
	}
	r.mu.RUnlock()
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// RoundTrip dispatches an HTTP/2 request over the live reverse tunnel for nodeID,
// returning the response on the originating bidirectional H2 stream.
func (r *ReverseTunnelRegistry) RoundTrip(nodeID int64, req *http.Request) (*http.Response, error) {
	r.mu.RLock()
	entry, exists := r.tunnels[nodeID]
	r.mu.RUnlock()
	if !exists || entry == nil || entry.h2cc.State().Closed {
		if exists && entry != nil {
			r.Unregister(nodeID, entry.generation)
		}
		return nil, fmt.Errorf("%w: node %d", ErrReverseTunnelUnavailable, nodeID)
	}

	outReq := req.Clone(req.Context())
	if entry.useHTTPS {
		outReq.URL.Scheme = "https"
	} else {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = fmt.Sprintf("node-%d.edge.internal", nodeID)
	}
	outReq.RequestURI = ""

	resp, err := entry.h2cc.RoundTrip(outReq)
	if err != nil {
		if entry.h2cc.State().Closed {
			r.Unregister(nodeID, entry.generation)
		}
		return nil, err
	}
	return resp, nil
}

// HasLiveTunnel reports whether nodeID currently has an active reverse tunnel.
func (r *ReverseTunnelRegistry) HasLiveTunnel(nodeID int64) bool {
	r.mu.RLock()
	entry, exists := r.tunnels[nodeID]
	r.mu.RUnlock()
	if !exists || entry == nil {
		return false
	}
	if entry.h2cc.State().Closed {
		r.Unregister(nodeID, entry.generation)
		return false
	}
	return true
}

// ActiveGeneration returns the currently active generation for nodeID, or 0 if offline.
func (r *ReverseTunnelRegistry) ActiveGeneration(nodeID int64) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if entry, exists := r.tunnels[nodeID]; exists && !entry.h2cc.State().Closed {
		return entry.generation
	}
	return 0
}

// LiveNodeIDs returns a snapshot set of all currently live reverse-tunnel node IDs.
func (r *ReverseTunnelRegistry) LiveNodeIDs() map[int64]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[int64]bool, len(r.tunnels))
	for id, entry := range r.tunnels {
		if entry != nil && !entry.h2cc.State().Closed {
			out[id] = true
		}
	}
	return out
}

// CloseAll closes all active reverse tunnels cleanly.
func (r *ReverseTunnelRegistry) CloseAll() {
	r.mu.Lock()
	entries := make([]*reverseTunnelEntry, 0, len(r.tunnels))
	for id, e := range r.tunnels {
		entries = append(entries, e)
		delete(r.tunnels, id)
	}
	r.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}
