package edge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

const (
	defaultMgmtMaxConns     = 1024
	defaultMgmtMaxPerSource = 32
	defaultMgmtDialTimeout  = 10 * time.Second
	defaultMgmtIdleTimeout  = 180 * time.Second
)

var spliceBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// MgmtEntryProxy runs on zone gateways (default :18443). It accepts client TCP
// connections, derives client IP strictly from the accepted socket peer address,
// signs a fixed-length BHE1 attestation preface with this node's Ed25519 private
// key, and splices bidirectionally to the hardcoded Berth Central target (zero SSRF).
type MgmtEntryProxy struct {
	NodeID        int64
	PrivateKey    ed25519.PrivateKey
	CentralTarget string
	MaxConns      int
	MaxPerSource  int
	DialTimeout   time.Duration
	IdleTimeout   time.Duration

	mu          sync.Mutex
	listener    net.Listener
	activeTotal atomic.Int64
	perSource   map[netip.Addr]int
	wg          sync.WaitGroup
}

// NewMgmtEntryProxy creates a BHE1 management-entry TCP proxy bound to centralTarget.
func NewMgmtEntryProxy(nodeID int64, priv ed25519.PrivateKey, centralTarget string) *MgmtEntryProxy {
	return &MgmtEntryProxy{
		NodeID:        nodeID,
		PrivateKey:    priv,
		CentralTarget: centralTarget,
		MaxConns:      defaultMgmtMaxConns,
		MaxPerSource:  defaultMgmtMaxPerSource,
		DialTimeout:   defaultMgmtDialTimeout,
		IdleTimeout:   defaultMgmtIdleTimeout,
		perSource:     make(map[netip.Addr]int),
	}
}

// ListenAndServe opens listenAddr and serves BHE1-attested connections until ctx is cancelled.
func (p *MgmtEntryProxy) ListenAndServe(ctx context.Context, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	return p.Serve(ctx, ln)
}

// Serve serves BHE1-attested connections on an existing net.Listener until ctx is cancelled.
func (p *MgmtEntryProxy) Serve(ctx context.Context, ln net.Listener) error {
	if p.NodeID <= 0 || len(p.PrivateKey) != ed25519.PrivateKeySize || p.CentralTarget == "" {
		return errors.New("edge: invalid mgmt_entry configuration")
	}
	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				p.wg.Wait()
				return nil
			}
			continue
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConn(ctx, c)
		}(conn)
	}
}

// Addr returns the active listener address, if started.
func (p *MgmtEntryProxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

func (p *MgmtEntryProxy) acquireSlot(ip netip.Addr) bool {
	if p.activeTotal.Add(1) > int64(p.MaxConns) {
		p.activeTotal.Add(-1)
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.perSource[ip] >= p.MaxPerSource {
		p.activeTotal.Add(-1)
		return false
	}
	p.perSource[ip]++
	return true
}

func (p *MgmtEntryProxy) releaseSlot(ip netip.Addr) {
	p.mu.Lock()
	if p.perSource[ip] <= 1 {
		delete(p.perSource, ip)
	} else {
		p.perSource[ip]--
	}
	p.mu.Unlock()
	p.activeTotal.Add(-1)
}

func (p *MgmtEntryProxy) handleConn(ctx context.Context, clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// Derive client IP strictly from the accepted socket peer (Codex Blocker #1.3).
	clientIP, err := edgeproto.ExtractClientIP(clientConn.RemoteAddr())
	if err != nil {
		return
	}
	if !p.acquireSlot(clientIP) {
		return
	}
	defer p.releaseSlot(clientIP)

	dialer := &net.Dialer{Timeout: p.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", p.CentralTarget)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	// Write fixed-length Ed25519-signed BHE1 attestation preface before splicing.
	attestedUpstream, err := edgeproto.WrapConn(upstream, p.PrivateKey, p.NodeID, clientIP, time.Now())
	if err != nil {
		return
	}

	spliceBidirectional(ctx, clientConn, attestedUpstream, p.IdleTimeout)
}

func spliceBidirectional(ctx context.Context, a, b net.Conn, idleTimeout time.Duration) {
	done := make(chan struct{}, 2)
	copySide := func(dst, src net.Conn) {
		bufPtr := spliceBufPool.Get().(*[]byte)
		defer spliceBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			if idleTimeout > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			}
			n, rerr := src.Read(buf)
			if n > 0 {
				if idleTimeout > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}

	go copySide(b, a)
	go copySide(a, b)

	select {
	case <-ctx.Done():
		_ = a.Close()
		_ = b.Close()
	case <-done:
		// Wait briefly for half-close drain, then close both sides.
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			_ = a.Close()
			_ = b.Close()
		}
	}
}

// BHE1Listener wraps a net.Listener on Berth Central's management-entry port so
// every accepted connection MUST present a valid, non-replayed, Ed25519-signed
// BHE1 preface from a registered management-entry node.
type BHE1Listener struct {
	net.Listener
	LookupPubKey   func(nodeID int64) (ed25519.PublicKey, error)
	NonceGuard     *edgeproto.NonceGuard
	PrefaceTimeout time.Duration
	OnReject       func(remoteAddr net.Addr, err error)
}

// Accept waits for the next connection, verifies its BHE1 preface, and returns *edgeproto.AttestedConn.
func (l *BHE1Listener) Accept() (net.Conn, error) {
	timeout := l.PrefaceTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ac, err := edgeproto.AcceptAttestedConn(raw, l.LookupPubKey, l.NonceGuard, timeout, time.Now())
		if err != nil {
			_ = raw.Close()
			if l.OnReject != nil {
				l.OnReject(raw.RemoteAddr(), err)
			}
			continue
		}
		return ac, nil
	}
}

var _ io.Closer = (*BHE1Listener)(nil)
