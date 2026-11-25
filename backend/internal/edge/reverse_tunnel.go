package edge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"golang.org/x/net/http2"
)

// ReverseTunnelHub runs on Transit/Relay nodes to accept authenticated,
// generation-fenced outbound reverse-tunnel connections from NAT/home Landing nodes.
type ReverseTunnelHub struct {
	Registry       *edgeproto.ReverseTunnelRegistry
	LookupPubKey   func(nodeID int64) (ed25519.PublicKey, error)
	NonceGuard     *edgeproto.NonceGuard
	HandshakeWait  time.Duration

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// NewReverseTunnelHub constructs a generation-fenced ReverseTunnelHub.
func NewReverseTunnelHub(
	lookupPubKey func(nodeID int64) (ed25519.PublicKey, error),
	onChange func(nodeID int64, online bool, generation uint64),
) *ReverseTunnelHub {
	return &ReverseTunnelHub{
		Registry:      edgeproto.NewReverseTunnelRegistry(onChange),
		LookupPubKey:  lookupPubKey,
		NonceGuard:    edgeproto.NewNonceGuard(edgeproto.DefaultMaxClockSkew, edgeproto.DefaultNonceTTL, edgeproto.DefaultMaxNonces),
		HandshakeWait: 10 * time.Second,
	}
}

// ListenAndServe opens listenAddr and accepts reverse-tunnel registrations until ctx is cancelled.
func (h *ReverseTunnelHub) ListenAndServe(ctx context.Context, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	return h.Serve(ctx, ln)
}

// Serve serves reverse-tunnel registrations on ln until ctx is cancelled.
func (h *ReverseTunnelHub) Serve(ctx context.Context, ln net.Listener) error {
	h.mu.Lock()
	h.listener = ln
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		h.Registry.CloseAll()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				h.wg.Wait()
				return nil
			}
			continue
		}
		h.wg.Add(1)
		go func(c net.Conn) {
			defer h.wg.Done()
			h.acceptOne(c)
		}(conn)
	}
}

// Addr returns the listener's bound address, if running.
func (h *ReverseTunnelHub) Addr() net.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listener == nil {
		return nil
	}
	return h.listener.Addr()
}

func (h *ReverseTunnelHub) acceptOne(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(h.HandshakeWait))
	reg, err := edgeproto.ReadAndVerifyReverseTunnelReg(conn, h.LookupPubKey, h.NonceGuard, time.Now())
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	done, err := h.Registry.RegisterReverseTunnel(reg.NodeID, reg.Generation, conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	<-done
}

// RoundTrip forwards an HTTP/2 request to landingNodeID over its live reverse tunnel.
func (h *ReverseTunnelHub) RoundTrip(landingNodeID int64, req *http.Request) (*http.Response, error) {
	return h.Registry.RoundTrip(landingNodeID, req)
}

// ReverseTunnelClient runs on NAT/home Landing nodes, dialing outbound to a Transit
// ReverseTunnelHub with a strictly increasing generation counter and serving Landing
// HTTP/2 requests directly on that persistent outbound connection.
type ReverseTunnelClient struct {
	NodeID       int64
	PrivateKey   ed25519.PrivateKey
	HubAddr      string
	Handler      http.Handler
	DialTimeout  time.Duration
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration

	generation atomic.Uint64
	connected  atomic.Bool
}

// NewReverseTunnelClient constructs a ReverseTunnelClient for a NAT/home Landing node.
func NewReverseTunnelClient(nodeID int64, priv ed25519.PrivateKey, hubAddr string, handler http.Handler) *ReverseTunnelClient {
	return &ReverseTunnelClient{
		NodeID:      nodeID,
		PrivateKey:  priv,
		HubAddr:     hubAddr,
		Handler:     handler,
		DialTimeout: 10 * time.Second,
		BaseBackoff: 100 * time.Millisecond,
		MaxBackoff:  10 * time.Second,
	}
}

// Generation returns the latest monotonic generation dialed by this client.
func (c *ReverseTunnelClient) Generation() uint64 { return c.generation.Load() }

// Connected reports whether the reverse tunnel is currently serving.
func (c *ReverseTunnelClient) Connected() bool { return c.connected.Load() }

// Run maintains the outbound reverse tunnel with exponential backoff until ctx is cancelled.
func (c *ReverseTunnelClient) Run(ctx context.Context) error {
	backoff := c.BaseBackoff
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}
	maxBackoff := c.MaxBackoff
	if maxBackoff < backoff {
		maxBackoff = 10 * time.Second
	}

	h2Srv := &http2.Server{}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.connectOnce(ctx, h2Srv)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			backoff = c.BaseBackoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (c *ReverseTunnelClient) connectOnce(ctx context.Context, h2Srv *http2.Server) error {
	dialer := &net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.HubAddr)
	if err != nil {
		return err
	}
	defer func() {
		c.connected.Store(false)
		_ = conn.Close()
	}()

	gen := c.generation.Add(1)
	if err := edgeproto.WriteReverseTunnelReg(conn, c.PrivateKey, c.NodeID, gen, time.Now()); err != nil {
		return err
	}

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	c.connected.Store(true)
	h2Srv.ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: c.Handler,
	})
	close(stopWatch)
	return nil
}
