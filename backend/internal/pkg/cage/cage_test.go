package cage

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/httpwire"
	"github.com/stretchr/testify/require"
)

// startHTTPConnectProxy spins up a local HTTP or HTTPS CONNECT proxy for tests.
func startHTTPConnectProxy(t *testing.T, useTLS bool) (proxyURL string, proxyCertPool *x509.CertPool, connectCount *atomic.Int64, cleanup func()) {
	t.Helper()
	var count atomic.Int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
			return
		}
		count.Add(1)
		targetConn, err := net.DialTimeout("tcp4", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = targetConn.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		clientConn, bufRW, err := hj.Hijack()
		if err != nil {
			_ = targetConn.Close()
			return
		}
		_, _ = bufRW.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = bufRW.Flush()

		go func() {
			defer func() { _ = targetConn.Close() }()
			defer func() { _ = clientConn.Close() }()
			_, _ = io.Copy(targetConn, bufRW)
		}()
		go func() {
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = targetConn.Close() }()
			_, _ = io.Copy(clientConn, targetConn)
		}()
	})

	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(handler)
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		return srv.URL, pool, &count, srv.Close
	}
	srv = httptest.NewServer(handler)
	return srv.URL, nil, &count, srv.Close
}

// startSOCKS5Proxy spins up a minimal local RFC 1928 SOCKS5 proxy for tests.
func startSOCKS5Proxy(t *testing.T) (addr string, dialCount *atomic.Int64, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	var count atomic.Int64

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				methods := make([]byte, hdr[1])
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})

				var req [4]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil {
					return
				}
				var targetHost string
				switch req[3] {
				case 0x01:
					var ip [4]byte
					if _, err := io.ReadFull(conn, ip[:]); err != nil {
						return
					}
					targetHost = net.IP(ip[:]).String()
				case 0x03:
					var l [1]byte
					if _, err := io.ReadFull(conn, l[:]); err != nil {
						return
					}
					dom := make([]byte, l[0])
					if _, err := io.ReadFull(conn, dom); err != nil {
						return
					}
					targetHost = string(dom)
				default:
					return
				}
				var portBuf [2]byte
				if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
					return
				}
				port := binary.BigEndian.Uint16(portBuf[:])
				targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))
				count.Add(1)

				dst, err := net.DialTimeout("tcp4", targetAddr, 5*time.Second)
				if err != nil {
					_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer func() { _ = dst.Close() }()
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

				go func() { _, _ = io.Copy(dst, conn) }()
				_, _ = io.Copy(conn, dst)
			}(c)
		}
	}()

	return ln.Addr().String(), &count, func() { _ = ln.Close() }
}

func TestCageGate_EpochBumpKillsLiveSocketsAndRejectsRacingStaleDials(t *testing.T) {
	var evictedCount atomic.Int64
	var evictedEpoch atomic.Int64

	gate := NewCageGate(42, WithEvictionCallback(func(cageID int64, newEpoch int64, reason string) {
		require.Equal(t, int64(42), cageID)
		evictedCount.Add(1)
		evictedEpoch.Store(newEpoch)
	}))

	// 1. Fail-closed when Closed.
	_, _, err := gate.CheckDialAllowed("api.anthropic.com:443")
	require.ErrorIs(t, err, ErrCageClosed)

	// 2. GateChecking allows ONLY probe allowlist targets.
	checkEpoch, err := gate.BeginChecking()
	require.NoError(t, err)
	_, _, err = gate.CheckDialAllowed("api.anthropic.com:443")
	require.ErrorIs(t, err, ErrProbeOnly)
	probeEpoch, isProbe, err := gate.CheckDialAllowed(SyntheticProbeAddr)
	require.NoError(t, err)
	require.True(t, isProbe)
	require.Equal(t, checkEpoch, probeEpoch)

	// 3. Open gate and register a live socket.
	openEpoch, err := gate.Open(DefaultGateLease)
	require.NoError(t, err)

	ep, isProbe, err := gate.CheckDialAllowed("api.anthropic.com:443")
	require.NoError(t, err)
	require.False(t, isProbe)
	require.Equal(t, openEpoch, ep)

	c1, s1 := net.Pipe()
	defer func() { _ = s1.Close() }()
	fenced, err := gate.RegisterConn(ep, c1, false)
	require.NoError(t, err)

	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, readErr := fenced.Read(buf)
		readErrCh <- readErr
	}()

	// 4. Simulate a racing stale dial that started at openEpoch before BumpEpoch.
	staleClient, staleServer := net.Pipe()
	defer func() { _ = staleServer.Close() }()

	// BumpEpoch must atomically increment epoch, kill live socket, and invoke eviction callback.
	newEpoch := gate.BumpEpoch("proxy_drift")
	require.Equal(t, openEpoch+1, newEpoch)
	require.Equal(t, int64(1), evictedCount.Load())
	require.Equal(t, newEpoch, evictedEpoch.Load())

	select {
	case rErr := <-readErrCh:
		require.Error(t, rErr, "live socket must be killed on epoch bump")
	case <-time.After(time.Second):
		t.Fatal("live socket was not closed on BumpEpoch")
	}

	// RegisterConn for the racing stale dial MUST reject AND immediately close staleClient.
	_, regErr := gate.RegisterConn(openEpoch, staleClient, false)
	require.ErrorIs(t, regErr, ErrGateEpochMismatch)
	_, writeErr := staleClient.Write([]byte("should-fail"))
	require.Error(t, writeErr, "stale dial connection must be closed immediately")

	// 5. Quarantine blocks opening until explicit ReanchorAndCheck.
	gate.Quarantine("exit_ip_changed")
	_, err = gate.Open(DefaultGateLease)
	require.ErrorIs(t, err, ErrCageQuarantined)
	_, err = gate.BeginChecking()
	require.ErrorIs(t, err, ErrCageQuarantined)

	reEpoch := gate.ReanchorAndCheck("operator_reanchor")
	require.Greater(t, reEpoch, newEpoch)
	_, err = gate.Open(DefaultGateLease)
	require.NoError(t, err)
}

func TestCageDialer_ZeroDirectEgressAndProtocolAndAntiSSRF(t *testing.T) {
	gate := NewCageGate(7)
	_, err := gate.Open(DefaultGateLease)
	require.NoError(t, err)

	// Empty proxy URL MUST fail closed (zero direct egress).
	_, err = NewCageDialer(DialerConfig{ProxyURL: "", Gate: gate})
	require.ErrorIs(t, err, ErrDirectEgressForbidden)

	proxyURL, _, connectCount, closeProxy := startHTTPConnectProxy(t, false)
	defer closeProxy()

	dialer, err := NewCageDialer(DialerConfig{
		ProxyURL:           proxyURL,
		Gate:               gate,
		DNSMode:            DNSModeSOCKS5hRemote, // bypass DoH for direct policy checks
		AllowedAuthorities: []string{"api.anthropic.com:443", "*.openai.com:443"},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Block UDP
	_, err = dialer.DialContext(ctx, "udp", "api.anthropic.com:443")
	require.ErrorIs(t, err, ErrUDPBlocked)

	// Block IPv6 network & literal
	_, err = dialer.DialContext(ctx, "tcp6", "api.anthropic.com:443")
	require.ErrorIs(t, err, ErrIPv6Blocked)

	// Block unlisted authority (Compat anti-SSRF)
	_, err = dialer.DialContext(ctx, "tcp4", "evil.example.com:443")
	require.ErrorIs(t, err, ErrAuthorityNotAllowed)

	// Block wrong port on allowed host
	_, err = dialer.DialContext(ctx, "tcp4", "api.anthropic.com:80")
	require.ErrorIs(t, err, ErrAuthorityNotAllowed)

	// Block RFC1918 & loopback when AllowTestLoopback=false
	dialerNoAllowlist, err := NewCageDialer(DialerConfig{
		ProxyURL: proxyURL,
		Gate:     gate,
		DNSMode:  DNSModeSOCKS5hRemote,
	})
	require.NoError(t, err)
	for _, blocked := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:80", "[2606:4700:4700::1111]:443"} {
		_, err = dialerNoAllowlist.DialContext(ctx, "tcp4", blocked)
		require.Error(t, err, "target %s must be blocked", blocked)
	}
	require.Equal(t, int64(0), connectCount.Load(), "blocked dials must never reach proxy")

	// Proxy outage fails closed (zero direct egress!).
	closeProxy()
	_, err = dialer.DialContext(ctx, "tcp4", "api.anthropic.com:443")
	require.ErrorIs(t, err, ErrProxyUnavailable)
}

func TestCageDialer_HTTPSProxyTLSBeforeCONNECTAndSOCKS5h(t *testing.T) {
	// Target echo server on 127.0.0.1
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.WriteString(conn, "pong")
			}(c)
		}
	}()

	gate := NewCageGate(9)
	_, err = gate.Open(DefaultGateLease)
	require.NoError(t, err)

	// 1. HTTPS proxy with real TLS handshake BEFORE CONNECT.
	httpsProxyURL, proxyCerts, connectCount, closeHTTPSProxy := startHTTPConnectProxy(t, true)
	defer closeHTTPSProxy()

	httpsDialer, err := NewCageDialer(DialerConfig{
		ProxyURL:          httpsProxyURL,
		Gate:              gate,
		DNSMode:           DNSModeSOCKS5hRemote,
		ProxyTLSConfig:    &tls.Config{RootCAs: proxyCerts, MinVersion: tls.VersionTLS12},
		AllowTestLoopback: true,
	})
	require.NoError(t, err)

	conn, err := httpsDialer.DialContext(context.Background(), "tcp4", echoLn.Addr().String())
	require.NoError(t, err)
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	_ = conn.Close()
	require.Equal(t, "pong", string(got))
	require.Equal(t, int64(1), connectCount.Load())

	// 2. Context-aware SOCKS5h proxy.
	socksAddr, socksCount, closeSocks := startSOCKS5Proxy(t)
	defer closeSocks()

	socksDialer, err := NewCageDialer(DialerConfig{
		ProxyURL:          "socks5h://" + socksAddr,
		Gate:              gate,
		DNSMode:           DNSModeSOCKS5hRemote,
		AllowTestLoopback: true,
	})
	require.NoError(t, err)

	sConn, err := socksDialer.DialContext(context.Background(), "tcp4", echoLn.Addr().String())
	require.NoError(t, err)
	got2, err := io.ReadAll(sConn)
	require.NoError(t, err)
	_ = sConn.Close()
	require.Equal(t, "pong", string(got2))
	require.Equal(t, int64(1), socksCount.Load())
}

func TestCageTransport_PinnedUTLSALPNDispatchOrderedHeadersAndAtomicEviction(t *testing.T) {
	// Capture raw HTTP/1.1 header order over TLS + negotiated ALPN.
	// Build a local TLS server using httptest's generated cert.
	certHolder := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tlsCert := certHolder.TLS.Certificates[0]
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certHolder.Certificate())
	certHolder.Close()

	// 1. Raw TLS H1.1 echo server capturing exact wire header order & ALPN.
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = rawLn.Close() }()

	var capturedMu sync.Mutex
	var capturedHeaderNames []string
	var capturedALPN string

	go func() {
		tlsLn := tls.NewListener(rawLn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"http/1.1"},
		})
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				br := bufio.NewReader(tc)
				_, err := br.ReadString('\n')
				if err != nil {
					return
				}
				var names []string
				for {
					line, rErr := br.ReadString('\n')
					if rErr != nil || line == "\r\n" {
						break
					}
					name, _, _ := strings.Cut(strings.TrimSuffix(line, "\r\n"), ":")
					names = append(names, name)
				}
				capturedMu.Lock()
				capturedHeaderNames = names
				capturedALPN = tc.ConnectionState().NegotiatedProtocol
				capturedMu.Unlock()
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(conn)
		}
	}()

	proxyURL, _, connectCount, closeProxy := startHTTPConnectProxy(t, false)
	defer closeProxy()

	pool := NewCageTransportPool()
	gate := NewCageGate(101, WithEvictionCallback(pool.EvictCage))
	_, err = gate.Open(DefaultGateLease)
	require.NoError(t, err)

	dialer, err := NewCageDialer(DialerConfig{
		ProxyURL:          proxyURL,
		Gate:              gate,
		DNSMode:           DNSModeSOCKS5hRemote,
		AllowTestLoopback: true,
	})
	require.NoError(t, err)

	oauthProfile, err := ProfileForPreset(PresetClaudeNode24OAuth)
	require.NoError(t, err)

	rt, err := pool.GetOrCreate(TransportConfig{
		CageID:   101,
		Plane:    PlaneOAuth,
		ProxyURL: proxyURL,
		Profile:  oauthProfile,
		Dialer:   dialer,
		RootCAs:  rootPool,
	})
	require.NoError(t, err)
	require.Equal(t, 1, pool.Size())
	require.NotNil(t, pool.SessionCacheForCage(101))

	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodPost, "https://"+rawLn.Addr().String()+"/v1/oauth/token", strings.NewReader(`{"grant_type":"refresh_token"}`))
	require.NoError(t, err)
	req.Header.Set("Connection", "close")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "axios/1.15.2")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "ok", string(body))
	require.Equal(t, int64(1), connectCount.Load())

	capturedMu.Lock()
	gotNames := append([]string(nil), capturedHeaderNames...)
	gotALPN := capturedALPN
	capturedMu.Unlock()

	// Claude OAuth preset MUST send NO ALPN and exact axios 8-header wire order!
	require.Equal(t, "", gotALPN)
	require.Equal(t, httpwire.PresetHeaderOrder(httpwire.PresetClaudeOAuthAxios115), gotNames)

	// 2. Codex pinned Chrome preset negotiating HTTP/2 via ALPN-following dispatch.
	h2Srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "proto=%s", r.Proto)
	}))
	h2Srv.EnableHTTP2 = true
	h2Srv.StartTLS()
	defer h2Srv.Close()
	h2Roots := x509.NewCertPool()
	h2Roots.AddCert(h2Srv.Certificate())

	codexProfile, err := ProfileForPreset(PresetCodexChromePinned)
	require.NoError(t, err)

	rtH2, err := pool.GetOrCreate(TransportConfig{
		CageID:   101,
		Plane:    PlaneUnified,
		ProxyURL: proxyURL,
		Profile:  codexProfile,
		Dialer:   dialer,
		RootCAs:  h2Roots,
	})
	require.NoError(t, err)
	require.Equal(t, 2, pool.Size())

	h2Client := &http.Client{Transport: rtH2}
	h2Resp, err := h2Client.Get(h2Srv.URL + "/backend-api/codex/responses")
	require.NoError(t, err)
	h2Body, err := io.ReadAll(h2Resp.Body)
	require.NoError(t, err)
	_ = h2Resp.Body.Close()
	require.Equal(t, "proto=HTTP/2.0", string(h2Body))

	// 3. Epoch bump MUST evict BOTH transport pool entries AND per-cage ClientSessionCache together!
	gate.BumpEpoch("anchor_drift")
	require.Equal(t, 0, pool.Size())
	require.Nil(t, pool.SessionCacheForCage(101))
}

func TestDoHResolver_IPv4OnlyRejectsLocalAndRedirects(t *testing.T) {
	// Mock RFC 8484 DoH server returning 93.184.216.34 for example.com and 10.0.0.5 for private.example.
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/dns-query", http.StatusFound)
			return
		}
		q, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		txID := binary.BigEndian.Uint16(q[0:2])
		// Build minimal response copying question + 1 A record.
		resp := make([]byte, 0, len(q)+16)
		resp = append(resp, q...)
		binary.BigEndian.PutUint16(resp[0:2], txID)
		binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR=1, RD=1, RA=1, NOERROR
		binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT=1
		// Name pointer 0xc00c, Type A (1), Class IN (1), TTL 120, RDLEN 4
		ip := [4]byte{93, 184, 216, 34}
		if strings.Contains(string(q), "private") {
			ip = [4]byte{10, 0, 0, 5}
		}
		resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04)
		resp = append(resp, ip[:]...)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer dohSrv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(dohSrv.Certificate())

	resolver, err := NewDoHResolver(DoHConfig{
		Endpoints:        []string{dohSrv.URL + "/dns-query"},
		ProxyDialContext: (&net.Dialer{}).DialContext,
		TLSConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Public IPv4 resolves cleanly.
	ips, err := resolver.LookupIPv4(ctx, "example.com")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	require.Equal(t, "93.184.216.34", ips[0].String())

	// AAAA always returns empty.
	aaaa, err := resolver.LookupAAAA(ctx, "example.com")
	require.NoError(t, err)
	require.Empty(t, aaaa)

	// RFC1918 answer is rejected.
	_, err = resolver.LookupIPv4(ctx, "private.example")
	require.ErrorIs(t, err, ErrPrivateIPBlocked)

	// .localhost / .local / .internal rejected immediately.
	for _, blocked := range []string{"localhost", "foo.localhost", "printer.local", "db.internal"} {
		_, err = resolver.LookupIPv4(ctx, blocked)
		require.ErrorIs(t, err, ErrBlockedDomain)
	}

	// IPv6 literal rejected.
	_, err = resolver.LookupIPv4(ctx, "2606:4700:4700::1111")
	require.ErrorIs(t, err, ErrIPv6Blocked)

	// Redirects refused.
	redirResolver, err := NewDoHResolver(DoHConfig{
		Endpoints:        []string{dohSrv.URL + "/redirect"},
		ProxyDialContext: (&net.Dialer{}).DialContext,
		TLSConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	})
	require.NoError(t, err)
	_, err = redirResolver.LookupIPv4(ctx, "example.com")
	require.True(t, errors.Is(err, ErrDoHRedirectBlocked))
}
