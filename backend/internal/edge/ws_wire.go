package edge

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

const (
	wsGUID               = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	WSCloseCageRebind    = uint16(4009)
	WSCloseNormalClosure = uint16(1000)
)

// ComputeWebSocketAccept computes the RFC 6455 Sec-WebSocket-Accept header value.
func ComputeWebSocketAccept(key string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(strings.TrimSpace(key) + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// IsWebSocketUpgrade reports whether r is an HTTP/1.1 WebSocket upgrade request.
func IsWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// WriteRFC6455Frame writes an RFC 6455 WebSocket frame.
// Bit 7 (0x80) carries FIN=1; bit 6 (0x40) without bit 7 marks a non-final fragment (FIN=0),
// matching Rust berth-edge `proto::write_rfc6455_frame` while keeping legacy bare opcodes final.
func WriteRFC6455Frame(w io.Writer, opcode byte, payload []byte, masked bool) error {
	var hdr [14]byte
	finBit := byte(0x80)
	if (opcode&0x40) != 0 && (opcode&0x80) == 0 {
		finBit = 0x00
	}
	hdr[0] = finBit | (opcode & 0x0F)
	n := len(payload)
	pos := 2
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		hdr[1] = maskBit | byte(n)
	case n <= 65535:
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		pos = 4
	default:
		hdr[1] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		pos = 10
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(rand.Reader, maskKey[:]); err != nil {
			return err
		}
		copy(hdr[pos:pos+4], maskKey[:])
		pos += 4
	}
	if _, err := w.Write(hdr[:pos]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if !masked {
		_, err := w.Write(payload)
		return err
	}
	maskedBuf := make([]byte, n)
	for i := 0; i < n; i++ {
		maskedBuf[i] = payload[i] ^ maskKey[i%4]
	}
	_, err := w.Write(maskedBuf)
	return err
}

// WriteRFC6455Close writes an RFC 6455 Close frame carrying status code and optional reason.
func WriteRFC6455Close(w io.Writer, code uint16, reason string, masked bool) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], reason)
	return WriteRFC6455Frame(w, edgeproto.WSOpClose, payload, masked)
}

// ReadRFC6455Frame reads a single RFC 6455 WebSocket frame bounded by maxPayload.
func ReadRFC6455Frame(r io.Reader, maxPayload int) (byte, []byte, error) {
	if maxPayload <= 0 {
		maxPayload = edgeproto.DefaultMaxWSFrameBytes
	}
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	fin := (hdr[0] & 0x80) != 0
	opcode := hdr[0] & 0x0F
	if fin {
		opcode |= 0x80
	} else {
		opcode |= 0x40
	}
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > uint64(maxPayload) {
		return 0, nil, edgeproto.ErrWSFrameTooLarge
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	}
	return opcode, payload, nil
}

// DialRFC6455WebSocket performs an RFC 6455 client upgrade over a CompatSSRFGuard-validated dialer.
func DialRFC6455WebSocket(
	ctx context.Context,
	guard *CompatSSRFGuard,
	tlsConfig *tls.Config,
	targetURL string,
	headers http.Header,
) (net.Conn, *bufio.Reader, *http.Response, error) {
	host, port, _, err := guard.ValidateURL(targetURL)
	if err != nil {
		return nil, nil, nil, err
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	addr := net.JoinHostPort(host, port)

	var conn net.Conn
	if scheme == "https" || scheme == "wss" {
		conn, err = guard.DialValidatedTLS(ctx, addr, tlsConfig)
	} else {
		conn, _, err = guard.DialValidatedTCP(ctx, addr)
	}
	if err != nil {
		return nil, nil, nil, err
	}

	var keyBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, keyBytes[:]); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	secKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", u.Host)
	reqBuf.WriteString("Upgrade: websocket\r\n")
	reqBuf.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", secKey)
	reqBuf.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, vals := range headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "upgrade" || lk == "connection" || strings.HasPrefix(lk, "sec-websocket-") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
		}
	}
	reqBuf.WriteString("\r\n")

	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, nil, resp, fmt.Errorf("edge: upstream ws upgrade rejected with status %d", resp.StatusCode)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != ComputeWebSocketAccept(secKey) {
		_ = conn.Close()
		return nil, nil, resp, errors.New("edge: upstream ws invalid Sec-WebSocket-Accept")
	}
	return conn, br, resp, nil
}
