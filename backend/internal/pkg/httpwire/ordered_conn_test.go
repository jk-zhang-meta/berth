package httpwire

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPresetHeaderOrdersCountsAndCasing(t *testing.T) {
	oauthOrder := PresetHeaderOrder(PresetClaudeOAuthAxios115)
	require.Len(t, oauthOrder, 8)
	require.Equal(t, []string{
		"Host", "Accept", "Content-Type", "User-Agent",
		"Accept-Language", "Content-Length", "Accept-Encoding", "Connection",
	}, oauthOrder)

	msgOrder := PresetHeaderOrder(PresetClaudeMessagesV2)
	require.Len(t, msgOrder, 22)
	require.Equal(t, "anthropic-beta", msgOrder[5])
	require.Equal(t, "X-Stainless-OS", msgOrder[13])
	require.Equal(t, "x-stainless-helper-method", msgOrder[17])

	ctOrder := PresetHeaderOrder(PresetClaudeCountTokensV2)
	require.Len(t, ctOrder, 21)
	require.NotContains(t, ctOrder, "x-stainless-helper-method")

	codexOrder := PresetHeaderOrder(PresetCodexCLIRS)
	require.NotEmpty(t, codexOrder)
	require.Equal(t, "chatgpt-account-id", codexOrder[2])

	require.Nil(t, PresetHeaderOrder("unknown_preset"))
}

func TestOrderedRequestConn_ClaudeOAuthExactWireOrderAndCasing(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()

	ordered, err := NewOrderedRequestConnFromPreset(clientRaw, PresetClaudeOAuthAxios115)
	require.NoError(t, err)

	capturedCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(serverRaw)
		var raw bytes.Buffer
		for {
			line, readErr := br.ReadString('\n')
			raw.WriteString(line)
			if readErr != nil || line == "\r\n" {
				break
			}
		}
		body := make([]byte, 15)
		_, _ = io.ReadFull(br, body)
		raw.Write(body)
		capturedCh <- raw.String()
	}()

	// Intentionally scrambled order and non-matching case.
	in := strings.Join([]string{
		"POST /v1/oauth/token HTTP/1.1",
		"connection: close",
		"accept-encoding: gzip, deflate",
		"content-length: 15",
		"user-agent: axios/1.15.2",
		"content-type: application/json",
		"accept: application/json, text/plain, */*",
		"host: platform.claude.com",
		"",
		`{"grant":"abc"}`,
	}, "\r\n")

	n, err := ordered.Write([]byte(in))
	require.NoError(t, err)
	require.Equal(t, len(in), n)

	got := <-capturedCh
	want := strings.Join([]string{
		"POST /v1/oauth/token HTTP/1.1",
		"Host: platform.claude.com",
		"Accept: application/json, text/plain, */*",
		"Content-Type: application/json",
		"User-Agent: axios/1.15.2",
		"Content-Length: 15",
		"Accept-Encoding: gzip, deflate",
		"Connection: close",
		"",
		`{"grant":"abc"}`,
	}, "\r\n")
	require.Equal(t, want, got)
}

func TestOrderedRequestConn_ClaudeMessages22HeaderOrderViaHTTPTransport(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	var capturedHeaders []string
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		_, _ = br.ReadString('\n') // request line
		for {
			line, readErr := br.ReadString('\n')
			if readErr != nil || line == "\r\n" {
				break
			}
			mu.Lock()
			capturedHeaders = append(capturedHeaders, strings.TrimSuffix(line, "\r\n"))
			mu.Unlock()
		}
		// Drain fixed body
		_, _ = io.CopyN(io.Discard, br, 2)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, dialErr := (&net.Dialer{}).DialContext(ctx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			return NewOrderedRequestConnFromPreset(raw, PresetClaudeMessagesV2)
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/v1/messages", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "claude-code-20250219")
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("x-app", "cli")
	req.Header.Set("User-Agent", "claude-cli/2.1.220 (external, cli)")
	req.Header.Set("X-Stainless-Retry-Count", "0")
	req.Header.Set("X-Stainless-Timeout", "600")
	req.Header.Set("X-Stainless-Lang", "js")
	req.Header.Set("X-Stainless-Package-Version", "0.74.0")
	req.Header.Set("X-Stainless-OS", "MacOS")
	req.Header.Set("X-Stainless-Arch", "arm64")
	req.Header.Set("X-Stainless-Runtime", "node")
	req.Header.Set("X-Stainless-Runtime-Version", "v24.11.0")
	req.Header.Set("x-stainless-helper-method", "stream")
	req.Header.Set("x-client-request-id", "req-1")
	req.Header.Set("x-claude-code-session-id", "sess-1")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	<-done

	mu.Lock()
	defer mu.Unlock()
	names := make([]string, 0, len(capturedHeaders))
	for _, h := range capturedHeaders {
		name, _, _ := strings.Cut(h, ":")
		names = append(names, name)
	}
	wantPrefix := PresetHeaderOrder(PresetClaudeMessagesV2)
	require.GreaterOrEqual(t, len(names), len(wantPrefix))
	require.Equal(t, wantPrefix, names[:len(wantPrefix)])
}

func TestOrderedRequestConn_StreamingSSEAndChunkedRequestAndCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: echo:%s\n\n", string(body))
		flusher.Flush()

		// Stream a second event, then wait for client cancellation.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(15 * time.Millisecond):
			_, _ = io.WriteString(w, "data: chunk2\n\n")
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	mux.HandleFunc("/second", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, dialErr := (&net.Dialer{}).DialContext(ctx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			return NewOrderedRequestConnFromPreset(raw, PresetClaudeMessagesV2)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	// 1. Chunked streaming request body + keep-alive reuse
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("part1-"))
		time.Sleep(10 * time.Millisecond)
		_, _ = pw.Write([]byte("part2"))
		_ = pw.Close()
	}()

	req1, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/second", pr)
	require.NoError(t, err)
	resp1, err := client.Do(req1)
	require.NoError(t, err)
	out1, err := io.ReadAll(resp1.Body)
	require.NoError(t, err)
	_ = resp1.Body.Close()
	require.Equal(t, "part1-part2", string(out1))

	// 2. Second request on same keep-alive connection (verifies chunked -> stateHead reset)
	req2, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/second", strings.NewReader("reused-conn"))
	require.NoError(t, err)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	out2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	require.Equal(t, "reused-conn", string(out2))

	// 3. Streaming SSE response + clean context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	req3, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/stream", strings.NewReader("hello-sse"))
	require.NoError(t, err)
	resp3, err := client.Do(req3)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()

	br := bufio.NewReader(resp3.Body)
	line1, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "data: echo:hello-sse\n", line1)
	_, _ = br.ReadString('\n')
	line2, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "data: chunk2\n", line2)
	blank2, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "\n", blank2)

	cancel()
	_, err = br.ReadString('\n')
	require.Error(t, err)
}

func TestOrderedRequestConn_RejectsAmbiguousFramingAndSmuggling(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
	}{
		{
			name: "conflicting Transfer-Encoding and Content-Length",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Transfer-Encoding: chunked",
				"Content-Length: 5",
				"",
				"0\r\n\r\n",
			}, "\r\n"),
			wantErr: ErrAmbiguousFraming,
		},
		{
			name: "duplicate Content-Length equal",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Content-Length: 5",
				"Content-Length: 5",
				"",
				"12345",
			}, "\r\n"),
			wantErr: ErrDuplicateContentLength,
		},
		{
			name: "duplicate Content-Length conflicting",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Content-Length: 5",
				"Content-Length: 10",
				"",
				"12345",
			}, "\r\n"),
			wantErr: ErrDuplicateContentLength,
		},
		{
			name: "signed Content-Length rejected",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Content-Length: +5",
				"",
				"12345",
			}, "\r\n"),
			wantErr: ErrInvalidContentLength,
		},
		{
			name: "duplicate chunked Transfer-Encoding",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Transfer-Encoding: chunked, chunked",
				"",
				"0\r\n\r\n",
			}, "\r\n"),
			wantErr: ErrAmbiguousFraming,
		},
		{
			name: "non-final chunked Transfer-Encoding",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Transfer-Encoding: chunked, gzip",
				"",
				"0\r\n\r\n",
			}, "\r\n"),
			wantErr: ErrAmbiguousFraming,
		},
		{
			name: "obs-fold continuation header rejected",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"X-Custom: a",
				" b",
				"",
				"",
			}, "\r\n"),
			wantErr: ErrMalformedRequestHead,
		},
		{
			name: "whitespace in header name rejected",
			payload: strings.Join([]string{
				"POST /v1/messages HTTP/1.1",
				"Host: api.anthropic.com",
				"Content-Length : 5",
				"",
				"12345",
			}, "\r\n"),
			wantErr: ErrMalformedRequestHead,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			defer func() { _ = clientRaw.Close() }()
			defer func() { _ = serverRaw.Close() }()

			ordered, err := NewOrderedRequestConnFromPreset(clientRaw, PresetClaudeOAuthAxios115)
			require.NoError(t, err)

			// Verify zero bytes leak to the server on rejection.
			serverRead := make(chan int, 1)
			go func() {
				buf := make([]byte, 64)
				_ = serverRaw.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, _ := serverRaw.Read(buf)
				serverRead <- n
			}()

			_, err = ordered.Write([]byte(tc.payload))
			require.True(t, errors.Is(err, tc.wantErr), "got %v want %v", err, tc.wantErr)
			require.Equal(t, 0, <-serverRead, "rejected request must emit zero wire bytes")
		})
	}
}

func TestOrderedRequestConn_ByteByByteChunkedAndKeepAlive(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()

	ordered := NewOrderedRequestConn(clientRaw, []string{"Host", "Transfer-Encoding", "X-Test"})

	received := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(serverRaw)
		received <- string(data)
	}()

	req1 := "POST /a HTTP/1.1\r\nX-Test: 1\r\nTransfer-Encoding: chunked\r\nHost: example.com\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: ok\r\n\r\n"
	req2 := "GET /b HTTP/1.1\r\nX-Test: 2\r\nHost: example.com\r\n\r\n"
	all := []byte(req1 + req2)

	// Feed 1 byte at a time to verify incremental framing boundaries.
	for i := range all {
		n, err := ordered.Write(all[i : i+1])
		require.NoError(t, err)
		require.Equal(t, 1, n)
	}
	_ = clientRaw.Close()

	got := <-received
	want := "POST /a HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nX-Test: 1\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: ok\r\n\r\n" +
		"GET /b HTTP/1.1\r\nHost: example.com\r\nX-Test: 2\r\n\r\n"
	require.Equal(t, want, got)
}
