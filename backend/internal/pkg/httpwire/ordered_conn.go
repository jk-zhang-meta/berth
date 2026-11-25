// Package httpwire provides post-TLS HTTP/1.1 connection framing that emits
// outbound request headers in exact client wire order with exact original casing
// while strictly rejecting ambiguous HTTP/1.1 framing (smuggling vectors).
package httpwire

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	// PresetClaudeOAuthAxios115 matches CPA axios/1.15.2 Claude OAuth wire order (7/8 headers).
	PresetClaudeOAuthAxios115 = "claude_oauth_axios_1_15"
	// PresetClaudeMessagesV2 matches CPA Claude Code /v1/messages wire order (22 headers).
	PresetClaudeMessagesV2 = "claude_messages_v2"
	// PresetClaudeCountTokensV2 matches CPA Claude Code /v1/messages/count_tokens wire order (21 headers).
	PresetClaudeCountTokensV2 = "claude_count_tokens_v2"
	// PresetCodexCLIRS matches OpenAI Codex CLI Rust client wire order.
	PresetCodexCLIRS = "codex_cli_rs"

	// defaultMaxHeaderBytes bounds buffered HTTP/1.1 request heads to protect low-RAM VPSes.
	defaultMaxHeaderBytes = 64 * 1024
)

var (
	// ErrHeaderTooLarge is returned when an outbound HTTP/1.1 request head exceeds maxHeaderBytes.
	ErrHeaderTooLarge = errors.New("httpwire: request header exceeds maximum size")
	// ErrMalformedRequestHead is returned when the outbound HTTP/1.1 request line or header syntax is invalid.
	ErrMalformedRequestHead = errors.New("httpwire: malformed HTTP/1.1 request head")
	// ErrAmbiguousFraming is returned when both Transfer-Encoding and Content-Length are present,
	// or when Transfer-Encoding contains invalid/conflicting framing.
	ErrAmbiguousFraming = errors.New("httpwire: ambiguous HTTP/1.1 framing")
	// ErrDuplicateContentLength is returned when more than one Content-Length header is present.
	ErrDuplicateContentLength = errors.New("httpwire: duplicate Content-Length header")
	// ErrInvalidContentLength is returned when Content-Length is not a strict non-negative base-10 integer.
	ErrInvalidContentLength = errors.New("httpwire: invalid Content-Length value")
	// ErrInvalidChunkedFraming is returned when a chunked body stream is syntactically malformed.
	ErrInvalidChunkedFraming = errors.New("httpwire: invalid chunked body framing")
)

// presetHeaderOrders defines exact wire header orders and exact wire casing per client preset.
var presetHeaderOrders = map[string][]string{
	// 8 slots (7 when Accept-Language is omitted on token calls, 8 when present).
	PresetClaudeOAuthAxios115: {
		"Host",
		"Accept",
		"Content-Type",
		"User-Agent",
		"Accept-Language",
		"Content-Length",
		"Accept-Encoding",
		"Connection",
	},
	// 22 exact wire slots for Claude Code /v1/messages.
	PresetClaudeMessagesV2: {
		"Host",
		"Accept",
		"Content-Type",
		"Authorization",
		"anthropic-version",
		"anthropic-beta",
		"anthropic-dangerous-direct-browser-access",
		"x-app",
		"User-Agent",
		"X-Stainless-Retry-Count",
		"X-Stainless-Timeout",
		"X-Stainless-Lang",
		"X-Stainless-Package-Version",
		"X-Stainless-OS",
		"X-Stainless-Arch",
		"X-Stainless-Runtime",
		"X-Stainless-Runtime-Version",
		"x-stainless-helper-method",
		"x-client-request-id",
		"x-claude-code-session-id",
		"Accept-Encoding",
		"Content-Length",
	},
	// 21 exact wire slots for Claude Code /v1/messages/count_tokens (omits x-stainless-helper-method).
	PresetClaudeCountTokensV2: {
		"Host",
		"Accept",
		"Content-Type",
		"Authorization",
		"anthropic-version",
		"anthropic-beta",
		"anthropic-dangerous-direct-browser-access",
		"x-app",
		"User-Agent",
		"X-Stainless-Retry-Count",
		"X-Stainless-Timeout",
		"X-Stainless-Lang",
		"X-Stainless-Package-Version",
		"X-Stainless-OS",
		"X-Stainless-Arch",
		"X-Stainless-Runtime",
		"X-Stainless-Runtime-Version",
		"x-client-request-id",
		"x-claude-code-session-id",
		"Accept-Encoding",
		"Content-Length",
	},
	// OpenAI Codex CLI Rust HTTP/1.1 header order.
	PresetCodexCLIRS: {
		"Host",
		"Authorization",
		"chatgpt-account-id",
		"OpenAI-Beta",
		"originator",
		"version",
		"session_id",
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Content-Type",
		"Content-Length",
		"Accept-Encoding",
		"Connection",
	},
}

// PresetHeaderOrder returns a copy of the exact wire header order for the given preset name.
// Returns nil if the preset is unknown.
func PresetHeaderOrder(preset string) []string {
	order, ok := presetHeaderOrders[strings.TrimSpace(preset)]
	if !ok {
		return nil
	}
	out := make([]string, len(order))
	copy(out, order)
	return out
}

type writeState uint8

const (
	stateHead writeState = iota
	stateFixedBody
	stateChunkedBody
	statePassthrough
)

type chunkParseState uint8

const (
	chunkSizeLine chunkParseState = iota
	chunkData
	chunkDataCR
	chunkDataLF
	chunkTrailers
)

// OrderedRequestConn wraps a post-TLS net.Conn and rewrites outbound HTTP/1.1
// request headers into the exact configured wire order and casing.
//
// Bodies (both Content-Length and Transfer-Encoding: chunked) are streamed
// directly to the underlying connection with zero whole-body buffering, and
// Read/Close/SetDeadline delegate directly to preserve SSE streaming and
// context cancellation.
type OrderedRequestConn struct {
	net.Conn

	order          []string
	orderIndex     map[string]int
	canonicalWire  map[string]string
	maxHeaderBytes int

	mu             sync.Mutex
	state          writeState
	headBuf        []byte
	bodyRemaining  int64
	chunkState     chunkParseState
	chunkLineBuf   []byte
	chunkRemaining int64
	trailerLineLen int
	trailerSawCR   bool
}

// NewOrderedRequestConn wraps conn to enforce the exact wire header order & casing
// specified by headerOrder. If headerOrder is empty, headers retain their original
// relative order while framing smuggling checks remain enforced.
func NewOrderedRequestConn(conn net.Conn, headerOrder []string) *OrderedRequestConn {
	orderCopy := make([]string, 0, len(headerOrder))
	orderIdx := make(map[string]int, len(headerOrder))
	wireNames := make(map[string]string, len(headerOrder))
	for _, h := range headerOrder {
		trimmed := strings.TrimSpace(h)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if _, exists := orderIdx[lower]; exists {
			continue
		}
		orderIdx[lower] = len(orderCopy)
		wireNames[lower] = trimmed
		orderCopy = append(orderCopy, trimmed)
	}
	return &OrderedRequestConn{
		Conn:           conn,
		order:          orderCopy,
		orderIndex:     orderIdx,
		canonicalWire:  wireNames,
		maxHeaderBytes: defaultMaxHeaderBytes,
		state:          stateHead,
	}
}

// NewOrderedRequestConnFromPreset wraps conn using a named CPA header-order preset.
func NewOrderedRequestConnFromPreset(conn net.Conn, preset string) (*OrderedRequestConn, error) {
	order := PresetHeaderOrder(preset)
	if len(order) == 0 {
		return nil, fmt.Errorf("httpwire: unknown header order preset %q", preset)
	}
	return NewOrderedRequestConn(conn, order), nil
}

// Write intercepts HTTP/1.1 request heads, reorders headers, rejects ambiguous
// framing, and streams request bodies directly to the underlying connection.
func (c *OrderedRequestConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	totalConsumed := 0
	rem := p

	for len(rem) > 0 {
		switch c.state {
		case statePassthrough:
			n, err := writeAll(c.Conn, rem)
			totalConsumed += n
			return totalConsumed, err

		case stateFixedBody:
			toWrite := int64(len(rem))
			if toWrite > c.bodyRemaining {
				toWrite = c.bodyRemaining
			}
			n, err := writeAll(c.Conn, rem[:toWrite])
			c.bodyRemaining -= int64(n)
			totalConsumed += n
			if err != nil {
				return totalConsumed, err
			}
			rem = rem[n:]
			if c.bodyRemaining == 0 {
				c.state = stateHead
			}

		case stateChunkedBody:
			consumed, err := c.writeChunkedLocked(rem)
			totalConsumed += consumed
			if err != nil {
				return totalConsumed, err
			}
			rem = rem[consumed:]

		case stateHead:
			// Append incrementally while searching for the \r\n\r\n terminator.
			prevLen := len(c.headBuf)
			// Only scan a bounded prefix if rem is huge to avoid unbounded buffering
			// when no header terminator exists.
			maxAdd := (c.maxHeaderBytes + 4) - prevLen
			if maxAdd <= 0 {
				return totalConsumed, ErrHeaderTooLarge
			}
			chunk := rem
			if len(chunk) > maxAdd {
				chunk = rem[:maxAdd]
			}
			c.headBuf = append(c.headBuf, chunk...)
			searchStart := prevLen - 3
			if searchStart < 0 {
				searchStart = 0
			}
			idx := bytes.Index(c.headBuf[searchStart:], []byte("\r\n\r\n"))
			if idx < 0 {
				if len(c.headBuf) > c.maxHeaderBytes {
					return totalConsumed, ErrHeaderTooLarge
				}
				totalConsumed += len(chunk)
				rem = rem[len(chunk):]
				continue
			}

			headEnd := searchStart + idx + 4
			consumedFromRem := headEnd - prevLen
			rawHead := c.headBuf[:headEnd]

			reordered, nextState, bodyLen, err := c.rewriteRequestHead(rawHead)
			if err != nil {
				c.headBuf = c.headBuf[:0]
				return totalConsumed, err
			}
			if _, err := writeAll(c.Conn, reordered); err != nil {
				c.headBuf = c.headBuf[:0]
				return totalConsumed, err
			}

			c.headBuf = c.headBuf[:0]
			c.state = nextState
			c.bodyRemaining = bodyLen
			if nextState == stateChunkedBody {
				c.chunkState = chunkSizeLine
				c.chunkLineBuf = c.chunkLineBuf[:0]
				c.chunkRemaining = 0
				c.trailerLineLen = 0
				c.trailerSawCR = false
			}

			totalConsumed += consumedFromRem
			rem = rem[consumedFromRem:]
		}
	}

	return totalConsumed, nil
}

// writeChunkedLocked validates and streams chunked transfer-encoded bytes through
// the underlying connection without buffering whole chunks. It returns after
// either exhausting data or completing the chunked message (transitioning back to stateHead).
func (c *OrderedRequestConn) writeChunkedLocked(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && c.state == stateChunkedBody {
		switch c.chunkState {
		case chunkData:
			avail := int64(len(data) - pos)
			step := avail
			if step > c.chunkRemaining {
				step = c.chunkRemaining
			}
			n, err := writeAll(c.Conn, data[pos:pos+int(step)])
			c.chunkRemaining -= int64(n)
			pos += n
			if err != nil {
				return pos, err
			}
			if c.chunkRemaining == 0 {
				c.chunkState = chunkDataCR
			}

		case chunkDataCR:
			if data[pos] != '\r' {
				return pos, ErrInvalidChunkedFraming
			}
			if _, err := writeAll(c.Conn, data[pos:pos+1]); err != nil {
				return pos, err
			}
			pos++
			c.chunkState = chunkDataLF

		case chunkDataLF:
			if data[pos] != '\n' {
				return pos, ErrInvalidChunkedFraming
			}
			if _, err := writeAll(c.Conn, data[pos:pos+1]); err != nil {
				return pos, err
			}
			pos++
			c.chunkState = chunkSizeLine
			c.chunkLineBuf = c.chunkLineBuf[:0]

		case chunkSizeLine:
			start := pos
			foundLF := false
			for pos < len(data) {
				b := data[pos]
				c.chunkLineBuf = append(c.chunkLineBuf, b)
				pos++
				if len(c.chunkLineBuf) > 4096 {
					return start, ErrInvalidChunkedFraming
				}
				if b == '\n' {
					foundLF = true
					break
				}
			}
			if foundLF {
				if len(c.chunkLineBuf) < 3 || c.chunkLineBuf[len(c.chunkLineBuf)-2] != '\r' {
					return start, ErrInvalidChunkedFraming
				}
				sizeLine := string(c.chunkLineBuf[:len(c.chunkLineBuf)-2])
				if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
					sizeLine = sizeLine[:semi]
				}
				sizeLine = strings.TrimSpace(sizeLine)
				if sizeLine == "" || !isASCIIHex(sizeLine) {
					return start, ErrInvalidChunkedFraming
				}
				chunkSize, err := strconv.ParseInt(sizeLine, 16, 64)
				if err != nil || chunkSize < 0 {
					return start, ErrInvalidChunkedFraming
				}
				if _, err := writeAll(c.Conn, data[start:pos]); err != nil {
					return start, err
				}
				c.chunkLineBuf = c.chunkLineBuf[:0]
				if chunkSize == 0 {
					c.chunkState = chunkTrailers
					c.trailerLineLen = 0
					c.trailerSawCR = false
				} else {
					c.chunkRemaining = chunkSize
					c.chunkState = chunkData
				}
			} else {
				if _, err := writeAll(c.Conn, data[start:pos]); err != nil {
					return start, err
				}
			}

		case chunkTrailers:
			start := pos
			done := false
			for pos < len(data) {
				b := data[pos]
				pos++
				if c.trailerSawCR {
					if b != '\n' {
						return start, ErrInvalidChunkedFraming
					}
					c.trailerSawCR = false
					if c.trailerLineLen == 0 {
						done = true
						break
					}
					c.trailerLineLen = 0
					continue
				}
				if b == '\r' {
					c.trailerSawCR = true
					continue
				}
				if b == '\n' {
					return start, ErrInvalidChunkedFraming
				}
				c.trailerLineLen++
				if c.trailerLineLen > c.maxHeaderBytes {
					return start, ErrHeaderTooLarge
				}
			}
			if _, err := writeAll(c.Conn, data[start:pos]); err != nil {
				return start, err
			}
			if done {
				c.state = stateHead
			}
		}
	}
	return pos, nil
}

type rawHeader struct {
	name      string
	lowerName string
	value     string
	seq       int
}

func (c *OrderedRequestConn) rewriteRequestHead(rawHead []byte) ([]byte, writeState, int64, error) {
	if !bytes.HasSuffix(rawHead, []byte("\r\n\r\n")) {
		return nil, stateHead, 0, ErrMalformedRequestHead
	}
	headBody := rawHead[:len(rawHead)-4]
	lines := bytes.Split(headBody, []byte("\r\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, stateHead, 0, ErrMalformedRequestHead
	}

	reqLine := string(lines[0])
	if strings.ContainsAny(reqLine, "\r\n") {
		return nil, stateHead, 0, ErrMalformedRequestHead
	}
	parts := strings.Split(reqLine, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return nil, stateHead, 0, ErrMalformedRequestHead
	}
	method := parts[0]

	headers := make([]rawHeader, 0, len(lines)-1)
	var (
		clCount        int
		contentLength  int64
		hasTE          bool
		teChunkedCount int
		teFinalChunked bool
		hasUpgrade     bool
	)

	for i, line := range lines[1:] {
		if len(line) == 0 {
			return nil, stateHead, 0, ErrMalformedRequestHead
		}
		if bytes.ContainsAny(line, "\r\n") {
			return nil, stateHead, 0, ErrMalformedRequestHead
		}
		// Reject obs-fold (leading whitespace on header line).
		if line[0] == ' ' || line[0] == '\t' {
			return nil, stateHead, 0, ErrMalformedRequestHead
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, stateHead, 0, ErrMalformedRequestHead
		}
		name := string(line[:colon])
		if !isValidHeaderName(name) {
			return nil, stateHead, 0, ErrMalformedRequestHead
		}
		value := strings.TrimSpace(string(line[colon+1:]))
		lower := strings.ToLower(name)

		switch lower {
		case "content-length":
			clCount++
			if clCount > 1 {
				return nil, stateHead, 0, ErrDuplicateContentLength
			}
			n, err := parseStrictContentLength(value)
			if err != nil {
				return nil, stateHead, 0, err
			}
			contentLength = n

		case "transfer-encoding":
			hasTE = true
			tokens := strings.Split(value, ",")
			if len(tokens) == 0 {
				return nil, stateHead, 0, ErrAmbiguousFraming
			}
			for ti, rawTok := range tokens {
				tok := strings.ToLower(strings.TrimSpace(rawTok))
				if tok == "" {
					return nil, stateHead, 0, ErrAmbiguousFraming
				}
				if tok == "chunked" {
					teChunkedCount++
					if teChunkedCount > 1 {
						return nil, stateHead, 0, ErrAmbiguousFraming
					}
					teFinalChunked = ti == len(tokens)-1
				} else {
					teFinalChunked = false
				}
			}

		case "upgrade":
			if value != "" {
				hasUpgrade = true
			}
		}

		wireName := name
		if canonical, ok := c.canonicalWire[lower]; ok {
			wireName = canonical
		}
		headers = append(headers, rawHeader{
			name:      wireName,
			lowerName: lower,
			value:     value,
			seq:       i,
		})
	}

	// Strictly reject TE + CL smuggling or malformed Transfer-Encoding.
	if hasTE && clCount > 0 {
		return nil, stateHead, 0, ErrAmbiguousFraming
	}
	if hasTE && !teFinalChunked {
		return nil, stateHead, 0, ErrAmbiguousFraming
	}

	ordered := reorderHeaders(headers, c.orderIndex)

	var out bytes.Buffer
	out.Grow(len(rawHead) + 32)
	out.WriteString(reqLine)
	out.WriteString("\r\n")
	for _, h := range ordered {
		out.WriteString(h.name)
		out.WriteString(": ")
		out.WriteString(h.value)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")

	switch {
	case method == "CONNECT" || hasUpgrade:
		return out.Bytes(), statePassthrough, 0, nil
	case hasTE:
		return out.Bytes(), stateChunkedBody, 0, nil
	case contentLength > 0:
		return out.Bytes(), stateFixedBody, contentLength, nil
	default:
		return out.Bytes(), stateHead, 0, nil
	}
}

func reorderHeaders(headers []rawHeader, orderIndex map[string]int) []rawHeader {
	if len(orderIndex) == 0 || len(headers) <= 1 {
		return headers
	}
	matched := make([][]rawHeader, len(orderIndex))
	var extras []rawHeader
	for _, h := range headers {
		if idx, ok := orderIndex[h.lowerName]; ok {
			matched[idx] = append(matched[idx], h)
		} else {
			extras = append(extras, h)
		}
	}
	result := make([]rawHeader, 0, len(headers))
	for _, bucket := range matched {
		result = append(result, bucket...)
	}
	result = append(result, extras...)
	return result
}

func parseStrictContentLength(v string) (int64, error) {
	if v == "" {
		return 0, ErrInvalidContentLength
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, ErrInvalidContentLength
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, ErrInvalidContentLength
	}
	return n, nil
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		// RFC 9110 tchar subset check: printable ASCII excluding delimiters and whitespace.
		if ch <= 0x20 || ch >= 0x7f {
			return false
		}
		switch ch {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}

func isASCIIHex(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		isDigit := ch >= '0' && ch <= '9'
		isLower := ch >= 'a' && ch <= 'f'
		isUpper := ch >= 'A' && ch <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

func writeAll(conn net.Conn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, errors.New("httpwire: short write with nil error")
		}
	}
	return total, nil
}
