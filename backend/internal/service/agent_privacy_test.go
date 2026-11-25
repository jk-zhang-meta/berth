//go:build unit

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func verifiedPrivacyTestProxy() *Proxy {
	offset := -5 * 60 * 60
	checked := time.Now().UTC()
	return &Proxy{
		ExitIP:               "198.51.100.44",
		ExitCountry:          "United States",
		ExitCountryCode:      "US",
		ExitRegion:           "Texas",
		ExitCity:             "Houston",
		ExitTimezone:         "America/Chicago",
		ExitUTCOffsetSeconds: &offset,
		ExitASN:              "AS64500 Example",
		ExitISP:              "Example ISP",
		ExitCheckedAt:        &checked,
	}
}

func TestBuildNetworkEgressContextAlwaysEmptyForPromptCacheStability(t *testing.T) {
	require.Empty(t, buildNetworkEgressContext(nil))
	require.Empty(t, buildNetworkEgressContext(verifiedPrivacyTestProxy()))
}

func TestSanitizeAgentRequestBody_ByteExactVerbatimAcrossAllProviders(t *testing.T) {
	proxy := verifiedPrivacyTestProxy()

	cases := []struct {
		name     string
		protocol agentPrivacyProtocol
		body     string
	}{
		{
			name:     "anthropic native with tool_result and non-alphabetical key order",
			protocol: agentPrivacyAnthropicMessages,
			body:     `{"z_order":1,"model":"claude-sonnet-4-5","system":[{"type":"text","text":"You are Claude Code","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tool_env","name":"Bash","input":{"command":"date && uname -a"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_env","content":"Thu Nov 26 01:00:00 PST 2026"}]}],"a_order":2}`,
		},
		{
			name:     "openai responses with environment context and shell tool output",
			protocol: agentPrivacyOpenAIResponses,
			body:     `{"z_first":true,"model":"gpt-5.4","instructions":"keep verbatim","input":[{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"command\":\"date\"}"},{"type":"function_call_output","call_id":"call_1","output":"Thu Nov 26 01:00:00 PST 2026"}]}`,
		},
		{
			name:     "openai chat completions with probe tool output",
			protocol: agentPrivacyOpenAIChatCompletions,
			body:     `{"model":"grok-4","messages":[{"role":"assistant","tool_calls":[{"id":"call_env","type":"function","function":{"name":"exec_command","arguments":"{\"cmd\":\"timedatectl\"}"}}]},{"role":"tool","tool_call_id":"call_env","content":"UTC 2026-11-26"}]}`,
		},
		{
			name:     "gemini generateContent with probe functionResponse",
			protocol: agentPrivacyGeminiGenerateContent,
			body:     `{"systemInstruction":{"parts":[{"text":"<environment_context><timezone>America/Los_Angeles</timezone></environment_context>"}]},"contents":[{"role":"model","parts":[{"functionCall":{"id":"call_env","name":"run_command","args":{"command":"hostname"}}}]},{"role":"user","parts":[{"functionResponse":{"id":"call_env","name":"run_command","response":{"output":"MacBook-Pro-a1b2"}}}]}]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.body)
			out, changed, err := sanitizeAgentRequestBody(raw, tc.protocol, proxy)
			require.NoError(t, err)
			require.False(t, changed)
			require.True(t, bytes.Equal(raw, out), "body must remain byte-for-byte identical")
			text := string(out)
			require.NotContains(t, text, agentNetworkEgressMarker)
			require.NotContains(t, text, "<checked_at>")
			require.NotContains(t, text, "<current_time>")
			require.NotContains(t, text, "<berth_environment_observation>")
			require.NotContains(t, text, "[redacted by Berth privacy policy]")
		})
	}
}

func TestSanitizeAgentRequestBody_10TurnPromptCachePrefixByteExactInvariance(t *testing.T) {
	proxy := verifiedPrivacyTestProxy()

	// Static prefix: tools + system + turn 1 (including a `date` tool_result that previously busted cache every second!).
	prefix := `{"tools":[{"name":"Bash","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],"system":[{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"run date"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"date && uname -a"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"Thu Nov 26 09:00:00 PST 2026 Darwin"}]}]`

	var baselinePrefixHash string
	var history strings.Builder
	history.WriteString(prefix)

	for turn := 1; turn <= 10; turn++ {
		// Simulate proxy probe refreshing ExitCheckedAt every turn (previously busted Bug B1!).
		refreshed := time.Now().UTC().Add(time.Duration(turn) * time.Minute)
		proxy.ExitCheckedAt = &refreshed

		if turn > 1 {
			history.WriteString(fmt.Sprintf(`,{"role":"assistant","content":"reply %d"},{"role":"user","content":"follow-up %d"}`, turn-1, turn))
		}
		turnBody := []byte(history.String() + `],"model":"claude-sonnet-4-5"}`)

		out, changed, err := sanitizeAgentRequestBody(turnBody, agentPrivacyAnthropicMessages, proxy)
		require.NoError(t, err)
		require.False(t, changed, "turn %d must not mutate prompt bytes", turn)
		require.Equal(t, turnBody, out, "turn %d must remain byte-for-byte verbatim", turn)

		// Verify exact prefix SHA-256 invariance across all 10 turns!
		require.True(t, bytes.HasPrefix(out, []byte(prefix)), "turn %d prefix bytes drifted", turn)
		sum := sha256.Sum256(out[:len(prefix)])
		h := hex.EncodeToString(sum[:])
		if baselinePrefixHash == "" {
			baselinePrefixHash = h
		} else {
			require.Equal(t, baselinePrefixHash, h, "turn %d prefix SHA-256 must match turn 1", turn)
		}
	}
}

func TestSanitizeAgentRequestBodyStripsLegacyEgressMarkerSurgically(t *testing.T) {
	body := []byte(`{"z_key":1,"instructions":"client instructions\n<network_egress_context><timezone>Asia/Shanghai</timezone><exit_ip>10.0.0.1</exit_ip></network_egress_context>","a_key":2,"input":[]}`)
	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	text := string(out)
	require.Contains(t, text, "client instructions")
	require.NotContains(t, text, agentNetworkEgressMarker)
	require.NotContains(t, text, "198.51.100.44")
	// Surgical edit preserves original non-alphabetical key order (`z_key` still precedes `a_key`).
	require.Less(t, strings.Index(text, `"z_key"`), strings.Index(text, `"a_key"`))
}

func TestSanitizeCodexWebSocketFramePreservesVerbatimBytes(t *testing.T) {
	responseCreate := []byte(`{"type":"response.create","model":"gpt-test","input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/work</cwd><timezone>America/Chicago</timezone></environment_context>"}]}]}`)
	out, changed, err := sanitizeCodexWebSocketFrame(responseCreate, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, responseCreate, out)

	sessionUpdate := []byte(`{"type":"session.update","session":{"instructions":"<cwd>/work</cwd>"}}`)
	out, changed, err = sanitizeCodexWebSocketFrame(sessionUpdate, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, sessionUpdate, out)
}

func TestSanitizeNativeClaudeCodeHeadersPreservesStainlessHeaders(t *testing.T) {
	header := http.Header{
		"User-Agent":                  []string{"claude-cli/9.9.9 (external, cli)"},
		"X-Stainless-Package-Version": []string{"9.9.9"},
		"X-Stainless-OS":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
		"X-Stainless-Runtime":         []string{"node"},
		"X-Stainless-Runtime-Version": []string{"v24.11.0"},
		"Anthropic-Beta":              []string{"example-beta"},
		"X-Claude-Code-Session-Id":    []string{"session-123"},
	}

	sanitizeNativeClaudeCodeHeaders(header)

	require.Equal(t, defaultFingerprint().UserAgent, getHeaderRaw(header, "User-Agent"))
	require.Equal(t, defaultFingerprint().StainlessPackageVersion, getHeaderRaw(header, "X-Stainless-Package-Version"))
	// Must NOT delete X-Stainless-OS/Arch/Runtime/Runtime-Version!
	require.Equal(t, "MacOS", getHeaderRaw(header, "X-Stainless-OS"))
	require.Equal(t, "arm64", getHeaderRaw(header, "X-Stainless-Arch"))
	require.Equal(t, "node", getHeaderRaw(header, "X-Stainless-Runtime"))
	require.Equal(t, "v24.11.0", getHeaderRaw(header, "X-Stainless-Runtime-Version"))
	require.Equal(t, "example-beta", getHeaderRaw(header, "Anthropic-Beta"))
	require.Equal(t, "session-123", getHeaderRaw(header, "X-Claude-Code-Session-Id"))
}

func TestSanitizeNativeClaudeCodeHeadersUsesRuntimeVersion(t *testing.T) {
	version := "9.9.8"
	withCLIVersionResolverForTest(t, func() string { return version })
	header := make(http.Header)

	sanitizeNativeClaudeCodeHeaders(header)
	require.Equal(t, "claude-cli/9.9.8 (external, cli)", getHeaderRaw(header, "User-Agent"))

	version = "9.9.9"
	sanitizeNativeClaudeCodeHeaders(header)
	require.Equal(t, "claude-cli/9.9.9 (external, cli)", getHeaderRaw(header, "User-Agent"))
	require.Equal(t, defaultFingerprint().StainlessPackageVersion, getHeaderRaw(header, "X-Stainless-Package-Version"))
}

func TestSanitizeNativeCodexHeadersReplacesOnlyClientDerivedMachineUserAgent(t *testing.T) {
	clientUserAgent := "codex_cli_rs/0.146.0 (macOS 15.0; arm64) Terminal.app"
	c := &gin.Context{Request: &http.Request{Header: make(http.Header)}}
	c.Request.Header.Set("User-Agent", clientUserAgent)
	c.Request.Header.Set("originator", "codex_cli_rs")

	header := http.Header{
		"User-Agent": []string{clientUserAgent},
		"originator": []string{"codex_cli_rs"},
		"version":    []string{"0.146.0"},
		"session_id": []string{"session-123"},
	}
	sanitizeNativeCodexHeaders(c, header)

	require.Equal(t, CodexCanonicalUserAgent(), getHeaderRaw(header, "User-Agent"))
	require.NotContains(t, getHeaderRaw(header, "User-Agent"), "macOS 15.0")
	require.NotContains(t, getHeaderRaw(header, "User-Agent"), "arm64")
	require.Equal(t, CodexCanonicalClientVersion(), getHeaderRaw(header, "version"))
	require.Equal(t, "session-123", getHeaderRaw(header, "session_id"))

	explicitGatewayHeader := http.Header{
		"User-Agent": []string{"gateway-client/1.0"},
		"originator": []string{"gateway"},
	}
	sanitizeNativeCodexHeaders(c, explicitGatewayHeader)
	require.Equal(t, "gateway-client/1.0", getHeaderRaw(explicitGatewayHeader, "User-Agent"))
	require.Equal(t, "gateway", getHeaderRaw(explicitGatewayHeader, "originator"))
}

func TestSanitizeNativeCodexHeadersRejectsDeceptiveSubstringUserAgent(t *testing.T) {
	clientUserAgent := "Mozilla/5.0 codex_cli_rs/0.146.0"
	c := &gin.Context{Request: &http.Request{Header: make(http.Header)}}
	c.Request.Header.Set("User-Agent", clientUserAgent)

	header := http.Header{"User-Agent": []string{clientUserAgent}}
	sanitizeNativeCodexHeaders(c, header)
	require.Equal(t, clientUserAgent, getHeaderRaw(header, "User-Agent"))
}

func TestAgentPrivacyBodyHasSignalsIgnoresOrdinaryPromptWords(t *testing.T) {
	require.False(t, agentPrivacyBodyHasSignals([]byte(`{"messages":[{"role":"user","content":"What is today's date and hostname syntax?"}]}`)))
	require.True(t, agentPrivacyBodyHasSignals([]byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"call_env","type":"function","function":{"name":"shell","arguments":"{\"command\":\"date\"}"}}]}]}`)))
	require.True(t, agentPrivacyBodyHasSignals([]byte(`{"systemInstruction":{"parts":[{"text":"\u003cenvironment_context\u003e\u003ctimezone\u003eAsia/Tokyo\u003c/timezone\u003e\u003c/environment_context\u003e"}]}}`)))
}

func TestAgentPrivacyAnthropicBodyHasSignalsIsStructural(t *testing.T) {
	require.False(t, agentPrivacyAnthropicBodyHasSignals([]byte(`{"messages":[{"role":"user","content":"Explain <environment_context> as documentation."}]}`)))
	require.True(t, agentPrivacyAnthropicBodyHasSignals([]byte(`{"system":[{"type":"text","text":"<environment_context><timezone>Asia/Tokyo</timezone></environment_context>"}],"messages":[]}`)))
	require.True(t, agentPrivacyAnthropicBodyHasSignals([]byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tool_env","name":"Bash","input":{"command":"curl https://ipinfo.io/json"}}]}]}`)))
}

func TestMergeInstructionsWithNetworkEgressStripsLegacyMarker(t *testing.T) {
	legacy := "<network_egress_context><checked_at>2026-01-01T00:00:00Z</checked_at></network_egress_context>"
	require.Equal(t, "default codex instructions", mergeInstructionsWithNetworkEgress(legacy, "default codex instructions"))

	existing := "client instructions\n\n" + legacy
	require.Equal(t, "client instructions", mergeInstructionsWithNetworkEgress(existing, "default codex instructions"))
}
