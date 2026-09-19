//go:build unit

package service

import (
	"encoding/json"
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

func TestSanitizeAgentRequestBodyCodexRewritesTimezoneFromVerifiedProxy(t *testing.T) {
	proxy := verifiedPrivacyTestProxy()
	body := []byte(`{"model":"gpt-test","instructions":"keep","input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/home/private/work</cwd><shell>zsh</shell><current_date>2026-09-17</current_date><timezone>Asia/Shanghai</timezone></environment_context>"}]}]}`)
	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, proxy)
	require.NoError(t, err)
	require.True(t, changed)
	text := string(out)
	require.Contains(t, text, "/home/private/work")
	require.Contains(t, text, "<shell>zsh</shell>")
	require.Contains(t, text, "<current_date>"+agentCurrentDateForProxy(proxy, time.Now())+"</current_date>")
	require.NotContains(t, text, "Asia/Shanghai")
	require.Contains(t, text, "<timezone>America/Chicago</timezone>")
	require.NotContains(t, text, agentNetworkEgressMarker)
	require.Contains(t, text, `"instructions":"keep"`)
}

func TestSanitizeAgentRequestBodyOpenAIRewritesEnvironmentProbeOutput(t *testing.T) {
	body := []byte(`{"model":"gpt-test","input":[{"type":"function_call","call_id":"call_env","name":"shell","arguments":"{\"command\":\"curl -s https://ipwho.is && date\"}"},{"type":"function_call_output","call_id":"call_env","output":"203.0.113.77 Asia/Shanghai 2026-09-18"},{"type":"function_call","call_id":"call_file","name":"shell","arguments":"{\"command\":\"cat README.md\"}"},{"type":"function_call_output","call_id":"call_file","output":"keep me"}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "203.0.113.77")
	require.NotContains(t, string(out), "Asia/Shanghai")
	require.Contains(t, string(out), "198.51.100.44")
	require.Contains(t, string(out), "America/Chicago")
	require.Contains(t, string(out), "keep me")
}

func TestSanitizeAgentRequestBodyAnthropicRewritesMatchedToolResultOnly(t *testing.T) {
	body := []byte(`{"model":"claude-test","system":"You are Claude Code","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tool_env","name":"Bash","input":{"command":"Get-TimeZone; curl https://ipinfo.io/json"}},{"type":"tool_use","id":"tool_file","name":"Bash","input":{"command":"cat README.md"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_env","content":"Asia/Shanghai 203.0.113.90"},{"type":"tool_result","tool_use_id":"tool_file","content":"ordinary file output"}]}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyAnthropicMessages, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "203.0.113.90")
	require.NotContains(t, string(out), "Asia/Shanghai")
	require.Contains(t, string(out), "198.51.100.44")
	require.Contains(t, string(out), "America/Chicago")
	require.Contains(t, string(out), "ordinary file output")
}

func TestSanitizeAgentRequestBodyChatCompletionsRewritesEnvironmentProbeOutput(t *testing.T) {
	body := []byte(`{"model":"grok-test","messages":[{"role":"assistant","tool_calls":[{"id":"call_env","type":"function","function":{"name":"exec_command","arguments":"{\"cmd\":\"timedatectl && curl https://api.ipify.org\"}"}}]},{"role":"tool","tool_call_id":"call_env","content":"Asia/Tokyo 203.0.113.91"}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIChatCompletions, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "203.0.113.91")
	require.NotContains(t, string(out), "Asia/Tokyo")
	require.Contains(t, string(out), "198.51.100.44")
	require.Contains(t, string(out), "America/Chicago")
}

func TestSanitizeAgentRequestBodyGeminiRewritesEnvironmentProbeOutput(t *testing.T) {
	body := []byte(`{"systemInstruction":{"parts":[{"text":"<environment_context><cwd>/Users/private/work</cwd><timezone>Asia/Tokyo</timezone><current_date>2026-09-17</current_date></environment_context>"}]},"contents":[{"role":"model","parts":[{"functionCall":{"id":"call_env","name":"run_command","args":{"command":"hostname; uname -a; curl https://ipapi.co/json"}}}]},{"role":"user","parts":[{"functionResponse":{"id":"call_env","name":"run_command","response":{"output":"private-host Darwin 203.0.113.92"}}}]}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyGeminiGenerateContent, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "/Users/private/work")
	require.NotContains(t, string(out), "private-host")
	require.NotContains(t, string(out), "203.0.113.92")
	require.NotContains(t, string(out), "Asia/Tokyo")
	require.Contains(t, string(out), "198.51.100.44")
	require.Contains(t, string(out), "America/Chicago")
}

func TestSanitizeAgentRequestBodyProbeWithoutVerifiedProxyDoesNotLeakLocalOutput(t *testing.T) {
	body := []byte(`{"input":[{"type":"function_call","call_id":"call_env","name":"shell","arguments":"{\"command\":\"date\"}"},{"type":"function_call_output","call_id":"call_env","output":"Fri Sep 18 21:00:00 CST 2026"}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, &Proxy{})
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "Fri Sep 18")
	require.Contains(t, string(out), "verified network egress profile unavailable")
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

func TestSanitizeAnthropicLocalContextTextLeavesMixedInstructionsUntouched(t *testing.T) {
	text := "Explain that <cwd>/example/path</cwd> is a sample tag, not runtime context."
	out, changed := sanitizeAnthropicLocalContextText(text, verifiedPrivacyTestProxy())
	require.False(t, changed)
	require.Equal(t, text, out)
}

func TestSanitizeAnthropicLocalContextTextRewritesEmbeddedEnvironmentBlock(t *testing.T) {
	text := "Keep this instruction. <environment_context><cwd>/private/repo</cwd><current_date>2026-09-17</current_date><timezone>Asia/Tokyo</timezone></environment_context> Keep this too."
	out, changed := sanitizeAnthropicLocalContextText(text, verifiedPrivacyTestProxy())
	require.True(t, changed)
	require.Contains(t, out, "Keep this instruction.")
	require.Contains(t, out, "Keep this too.")
	require.NotContains(t, out, "/private/repo")
	require.NotContains(t, out, "Asia/Tokyo")
	require.Contains(t, out, "America/Chicago")
}

func TestSanitizeAgentRequestBodyClaudePreservesSystemShapeAndIsIdempotent(t *testing.T) {
	body := []byte(`{"model":"claude-test","system":[{"type":"text","text":"You are Claude Code"},{"type":"text","text":"<cwd>/Users/private/repo</cwd><timezone>Europe/London</timezone>"}],"messages":[{"role":"user","content":"hello"}]}`)
	first, changed, err := sanitizeAgentRequestBody(body, agentPrivacyAnthropicMessages, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(first), "/Users/private/repo")
	require.NotContains(t, string(first), "Europe/London")

	second, changed, err := sanitizeAgentRequestBody(first, agentPrivacyAnthropicMessages, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, first, second)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(second, &payload))
	system, ok := payload["system"].([]any)
	require.True(t, ok)
	count := 0
	for _, item := range system {
		part, _ := item.(map[string]any)
		if strings.Contains(part["text"].(string), agentNetworkEgressMarker) {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func TestSanitizeAgentRequestBodyWithoutVerifiedProxyLeavesEnvironmentContextUnchanged(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/secret</cwd><timezone>UTC</timezone></environment_context>"}]}]}`)
	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, &Proxy{})
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, body, out)
}

func TestSanitizeAgentRequestBodyCodexUsesLastVerifiedProxyTimezoneWhenSnapshotIsStale(t *testing.T) {
	checked := time.Now().UTC().Add(-verifiedProxyExitProfileMaxAge - time.Minute)
	proxy := &Proxy{ExitIP: "198.51.100.44", ExitTimezone: "America/Chicago", ExitCheckedAt: &checked}
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/work</cwd><shell>bash</shell><timezone>Asia/Shanghai</timezone></environment_context>"}]}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, proxy)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "Asia/Shanghai")
	require.Contains(t, string(out), "<timezone>America/Chicago</timezone>")
}

func TestSanitizeAgentRequestBodyCodexDoesNotInventMissingLocationFields(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/work</cwd><shell>bash</shell><current_date>2026-09-17</current_date></environment_context>"}]}]}`)

	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, body, out)
}

func TestSanitizeCodexWebSocketFrameOnlyMutatesResponseCreate(t *testing.T) {
	responseCreate := []byte(`{"type":"response.create","model":"gpt-test","input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><cwd>/private/repo</cwd><timezone>Asia/Shanghai</timezone></environment_context>"}]}]}`)
	out, changed, err := sanitizeCodexWebSocketFrame(responseCreate, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.Contains(t, string(out), "/private/repo")
	require.NotContains(t, string(out), "Asia/Shanghai")
	require.Contains(t, string(out), "<timezone>America/Chicago</timezone>")
	require.NotContains(t, string(out), agentNetworkEgressMarker)

	sessionUpdate := []byte(`{"type":"session.update","session":{"instructions":"<cwd>/private/repo</cwd>"}}`)
	out, changed, err = sanitizeCodexWebSocketFrame(sessionUpdate, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, sessionUpdate, out)
}

func TestSanitizeCodexWebSocketFrameTreatsMissingTypeAsResponseCreate(t *testing.T) {
	body := []byte(`{"model":"gpt-test","input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context><timezone>Asia/Shanghai</timezone></environment_context>"}]}]}`)
	out, changed, err := sanitizeCodexWebSocketFrame(body, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(out), "Asia/Shanghai")
	require.Contains(t, string(out), "<timezone>America/Chicago</timezone>")
	require.NotContains(t, string(out), agentNetworkEgressMarker)
}

func TestSanitizeNativeClaudeCodeHeadersRemovesMachineSignals(t *testing.T) {
	header := http.Header{
		"User-Agent":                  []string{"claude-cli/9.9.9 (external, cli)"},
		"X-Stainless-Package-Version": []string{"9.9.9"},
		"X-Stainless-OS":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
		"X-Stainless-Runtime":         []string{"node"},
		"X-Stainless-Runtime-Version": []string{"v99.0.0"},
		"Anthropic-Beta":              []string{"example-beta"},
		"X-Claude-Code-Session-Id":    []string{"session-123"},
	}

	sanitizeNativeClaudeCodeHeaders(header)

	require.Equal(t, defaultFingerprint.UserAgent, getHeaderRaw(header, "User-Agent"))
	require.Equal(t, defaultFingerprint.StainlessPackageVersion, getHeaderRaw(header, "X-Stainless-Package-Version"))
	require.Empty(t, getHeaderRaw(header, "X-Stainless-OS"))
	require.Empty(t, getHeaderRaw(header, "X-Stainless-Arch"))
	require.Empty(t, getHeaderRaw(header, "X-Stainless-Runtime"))
	require.Empty(t, getHeaderRaw(header, "X-Stainless-Runtime-Version"))
	require.Equal(t, "example-beta", getHeaderRaw(header, "Anthropic-Beta"))
	require.Equal(t, "session-123", getHeaderRaw(header, "X-Claude-Code-Session-Id"))
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

func TestSanitizeAgentRequestBodyStripsLegacyCodexEgressMarker(t *testing.T) {
	body := []byte(`{"instructions":"client instructions\n<network_egress_context><timezone>Asia/Shanghai</timezone><exit_ip>10.0.0.1</exit_ip></network_egress_context>","input":[]}`)
	out, changed, err := sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, verifiedPrivacyTestProxy())
	require.NoError(t, err)
	require.True(t, changed)
	text := string(out)
	require.Contains(t, text, "client instructions")
	require.NotContains(t, text, "Asia/Shanghai")
	require.NotContains(t, text, "10.0.0.1")
	require.NotContains(t, text, agentNetworkEgressMarker)
	require.NotContains(t, text, "198.51.100.44")
}

func TestMergeInstructionsWithNetworkEgressKeepsCodexDefault(t *testing.T) {
	block := buildNetworkEgressContext(verifiedPrivacyTestProxy())
	require.NotEmpty(t, block)
	merged := mergeInstructionsWithNetworkEgress(block, "default codex instructions")
	require.True(t, strings.HasPrefix(merged, "default codex instructions"))
	require.Contains(t, merged, block)

	existing := "client instructions\n\n" + block
	require.Equal(t, existing, mergeInstructionsWithNetworkEgress(existing, "default codex instructions"))
}
