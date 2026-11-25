package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/pkg/openai"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type agentPrivacyProtocol uint8

const (
	agentPrivacyOpenAIResponses agentPrivacyProtocol = iota + 1
	agentPrivacyAnthropicMessages
	agentPrivacyOpenAIChatCompletions
	agentPrivacyGeminiGenerateContent
)

const agentNetworkEgressMarker = "<network_egress_context>"
const agentPrivacyNativeClaudeCodeContextKey = "agent_privacy_native_claude_code"

var agentLocalContextPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<cwd>.*?</cwd>`),
	regexp.MustCompile(`(?is)<shell>.*?</shell>`),
	regexp.MustCompile(`(?is)<timezone>.*?</timezone>`),
}

var agentEnvironmentContextPattern = regexp.MustCompile(`(?is)<environment_context>.*?</environment_context>`)

var agentEnvironmentProbePattern = regexp.MustCompile(`(?i)(^|[\"':=,\s;&|()])(date|timedatectl|hostname|uname|systeminfo|sw_vers|get-timezone|get-date|tzutil)([\s\"';&|()+,=-]|$)|/etc/os-release|/proc/version|time\.tzname|astimezone\(|tzlocal|ipwho\.is|ipinfo\.io|ipapi\.co|ip-api\.com|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com|api\.myip\.com`)

var agentLocalContextNonSensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<current_date>.*?</current_date>`),
	regexp.MustCompile(`(?is)</?environment_context>`),
}

// sanitizeAgentRequestBody preserves prompt-cache byte stability across all 4
// providers (Bug B1/B2/B3 fix):
//   - NEVER injects <network_egress_context> or <checked_at> into system prompts.
//   - NEVER injects time.Now() / <current_time> / <berth_environment_observation>
//     or [redacted by Berth privacy policy] into tool outputs or prompts.
//   - NEVER round-trips request bodies through map[string]any (preserving exact
//     JSON key order and raw bytes verbatim for Anthropic & OpenAI prompt caching).
//
// Only legacy client-echoed <network_egress_context> blocks are surgically stripped
// via byte-preserving sjson edits; all normal requests return (body, false, nil)
// byte-for-byte untouched.
func sanitizeAgentRequestBody(body []byte, protocol agentPrivacyProtocol, _ *Proxy) ([]byte, bool, error) {
	switch protocol {
	case agentPrivacyOpenAIResponses, agentPrivacyAnthropicMessages, agentPrivacyOpenAIChatCompletions, agentPrivacyGeminiGenerateContent:
	default:
		return nil, false, fmt.Errorf("unknown agent privacy protocol: %d", protocol)
	}
	if len(body) == 0 || !bytes.Contains(body, []byte(agentNetworkEgressMarker)) {
		return body, false, nil
	}
	return stripLegacyNetworkEgressMarkerSurgical(body, protocol)
}

func stripLegacyNetworkEgressMarkerSurgical(body []byte, protocol agentPrivacyProtocol) ([]byte, bool, error) {
	out := body
	changed := false

	switch protocol {
	case agentPrivacyOpenAIResponses:
		inst := gjson.GetBytes(out, "instructions")
		if inst.Exists() && inst.Type == gjson.String {
			if marker := strings.Index(inst.String(), agentNetworkEgressMarker); marker >= 0 {
				trimmed := strings.TrimSpace(inst.String()[:marker])
				next, err := sjson.SetBytes(out, "instructions", trimmed)
				if err != nil {
					return nil, false, fmt.Errorf("strip legacy network egress from instructions: %w", err)
				}
				out = next
				changed = true
			}
		}

	case agentPrivacyAnthropicMessages:
		sys := gjson.GetBytes(out, "system")
		if sys.Type == gjson.String {
			if marker := strings.Index(sys.String(), agentNetworkEgressMarker); marker >= 0 {
				trimmed := strings.TrimSpace(sys.String()[:marker])
				next, err := sjson.SetBytes(out, "system", trimmed)
				if err != nil {
					return nil, false, fmt.Errorf("strip legacy network egress from system: %w", err)
				}
				out = next
				changed = true
			}
		} else if sys.IsArray() {
			var kept [][]byte
			sys.ForEach(func(_, item gjson.Result) bool {
				textRes := item.Get("text")
				if textRes.Exists() && textRes.Type == gjson.String {
					if marker := strings.Index(textRes.String(), agentNetworkEgressMarker); marker >= 0 {
						changed = true
						prefix := strings.TrimSpace(textRes.String()[:marker])
						if prefix == "" {
							return true
						}
						patched, err := sjson.SetBytes([]byte(item.Raw), "text", prefix)
						if err == nil {
							kept = append(kept, patched)
							return true
						}
					}
				}
				kept = append(kept, []byte(item.Raw))
				return true
			})
			if changed {
				next, err := sjson.SetRawBytes(out, "system", buildJSONArrayRaw(kept))
				if err != nil {
					return nil, false, fmt.Errorf("strip legacy network egress from system array: %w", err)
				}
				out = next
			}
		}
	}

	if !changed {
		return body, false, nil
	}
	return out, true, nil
}

func sanitizeCodexWebSocketFrame(body []byte, proxy *Proxy) ([]byte, bool, error) {
	eventType := strings.TrimSpace(gjson.GetBytes(body, "type").String())
	if eventType != "" && eventType != "response.create" {
		return body, false, nil
	}
	return sanitizeAgentRequestBody(body, agentPrivacyOpenAIResponses, proxy)
}

func markNativeClaudeCodePrivacyRequest(c *gin.Context) {
	if c != nil {
		c.Set(agentPrivacyNativeClaudeCodeContextKey, true)
	}
}

func isNativeClaudeCodePrivacyRequest(c *gin.Context) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(agentPrivacyNativeClaudeCodeContextKey)
	if !ok {
		return false
	}
	enabled, _ := value.(bool)
	return enabled
}

// sanitizeNativeClaudeCodeHeaders aligns User-Agent and X-Stainless-Package-Version
// while preserving X-Stainless-OS, X-Stainless-Arch, X-Stainless-Runtime, and
// X-Stainless-Runtime-Version (stamped by IdentityService / Account Cage).
func sanitizeNativeClaudeCodeHeaders(header http.Header) {
	if header == nil {
		return
	}
	fingerprint := defaultFingerprint()
	if userAgent := strings.TrimSpace(fingerprint.UserAgent); userAgent != "" {
		setHeaderRaw(header, "User-Agent", userAgent)
	}
	if packageVersion := strings.TrimSpace(fingerprint.StainlessPackageVersion); packageVersion != "" {
		setHeaderRaw(header, "X-Stainless-Package-Version", packageVersion)
	}
}

func sanitizeNativeCodexHeaders(c *gin.Context, header http.Header) {
	if c == nil || header == nil {
		return
	}
	clientUserAgent := strings.TrimSpace(c.GetHeader("User-Agent"))
	if !openai.IsCodexOfficialClientByHeadersStrict(clientUserAgent, c.GetHeader("originator")) {
		return
	}

	// Only replace client-derived identity. Explicit gateway/account identity is
	// an administrator choice and must remain authoritative.
	outboundUserAgent := strings.TrimSpace(getHeaderRaw(header, "User-Agent"))
	if outboundUserAgent != "" && outboundUserAgent != clientUserAgent {
		return
	}

	canonicalUserAgent := strings.TrimSpace(CodexCanonicalUserAgent())
	if canonicalUserAgent == "" {
		return
	}
	setHeaderRaw(header, "User-Agent", canonicalUserAgent)
	if getHeaderRaw(header, "originator") != "" {
		if originator, _, ok := openai.PairCodexClientIdentity(canonicalUserAgent); ok {
			setHeaderRaw(header, "originator", originator)
		}
	}
	if getHeaderRaw(header, "version") != "" {
		setHeaderRaw(header, "version", CodexCanonicalClientVersion())
	}
}

func agentCurrentDateForProxy(proxy *Proxy, now time.Time) string {
	localized, ok := agentTimeForProxy(proxy, now)
	if !ok {
		return ""
	}
	return localized.Format("2006-01-02")
}

func agentTimeForProxy(proxy *Proxy, now time.Time) (time.Time, bool) {
	if proxy == nil || !proxy.HasVerifiedExitProfile() || now.IsZero() {
		return time.Time{}, false
	}
	timezone := strings.TrimSpace(proxy.ExitTimezone)
	if timezone != "" {
		if location, err := time.LoadLocation(timezone); err == nil {
			return now.In(location), true
		}
	}
	if proxy.ExitUTCOffsetSeconds != nil {
		return now.In(time.FixedZone("UTC", *proxy.ExitUTCOffsetSeconds)), true
	}
	return time.Time{}, false
}

func agentPrivacyBodyHasSignals(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	normalized := strings.NewReplacer(
		`\u003c`, `<`,
		`\u003e`, `>`,
		`\u0026`, `&`,
		`\"`, `"`,
	).Replace(lower)
	for _, marker := range []string{
		"<environment_context>", "<timezone>", "<cwd>", "<shell>",
		agentNetworkEgressMarker,
	} {
		if strings.Contains(normalized, strings.ToLower(marker)) {
			return true
		}
	}
	toolStructure := false
	for _, marker := range []string{
		`"tool_use"`, `"tool_calls"`, `"function_call"`, `"functioncall"`, `"local_shell_call"`,
	} {
		if strings.Contains(normalized, marker) {
			toolStructure = true
			break
		}
	}
	if !toolStructure {
		return false
	}
	return agentEnvironmentProbePattern.MatchString(normalized)
}

func agentPrivacyAnthropicBodyHasSignals(body []byte) bool {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	hasLocalContext := func(text string) bool {
		if agentEnvironmentContextPattern.MatchString(text) {
			return true
		}
		return hasOnlyLocalContextTags(text)
	}
	switch system := payload["system"].(type) {
	case string:
		if hasLocalContext(system) {
			return true
		}
	case []any:
		for _, raw := range system {
			part, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := part["text"].(string); ok && hasLocalContext(text) {
				return true
			}
		}
	}
	messages, ok := payload["messages"].([]any)
	if !ok {
		return false
	}
	for _, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			continue
		}
		content, ok := message["content"].([]any)
		if !ok {
			continue
		}
		for _, rawPart := range content {
			part, ok := rawPart.(map[string]any)
			if !ok || strings.ToLower(agentMapString(part["type"])) != "tool_use" {
				continue
			}
			if detectAgentEnvironmentProbe(agentMapString(part["name"]), part["input"]) {
				return true
			}
		}
	}
	return false
}

func hasOnlyLocalContextTags(text string) bool {
	residue := text
	foundLocalContext := false
	for _, pattern := range agentLocalContextPatterns {
		if pattern.MatchString(residue) {
			foundLocalContext = true
		}
		residue = pattern.ReplaceAllString(residue, "")
	}
	if !foundLocalContext {
		return false
	}
	for _, pattern := range agentLocalContextNonSensitivePatterns {
		residue = pattern.ReplaceAllString(residue, "")
	}
	return strings.TrimSpace(residue) == ""
}

func detectAgentEnvironmentProbe(name string, input any) bool {
	var raw string
	switch value := input.(type) {
	case string:
		raw = value
	case []byte:
		raw = string(value)
	default:
		if encoded, err := json.Marshal(input); err == nil {
			raw = string(encoded)
		} else {
			raw = fmt.Sprint(input)
		}
	}
	return agentEnvironmentProbePattern.MatchString(strings.TrimSpace(name) + " " + raw)
}

func agentMapString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

// buildNetworkEgressContext intentionally returns "" (Bug B1 fix).
// Injecting dynamic <network_egress_context><checked_at> blocks into system prompts
// invalidates Anthropic/OpenAI prompt caches on every 15-minute proxy probe refresh
// and exposes Berth-identifying text to upstream providers.
func buildNetworkEgressContext(_ *Proxy) string {
	return ""
}

func mergeInstructionsWithNetworkEgress(instructions, fallback string) string {
	instructions = strings.TrimSpace(instructions)
	fallback = strings.TrimSpace(fallback)
	if marker := strings.Index(instructions, agentNetworkEgressMarker); marker >= 0 {
		instructions = strings.TrimSpace(instructions[:marker])
	}
	if instructions != "" {
		return instructions
	}
	return fallback
}
