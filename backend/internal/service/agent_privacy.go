package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/openai"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
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

var agentTimezonePattern = regexp.MustCompile(`(?is)<timezone>.*?</timezone>`)
var agentCurrentDatePattern = regexp.MustCompile(`(?is)<current_date>.*?</current_date>`)
var agentEnvironmentContextPattern = regexp.MustCompile(`(?is)<environment_context>.*?</environment_context>`)

var agentEnvironmentProbePattern = regexp.MustCompile(`(?i)(^|[\"':=,\s;&|()])(date|timedatectl|hostname|uname|systeminfo|sw_vers|get-timezone|get-date|tzutil)([\s\"';&|()+,=-]|$)|/etc/os-release|/proc/version|time\.tzname|astimezone\(|tzlocal|ipwho\.is|ipinfo\.io|ipapi\.co|ip-api\.com|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com|api\.myip\.com`)

var agentLocalContextNonSensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<current_date>.*?</current_date>`),
	regexp.MustCompile(`(?is)</?environment_context>`),
}

func sanitizeAgentRequestBody(body []byte, protocol agentPrivacyProtocol, proxy *Proxy) ([]byte, bool, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false, fmt.Errorf("decode agent request for privacy filtering: %w", err)
	}

	var changed bool
	switch protocol {
	case agentPrivacyOpenAIResponses:
		changed = sanitizeOpenAIResponsesLocalContext(payload, proxy)
		changed = sanitizeOpenAIResponsesToolResults(payload, proxy) || changed
		changed = stripAgentNetworkEgressContext(payload, protocol) || changed
	case agentPrivacyAnthropicMessages:
		changed = sanitizeAnthropicSystemLocalContext(payload, proxy)
		changed = sanitizeAnthropicToolResults(payload, proxy) || changed
		if block := buildNetworkEgressContext(proxy); block != "" {
			changed = appendAnthropicSystemBlock(payload, block) || changed
		} else {
			changed = stripAgentNetworkEgressContext(payload, protocol) || changed
		}
	case agentPrivacyOpenAIChatCompletions:
		changed = sanitizeOpenAIChatCompletionsLocalContext(payload, proxy)
		changed = sanitizeOpenAIChatCompletionsToolResults(payload, proxy) || changed
	case agentPrivacyGeminiGenerateContent:
		changed = sanitizeGeminiLocalContext(payload, proxy)
		changed = sanitizeGeminiToolResults(payload, proxy) || changed
	default:
		return nil, false, fmt.Errorf("unknown agent privacy protocol: %d", protocol)
	}
	if !changed {
		return body, false, nil
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, false, fmt.Errorf("encode agent request after privacy filtering: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true, nil
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

func sanitizeNativeClaudeCodeHeaders(header http.Header) {
	if header == nil {
		return
	}
	if userAgent := strings.TrimSpace(defaultFingerprint.UserAgent); userAgent != "" {
		setHeaderRaw(header, "User-Agent", userAgent)
	}
	if packageVersion := strings.TrimSpace(defaultFingerprint.StainlessPackageVersion); packageVersion != "" {
		setHeaderRaw(header, "X-Stainless-Package-Version", packageVersion)
	}
	for _, key := range []string{
		"X-Stainless-OS",
		"X-Stainless-Arch",
		"X-Stainless-Runtime",
		"X-Stainless-Runtime-Version",
	} {
		deleteHeaderAllForms(header, key)
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

func sanitizeOpenAIResponsesLocalContext(payload map[string]any, proxy *Proxy) bool {
	// Codex should never fall back to the client machine timezone just because
	// the last verified egress snapshot aged past the scheduling freshness
	// window. A later probe can replace this snapshot when the proxy changes.
	if proxy == nil || !proxy.HasVerifiedExitProfile() {
		return false
	}
	timezone := strings.TrimSpace(proxy.ExitTimezone)
	if timezone == "" {
		return false
	}
	currentDate := agentCurrentDateForProxy(proxy, time.Now())
	input, ok := payload["input"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, item := range input {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if sanitizeCodexInputTextPart(entry, timezone, currentDate) {
			changed = true
		}
		content, ok := entry["content"].([]any)
		if !ok {
			continue
		}
		for _, rawPart := range content {
			part, ok := rawPart.(map[string]any)
			if ok && sanitizeCodexInputTextPart(part, timezone, currentDate) {
				changed = true
			}
		}
	}
	return changed
}

func sanitizeCodexInputTextPart(part map[string]any, timezone, currentDate string) bool {
	if part == nil || strings.TrimSpace(strings.ToLower(fmt.Sprint(part["type"]))) != "input_text" {
		return false
	}
	text, ok := part["text"].(string)
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(text)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "<environment_context>") || !strings.HasSuffix(lower, "</environment_context>") {
		return false
	}
	if !agentTimezonePattern.MatchString(text) {
		return false
	}
	next := agentTimezonePattern.ReplaceAllStringFunc(text, func(match string) string {
		openEnd := strings.IndexByte(match, '>')
		closeStart := strings.LastIndex(match, "</")
		if openEnd < 0 || closeStart <= openEnd {
			return match
		}
		return match[:openEnd+1] + html.EscapeString(timezone) + match[closeStart:]
	})
	if currentDate != "" {
		next = agentCurrentDatePattern.ReplaceAllStringFunc(next, func(match string) string {
			openEnd := strings.IndexByte(match, '>')
			closeStart := strings.LastIndex(match, "</")
			if openEnd < 0 || closeStart <= openEnd {
				return match
			}
			return match[:openEnd+1] + html.EscapeString(currentDate) + match[closeStart:]
		})
	}
	if next == text {
		return false
	}
	part["text"] = next
	return true
}

func sanitizeAnthropicSystemLocalContext(payload map[string]any, proxy *Proxy) bool {
	switch system := payload["system"].(type) {
	case string:
		next, changed := sanitizeAnthropicLocalContextText(system, proxy)
		if changed {
			payload["system"] = next
		}
		return changed
	case []any:
		changed := false
		for _, item := range system {
			part, ok := item.(map[string]any)
			if !ok {
				continue
			}
			text, ok := part["text"].(string)
			if !ok {
				continue
			}
			next, itemChanged := sanitizeAnthropicLocalContextText(text, proxy)
			if itemChanged {
				part["text"] = next
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func sanitizeAnthropicLocalContextText(text string, proxy *Proxy) (string, bool) {
	sanitizeBlock := func(block string) string {
		next := block
		next = agentLocalContextPatterns[0].ReplaceAllString(next, "<cwd>[redacted by Berth privacy policy]</cwd>")
		next = agentLocalContextPatterns[1].ReplaceAllString(next, "<shell>[redacted by Berth privacy policy]</shell>")

		timezone := "[redacted by Berth privacy policy]"
		if proxy != nil && proxy.HasVerifiedExitProfile() && strings.TrimSpace(proxy.ExitTimezone) != "" {
			timezone = strings.TrimSpace(proxy.ExitTimezone)
		}
		next = replaceAgentTaggedValue(next, agentTimezonePattern, timezone)
		if currentDate := agentCurrentDateForProxy(proxy, time.Now()); currentDate != "" {
			next = replaceAgentTaggedValue(next, agentCurrentDatePattern, currentDate)
		}
		return next
	}

	if agentEnvironmentContextPattern.MatchString(text) {
		next := agentEnvironmentContextPattern.ReplaceAllStringFunc(text, sanitizeBlock)
		return next, next != text
	}
	if _, localContextOnly := redactAnthropicLocalContextBlock(text); !localContextOnly {
		return text, false
	}
	next := sanitizeBlock(text)
	return next, next != text
}

func replaceAgentTaggedValue(text string, pattern *regexp.Regexp, value string) string {
	return pattern.ReplaceAllStringFunc(text, func(match string) string {
		openEnd := strings.IndexByte(match, '>')
		closeStart := strings.LastIndex(match, "</")
		if openEnd < 0 || closeStart <= openEnd {
			return match
		}
		return match[:openEnd+1] + html.EscapeString(value) + match[closeStart:]
	})
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
		return now.In(time.FixedZone("Berth egress", *proxy.ExitUTCOffsetSeconds)), true
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
		_, changed := redactAnthropicLocalContextBlock(text)
		return changed
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

func buildAgentEnvironmentObservation(proxy *Proxy) string {
	if proxy == nil || !proxy.HasVerifiedExitProfile() {
		return "<berth_environment_observation>local environment output redacted; verified network egress profile unavailable</berth_environment_observation>"
	}

	var b strings.Builder
	_, _ = b.WriteString("<berth_environment_observation>\n")
	if localized, ok := agentTimeForProxy(proxy, time.Now()); ok {
		fmt.Fprintf(&b, "<current_date>%s</current_date>\n", localized.Format("2006-01-02"))
		fmt.Fprintf(&b, "<current_time>%s</current_time>\n", localized.Format(time.RFC3339))
	}
	write := func(name, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			fmt.Fprintf(&b, "<%s>%s</%s>\n", name, html.EscapeString(value), name)
		}
	}
	write("timezone", proxy.ExitTimezone)
	write("exit_ip", proxy.ExitIP)
	write("country", proxy.ExitCountry)
	write("country_code", proxy.ExitCountryCode)
	write("region", proxy.ExitRegion)
	write("city", proxy.ExitCity)
	write("asn", proxy.ExitASN)
	write("isp", proxy.ExitISP)
	if proxy.ExitCheckedAt != nil {
		write("checked_at", proxy.ExitCheckedAt.UTC().Format(time.RFC3339))
	}
	_, _ = b.WriteString("<local_hostname>[redacted by Berth privacy policy]</local_hostname>\n")
	_, _ = b.WriteString("<local_os>[redacted by Berth privacy policy]</local_os>\n")
	_, _ = b.WriteString("</berth_environment_observation>")
	return b.String()
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

func agentCallIDs(item map[string]any) []string {
	seen := make(map[string]struct{}, 3)
	ids := make([]string, 0, 3)
	for _, key := range []string{"call_id", "tool_call_id", "tool_use_id", "id"} {
		id := agentMapString(item[key])
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

func agentToolNameAndInput(item map[string]any) (string, any) {
	name := agentMapString(item["name"])
	if function, ok := item["function"].(map[string]any); ok {
		if name == "" {
			name = agentMapString(function["name"])
		}
		if arguments, ok := function["arguments"]; ok {
			return name, arguments
		}
	}
	for _, key := range []string{"arguments", "input", "action", "command", "args"} {
		if value, ok := item[key]; ok {
			return name, value
		}
	}
	return name, item
}

func isOpenAIResponsesCallType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "function_call", "local_shell_call", "custom_tool_call", "mcp_tool_call", "tool_call":
		return true
	default:
		return false
	}
}

func isOpenAIResponsesOutputType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "function_call_output", "local_shell_call_output", "custom_tool_call_output", "mcp_tool_call_output", "tool_call_output":
		return true
	default:
		return false
	}
}

func sanitizeOpenAIResponsesToolResults(payload map[string]any, proxy *Proxy) bool {
	input, ok := payload["input"].([]any)
	if !ok {
		return false
	}
	probeCalls := make(map[string]struct{})
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || !isOpenAIResponsesCallType(agentMapString(item["type"])) {
			continue
		}
		name, args := agentToolNameAndInput(item)
		if !detectAgentEnvironmentProbe(name, args) {
			continue
		}
		for _, id := range agentCallIDs(item) {
			probeCalls[id] = struct{}{}
		}
	}
	if len(probeCalls) == 0 {
		return false
	}
	replacement := buildAgentEnvironmentObservation(proxy)
	changed := false
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || !isOpenAIResponsesOutputType(agentMapString(item["type"])) {
			continue
		}
		matched := false
		for _, id := range agentCallIDs(item) {
			if _, ok := probeCalls[id]; ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if _, ok := item["output"]; ok {
			item["output"] = replacement
		} else if _, ok := item["content"]; ok {
			item["content"] = replacement
		} else {
			item["output"] = replacement
		}
		delete(item, "images")
		changed = true
	}
	return changed
}

func sanitizeAnthropicToolResults(payload map[string]any, proxy *Proxy) bool {
	messages, ok := payload["messages"].([]any)
	if !ok {
		return false
	}
	probeCalls := make(map[string]struct{})
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
				for _, id := range agentCallIDs(part) {
					probeCalls[id] = struct{}{}
				}
			}
		}
	}
	if len(probeCalls) == 0 {
		return false
	}
	replacement := buildAgentEnvironmentObservation(proxy)
	changed := false
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
			if !ok || strings.ToLower(agentMapString(part["type"])) != "tool_result" {
				continue
			}
			matched := false
			for _, id := range agentCallIDs(part) {
				if _, ok := probeCalls[id]; ok {
					matched = true
					break
				}
			}
			if matched {
				part["content"] = replacement
				part["is_error"] = false
				changed = true
			}
		}
	}
	return changed
}

func sanitizeOpenAIChatCompletionsLocalContext(payload map[string]any, proxy *Proxy) bool {
	changed := false
	if instructions, ok := payload["instructions"].(string); ok {
		if next, itemChanged := sanitizeAnthropicLocalContextText(instructions, proxy); itemChanged {
			payload["instructions"] = next
			changed = true
		}
	}
	messages, ok := payload["messages"].([]any)
	if !ok {
		return changed
	}
	for _, raw := range messages {
		message, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role := strings.ToLower(agentMapString(message["role"]))
		if role != "system" && role != "developer" {
			continue
		}
		if content, ok := message["content"].(string); ok {
			if next, itemChanged := sanitizeAnthropicLocalContextText(content, proxy); itemChanged {
				message["content"] = next
				changed = true
			}
		}
	}
	return changed
}

func sanitizeOpenAIChatCompletionsToolResults(payload map[string]any, proxy *Proxy) bool {
	messages, ok := payload["messages"].([]any)
	if !ok {
		return false
	}
	probeCalls := make(map[string]struct{})
	for _, raw := range messages {
		message, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		toolCalls, ok := message["tool_calls"].([]any)
		if !ok {
			continue
		}
		for _, rawCall := range toolCalls {
			call, ok := rawCall.(map[string]any)
			if !ok {
				continue
			}
			name, args := agentToolNameAndInput(call)
			if detectAgentEnvironmentProbe(name, args) {
				for _, id := range agentCallIDs(call) {
					probeCalls[id] = struct{}{}
				}
			}
		}
	}
	if len(probeCalls) == 0 {
		return false
	}
	replacement := buildAgentEnvironmentObservation(proxy)
	changed := false
	for _, raw := range messages {
		message, ok := raw.(map[string]any)
		if !ok || strings.ToLower(agentMapString(message["role"])) != "tool" {
			continue
		}
		for _, id := range agentCallIDs(message) {
			if _, ok := probeCalls[id]; ok {
				message["content"] = replacement
				changed = true
				break
			}
		}
	}
	return changed
}

func sanitizeGeminiLocalContext(payload map[string]any, proxy *Proxy) bool {
	changed := sanitizeGeminiLocalContextRoot(payload, proxy)
	if request, ok := payload["request"].(map[string]any); ok {
		changed = sanitizeGeminiLocalContextRoot(request, proxy) || changed
	}
	return changed
}

func sanitizeGeminiLocalContextRoot(payload map[string]any, proxy *Proxy) bool {
	system, ok := payload["systemInstruction"].(map[string]any)
	if !ok {
		return false
	}
	parts, ok := system["parts"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, raw := range parts {
		part, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		text, ok := part["text"].(string)
		if !ok {
			continue
		}
		if next, itemChanged := sanitizeAnthropicLocalContextText(text, proxy); itemChanged {
			part["text"] = next
			changed = true
		}
	}
	return changed
}

func sanitizeGeminiToolResults(payload map[string]any, proxy *Proxy) bool {
	changed := sanitizeGeminiToolResultsRoot(payload, proxy)
	if request, ok := payload["request"].(map[string]any); ok {
		changed = sanitizeGeminiToolResultsRoot(request, proxy) || changed
	}
	return changed
}

func sanitizeGeminiToolResultsRoot(payload map[string]any, proxy *Proxy) bool {
	contents, ok := payload["contents"].([]any)
	if !ok {
		return false
	}
	probeKeys := make(map[string]struct{})
	for _, rawContent := range contents {
		content, ok := rawContent.(map[string]any)
		if !ok {
			continue
		}
		parts, ok := content["parts"].([]any)
		if !ok {
			continue
		}
		for _, rawPart := range parts {
			part, ok := rawPart.(map[string]any)
			if !ok {
				continue
			}
			call, ok := part["functionCall"].(map[string]any)
			if !ok {
				continue
			}
			name := agentMapString(call["name"])
			if !detectAgentEnvironmentProbe(name, call["args"]) {
				continue
			}
			key := agentMapString(call["id"])
			if key == "" {
				key = "name:" + name
			}
			if key != "name:" {
				probeKeys[key] = struct{}{}
			}
		}
	}
	if len(probeKeys) == 0 {
		return false
	}
	replacement := buildAgentEnvironmentObservation(proxy)
	changed := false
	for _, rawContent := range contents {
		content, ok := rawContent.(map[string]any)
		if !ok {
			continue
		}
		parts, ok := content["parts"].([]any)
		if !ok {
			continue
		}
		for _, rawPart := range parts {
			part, ok := rawPart.(map[string]any)
			if !ok {
				continue
			}
			response, ok := part["functionResponse"].(map[string]any)
			if !ok {
				continue
			}
			key := agentMapString(response["id"])
			if key == "" {
				key = "name:" + agentMapString(response["name"])
			}
			if _, ok := probeKeys[key]; !ok {
				continue
			}
			response["response"] = map[string]any{"output": replacement}
			changed = true
		}
	}
	return changed
}

func redactAnthropicLocalContextBlock(text string) (string, bool) {
	residue := text
	foundLocalContext := false
	for _, pattern := range agentLocalContextPatterns {
		if pattern.MatchString(residue) {
			foundLocalContext = true
		}
		residue = pattern.ReplaceAllString(residue, "")
	}
	if !foundLocalContext {
		return text, false
	}
	for _, pattern := range agentLocalContextNonSensitivePatterns {
		residue = pattern.ReplaceAllString(residue, "")
	}
	if strings.TrimSpace(residue) != "" {
		return text, false
	}
	next := redactAgentLocalContext(text)
	return next, next != text
}

func redactAgentLocalContext(text string) string {
	out := text
	replacements := []string{
		"<cwd>[redacted by Berth privacy policy]</cwd>",
		"<shell>[redacted by Berth privacy policy]</shell>",
		"<timezone>[redacted by Berth privacy policy]</timezone>",
	}
	for i, pattern := range agentLocalContextPatterns {
		out = pattern.ReplaceAllString(out, replacements[i])
	}
	return out
}

func buildNetworkEgressContext(proxy *Proxy) string {
	if proxy == nil || !proxy.HasFreshVerifiedExitProfile(time.Now()) {
		return ""
	}
	var b strings.Builder
	_, _ = b.WriteString(agentNetworkEgressMarker)
	_, _ = b.WriteString("\nThis is Berth's recently verified network egress snapshot for the upstream account. It is not the user's device location.\n")
	writeEgressField := func(name, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		fmt.Fprintf(&b, "<%s>%s</%s>\n", name, html.EscapeString(value), name)
	}
	writeEgressField("exit_ip", proxy.ExitIP)
	writeEgressField("country", proxy.ExitCountry)
	writeEgressField("country_code", proxy.ExitCountryCode)
	writeEgressField("region", proxy.ExitRegion)
	writeEgressField("city", proxy.ExitCity)
	writeEgressField("exit_timezone", proxy.ExitTimezone)
	if proxy.ExitUTCOffsetSeconds != nil {
		writeEgressField("utc_offset_seconds", fmt.Sprintf("%d", *proxy.ExitUTCOffsetSeconds))
	}
	writeEgressField("asn", proxy.ExitASN)
	writeEgressField("isp", proxy.ExitISP)
	writeEgressField("checked_at", proxy.ExitCheckedAt.UTC().Format(time.RFC3339))
	_, _ = b.WriteString("</network_egress_context>")
	return b.String()
}

func stripAgentNetworkEgressContext(payload map[string]any, protocol agentPrivacyProtocol) bool {
	switch protocol {
	case agentPrivacyOpenAIResponses:
		instructions, ok := payload["instructions"].(string)
		if !ok {
			return false
		}
		if marker := strings.Index(instructions, agentNetworkEgressMarker); marker >= 0 {
			payload["instructions"] = strings.TrimSpace(instructions[:marker])
			return true
		}
	case agentPrivacyAnthropicMessages:
		switch system := payload["system"].(type) {
		case string:
			if marker := strings.Index(system, agentNetworkEgressMarker); marker >= 0 {
				payload["system"] = strings.TrimSpace(system[:marker])
				return true
			}
		case []any:
			changed := false
			next := make([]any, 0, len(system))
			for _, item := range system {
				part, ok := item.(map[string]any)
				if !ok {
					next = append(next, item)
					continue
				}
				text, ok := part["text"].(string)
				if !ok {
					next = append(next, item)
					continue
				}
				marker := strings.Index(text, agentNetworkEgressMarker)
				if marker < 0 {
					next = append(next, item)
					continue
				}
				changed = true
				prefix := strings.TrimSpace(text[:marker])
				if prefix == "" {
					continue
				}
				part["text"] = prefix
				next = append(next, item)
			}
			if changed {
				payload["system"] = next
			}
			return changed
		}
	}
	return false
}

func mergeInstructionsWithNetworkEgress(instructions, fallback string) string {
	instructions = strings.TrimSpace(instructions)
	fallback = strings.TrimSpace(fallback)
	marker := strings.Index(instructions, agentNetworkEgressMarker)
	if marker < 0 {
		if instructions != "" {
			return instructions
		}
		return fallback
	}
	egress := strings.TrimSpace(instructions[marker:])
	prefix := strings.TrimSpace(instructions[:marker])
	if prefix != "" {
		return prefix + "\n\n" + egress
	}
	if fallback == "" {
		return egress
	}
	return fallback + "\n\n" + egress
}

func appendAnthropicSystemBlock(payload map[string]any, block string) bool {
	if block == "" {
		return false
	}
	switch system := payload["system"].(type) {
	case string:
		if strings.Contains(system, block) {
			return false
		}
		if marker := strings.Index(system, agentNetworkEgressMarker); marker >= 0 {
			system = strings.TrimSpace(system[:marker])
		}
		if strings.TrimSpace(system) == "" {
			payload["system"] = block
		} else {
			payload["system"] = strings.TrimSpace(system) + "\n\n" + block
		}
		return true
	case []any:
		for _, item := range system {
			if part, ok := item.(map[string]any); ok {
				if text, _ := part["text"].(string); strings.Contains(text, block) {
					return false
				}
			}
		}
		for _, item := range system {
			part, ok := item.(map[string]any)
			if !ok {
				continue
			}
			text, _ := part["text"].(string)
			if marker := strings.Index(text, agentNetworkEgressMarker); marker >= 0 {
				part["text"] = strings.TrimSpace(text[:marker])
			}
		}
		payload["system"] = append(system, map[string]any{"type": "text", "text": block})
		return true
	case nil:
		payload["system"] = []any{map[string]any{"type": "text", "text": block}}
		return true
	default:
		return false
	}
}
