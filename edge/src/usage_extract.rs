//! Lightweight, bounded-memory usage/model extractor for Landing HTTP/SSE/WebSocket
//! streams across Anthropic Messages, OpenAI/Codex Responses & Chat Completions,
//! and Google Gemini / Antigravity Cloud Code responses.

use std::io::Write;

use serde_json::Value;

const MAX_SSE_LINE_BYTES: usize = 256 * 1024;
const MAX_JSON_BODY_BYTES: usize = 512 * 1024;
const MAX_REQ_INSPECT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECOMPRESSED_TAP_BYTES: usize = 16 * 1024 * 1024;

/// Bounded in-memory sink for streaming read-only response decompression.
/// Fails closed (stops sniffing without affecting data-plane forwarding) if the
/// decompressed byte budget is exceeded (zip-bomb guard).
struct BoundedTapSink {
    buf: Vec<u8>,
    total: usize,
    limit: usize,
}

impl BoundedTapSink {
    fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            total: 0,
            limit,
        }
    }

    fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

impl Write for BoundedTapSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self.total.saturating_add(data.len());
        if next > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "decompressed usage tap limit exceeded",
            ));
        }
        self.total = next;
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum TapDecoder {
    Gzip(flate2::write::GzDecoder<BoundedTapSink>),
    Deflate(flate2::write::ZlibDecoder<BoundedTapSink>),
    Brotli(Box<brotli::DecompressorWriter<BoundedTapSink>>),
}

impl TapDecoder {
    fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            TapDecoder::Gzip(d) => {
                if d.write_all(chunk).is_err() || d.flush().is_err() {
                    return Err(());
                }
                Ok(d.get_mut().take_bytes())
            }
            TapDecoder::Deflate(d) => {
                if d.write_all(chunk).is_err() || d.flush().is_err() {
                    return Err(());
                }
                Ok(d.get_mut().take_bytes())
            }
            TapDecoder::Brotli(d) => {
                if d.write_all(chunk).is_err() || d.flush().is_err() {
                    return Err(());
                }
                Ok(d.get_mut().take_bytes())
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            TapDecoder::Gzip(d) => d.finish().map(|mut s| s.take_bytes()).unwrap_or_default(),
            TapDecoder::Deflate(d) => d.finish().map(|mut s| s.take_bytes()).unwrap_or_default(),
            TapDecoder::Brotli(d) => match d.into_inner() {
                Ok(mut s) | Err(mut s) => s.take_bytes(),
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestMeta {
    pub model: String,
    pub stream: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractedUsage {
    pub model: String,
    pub stream: bool,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub cache_creation_tokens: i32,
    pub cache_read_tokens: i32,
    pub request_count: i32,
}

/// Extracts requested model and stream flag from the upstream URL and JSON body.
pub fn extract_request_meta(url: &str, body: &[u8]) -> RequestMeta {
    let mut meta = RequestMeta::default();

    let url_lower = url.to_ascii_lowercase();
    if url_lower.contains("streamgeneratecontent") || url_lower.contains("alt=sse") {
        meta.stream = true;
    }

    // Gemini / Vertex style URL: .../models/<model>:streamGenerateContent
    if let Some(idx) = url.find("/models/") {
        let rest = &url[idx + "/models/".len()..];
        let end = rest
            .find([':', '?', '/', '&'])
            .unwrap_or(rest.len());
        let cand = rest[..end].trim();
        if !cand.is_empty() && cand.len() <= 100 {
            meta.model = cand.to_string();
        }
    }

    if !body.is_empty() && body.len() <= MAX_REQ_INSPECT_BYTES {
        let trimmed = trim_ascii_start(body);
        if trimmed.first() == Some(&b'{') && contains_any_bytes(trimmed, &[b"\"model\"", b"\"stream\""]) {
            if let Ok(v) = serde_json::from_slice::<Value>(trimmed) {
                if let Some(m) = v.get("model").and_then(Value::as_str) {
                    let m = m.trim();
                    if !m.is_empty() {
                        meta.model = truncate_model(m);
                    }
                }
                if let Some(s) = v.get("stream").and_then(Value::as_bool) {
                    meta.stream = s;
                }
            }
        }
    }

    meta
}

/// Bounded streaming sniffer that observes response chunks (HTTP JSON, SSE, or WebSocket text)
/// without buffering unbounded payloads or failing the data plane on malformed chunks.
pub struct UsageStreamSniffer {
    model: String,
    stream: bool,
    is_sse: bool,
    disabled: bool,
    decoder: Option<TapDecoder>,
    input_tokens: i32,
    output_tokens: i32,
    cache_creation_tokens: i32,
    cache_read_tokens: i32,
    completed_turns: i32,
    line_buf: Vec<u8>,
    drop_until_newline: bool,
    json_buf: Vec<u8>,
    json_overflowed: bool,
}

impl UsageStreamSniffer {
    pub fn new_http(meta: RequestMeta, is_sse: bool, content_encoding: Option<&str>) -> Self {
        let enc = content_encoding
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());
        let (disabled, decoder) = match enc.as_deref() {
            None | Some("identity") => (false, None),
            Some("gzip") | Some("x-gzip") => (
                false,
                Some(TapDecoder::Gzip(flate2::write::GzDecoder::new(
                    BoundedTapSink::new(MAX_DECOMPRESSED_TAP_BYTES),
                ))),
            ),
            Some("deflate") => (
                false,
                Some(TapDecoder::Deflate(flate2::write::ZlibDecoder::new(
                    BoundedTapSink::new(MAX_DECOMPRESSED_TAP_BYTES),
                ))),
            ),
            Some("br") => (
                false,
                Some(TapDecoder::Brotli(Box::new(
                    brotli::DecompressorWriter::new(
                        BoundedTapSink::new(MAX_DECOMPRESSED_TAP_BYTES),
                        4096,
                    ),
                ))),
            ),
            // Unknown or stacked Content-Encoding (e.g. zstd): gracefully skip sniffing without
            // disturbing wire forwarding.
            Some(_) => (true, None),
        };
        Self {
            model: meta.model,
            stream: meta.stream || is_sse,
            is_sse,
            disabled,
            decoder,
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            completed_turns: 0,
            line_buf: Vec::new(),
            drop_until_newline: false,
            json_buf: Vec::new(),
            json_overflowed: false,
        }
    }

    pub fn new_ws(meta: RequestMeta) -> Self {
        Self {
            model: meta.model,
            stream: true,
            is_sse: false,
            disabled: false,
            decoder: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            completed_turns: 0,
            line_buf: Vec::new(),
            drop_until_newline: false,
            json_buf: Vec::new(),
            json_overflowed: false,
        }
    }

    pub fn feed_http_chunk(&mut self, chunk: &[u8]) {
        if self.disabled || chunk.is_empty() {
            return;
        }
        if let Some(ref mut dec) = self.decoder {
            match dec.feed(chunk) {
                Ok(plain) => {
                    if !plain.is_empty() {
                        self.feed_plain_chunk(&plain);
                    }
                }
                Err(()) => {
                    self.disabled = true;
                    self.decoder = None;
                }
            }
            return;
        }
        self.feed_plain_chunk(chunk);
    }

    fn feed_plain_chunk(&mut self, chunk: &[u8]) {
        if self.disabled || chunk.is_empty() {
            return;
        }
        if self.is_sse {
            for &b in chunk {
                if b == b'\n' {
                    if !self.drop_until_newline && !self.line_buf.is_empty() {
                        let line = std::mem::take(&mut self.line_buf);
                        self.process_sse_line(&line);
                    } else {
                        self.line_buf.clear();
                    }
                    self.drop_until_newline = false;
                } else if !self.drop_until_newline {
                    if self.line_buf.len() < MAX_SSE_LINE_BYTES {
                        self.line_buf.push(b);
                    } else {
                        self.line_buf.clear();
                        self.drop_until_newline = true;
                    }
                }
            }
        } else if !self.json_overflowed {
            if self.json_buf.len().saturating_add(chunk.len()) <= MAX_JSON_BODY_BYTES {
                self.json_buf.extend_from_slice(chunk);
            } else {
                self.json_buf.clear();
                self.json_overflowed = true;
            }
        }
    }

    pub fn feed_ws_client_text(&mut self, payload: &[u8]) {
        if payload.is_empty() || payload.len() > MAX_SSE_LINE_BYTES {
            return;
        }
        if !contains_any_bytes(payload, &[b"\"model\""]) {
            return;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(payload) {
            if let Some(m) = v
                .get("model")
                .and_then(Value::as_str)
                .or_else(|| v.pointer("/response/model").and_then(Value::as_str))
            {
                let m = m.trim();
                if !m.is_empty() {
                    self.model = truncate_model(m);
                }
            }
        }
    }

    pub fn feed_ws_server_text(&mut self, payload: &[u8]) {
        if payload.is_empty() || payload.len() > MAX_JSON_BODY_BYTES {
            return;
        }
        if !contains_any_bytes(
            payload,
            &[b"\"usage\"", b"\"usageMetadata\"", b"response.completed", b"response.done"],
        ) {
            return;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(payload) {
            self.apply_json_value(&v, true);
        }
    }

    pub fn finish(mut self) -> ExtractedUsage {
        if !self.disabled {
            if let Some(dec) = self.decoder.take() {
                let tail = dec.finish();
                if !tail.is_empty() {
                    self.feed_plain_chunk(&tail);
                }
            }
            if self.is_sse {
                if !self.drop_until_newline && !self.line_buf.is_empty() {
                    let line = std::mem::take(&mut self.line_buf);
                    self.process_sse_line(&line);
                }
            } else if !self.json_overflowed && !self.json_buf.is_empty() {
                let raw = std::mem::take(&mut self.json_buf);
                let trimmed = trim_ascii_start(&raw);
                if trimmed.first() == Some(&b'{')
                    && contains_any_bytes(trimmed, &[b"\"usage\"", b"\"usageMetadata\""])
                {
                    if let Ok(v) = serde_json::from_slice::<Value>(trimmed) {
                        self.apply_json_value(&v, false);
                    }
                }
            }
        }

        ExtractedUsage {
            model: self.model,
            stream: self.stream,
            input_tokens: self.input_tokens.max(0),
            output_tokens: self.output_tokens.max(0),
            cache_creation_tokens: self.cache_creation_tokens.max(0),
            cache_read_tokens: self.cache_read_tokens.max(0),
            request_count: self.completed_turns.max(1),
        }
    }

    fn process_sse_line(&mut self, raw: &[u8]) {
        let trimmed = trim_ascii(raw);
        let Some(rest) = trimmed.strip_prefix(b"data:") else {
            return;
        };
        let payload = trim_ascii(rest);
        if payload.is_empty() || payload == b"[DONE]" || payload.first() != Some(&b'{') {
            return;
        }
        // Fast prefilter avoids JSON parsing for 99% of streaming text delta chunks.
        if !contains_any_bytes(
            payload,
            &[
                b"\"usage\"",
                b"\"usageMetadata\"",
                b"message_start",
                b"message_delta",
                b"response.completed",
                b"response.done",
                b"response.incomplete",
            ],
        ) {
            return;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(payload) {
            self.apply_json_value(&v, false);
        }
    }

    fn apply_json_value(&mut self, v: &Value, accumulate_ws_turn: bool) {
        let ev_type = v.get("type").and_then(Value::as_str).unwrap_or("");

        // 1) Anthropic SSE message_start / message_delta
        if ev_type == "message_start" {
            if let Some(msg) = v.get("message") {
                if let Some(m) = msg.get("model").and_then(Value::as_str) {
                    if !m.trim().is_empty() {
                        self.model = truncate_model(m);
                    }
                }
                if let Some(u) = msg.get("usage") {
                    self.apply_anthropic_usage(u);
                }
            }
            return;
        }
        if ev_type == "message_delta" {
            if let Some(u) = v.get("usage") {
                self.apply_anthropic_usage(u);
            }
            return;
        }

        // 2) OpenAI / Codex Responses SSE or WS terminal event
        if matches!(
            ev_type,
            "response.completed" | "response.done" | "response.incomplete"
        ) {
            let obj = v.get("response").unwrap_or(v);
            if let Some(m) = obj.get("model").and_then(Value::as_str) {
                if !m.trim().is_empty() {
                    self.model = truncate_model(m);
                }
            }
            if let Some(u) = obj.get("usage") {
                self.apply_openai_responses_usage(u, accumulate_ws_turn);
            }
            return;
        }

        // 3) Google Gemini / Antigravity Cloud Code (top-level or wrapped in "response")
        let gemini_root = if v.get("usageMetadata").is_some() {
            Some(v)
        } else {
            v.get("response").filter(|r| r.get("usageMetadata").is_some())
        };
        if let Some(root) = gemini_root {
            if let Some(m) = root
                .get("modelVersion")
                .and_then(Value::as_str)
                .or_else(|| v.get("modelVersion").and_then(Value::as_str))
            {
                if !m.trim().is_empty() {
                    self.model = truncate_model(m);
                }
            }
            if let Some(um) = root.get("usageMetadata") {
                let prompt = json_i32(um.get("promptTokenCount"));
                let cached = json_i32(um.get("cachedContentTokenCount"));
                let cand = json_i32(um.get("candidatesTokenCount"));
                let thoughts = json_i32(um.get("thoughtsTokenCount"));
                self.input_tokens = (prompt - cached).max(0);
                self.output_tokens = (cand + thoughts).max(0);
                self.cache_read_tokens = cached.max(0);
            }
            return;
        }

        // 4) Non-streaming JSON responses (Anthropic / OpenAI Responses / OpenAI Chat Completions)
        if let Some(m) = v.get("model").and_then(Value::as_str) {
            if !m.trim().is_empty() {
                self.model = truncate_model(m);
            }
        }
        if let Some(u) = v.get("usage") {
            let is_chat_completions = u.get("prompt_tokens").is_some() || u.get("completion_tokens").is_some();
            let is_openai_responses = v.get("object").and_then(Value::as_str) == Some("response")
                || u.get("input_tokens_details").is_some()
                || u.get("output_tokens_details").is_some();
            if is_chat_completions {
                let prompt = json_i32(u.get("prompt_tokens"));
                let cached = json_i32(u.pointer("/prompt_tokens_details/cached_tokens"));
                let completion = json_i32(u.get("completion_tokens"));
                self.input_tokens = (prompt - cached).max(0);
                self.output_tokens = completion.max(0);
                self.cache_read_tokens = cached.max(0);
            } else if is_openai_responses {
                self.apply_openai_responses_usage(u, accumulate_ws_turn);
            } else if u.get("input_tokens").is_some() || u.get("output_tokens").is_some() {
                self.apply_anthropic_usage(u);
            }
        }
    }

    fn apply_anthropic_usage(&mut self, u: &Value) {
        if let Some(v) = u.get("input_tokens").and_then(Value::as_i64) {
            if v > 0 || self.input_tokens == 0 {
                self.input_tokens = clamp_i32(v);
            }
        }
        if let Some(v) = u.get("output_tokens").and_then(Value::as_i64) {
            if v > 0 || self.output_tokens == 0 {
                self.output_tokens = clamp_i32(v);
            }
        }
        if let Some(v) = u.get("cache_creation_input_tokens").and_then(Value::as_i64) {
            if v > 0 || self.cache_creation_tokens == 0 {
                self.cache_creation_tokens = clamp_i32(v);
            }
        }
        if let Some(v) = u.get("cache_read_input_tokens").and_then(Value::as_i64) {
            if v > 0 || self.cache_read_tokens == 0 {
                self.cache_read_tokens = clamp_i32(v);
            }
        }
    }

    fn apply_openai_responses_usage(&mut self, u: &Value, accumulate_ws_turn: bool) {
        let raw_in = json_i32(u.get("input_tokens"));
        let cached = json_i32(u.pointer("/input_tokens_details/cached_tokens"));
        let net_in = (raw_in - cached).max(0);
        let out = json_i32(u.get("output_tokens")).max(0);
        let cache_read = cached.max(0);

        if accumulate_ws_turn {
            self.input_tokens = self.input_tokens.saturating_add(net_in);
            self.output_tokens = self.output_tokens.saturating_add(out);
            self.cache_read_tokens = self.cache_read_tokens.saturating_add(cache_read);
            self.completed_turns = self.completed_turns.saturating_add(1);
        } else {
            self.input_tokens = net_in;
            self.output_tokens = out;
            self.cache_read_tokens = cache_read;
        }
    }
}

fn json_i32(v: Option<&Value>) -> i32 {
    v.and_then(Value::as_i64).map(clamp_i32).unwrap_or(0)
}

fn clamp_i32(v: i64) -> i32 {
    if v <= 0 {
        0
    } else if v > i32::MAX as i64 {
        i32::MAX
    } else {
        v as i32
    }
}

fn truncate_model(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= 100 {
        trimmed.to_string()
    } else {
        trimmed.chars().take(100).collect()
    }
}

fn trim_ascii_start(mut b: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = b.split_first() {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn trim_ascii(mut b: &[u8]) -> &[u8] {
    b = trim_ascii_start(b);
    while let Some((&last, rest)) = b.split_last() {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn contains_any_bytes(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == *needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_anthropic_sse_usage() {
        let meta = extract_request_meta(
            "https://api.anthropic.com/v1/messages",
            br#"{"model":"claude-haiku-4-5-20251001","stream":true,"max_tokens":32}"#,
        );
        assert_eq!(meta.model, "claude-haiku-4-5-20251001");
        assert!(meta.stream);

        let mut sniffer = UsageStreamSniffer::new_http(meta, true, None);
        sniffer.feed_http_chunk(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-haiku-4-5-20251001\",\"usage\":{\"input_tokens\":120,\"cache_creation_input_tokens\":40,\"cache_read_input_tokens\":300,\"output_tokens\":1}}}\n\n",
        );
        sniffer.feed_http_chunk(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n",
        );
        sniffer.feed_http_chunk(
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":27}}\n\n",
        );
        let u = sniffer.finish();
        assert_eq!(u.model, "claude-haiku-4-5-20251001");
        assert!(u.stream);
        assert_eq!(u.input_tokens, 120);
        assert_eq!(u.output_tokens, 27);
        assert_eq!(u.cache_creation_tokens, 40);
        assert_eq!(u.cache_read_tokens, 300);
        assert_eq!(u.request_count, 1);
    }

    #[test]
    fn extracts_openai_codex_sse_and_subtracts_cached_tokens() {
        let meta = extract_request_meta(
            "https://chatgpt.com/backend-api/codex/responses",
            br#"{"model":"gpt-5.3-codex","stream":true}"#,
        );
        let mut sniffer = UsageStreamSniffer::new_http(meta, true, None);
        sniffer.feed_http_chunk(
            b"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.3-codex\",\"usage\":{\"input_tokens\":1000,\"input_tokens_details\":{\"cached_tokens\":600},\"output_tokens\":85}}}\n\n",
        );
        let u = sniffer.finish();
        assert_eq!(u.model, "gpt-5.3-codex");
        assert_eq!(u.input_tokens, 400);
        assert_eq!(u.cache_read_tokens, 600);
        assert_eq!(u.output_tokens, 85);
    }

    #[test]
    fn extracts_openai_ws_multi_turn_accumulated() {
        let mut sniffer = UsageStreamSniffer::new_ws(RequestMeta::default());
        sniffer.feed_ws_client_text(br#"{"type":"response.create","model":"gpt-5.3-codex"}"#);
        sniffer.feed_ws_server_text(
            br#"{"type":"response.completed","response":{"model":"gpt-5.3-codex","usage":{"input_tokens":500,"input_tokens_details":{"cached_tokens":100},"output_tokens":30}}}"#,
        );
        sniffer.feed_ws_server_text(
            br#"{"type":"response.completed","response":{"model":"gpt-5.3-codex","usage":{"input_tokens":700,"input_tokens_details":{"cached_tokens":300},"output_tokens":45}}}"#,
        );
        let u = sniffer.finish();
        assert_eq!(u.model, "gpt-5.3-codex");
        assert_eq!(u.input_tokens, 800);
        assert_eq!(u.cache_read_tokens, 400);
        assert_eq!(u.output_tokens, 75);
        assert_eq!(u.request_count, 2);
    }

    #[test]
    fn extracts_gemini_antigravity_wrapped_sse_with_thoughts() {
        let meta = extract_request_meta(
            "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:streamGenerateContent?alt=sse",
            br#"{"model":"gemini-2.5-pro","request":{"contents":[]}}"#,
        );
        assert_eq!(meta.model, "gemini-2.5-pro");
        assert!(meta.stream);

        let mut sniffer = UsageStreamSniffer::new_http(meta, true, None);
        sniffer.feed_http_chunk(
            b"data: {\"response\":{\"modelVersion\":\"gemini-2.5-pro-preview\",\"usageMetadata\":{\"promptTokenCount\":250,\"cachedContentTokenCount\":50,\"candidatesTokenCount\":40,\"thoughtsTokenCount\":60}}}\n\n",
        );
        let u = sniffer.finish();
        assert_eq!(u.model, "gemini-2.5-pro-preview");
        assert_eq!(u.input_tokens, 200);
        assert_eq!(u.cache_read_tokens, 50);
        assert_eq!(u.output_tokens, 100);
    }

    #[test]
    fn extracts_non_streaming_anthropic_and_openai_chat_json() {
        let mut s1 = UsageStreamSniffer::new_http(RequestMeta::default(), false, None);
        s1.feed_http_chunk(
            br#"{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","usage":{"input_tokens":55,"output_tokens":12,"cache_creation_input_tokens":5,"cache_read_input_tokens":10}}"#,
        );
        let u1 = s1.finish();
        assert_eq!(u1.model, "claude-sonnet-4-6");
        assert_eq!(u1.input_tokens, 55);
        assert_eq!(u1.output_tokens, 12);
        assert_eq!(u1.cache_creation_tokens, 5);
        assert_eq!(u1.cache_read_tokens, 10);

        let mut s2 = UsageStreamSniffer::new_http(RequestMeta::default(), false, None);
        s2.feed_http_chunk(
            br#"{"id":"chatcmpl_1","object":"chat.completion","model":"gpt-4o","usage":{"prompt_tokens":90,"completion_tokens":15,"prompt_tokens_details":{"cached_tokens":20}}}"#,
        );
        let u2 = s2.finish();
        assert_eq!(u2.model, "gpt-4o");
        assert_eq!(u2.input_tokens, 70);
        assert_eq!(u2.cache_read_tokens, 20);
        assert_eq!(u2.output_tokens, 15);
    }

    #[test]
    fn extracts_gzip_and_brotli_compressed_sse_usage() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let anth_sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":88,\"cache_read_input_tokens\":500,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":19}}\n\n";
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(anth_sse).unwrap();
        let gz_bytes = gz.finish().unwrap();

        let mut s_gz = UsageStreamSniffer::new_http(RequestMeta::default(), true, Some("gzip"));
        for chunk in gz_bytes.chunks(17) {
            s_gz.feed_http_chunk(chunk);
        }
        let u_gz = s_gz.finish();
        assert_eq!(u_gz.model, "claude-opus-4-6");
        assert_eq!(u_gz.input_tokens, 88);
        assert_eq!(u_gz.cache_read_tokens, 500);
        assert_eq!(u_gz.output_tokens, 19);

        let codex_sse = b"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-6.2-sol\",\"usage\":{\"input_tokens\":1200,\"input_tokens_details\":{\"cached_tokens\":900},\"output_tokens\":42}}}\n\n";
        let mut br_out = Vec::new();
        {
            let mut br = brotli::CompressorWriter::new(&mut br_out, 4096, 5, 22);
            br.write_all(codex_sse).unwrap();
            br.flush().unwrap();
        }
        let mut s_br = UsageStreamSniffer::new_http(RequestMeta::default(), true, Some("br"));
        for chunk in br_out.chunks(13) {
            s_br.feed_http_chunk(chunk);
        }
        let u_br = s_br.finish();
        assert_eq!(u_br.model, "gpt-6.2-sol");
        assert_eq!(u_br.input_tokens, 300);
        assert_eq!(u_br.cache_read_tokens, 900);
        assert_eq!(u_br.output_tokens, 42);
    }
}
