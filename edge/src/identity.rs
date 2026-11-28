//! Strict per-platform outbound header allowlists, Cage identity convergence,
//! byte-preserving surgical JSON body normalization, and Google Antigravity
//! Gemini-REST <-> Cloud Code `v1internal` wire bridging on Landing Edge nodes.

use std::collections::HashMap;
use std::io::Read;

use bytes::Bytes;
use flate2::read::MultiGzDecoder;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::cage::{accept_language_for_locale, apply_credential_headers};
use crate::central::{CageIdentityDto, UpstreamCredentialDto};
use crate::proto::SessionLeaseClaims;

const CLAUDE_FINGERPRINT_SALT: &str = "59cf53e54c78";
const CODEX_MIN_UPSTREAM_VERSION: &str = "0.144.0";
const MAX_DECODED_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const BERTH_SESSION_UUID_NS: Uuid = Uuid::from_bytes([
    0x6b, 0x1e, 0x9f, 0x41, 0x7c, 0x2d, 0x4a, 0x8b, 0x91, 0x5c, 0x3e, 0x77, 0xa2, 0xd4, 0x56, 0x09,
]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    BadRequest(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
}

impl IdentityError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::PayloadTooLarge(_) => 413,
            Self::UnsupportedMediaType(_) => 415,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "invalid_request_body",
            Self::PayloadTooLarge(_) => "request_body_too_large",
            Self::UnsupportedMediaType(_) => "unsupported_content_encoding",
        }
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(m) | Self::PayloadTooLarge(m) | Self::UnsupportedMediaType(m) => {
                f.write_str(m)
            }
        }
    }
}

/// Decodes a single `gzip` Content-Encoding under bounded expanded limits for JSON-inspected
/// OAuth routes. Rejects stacked encodings, unsupported encodings, corrupt gzip, or oversize
/// expanded bodies locally so compressed bytes are NEVER mislabeled or silently replaced.
pub fn decode_request_body_if_encoded(
    headers: &HeaderMap,
    body: Bytes,
    max_decoded_bytes: usize,
) -> Result<Bytes, IdentityError> {
    let mut encodings: Vec<String> = Vec::new();
    for val in headers.get_all(http::header::CONTENT_ENCODING) {
        let Ok(s) = val.to_str() else {
            return Err(IdentityError::BadRequest(
                "non-ASCII Content-Encoding header".into(),
            ));
        };
        for part in s.split(',') {
            let tok = part.trim().to_ascii_lowercase();
            if !tok.is_empty() {
                encodings.push(tok);
            }
        }
    }
    if encodings.is_empty() || (encodings.len() == 1 && encodings[0] == "identity") {
        if body.len() > max_decoded_bytes {
            return Err(IdentityError::PayloadTooLarge(format!(
                "request body exceeds {max_decoded_bytes} bytes"
            )));
        }
        return Ok(body);
    }
    if encodings.len() > 1 {
        return Err(IdentityError::UnsupportedMediaType(format!(
            "stacked Content-Encoding `{}` is not supported",
            encodings.join(", ")
        )));
    }
    match encodings[0].as_str() {
        "gzip" | "x-gzip" => {
            if body.is_empty() {
                return Err(IdentityError::BadRequest(
                    "invalid gzip request body: empty payload".into(),
                ));
            }
            let mut decoder = MultiGzDecoder::new(body.as_ref());
            let mut limited = (&mut decoder).take((max_decoded_bytes as u64).saturating_add(1));
            let mut decoded = Vec::new();
            limited.read_to_end(&mut decoded).map_err(|e| {
                IdentityError::BadRequest(format!("invalid gzip request body: {e}"))
            })?;
            if decoded.len() > max_decoded_bytes {
                return Err(IdentityError::PayloadTooLarge(format!(
                    "decoded gzip request body exceeds {max_decoded_bytes} bytes"
                )));
            }
            Ok(Bytes::from(decoded))
        }
        other => Err(IdentityError::UnsupportedMediaType(format!(
            "unsupported request Content-Encoding `{other}`"
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntigravityBridgeMode {
    None,
    ModelsList,
    UnaryGenerate,
    StreamGenerate,
}

#[derive(Debug)]
pub struct PreparedUpstreamRequest {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub agy_bridge: AntigravityBridgeMode,
}

/// Builds a strictly allowlisted, Cage-converged outbound HTTP request for Landing execution.
///
/// Key invariants:
/// - Client credential/selector/proxy/cookie headers NEVER survive to upstream.
/// - Anthropic & OpenAI request bodies are patched surgically ONLY on target sub-values
///   (`metadata.user_id`, `system[0].text` billing header, `client_metadata`), leaving
///   `messages`, `input`, `tools`, `system[1..]`, and `cache_control` byte-for-byte untouched.
/// - Antigravity OAuth requests from stock `agy` (`/v1beta/models*`) are bridged cleanly
///   to Google Cloud Code `/v1internal:*` with `X-Goog-Ext-525006001-Bin` stripped.
pub fn prepare_landing_http_request(
    method: Method,
    up_url: &str,
    client_headers: &HeaderMap,
    body: Bytes,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
    is_failover_retry: bool,
) -> Result<PreparedUpstreamRequest, IdentityError> {
    let platform = cred
        .map(|c| c.platform.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(claims.platform.as_str())
        .trim()
        .to_ascii_lowercase();
    let acc_type = cred
        .map(|c| c.account_type.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let cage = cred.and_then(|c| c.cage_identity.as_ref());

    match (platform.as_str(), acc_type.as_str()) {
        ("anthropic" | "claude", "oauth" | "setup-token" | "setup_token") => {
            let body =
                decode_request_body_if_encoded(client_headers, body, MAX_DECODED_REQUEST_BODY_BYTES)?;
            prepare_anthropic_oauth_http(
                method,
                up_url,
                client_headers,
                body,
                claims,
                cred,
                cage,
            )
        }
        ("openai" | "codex", "oauth") => {
            let body =
                decode_request_body_if_encoded(client_headers, body, MAX_DECODED_REQUEST_BODY_BYTES)?;
            prepare_openai_codex_oauth_http(
                method,
                up_url,
                client_headers,
                body,
                claims,
                cred,
                cage,
                is_failover_retry,
            )
        }
        ("antigravity", "oauth") => {
            let body =
                decode_request_body_if_encoded(client_headers, body, MAX_DECODED_REQUEST_BODY_BYTES)?;
            prepare_antigravity_oauth_http(method, up_url, client_headers, body, claims, cred, cage)
        }
        _ => Ok(prepare_generic_allowlisted_http(
            method,
            up_url,
            client_headers,
            body,
            claims,
            cred,
        )),
    }
}

/// Authoritative Codex WebSocket session normalization context shared between
/// the HTTP Upgrade handshake and every subsequent client `response.create` text frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexWsContext {
    pub install_id: String,
    pub sandbox: String,
}

/// Normalizes a Codex WebSocket client text message (e.g., `response.create`) so
/// embedded `client_metadata` and `x-codex-turn-metadata` match the upgraded socket's
/// per-(os, arch) `installation_id` and OS-aligned `sandbox`.
/// Fails closed (`Err(IdentityError::BadRequest)`) if `client_metadata` is duplicated
/// or unparseable so unnormalized identity fields can never be forwarded upstream.
pub fn normalize_codex_ws_client_frame(
    payload: &[u8],
    ctx: &CodexWsContext,
) -> Result<Option<Vec<u8>>, IdentityError> {
    if payload.is_empty() || ctx.install_id.is_empty() {
        return Ok(None);
    }
    rewrite_codex_body_client_metadata_surgical(payload, &ctx.install_id, &ctx.sandbox)
}

/// Builds strictly allowlisted, Cage-converged WebSocket upgrade headers AND optional
/// Codex frame-normalization context for Landing execution.
pub fn prepare_landing_ws_session(
    client_headers: &HeaderMap,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
) -> (HeaderMap, Option<CodexWsContext>) {
    let platform = cred
        .map(|c| c.platform.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(claims.platform.as_str())
        .trim()
        .to_ascii_lowercase();
    let acc_type = cred
        .map(|c| c.account_type.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let cage = cred.and_then(|c| c.cage_identity.as_ref());

    if matches!(platform.as_str(), "openai" | "codex") && acc_type == "oauth" {
        let prepared = prepare_openai_codex_oauth_http(
            Method::GET,
            "wss://chatgpt.com/backend-api/codex/responses",
            client_headers,
            Bytes::new(),
            claims,
            cred,
            cage,
            false,
        );
        let mut h = match prepared {
            Ok(p) => p.headers,
            Err(_) => HeaderMap::new(),
        };
        // Preserve RFC 6455 subprotocol header if the client requested one.
        if let Some(proto) = client_headers.get("sec-websocket-protocol") {
            h.insert(
                HeaderName::from_static("sec-websocket-protocol"),
                proto.clone(),
            );
        }
        let ws_ctx = h
            .get("x-codex-installation-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.trim().is_empty())
            .map(|iid| {
                let ua = h
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                let (codex_os, _, _) = resolve_codex_os_arch(ua, client_headers, cage);
                CodexWsContext {
                    install_id: iid.to_string(),
                    sandbox: codex_sandbox_for_os(&codex_os).to_string(),
                }
            });
        return (h, ws_ctx);
    }

    let mut dst = HeaderMap::new();
    for (k, v) in client_headers {
        let lk = k.as_str().to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "accept"
                | "accept-language"
                | "user-agent"
                | "openai-beta"
                | "sec-websocket-protocol"
                | "anthropic-version"
                | "anthropic-beta"
        ) {
            dst.append(k.clone(), v.clone());
        }
    }
    if let Some(c) = cred {
        apply_credential_headers(&mut dst, &c.headers);
    }
    set_accept_language(&mut dst, cage, claims);
    (dst, None)
}

/// Builds strictly allowlisted, Cage-converged WebSocket upgrade headers for Landing execution.
pub fn prepare_landing_ws_headers(
    client_headers: &HeaderMap,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
) -> HeaderMap {
    prepare_landing_ws_session(client_headers, claims, cred).0
}

// ---------- Anthropic / Claude OAuth Convergence ----------

fn prepare_anthropic_oauth_http(
    method: Method,
    up_url: &str,
    client_headers: &HeaderMap,
    mut body: Bytes,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
    cage: Option<&CageIdentityDto>,
) -> Result<PreparedUpstreamRequest, IdentityError> {
    let mut dst = HeaderMap::new();

    // Strict allowlist of legitimate Claude Code client headers (never forward cookies,
    // x-api-key, x-forwarded-*, via, origin, proxy-authorization, or x-berth-*).
    for (k, v) in client_headers {
        let lk = k.as_str().to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "content-type"
                | "accept"
                | "accept-encoding"
                | "anthropic-version"
                | "anthropic-beta"
                | "anthropic-dangerous-direct-browser-access"
                | "x-app"
                | "x-claude-code-session-id"
                | "x-stainless-lang"
                | "x-stainless-package-version"
                | "x-stainless-os"
                | "x-stainless-arch"
                | "x-stainless-runtime"
                | "x-stainless-runtime-version"
                | "x-stainless-retry-count"
                | "x-stainless-timeout"
                | "x-stainless-helper-method"
                | "x-client-request-id"
        ) {
            dst.append(k.clone(), v.clone());
        }
    }

    // Required defaults.
    if !dst.contains_key(http::header::CONTENT_TYPE) {
        dst.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    if !dst.contains_key("anthropic-version") {
        dst.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static("2023-06-01"),
        );
    }
    if !dst.contains_key("x-app") {
        dst.insert(HeaderName::from_static("x-app"), HeaderValue::from_static("cli"));
    }
    if !dst.contains_key("anthropic-dangerous-direct-browser-access") {
        dst.insert(
            HeaderName::from_static("anthropic-dangerous-direct-browser-access"),
            HeaderValue::from_static("true"),
        );
    }

    // Synchronize User-Agent: monotonic non-downgrading version (never below Cage floor,
    // never downgrade a newer official local CLI!). Preserve client entrypoint suffix
    // (`(external, sdk-cli)` vs `(external, cli)`) so it matches `cc_entrypoint` in body.
    let client_ua = header_str(client_headers, "user-agent").unwrap_or_default();
    let client_ver = extract_claude_cli_version(&client_ua).unwrap_or_default();
    let cage_ver = cage
        .map(|c| c.client_app_version.as_str())
        .unwrap_or_default();
    let effective_ver = max_semver(&[&client_ver, cage_ver, "2.1.283"]);
    let ua_suffix = if client_ua.contains("sdk-cli") {
        "(external, sdk-cli)"
    } else {
        "(external, cli)"
    };
    let final_ua = format!("claude-cli/{effective_ver} {ua_suffix}");
    insert_header_str(&mut dst, "user-agent", &final_ua);

    // Align x-stainless-* OS/arch/runtime headers with the real execution client so
    // HTTP headers NEVER contradict the CLI prompt body (platform, shell, paths).
    // Deduplicate x-stainless-os and x-stainless-arch to single canonical values so
    // repeated client headers cannot disagree with the chosen Per-OS device slot.
    let exec_hint = resolve_exec_os_hint(client_headers);
    insert_header_str(&mut dst, "x-stainless-lang", "js");
    let resolved_os = dst
        .get("x-stainless-os")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_os_family)
        .or(exec_hint.os_family)
        .or_else(|| {
            cage.map(|c| c.client_os.as_str())
                .filter(|s| !s.is_empty())
                .and_then(normalize_os_family)
        });
    if let Some(os) = resolved_os {
        insert_header_str(&mut dst, "x-stainless-os", os);
    } else if let Some(c) = cage.filter(|c| !c.client_os.is_empty()) {
        insert_header_str(&mut dst, "x-stainless-os", &c.client_os);
    } else {
        dst.remove("x-stainless-os");
    }
    let resolved_arch = dst
        .get("x-stainless-arch")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_arch_stainless)
        .or(exec_hint.arch)
        .or_else(|| {
            cage.map(|c| c.client_arch.as_str())
                .filter(|s| !s.is_empty())
                .and_then(normalize_arch_stainless)
        });
    if let Some(arch) = resolved_arch {
        insert_header_str(&mut dst, "x-stainless-arch", arch);
    } else if let Some(c) = cage.filter(|c| !c.client_arch.is_empty()) {
        insert_header_str(&mut dst, "x-stainless-arch", &c.client_arch);
    } else {
        dst.remove("x-stainless-arch");
    }
    if let Some(c) = cage {
        if !dst.contains_key("x-stainless-runtime") && !c.client_runtime.is_empty() {
            insert_header_str(&mut dst, "x-stainless-runtime", &c.client_runtime);
        }
        if !dst.contains_key("x-stainless-runtime-version") && !c.client_runtime_version.is_empty() {
            insert_header_str(
                &mut dst,
                "x-stainless-runtime-version",
                &c.client_runtime_version,
            );
        }
    }
    if !dst.contains_key("x-stainless-package-version") {
        insert_header_str(&mut dst, "x-stainless-package-version", "0.112.1");
    }

    // Ensure `oauth-2025-04-20` and `claude-code-20250219` are present in `anthropic-beta`.
    let mut beta_tokens: Vec<String> = dst
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for required in ["claude-code-20250219", "oauth-2025-04-20"] {
        if !beta_tokens.iter().any(|t| t == required) {
            beta_tokens.push(required.to_string());
        }
    }
    insert_header_str(&mut dst, "anthropic-beta", &beta_tokens.join(","));

    // Apply trusted Central credential headers (Authorization: Bearer ...) and strip x-api-key.
    if let Some(c) = cred {
        apply_credential_headers(&mut dst, &c.headers);
    }
    dst.remove("x-api-key");
    set_accept_language(&mut dst, cage, claims);

    // Surgical byte-preserving body normalization:
    // 1) metadata.user_id: inject per-(os,arch) Cage device_id + real OAuth account_uuid + account-scoped session_id
    // 2) sync X-Claude-Code-Session-Id header to the exact same session_id
    // 3) sync system[0] x-anthropic-billing-header cc_version ONLY if version or 3-hex fp differs
    let effective_claude_os = dst
        .get("x-stainless-os")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_os_family);
    let effective_claude_arch = dst
        .get("x-stainless-arch")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_arch_stainless);
    if !body.is_empty() && method == Method::POST {
        let mut raw = body.to_vec();
        if let Some(c) = cage {
            if !c.claude_device_id.is_empty() || !c.claude_account_uuid.is_empty() {
                let slot_device_id = derive_slot_claude_device_id(
                    &c.claude_device_id,
                    Some(c),
                    effective_claude_os,
                    effective_claude_arch,
                );
                let (patched, synced_session) = rewrite_claude_metadata_user_id_surgical(
                    &raw,
                    &slot_device_id,
                    &c.claude_account_uuid,
                    claims.api_key_id,
                    claims.account_id,
                )?;
                if let Some(new_raw) = patched {
                    raw = new_raw;
                }
                if let Some(sid) = synced_session {
                    if dst.contains_key("x-claude-code-session-id") {
                        insert_header_str(&mut dst, "x-claude-code-session-id", &sid);
                    }
                } else {
                    // Never forward an un-isolated client session header when body had no session_id.
                    dst.remove("x-claude-code-session-id");
                }
            }
        }
        if let Some(new_raw) = sync_claude_billing_header_surgical(&raw, &effective_ver) {
            raw = new_raw;
        }
        body = Bytes::from(raw);
    }

    Ok(PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    })
}

// ---------- OpenAI Codex OAuth Convergence ----------

#[allow(clippy::too_many_arguments)]
fn prepare_openai_codex_oauth_http(
    method: Method,
    up_url: &str,
    client_headers: &HeaderMap,
    mut body: Bytes,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
    cage: Option<&CageIdentityDto>,
    is_failover_retry: bool,
) -> Result<PreparedUpstreamRequest, IdentityError> {
    let mut dst = HeaderMap::new();

    // Strict allowlist of genuine Codex CLI headers.
    // Explicitly excludes client-supplied `authorization`, `chatgpt-account-id`,
    // `x-openai-fedramp`, `x-api-key`, `cookie`, `proxy-authorization`, `x-forwarded-*`, etc.
    for (k, v) in client_headers {
        let lk = k.as_str().to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "content-type"
                | "accept"
                | "accept-encoding"
                | "session-id"
                | "session_id"
                | "conversation_id"
                | "thread-id"
                | "x-client-request-id"
                | "x-codex-beta-features"
                | "x-codex-window-id"
                | "x-codex-turn-metadata"
                | "x-codex-turn-state"
                | "x-openai-internal-codex-responses-lite"
                | "openai-beta"
        ) {
            if lk == "x-codex-turn-state" && is_failover_retry {
                continue;
            }
            dst.append(k.clone(), v.clone());
        }
    }

    // Strip legacy `responses=experimental` beta token while preserving any other beta tokens.
    if let Some(beta_val) = dst
        .get("openai-beta")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    {
        let kept: Vec<&str> = beta_val
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("responses=experimental"))
            .collect();
        if kept.is_empty() {
            dst.remove("openai-beta");
        } else {
            insert_header_str(&mut dst, "openai-beta", &kept.join(","));
        }
    }

    let is_compact = up_url.contains("/compact");
    if is_compact {
        insert_header_str(&mut dst, "accept", "application/json");
    } else if !dst.contains_key(http::header::ACCEPT) {
        insert_header_str(&mut dst, "accept", "text/event-stream");
    }
    if !dst.contains_key(http::header::CONTENT_TYPE) && method == Method::POST {
        insert_header_str(&mut dst, "content-type", "application/json");
    }

    // Paired originator + User-Agent + version (never below 0.144.0, never downgrade local CLI).
    // Align OS/Arch and turn-metadata sandbox with the real execution client so HTTP headers
    // NEVER contradict the CLI prompt body (`<environment_context>`, shell, paths).
    let client_orig = header_str(client_headers, "originator").unwrap_or_default();
    let originator = if client_orig.eq_ignore_ascii_case("codex_exec") {
        "codex_exec"
    } else {
        "codex_cli_rs"
    };
    let client_ua = header_str(client_headers, "user-agent").unwrap_or_default();
    let client_ver = extract_codex_version(&client_ua)
        .or_else(|| header_str(client_headers, "version"))
        .unwrap_or_default();
    let cage_ver = cage
        .map(|c| c.client_app_version.as_str())
        .unwrap_or_default();
    let effective_ver = max_semver(&[&client_ver, cage_ver, CODEX_MIN_UPSTREAM_VERSION]);
    let (codex_os, codex_os_family, codex_arch) =
        resolve_codex_os_arch(&client_ua, client_headers, cage);
    let final_ua = if originator == "codex_exec" {
        format!("{originator}/{effective_ver} ({codex_os}; {codex_arch}) xterm-256color ({originator}; {effective_ver})")
    } else {
        format!("{originator}/{effective_ver} ({codex_os}; {codex_arch}) xterm-256color")
    };
    insert_header_str(&mut dst, "originator", originator);
    insert_header_str(&mut dst, "user-agent", &final_ua);
    insert_header_str(&mut dst, "version", &effective_ver);

    // Geo-aligned language headers from Cage.
    set_accept_language(&mut dst, cage, claims);
    let oai_lang = cage
        .map(|c| c.oai_language.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("en-US");
    insert_header_str(&mut dst, "oai-language", oai_lang);

    // Device-mode fingerprint convergence (converges ONLY installation_id + OS-aligned sandbox
    // + scrubs path-like agent_name; keeps session_id/thread_id/turn_id/window_id natural to
    // avoid Sub2API #5555/#5582 session-collapse quota throttling).
    let fp_mode = cage
        .map(|c| c.codex_fingerprint_mode.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "device".to_string());
    let base_install_id = cage
        .map(|c| c.codex_installation_id.trim())
        .filter(|s| !s.is_empty());
    let effective_codex_os = codex_os_family.or_else(|| normalize_os_family(&codex_os));
    let effective_codex_arch = normalize_arch_stainless(&codex_arch);
    let slot_install_id = base_install_id.map(|base| {
        derive_slot_codex_installation_id(base, cage, effective_codex_os, effective_codex_arch)
    });
    // Always scrub undecodable non-UTF-8 or malformed JSON `x-codex-turn-metadata` headers
    // unconditionally, even when fingerprint convergence is disabled.
    if dst.contains_key("x-codex-turn-metadata") {
        let valid_json = dst
            .get("x-codex-turn-metadata")
            .and_then(|v| v.to_str().ok())
            .and_then(|raw| serde_json::from_str::<Map<String, Value>>(raw.trim()).ok())
            .is_some();
        if !valid_json {
            dst.remove("x-codex-turn-metadata");
        }
    }
    if fp_mode != "off" {
        if let Some(ref iid) = slot_install_id {
            insert_header_str(&mut dst, "x-codex-installation-id", iid);
            let exec_sandbox = codex_sandbox_for_os(effective_codex_os.unwrap_or(&codex_os));
            if dst.contains_key("x-codex-turn-metadata") {
                let rewritten = dst
                    .get("x-codex-turn-metadata")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|raw_tm| rewrite_codex_turn_metadata_json(raw_tm, iid, exec_sandbox));
                if let Some(rewritten_tm) = rewritten {
                    insert_header_str(&mut dst, "x-codex-turn-metadata", &rewritten_tm);
                } else {
                    dst.remove("x-codex-turn-metadata");
                }
            }
            if !body.is_empty() && method == Method::POST {
                let mut raw = body.to_vec();
                if let Some(patched) =
                    rewrite_codex_body_client_metadata_surgical(&raw, iid, exec_sandbox)?
                {
                    raw = patched;
                }
                if up_url.contains("/responses") && !is_compact {
                    if let Some(with_store) = ensure_json_store_false_surgical(&raw) {
                        raw = with_store;
                    }
                }
                body = Bytes::from(raw);
            }
        }
    }

    // Apply trusted Central credentials LAST (Authorization, Chatgpt-Account-Id, x-openai-fedramp).
    if let Some(c) = cred {
        apply_credential_headers(&mut dst, &c.headers);
    }

    Ok(PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    })
}

// ---------- Google Antigravity OAuth Convergence + v1internal Bridge ----------

fn prepare_antigravity_oauth_http(
    method: Method,
    up_url: &str,
    client_headers: &HeaderMap,
    body: Bytes,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
    cage: Option<&CageIdentityDto>,
) -> Result<PreparedUpstreamRequest, IdentityError> {
    // Strict minimal allowlist matching official Antigravity Cloud Code client.
    // Deliberately strips `X-Goog-Ext-525006001-Bin` (`cli_gateway` leak!), `x-goog-api-key`,
    // cookies, `x-berth-*`, and all extraneous headers.
    let mut dst = HeaderMap::new();
    insert_header_str(&mut dst, "content-type", "application/json");
    // Request identity encoding so v1internal JSON / SSE unwrapping is guaranteed clean.
    insert_header_str(&mut dst, "accept-encoding", "identity");

    let ua = build_antigravity_user_agent(client_headers, cage);
    insert_header_str(&mut dst, "user-agent", &ua);
    set_accept_language(&mut dst, cage, claims);
    if let Some(c) = cred {
        apply_credential_headers(&mut dst, &c.headers);
    }

    let project_id = cage
        .map(|c| c.antigravity_project_id.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let Ok(parsed) = Url::parse(up_url) else {
        return Ok(PreparedUpstreamRequest {
            method,
            url: up_url.to_string(),
            headers: dst,
            body,
            agy_bridge: AntigravityBridgeMode::None,
        });
    };
    let origin = format!(
        "{}://{}{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or("cloudcode-pa.googleapis.com"),
        parsed
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default()
    );
    let path = parsed.path();

    // 1) GET /v1beta/models -> POST /v1internal:fetchAvailableModels
    if method == Method::GET && (path == "/v1beta/models" || path == "/v1/models") {
        let req_body = if project_id.is_empty() {
            Bytes::from_static(b"{}")
        } else {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "project": project_id }))
                    .unwrap_or_else(|_| b"{}".to_vec()),
            )
        };
        return Ok(PreparedUpstreamRequest {
            method: Method::POST,
            url: format!("{origin}/v1internal:fetchAvailableModels"),
            headers: dst,
            body: req_body,
            agy_bridge: AntigravityBridgeMode::ModelsList,
        });
    }

    // 2) POST /v1beta/models/<model>:streamGenerateContent or :generateContent
    if method == Method::POST {
        if let Some((model, action)) = parse_gemini_model_action(path) {
            if action == "streamGenerateContent" || action == "generateContent" {
                let is_stream = action == "streamGenerateContent";
                let target_url = if is_stream {
                    format!("{origin}/v1internal:streamGenerateContent?alt=sse")
                } else {
                    format!("{origin}/v1internal:generateContent")
                };
                let wrapped = wrap_gemini_body_for_v1internal(&body, &model, project_id)?;
                return Ok(PreparedUpstreamRequest {
                    method: Method::POST,
                    url: target_url,
                    headers: dst,
                    body: Bytes::from(wrapped),
                    agy_bridge: if is_stream {
                        AntigravityBridgeMode::StreamGenerate
                    } else {
                        AntigravityBridgeMode::UnaryGenerate
                    },
                });
            }
        }
    }

    // Direct /v1internal:* passthrough with hardened headers & strict JSON object validation.
    if method == Method::POST && path.contains("/v1internal:") {
        let parsed: Value = serde_json::from_slice(&body).map_err(|e| {
            IdentityError::BadRequest(format!("invalid v1internal JSON request body: {e}"))
        })?;
        if !parsed.is_object() {
            return Err(IdentityError::BadRequest(
                "v1internal JSON request body must be a JSON object".into(),
            ));
        }
    }
    Ok(PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    })
}

fn prepare_generic_allowlisted_http(
    method: Method,
    up_url: &str,
    client_headers: &HeaderMap,
    body: Bytes,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
) -> PreparedUpstreamRequest {
    let mut dst = HeaderMap::new();
    for (k, v) in client_headers {
        let lk = k.as_str().to_ascii_lowercase();
        if lk.starts_with("x-berth-")
            || lk.starts_with("x-forwarded-")
            || matches!(
                lk.as_str(),
                "authorization"
                    | "x-api-key"
                    | "x-goog-api-key"
                    | "chatgpt-account-id"
                    | "x-openai-fedramp"
                    | "cookie"
                    | "proxy-authorization"
                    | "via"
                    | "forwarded"
                    | "x-real-ip"
                    | "host"
                    | "connection"
                    | "transfer-encoding"
                    | "content-length"
                    | "upgrade"
                    | "keep-alive"
            )
        {
            continue;
        }
        dst.append(k.clone(), v.clone());
    }
    if let Some(c) = cred {
        apply_credential_headers(&mut dst, &c.headers);
    }
    set_accept_language(&mut dst, cred.and_then(|c| c.cage_identity.as_ref()), claims);
    PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    }
}

// ---------- Antigravity Response Bridging (Models, Unary, Streaming SSE) ----------

/// Transforms Google Cloud Code `/v1internal:fetchAvailableModels` response JSON
/// into standard Gemini REST `/v1beta/models` format expected by `agy`.
pub fn transform_v1internal_models_response(raw: &[u8]) -> Vec<u8> {
    let Ok(val) = serde_json::from_slice::<Value>(raw) else {
        return raw.to_vec();
    };
    let mut models = Vec::new();
    if let Some(obj) = val.get("models").and_then(Value::as_object) {
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        for model_id in keys {
            let info = &obj[model_id];
            let display = info
                .get("displayName")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(model_id.as_str());
            let mut item = serde_json::json!({
                "name": format!("models/{model_id}"),
                "displayName": display,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
            });
            if let Some(limit) = info.get("maxInputTokens").and_then(Value::as_u64) {
                item["inputTokenLimit"] = Value::from(limit);
            }
            if let Some(limit) = info.get("maxOutputTokens").and_then(Value::as_u64) {
                item["outputTokenLimit"] = Value::from(limit);
            }
            models.push(item);
        }
    }
    serde_json::to_vec(&serde_json::json!({ "models": models })).unwrap_or_else(|_| raw.to_vec())
}

/// Unwraps unary `/v1internal:generateContent` `{"response": <gemini>}` -> `<gemini>`.
pub fn unwrap_v1internal_unary_response(raw: &[u8]) -> Vec<u8> {
    if let Ok(mut val) = serde_json::from_slice::<Value>(raw) {
        if let Some(inner) = val.get_mut("response").map(Value::take) {
            if !inner.is_null() {
                if let Ok(out) = serde_json::to_vec(&inner) {
                    return out;
                }
            }
        }
    }
    raw.to_vec()
}

/// Line-buffered streaming SSE unwrapper for Google Cloud Code `/v1internal:streamGenerateContent?alt=sse`.
/// Unwraps each `data: {"response": <gemini>}` line into `data: <gemini>` without buffering the stream.
#[derive(Default)]
pub struct AntigravitySseUnwrapper {
    pending: Vec<u8>,
}

impl AntigravitySseUnwrapper {
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len());
        self.pending.extend_from_slice(chunk);
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            self.emit_line(&line, &mut out);
        }
        out
    }

    pub fn finish(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let tail = std::mem::take(&mut self.pending);
        let mut out = Vec::with_capacity(tail.len());
        self.emit_line(&tail, &mut out);
        out
    }

    fn emit_line(&self, line: &[u8], out: &mut Vec<u8>) {
        let ends_lf = line.ends_with(b"\n");
        let core = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap_or(line);
        if let Some(rest) = core.strip_prefix(b"data:") {
            let trimmed = rest.trim_ascii();
            if trimmed.starts_with(b"{") {
                if let Ok(mut val) = serde_json::from_slice::<Value>(trimmed) {
                    if let Some(inner) = val.get_mut("response").map(Value::take) {
                        if !inner.is_null() {
                            if let Ok(unwrapped) = serde_json::to_vec(&inner) {
                                out.extend_from_slice(b"data: ");
                                out.extend_from_slice(&unwrapped);
                                if ends_lf {
                                    out.push(b'\n');
                                }
                                return;
                            }
                        }
                    }
                }
            }
        }
        out.extend_from_slice(core);
        if ends_lf {
            out.push(b'\n');
        }
    }
}

fn parse_gemini_model_action(path: &str) -> Option<(String, String)> {
    let rest = path
        .strip_prefix("/v1beta/models/")
        .or_else(|| path.strip_prefix("/v1/models/"))?;
    let (model, action) = rest.split_once(':')?;
    let model = model.trim();
    let action = action.trim();
    if model.is_empty() || action.is_empty() || model.contains('/') {
        return None;
    }
    Some((model.to_string(), action.to_string()))
}

fn wrap_gemini_body_for_v1internal(
    raw: &[u8],
    model: &str,
    project_id: &str,
) -> Result<Vec<u8>, IdentityError> {
    let mut inner = serde_json::from_slice::<Value>(raw).map_err(|e| {
        IdentityError::BadRequest(format!("invalid Gemini/Antigravity JSON request body: {e}"))
    })?;
    if !inner.is_object() {
        return Err(IdentityError::BadRequest(
            "Gemini/Antigravity request body must be a JSON object".into(),
        ));
    }
    if let Some(obj) = inner.as_object_mut() {
        // Compute a stable sessionId from the first user text (matches Berth Go Antigravity client).
        if !obj.contains_key("sessionId") {
            let sid = derive_antigravity_session_id(obj);
            obj.insert("sessionId".to_string(), Value::String(sid));
        }
        if !obj.contains_key("toolConfig") {
            obj.insert(
                "toolConfig".to_string(),
                serde_json::json!({ "functionCallingConfig": { "mode": "VALIDATED" } }),
            );
        }
    }
    let mut envelope = Map::new();
    if !project_id.is_empty() {
        envelope.insert("project".to_string(), Value::String(project_id.to_string()));
    }
    envelope.insert("model".to_string(), Value::String(model.to_string()));
    envelope.insert("request".to_string(), inner);
    envelope.insert("requestType".to_string(), Value::String("agent".to_string()));
    envelope.insert("userAgent".to_string(), Value::String("antigravity".to_string()));
    envelope.insert(
        "requestId".to_string(),
        Value::String(format!("agent-{}", Uuid::new_v4())),
    );
    serde_json::to_vec(&Value::Object(envelope)).map_err(|e| {
        IdentityError::BadRequest(format!("failed to serialize v1internal request envelope: {e}"))
    })
}

fn derive_antigravity_session_id(req_obj: &Map<String, Value>) -> String {
    if let Some(contents) = req_obj.get("contents").and_then(Value::as_array) {
        for item in contents {
            if item.get("role").and_then(Value::as_str) == Some("user") {
                if let Some(parts) = item.get("parts").and_then(Value::as_array) {
                    for p in parts {
                        if let Some(text) = p.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                let sum = Sha256::digest(text.as_bytes());
                                let n = u64::from_be_bytes(sum[0..8].try_into().unwrap()) & 0x7FFF_FFFF_FFFF_FFFF;
                                return format!("-{n}");
                            }
                        }
                    }
                }
            }
        }
    }
    let bytes = Uuid::new_v4().into_bytes();
    let n = u64::from_be_bytes(bytes[0..8].try_into().unwrap()) & 0x7FFF_FFFF_FFFF_FFFF;
    format!("-{n}")
}

#[derive(Debug, Default)]
struct ExecOsHint {
    os_family: Option<&'static str>, // "MacOS" | "Linux" | "Windows"
    os_version: Option<String>,
    arch: Option<&'static str>, // "arm64" | "x64"
}

fn normalize_os_family(raw: &str) -> Option<&'static str> {
    let lc = raw.trim().to_ascii_lowercase();
    if lc.is_empty() {
        return None;
    }
    if lc.contains("mac") || lc.contains("darwin") || lc.contains("osx") {
        Some("MacOS")
    } else if lc.contains("win") {
        Some("Windows")
    } else if lc.contains("linux")
        || lc.contains("ubuntu")
        || lc.contains("debian")
        || lc.contains("fedora")
        || lc.contains("arch")
        || lc.contains("alpine")
    {
        Some("Linux")
    } else {
        None
    }
}

fn normalize_arch_stainless(raw: &str) -> Option<&'static str> {
    let lc = raw.trim().to_ascii_lowercase();
    match lc.as_str() {
        "arm64" | "aarch64" => Some("arm64"),
        "x64" | "x86_64" | "amd64" => Some("x64"),
        _ => None,
    }
}

fn sanitize_os_token(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .filter(|c| !matches!(c, '(' | ')' | ';'))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed.len() > 48 {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_exec_os_hint(client_headers: &HeaderMap) -> ExecOsHint {
    let os_family = header_str(client_headers, "x-berth-exec-os")
        .as_deref()
        .and_then(normalize_os_family);
    let os_version = header_str(client_headers, "x-berth-exec-os-version")
        .as_deref()
        .and_then(sanitize_os_token);
    let arch = header_str(client_headers, "x-berth-exec-arch")
        .as_deref()
        .and_then(normalize_arch_stainless);
    ExecOsHint {
        os_family,
        os_version,
        arch,
    }
}

fn primary_cage_os_arch(cage: Option<&CageIdentityDto>) -> (Option<&'static str>, Option<&'static str>) {
    let Some(c) = cage else {
        return (None, None);
    };
    (
        normalize_os_family(&c.client_os),
        normalize_arch_stainless(&c.client_arch),
    )
}

/// Derives a stable, deterministic per-(OS, arch) Claude `device_id` (64 lowercase hex) so a
/// single account used across two real OSes (e.g., macOS arm64 + Linux arm64/x64) presents
/// distinct fixed devices instead of one device mutating CPU/OS across requests.
/// Returns `base_id` unchanged when execution (os, arch) matches the Cage primary slot or is unknown.
fn derive_slot_claude_device_id(
    base_id: &str,
    cage: Option<&CageIdentityDto>,
    exec_os: Option<&str>,
    exec_arch: Option<&str>,
) -> String {
    let base = base_id.trim();
    if base.is_empty() {
        return String::new();
    }
    let (Some(os), Some(arch)) = (exec_os, exec_arch) else {
        return base.to_string();
    };
    let (prim_os, prim_arch) = primary_cage_os_arch(cage);
    if prim_os == Some(os) && prim_arch == Some(arch) {
        return base.to_string();
    }
    let mut h = Sha256::new();
    h.update(b"berth-device-slot-v1:claude:");
    h.update(base.as_bytes());
    h.update(b":");
    h.update(os.as_bytes());
    h.update(b":");
    h.update(arch.as_bytes());
    hex::encode(h.finalize())
}

/// Derives a stable, deterministic RFC 4122 v4-shaped per-(OS, arch) Codex `installation_id`
/// when execution (os, arch) differs from the Cage primary slot. Returns `base_id` unchanged
/// when execution (os, arch) matches the Cage primary slot or is unknown.
fn derive_slot_codex_installation_id(
    base_id: &str,
    cage: Option<&CageIdentityDto>,
    exec_os: Option<&str>,
    exec_arch: Option<&str>,
) -> String {
    let base = base_id.trim();
    if base.is_empty() {
        return String::new();
    }
    let (Some(os), Some(arch)) = (exec_os, exec_arch) else {
        return base.to_string();
    };
    let (prim_os, prim_arch) = primary_cage_os_arch(cage);
    if prim_os == Some(os) && prim_arch == Some(arch) {
        return base.to_string();
    }
    let mut h = Sha256::new();
    h.update(b"berth-device-slot-v1:codex:");
    h.update(base.as_bytes());
    h.update(b":");
    h.update(os.as_bytes());
    h.update(b":");
    h.update(arch.as_bytes());
    let digest = h.finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    Uuid::from_bytes(raw).to_string()
}

fn build_antigravity_user_agent(
    client_headers: &HeaderMap,
    cage: Option<&CageIdentityDto>,
) -> String {
    let ver = cage
        .map(|c| c.client_app_version.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("2.23.0");
    let exec_hint = resolve_exec_os_hint(client_headers);
    let client_ua_lc = header_str(client_headers, "user-agent")
        .unwrap_or_default()
        .to_ascii_lowercase();

    let os_family = exec_hint
        .os_family
        .or_else(|| normalize_os_family(&client_ua_lc))
        .or_else(|| cage.and_then(|c| normalize_os_family(&c.client_os)))
        .unwrap_or("Linux");
    let os_tok = match os_family {
        "MacOS" => "darwin",
        "Windows" => "windows",
        _ => "linux",
    };

    let arch_from_ua = if client_ua_lc.contains("arm64") || client_ua_lc.contains("aarch64") {
        Some("arm64")
    } else if client_ua_lc.contains("amd64")
        || client_ua_lc.contains("x86_64")
        || client_ua_lc.contains("x64")
    {
        Some("x64")
    } else {
        None
    };
    let arch_tok = match exec_hint
        .arch
        .or(arch_from_ua)
        .or_else(|| cage.and_then(|c| normalize_arch_stainless(&c.client_arch)))
        .unwrap_or("arm64")
    {
        "arm64" => "arm64",
        _ => "amd64",
    };
    format!("antigravity/hub/{ver} {os_tok}/{arch_tok}")
}

// ---------- Claude Surgical Body Helpers (Byte-Preserving for Prompt Cache!) ----------

/// Computes the exact 3-hex Claude Code billing fingerprint matching official CLI / Parrot / Berth Go:
/// JS UTF-16 code units at indices `[4, 7, 20]` of the first user text, padded with `'0'`,
/// decoded as UTF-8, hashed as `SHA256("59cf53e54c78" + sample + version)[..3]`.
pub fn compute_claude_code_fingerprint(body: &[u8], version: &str) -> String {
    let first_text = extract_first_claude_user_text(body).unwrap_or_default();
    compute_claude_code_fingerprint_from_text(&first_text, version)
}

fn compute_claude_code_fingerprint_from_text(first_text: &str, version: &str) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(22);
    for ch in first_text.chars() {
        let mut buf = [0u16; 2];
        for u in ch.encode_utf16(&mut buf) {
            units.push(*u);
            if units.len() > 20 {
                break;
            }
        }
        if units.len() > 20 {
            break;
        }
    }
    let sampled: [u16; 3] = [
        units.get(4).copied().unwrap_or(b'0' as u16),
        units.get(7).copied().unwrap_or(b'0' as u16),
        units.get(20).copied().unwrap_or(b'0' as u16),
    ];
    let sample: String = std::char::decode_utf16(sampled)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(CLAUDE_FINGERPRINT_SALT.as_bytes());
    hasher.update(sample.as_bytes());
    hasher.update(version.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..2])[..3].to_string()
}

fn extract_first_claude_user_text(body: &[u8]) -> Option<String> {
    let val = serde_json::from_slice::<Value>(body).ok()?;
    let Some(msgs) = val.get("messages").and_then(Value::as_array) else {
        return Some(String::new());
    };
    for msg in msgs {
        if msg.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        if let Some(s) = msg.get("content").and_then(Value::as_str) {
            return Some(s.to_string());
        }
        if let Some(arr) = msg.get("content").and_then(Value::as_array) {
            for blk in arr {
                if blk.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = blk.get("text").and_then(Value::as_str) {
                        return Some(t.to_string());
                    }
                }
            }
        }
        break;
    }
    Some(String::new())
}

/// Surgically rewrites `metadata.user_id` in O(n) single-pass without re-serializing any
/// other part of the JSON body. Fails closed (`IdentityError::BadRequest`) on duplicate
/// `metadata` or `metadata.user_id` keys or unnormalizable `user_id` values, preventing both
/// conflicting session/device smuggling and quadratic splice amplification.
pub fn rewrite_claude_metadata_user_id_surgical(
    body: &[u8],
    cage_device_id: &str,
    account_uuid: &str,
    api_key_id: i64,
    account_id: i64,
) -> Result<(Option<Vec<u8>>, Option<String>), IdentityError> {
    let meta_spans = find_all_top_level_field_value_spans_strict(body, "metadata")?;
    if meta_spans.is_empty() {
        return Ok((None, None));
    }
    if meta_spans.len() > 1 {
        return Err(IdentityError::BadRequest(
            "duplicate top-level `metadata` key in Anthropic request body".into(),
        ));
    }
    let (meta_start, meta_end) = meta_spans[0];
    let meta_slice = &body[meta_start..meta_end];
    let uid_spans = find_all_top_level_field_value_spans_strict(meta_slice, "user_id")?;
    if uid_spans.is_empty() {
        return Ok((None, None));
    }
    if uid_spans.len() > 1 {
        return Err(IdentityError::BadRequest(
            "duplicate `metadata.user_id` key in Anthropic request body".into(),
        ));
    }
    let (uid_rel_start, uid_rel_end) = uid_spans[0];
    let uid_start = meta_start + uid_rel_start;
    let uid_end = meta_start + uid_rel_end;
    let raw_uid = serde_json::from_slice::<String>(&body[uid_start..uid_end]).map_err(|_| {
        IdentityError::BadRequest("invalid non-string `metadata.user_id` value".into())
    })?;
    let (new_uid, sess_opt) = normalize_single_claude_user_id(
        &raw_uid,
        cage_device_id,
        account_uuid,
        api_key_id,
        account_id,
    )
    .ok_or_else(|| {
        IdentityError::BadRequest("unrecognized or malformed `metadata.user_id` format".into())
    })?;
    if new_uid == raw_uid {
        return Ok((None, sess_opt));
    }
    let encoded = serde_json::to_vec(&new_uid)
        .map_err(|e| IdentityError::BadRequest(format!("encode normalized user_id: {e}")))?;
    let mut out = Vec::with_capacity(body.len() + encoded.len());
    out.extend_from_slice(&body[..uid_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&body[uid_end..]);
    Ok((Some(out), sess_opt))
}

fn normalize_single_claude_user_id(
    raw_uid: &str,
    cage_device_id: &str,
    account_uuid: &str,
    api_key_id: i64,
    account_id: i64,
) -> Option<(String, Option<String>)> {
    if raw_uid.trim_start().starts_with('{') {
        // New JSON-encoded metadata.user_id format (Claude Code 2.1.x):
        // `{"device_id":"...","account_uuid":"...","session_id":"..."}`
        let mut obj = serde_json::from_str::<Map<String, Value>>(raw_uid).ok()?;
        let scoped_session = match obj.get("session_id") {
            None => String::new(),
            Some(val) => {
                // If `session_id` key is present, it MUST be a non-empty string (reject blank/non-string!).
                let s = val.as_str()?.trim();
                if s.is_empty() {
                    return None;
                }
                isolate_session_uuid("claude", api_key_id, account_id, s)
            }
        };
        if !cage_device_id.is_empty() {
            obj.insert("device_id".to_string(), Value::String(cage_device_id.to_string()));
        }
        if !account_uuid.is_empty() {
            obj.insert("account_uuid".to_string(), Value::String(account_uuid.to_string()));
        }
        if !scoped_session.is_empty() {
            obj.insert("session_id".to_string(), Value::String(scoped_session.clone()));
        }
        // Preserve canonical key order: device_id, account_uuid, session_id, then extras.
        let mut ordered = String::from("{");
        let mut first = true;
        for key in ["device_id", "account_uuid", "session_id"] {
            if let Some(val) = obj.remove(key) {
                if !first {
                    ordered.push(',');
                }
                first = false;
                ordered.push_str(&serde_json::to_string(key).unwrap());
                ordered.push(':');
                ordered.push_str(&serde_json::to_string(&val).unwrap());
            }
        }
        for (k, v) in obj {
            if !first {
                ordered.push(',');
            }
            first = false;
            ordered.push_str(&serde_json::to_string(&k).unwrap());
            ordered.push(':');
            ordered.push_str(&serde_json::to_string(&v).unwrap());
        }
        ordered.push('}');
        let sid_opt = (!scoped_session.is_empty()).then_some(scoped_session);
        Some((ordered, sid_opt))
    } else if let Some(rest) = raw_uid.strip_prefix("user_") {
        // Legacy format: `user_<64hex>_account_<uuid>_session_<uuid>`
        let (orig_dev, after_acct) = rest.split_once("_account_")?;
        let (orig_acct, orig_sess) = after_acct.split_once("_session_")?;
        let dev = if cage_device_id.is_empty() {
            orig_dev
        } else {
            cage_device_id
        };
        let acct = if account_uuid.is_empty() {
            orig_acct
        } else {
            account_uuid
        };
        let sess = isolate_session_uuid("claude", api_key_id, account_id, orig_sess);
        Some((format!("user_{dev}_account_{acct}_session_{sess}"), Some(sess)))
    } else {
        None
    }
}

/// Surgically updates `cc_version=X.Y.Z.{fp}` in `system[0]`'s `x-anthropic-billing-header`
/// text block when the version or 3-hex fingerprint differs. Never touches `system[1..]`
/// or `cache_control` or injects deprecated `cch=`.
pub fn sync_claude_billing_header_surgical(body: &[u8], target_version: &str) -> Option<Vec<u8>> {
    if target_version.is_empty() {
        return None;
    }
    let (sys_start, sys_end) = find_top_level_field_value_span(body, "system")?;
    let sys_slice = &body[sys_start..sys_end];
    if sys_slice.first() != Some(&b'[') {
        return None;
    }
    let (blk_rel_start, blk_rel_end) = find_first_array_element_span(sys_slice)?;
    let blk_slice = &sys_slice[blk_rel_start..blk_rel_end];
    let (txt_rel_start, txt_rel_end) = find_top_level_field_value_span(blk_slice, "text")?;
    let txt_abs_start = sys_start + blk_rel_start + txt_rel_start;
    let txt_abs_end = sys_start + blk_rel_start + txt_rel_end;
    let text = serde_json::from_slice::<String>(&body[txt_abs_start..txt_abs_end]).ok()?;
    if !text.starts_with("x-anthropic-billing-header") {
        return None;
    }

    let cc_pos = text.find("cc_version=")?;
    let ver_start = cc_pos + "cc_version=".len();
    let tail = &text[ver_start..];
    let token_end = tail
        .find(|c: char| c == ';' || c.is_ascii_whitespace())
        .unwrap_or(tail.len());
    let cur_token = &tail[..token_end];
    let (cur_ver, cur_fp) = split_cc_version_and_fp(cur_token);
    let replacement = if let Some(existing_fp) = cur_fp {
        let Some(first_text) = extract_first_claude_user_text(body) else {
            // Never fabricate a fingerprint from an empty-text fallback when full JSON
            // could not be parsed; preserve the existing billing header unchanged.
            return None;
        };
        let expected_fp = compute_claude_code_fingerprint_from_text(&first_text, target_version);
        if cur_ver == target_version && existing_fp.eq_ignore_ascii_case(&expected_fp) {
            return None; // Already synced -> keep 100% byte-identical!
        }
        format!("{target_version}.{expected_fp}")
    } else {
        if cur_ver == target_version {
            return None;
        }
        target_version.to_string()
    };
    let mut new_text = String::with_capacity(text.len() + 16);
    new_text.push_str(&text[..ver_start]);
    new_text.push_str(&replacement);
    new_text.push_str(&tail[token_end..]);

    let encoded = serde_json::to_vec(&new_text).ok()?;
    let mut out = Vec::with_capacity(body.len() + encoded.len());
    out.extend_from_slice(&body[..txt_abs_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&body[txt_abs_end..]);
    Some(out)
}

fn split_cc_version_and_fp(token: &str) -> (&str, Option<&str>) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 4
        && parts[3].len() == 3
        && parts[3].bytes().all(|b| b.is_ascii_hexdigit())
    {
        let ver_len = token.len() - 4;
        (&token[..ver_len], Some(parts[3]))
    } else {
        (token, None)
    }
}

// ---------- Codex Surgical Body & Header Helpers ----------

fn parse_codex_ua_os_arch(client_ua: &str) -> Option<(String, String)> {
    let open = client_ua.find('(')?;
    let close_rel = client_ua[open + 1..].find(')')?;
    let inside = &client_ua[open + 1..open + 1 + close_rel];
    let (raw_os, raw_arch) = inside.split_once(';')?;
    let os_clean = sanitize_os_token(raw_os)?;
    // Verify the parsed OS token actually looks like an OS rather than junk.
    normalize_os_family(&os_clean)?;
    let arch_clean = match normalize_arch_stainless(raw_arch)? {
        "arm64" => "arm64".to_string(),
        _ => "x86_64".to_string(),
    };
    Some((os_clean, arch_clean))
}

fn resolve_codex_os_arch(
    client_ua: &str,
    client_headers: &HeaderMap,
    cage: Option<&CageIdentityDto>,
) -> (String, Option<&'static str>, String) {
    // 1) Real execution CLI User-Agent (matches prompt body `<environment_context>` & shell).
    if let Some((os_str, arch_str)) = parse_codex_ua_os_arch(client_ua) {
        let fam = normalize_os_family(&os_str);
        return (os_str, fam, arch_str);
    }
    // 2) Authoritative internal execution-OS hint from Berth CageShim (e.g. macOS Seatbelt
    //    vs Apple Silicon ARM64 Linux Micro-VM vs WSL bwrap). Preserves explicit `os_fam`
    //    directly so unrecognized Linux distro display names never lose their Linux slot.
    let hint = resolve_exec_os_hint(client_headers);
    if let Some(os_fam) = hint.os_family {
        let os_str = match os_fam {
            "MacOS" => match hint.os_version.as_deref() {
                Some(v) if v.to_ascii_lowercase().starts_with("mac") => v.to_string(),
                Some(v) => format!("Mac OS {v}"),
                None => "Mac OS 15.3.1".to_string(),
            },
            "Windows" => match hint.os_version.as_deref() {
                Some(v) if v.to_ascii_lowercase().starts_with("win") => v.to_string(),
                Some(v) => format!("Windows {v}"),
                None => "Windows 11".to_string(),
            },
            _ => hint
                .os_version
                .unwrap_or_else(|| "Ubuntu 24.04".to_string()),
        };
        let arch_str = match hint.arch.unwrap_or("x64") {
            "arm64" => "arm64".to_string(),
            _ => "x86_64".to_string(),
        };
        return (os_str, Some(os_fam), arch_str);
    }
    // 3) Fallback to Account Cage defaults when no client OS signal is present.
    let (os_str, arch_str) = cage_codex_os_arch(cage);
    let fam = cage
        .map(|c| c.client_os.as_str())
        .filter(|s| !s.is_empty())
        .and_then(normalize_os_family)
        .or_else(|| normalize_os_family(&os_str));
    (os_str, fam, arch_str)
}

fn cage_codex_os_arch(cage: Option<&CageIdentityDto>) -> (String, String) {
    let Some(c) = cage else {
        return ("Mac OS 15.3.1".to_string(), "arm64".to_string());
    };
    let os_lc = c.client_os.trim().to_ascii_lowercase();
    let ver = c.client_os_version.trim();
    let os_str = if os_lc.contains("mac") || os_lc.contains("darwin") {
        if ver.is_empty() {
            "Mac OS 15.3.1".to_string()
        } else {
            format!("Mac OS {ver}")
        }
    } else if os_lc.contains("win") {
        "Windows 11".to_string()
    } else {
        "Ubuntu 24.04".to_string()
    };
    let arch_lc = c.client_arch.trim().to_ascii_lowercase();
    let arch_str = if arch_lc == "arm64" || arch_lc == "aarch64" {
        "arm64".to_string()
    } else {
        "x86_64".to_string()
    };
    (os_str, arch_str)
}

fn codex_sandbox_for_os(os_str: &str) -> &'static str {
    let os_lc = os_str.trim().to_ascii_lowercase();
    if os_lc.contains("mac") || os_lc.contains("darwin") {
        "seatbelt"
    } else if os_lc.contains("win") {
        "windows-restricted-token"
    } else {
        "linux-sandbox"
    }
}

fn rewrite_codex_turn_metadata_json(
    raw: &str,
    install_id: &str,
    cage_sandbox: &str,
) -> Option<String> {
    let mut obj: Map<String, Value> = serde_json::from_str(raw.trim()).ok()?;
    obj.insert(
        "installation_id".to_string(),
        Value::String(install_id.to_string()),
    );
    if let Some(sb) = obj.get("sandbox").and_then(Value::as_str) {
        // Align platform-specific sandbox token with Cage OS so Windows UA never advertises macOS seatbelt.
        if !sb.eq_ignore_ascii_case("none") && !sb.eq_ignore_ascii_case("danger-full-access") {
            obj.insert(
                "sandbox".to_string(),
                Value::String(cage_sandbox.to_string()),
            );
        }
    }
    if let Some(an) = obj.get("agent_name").and_then(Value::as_str) {
        if an.starts_with('/') || an.contains('\\') || an.contains(":\\") {
            obj.remove("agent_name");
        }
    }
    serde_json::to_string(&Value::Object(obj)).ok()
}

/// Surgically updates `client_metadata` in O(n) single-pass (`x-codex-installation-id` +
/// embedded `x-codex-turn-metadata`) while leaving `input`, `tools`, `prompt_cache_key`,
/// and `reasoning` 100% byte-identical. Fails closed (`IdentityError::BadRequest`) on
/// duplicate `client_metadata` keys or non-object/unparseable `client_metadata` values.
pub fn rewrite_codex_body_client_metadata_surgical(
    body: &[u8],
    install_id: &str,
    cage_sandbox: &str,
) -> Result<Option<Vec<u8>>, IdentityError> {
    let spans = find_all_top_level_field_value_spans_strict(body, "client_metadata")?;
    if spans.is_empty() {
        return Ok(None);
    }
    if spans.len() > 1 {
        return Err(IdentityError::BadRequest(
            "duplicate top-level `client_metadata` key in Codex payload".into(),
        ));
    }
    let (cm_start, cm_end) = spans[0];
    let mut cm_obj =
        serde_json::from_slice::<Map<String, Value>>(&body[cm_start..cm_end]).map_err(|_| {
            IdentityError::BadRequest("invalid non-object `client_metadata` in Codex payload".into())
        })?;
    cm_obj.insert(
        "x-codex-installation-id".to_string(),
        Value::String(install_id.to_string()),
    );
    if let Some(tm_val) = cm_obj.get("x-codex-turn-metadata").cloned() {
        if let Some(tm_raw) = tm_val.as_str() {
            if let Some(rewritten) =
                rewrite_codex_turn_metadata_json(tm_raw, install_id, cage_sandbox)
            {
                cm_obj.insert(
                    "x-codex-turn-metadata".to_string(),
                    Value::String(rewritten),
                );
            } else {
                // Scrub malformed turn-metadata instead of forwarding unverified local fields.
                cm_obj.remove("x-codex-turn-metadata");
            }
        } else {
            cm_obj.remove("x-codex-turn-metadata");
        }
    }
    let encoded = serde_json::to_vec(&Value::Object(cm_obj))
        .map_err(|e| IdentityError::BadRequest(format!("encode client_metadata: {e}")))?;
    let mut out = Vec::with_capacity(body.len() + encoded.len());
    out.extend_from_slice(&body[..cm_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&body[cm_end..]);
    Ok(Some(out))
}

fn ensure_json_store_false_surgical(body: &[u8]) -> Option<Vec<u8>> {
    if let Some((start, end)) = find_top_level_field_value_span(body, "store") {
        let cur = body[start..end].trim_ascii();
        if cur == b"false" {
            return None;
        }
        let mut out = Vec::with_capacity(body.len() + 8);
        out.extend_from_slice(&body[..start]);
        out.extend_from_slice(b"false");
        out.extend_from_slice(&body[end..]);
        return Some(out);
    }
    let trimmed = body.trim_ascii_end();
    if trimmed.first() != Some(&b'{') || trimmed.last() != Some(&b'}') {
        return None;
    }
    let close_idx = trimmed.len() - 1;
    let is_empty_obj = trimmed[1..close_idx].trim_ascii().is_empty();
    let mut out = Vec::with_capacity(trimmed.len() + 16);
    out.extend_from_slice(&trimmed[..close_idx]);
    if !is_empty_obj {
        out.push(b',');
    }
    out.extend_from_slice(b"\"store\":false}");
    Some(out)
}

// ---------- Generic JSON Top-Level Span Scanner (Zero Re-Serialization!) ----------

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn skip_json_string(b: &[u8], start: usize) -> Option<usize> {
    if b.get(start) != Some(&b'"') {
        return None;
    }
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_json_value(b: &[u8], start: usize) -> Option<usize> {
    let i = skip_ws(b, start);
    let &ch = b.get(i)?;
    match ch {
        b'"' => skip_json_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut cur = i;
            while cur < b.len() {
                match b[cur] {
                    b'"' => cur = skip_json_string(b, cur)?,
                    b'{' | b'[' => {
                        depth += 1;
                        cur += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        cur += 1;
                        if depth == 0 {
                            return Some(cur);
                        }
                    }
                    _ => cur += 1,
                }
            }
            None
        }
        _ => {
            let mut cur = i;
            while cur < b.len() && !matches!(b[cur], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                cur += 1;
            }
            if cur > i { Some(cur) } else { None }
        }
    }
}

/// Finds the exact `(value_start, value_end)` byte span of the first top-level JSON object key.
fn find_top_level_field_value_span(b: &[u8], target_key: &str) -> Option<(usize, usize)> {
    find_all_top_level_field_value_spans(b, target_key).into_iter().next()
}

/// Finds ALL `(value_start, value_end)` byte spans matching a top-level JSON object key,
/// strictly distinguishing JSON syntax errors (`Err(IdentityError::BadRequest)`) from field
/// absence (`Ok(vec![])`) so malformed JSON before protected identity fields can NEVER bypass
/// surgical normalization.
fn find_all_top_level_field_value_spans_strict(
    b: &[u8],
    target_key: &str,
) -> Result<Vec<(usize, usize)>, IdentityError> {
    let mut spans = Vec::new();
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return Err(IdentityError::BadRequest(
            "expected JSON object in request payload".into(),
        ));
    }
    i = skip_ws(b, i + 1);
    if b.get(i) == Some(&b'}') {
        let rest = skip_ws(b, i + 1);
        if rest != b.len() {
            return Err(IdentityError::BadRequest(
                "trailing bytes after JSON object".into(),
            ));
        }
        return Ok(spans);
    }
    while i < b.len() {
        let Some(key_end) = skip_json_string(b, i) else {
            return Err(IdentityError::BadRequest(
                "malformed JSON object key".into(),
            ));
        };
        let Ok(key_str) = serde_json::from_slice::<String>(&b[i..key_end]) else {
            return Err(IdentityError::BadRequest(
                "invalid UTF-8/escape in JSON object key".into(),
            ));
        };
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return Err(IdentityError::BadRequest(
                "expected ':' after JSON object key".into(),
            ));
        }
        let val_start = skip_ws(b, i + 1);
        let Some(val_end) = skip_json_value(b, val_start) else {
            return Err(IdentityError::BadRequest(
                "malformed JSON object value".into(),
            ));
        };
        if key_str == target_key {
            spans.push((val_start, val_end));
        }
        i = skip_ws(b, val_end);
        match b.get(i) {
            Some(&b',') => {
                i = skip_ws(b, i + 1);
                if i >= b.len() || b[i] == b'}' {
                    return Err(IdentityError::BadRequest(
                        "trailing comma or truncated JSON object".into(),
                    ));
                }
            }
            Some(&b'}') => {
                let rest = skip_ws(b, i + 1);
                if rest != b.len() {
                    return Err(IdentityError::BadRequest(
                        "trailing bytes after JSON object".into(),
                    ));
                }
                return Ok(spans);
            }
            _ => {
                return Err(IdentityError::BadRequest(
                    "malformed separator in JSON object".into(),
                ));
            }
        }
    }
    Err(IdentityError::BadRequest("unterminated JSON object".into()))
}

/// Finds ALL `(value_start, value_end)` byte spans matching a top-level JSON object key
/// (non-failing helper used for best-effort auxiliary fields such as `system`/`store`).
fn find_all_top_level_field_value_spans(b: &[u8], target_key: &str) -> Vec<(usize, usize)> {
    find_all_top_level_field_value_spans_strict(b, target_key).unwrap_or_default()
}

fn find_first_array_element_span(b: &[u8]) -> Option<(usize, usize)> {
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'[') {
        return None;
    }
    i = skip_ws(b, i + 1);
    if b.get(i) == Some(&b']') {
        return None;
    }
    let end = skip_json_value(b, i)?;
    Some((i, end))
}

// ---------- Small Utilities ----------

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn insert_header_str(dst: &mut HeaderMap, name: &'static str, val: &str) {
    if let Ok(hv) = HeaderValue::from_str(val.trim()) {
        dst.insert(HeaderName::from_static(name), hv);
    }
}

fn set_accept_language(
    dst: &mut HeaderMap,
    cage: Option<&CageIdentityDto>,
    claims: &SessionLeaseClaims,
) {
    let al = cage
        .map(|c| c.accept_language.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            (!claims.cohort_locale.trim().is_empty())
                .then(|| accept_language_for_locale(&claims.cohort_locale))
        });
    if let Some(v) = al {
        insert_header_str(dst, "accept-language", &v);
    }
}

fn isolate_session_uuid(platform: &str, api_key_id: i64, account_id: i64, raw_session: &str) -> String {
    let input = format!("{platform}:k{api_key_id}:a{account_id}:{raw_session}");
    Uuid::new_v5(&BERTH_SESSION_UUID_NS, input.as_bytes()).to_string()
}

fn extract_claude_cli_version(ua: &str) -> Option<String> {
    let rest = ua.trim().strip_prefix("claude-cli/")?;
    let ver = rest.split_whitespace().next()?;
    is_valid_semver(ver).then(|| ver.to_string())
}

fn extract_codex_version(ua: &str) -> Option<String> {
    let (_, rest) = ua.trim().split_once('/')?;
    let ver = rest.split_whitespace().next()?;
    let base = ver.split('-').next().unwrap_or(ver);
    is_valid_semver(base).then(|| ver.to_string())
}

fn is_valid_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_semver_tuple(s: &str) -> Option<(u64, u64, u64)> {
    let base = s.trim().split('-').next()?;
    let mut it = base.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

fn max_semver(candidates: &[&str]) -> String {
    let mut best: Option<((u64, u64, u64), &str)> = None;
    for &raw in candidates {
        let s = raw.trim();
        if let Some(t) = parse_semver_tuple(s) {
            if best.map_or(true, |(bt, _)| t > bt) {
                best = Some((t, s));
            }
        }
    }
    best.map(|(_, s)| s.to_string()).unwrap_or_default()
}

/// Helper to build a map of sanitized response headers (stripping upstream `x-berth-*`
/// so upstream can NEVER spoof `X-Berth-Action: cage_rebind_required`!).
pub fn is_blocked_upstream_response_header(name: &str) -> bool {
    let lk = name.to_ascii_lowercase();
    lk.starts_with("x-berth-")
}

#[allow(dead_code)]
fn _unused_hashmap_anchor(_: &HashMap<String, String>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_claims(platform: &str) -> SessionLeaseClaims {
        SessionLeaseClaims {
            lease_id: "l1".into(),
            jti: "j1".into(),
            user_id: 1,
            api_key_id: 26,
            work_session_id: 1,
            platform: platform.into(),
            account_id: 26,
            cage_id: 5,
            cage_epoch: 1,
            grant_id: 1,
            ingress_node_id: 1,
            landing_node_id: 15,
            route_chain: vec![],
            cohort_timezone: "Asia/Singapore".into(),
            cohort_country_code: "SG".into(),
            cohort_locale: "en_SG.UTF-8".into(),
            rev_seq: 1,
            lease_epoch: 1,
            iat: 100,
            exp: 999,
        }
    }

    #[test]
    fn claude_oauth_converges_headers_metadata_and_preserves_cache_bytes() {
        let mut client_hdrs = HeaderMap::new();
        client_hdrs.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.283 (external, sdk-cli)"));
        client_hdrs.insert("x-stainless-os", HeaderValue::from_static("Windows"));
        client_hdrs.insert("x-stainless-arch", HeaderValue::from_static("x64"));
        client_hdrs.insert("x-claude-code-session-id", HeaderValue::from_static("144d2ca6-29f0-46df-9d92-1487a6888e60"));
        client_hdrs.insert("anthropic-beta", HeaderValue::from_static("claude-code-20250219,effort-2025-11-24"));
        client_hdrs.insert("x-api-key", HeaderValue::from_static("spoofed-client-key"));
        client_hdrs.insert("cookie", HeaderValue::from_static("session=leak"));
        client_hdrs.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));

        let body = br#"{"model":"claude-opus-5-5","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.283.baa; cc_entrypoint=sdk-cli;"},{"type":"text","text":"PROMPT_KEEP_EXACT","cache_control":{"type":"ephemeral"}}],"metadata":{"user_id":"{\"device_id\":\"localdev\",\"account_uuid\":\"\",\"session_id\":\"144d2ca6-29f0-46df-9d92-1487a6888e60\"}"},"messages":[{"role":"user","content":"Hello world this is a long test message"}]}"#;

        let mut cred_hdrs = HashMap::new();
        cred_hdrs.insert("Authorization".into(), "Bearer real-oauth-tok".into());
        cred_hdrs.insert("anthropic-beta".into(), "oauth-2025-04-20".into());

        let cred = UpstreamCredentialDto {
            account_id: 26,
            platform: "anthropic".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs,
            base_url: "https://api.anthropic.com".into(),
            expires_at_unix: 9999999999,
            cage_identity: Some(CageIdentityDto {
                client_os: "MacOS".into(),
                client_arch: "arm64".into(),
                client_runtime: "node".into(),
                client_runtime_version: "v24.11.0".into(),
                client_app_version: "2.1.321".into(),
                accept_language: "en-SG,en;q=0.9".into(),
                claude_device_id: "4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e".into(),
                claude_account_uuid: "03be3d17-1731-44d3-9c30-13f93416e404".into(),
                ..Default::default()
            }),
        };

        let out = prepare_landing_http_request(
            Method::POST,
            "https://api.anthropic.com/v1/messages?beta=true",
            &client_hdrs,
            Bytes::from_static(body),
            &dummy_claims("anthropic"),
            Some(&cred),
            false,
        )
        .unwrap();

        assert_eq!(out.headers.get("authorization").unwrap(), "Bearer real-oauth-tok");
        assert!(out.headers.get("x-api-key").is_none());
        assert!(out.headers.get("cookie").is_none());
        assert!(out.headers.get("x-forwarded-for").is_none());
        // Real client x-stainless-os/arch are preserved so headers match prompt body OS!
        assert_eq!(out.headers.get("x-stainless-os").unwrap(), "Windows");
        assert_eq!(out.headers.get("x-stainless-arch").unwrap(), "x64");
        assert_eq!(out.headers.get("user-agent").unwrap(), "claude-cli/2.1.321 (external, sdk-cli)");
        let beta = out.headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert!(beta.contains("oauth-2025-04-20"));
        assert!(beta.contains("effort-2025-11-24"));

        let out_str = std::str::from_utf8(&out.body).unwrap();
        assert!(out_str.contains(r#"{"type":"text","text":"PROMPT_KEEP_EXACT","cache_control":{"type":"ephemeral"}}"#));
        // Secondary OS slot (Windows/x64 vs Cage primary MacOS/arm64) derives a distinct stable 64-hex device_id!
        let win_slot = derive_slot_claude_device_id(
            "4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e",
            cred.cage_identity.as_ref(),
            Some("Windows"),
            Some("x64"),
        );
        assert_eq!(win_slot.len(), 64);
        assert_ne!(win_slot, "4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e");
        assert!(out_str.contains(&win_slot));
        assert!(out_str.contains("03be3d17-1731-44d3-9c30-13f93416e404"));
        let expected_fp = compute_claude_code_fingerprint(body, "2.1.321");
        assert!(out_str.contains(&format!("cc_version=2.1.321.{expected_fp}")));
        // Header X-Claude-Code-Session-Id synced to rewritten session_id.
        let hdr_sid = out.headers.get("x-claude-code-session-id").unwrap().to_str().unwrap();
        assert_ne!(hdr_sid, "144d2ca6-29f0-46df-9d92-1487a6888e60");
        assert!(out_str.contains(hdr_sid));

        // Primary OS slot (MacOS/arm64 == Cage primary) preserves exact base claude_device_id!
        let mut mac_hdrs = HeaderMap::new();
        mac_hdrs.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.321 (external, cli)"));
        mac_hdrs.insert("x-stainless-os", HeaderValue::from_static("MacOS"));
        mac_hdrs.insert("x-stainless-arch", HeaderValue::from_static("arm64"));
        let out_mac = prepare_landing_http_request(
            Method::POST,
            "https://api.anthropic.com/v1/messages",
            &mac_hdrs,
            Bytes::from_static(body),
            &dummy_claims("anthropic"),
            Some(&cred),
            false,
        )
        .unwrap();
        assert!(
            std::str::from_utf8(&out_mac.body)
                .unwrap()
                .contains("4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e")
        );

        // When client omits x-stainless-os/arch, X-Berth-Exec-OS/Arch backfill cleanly without leaking x-berth-* upstream,
        // and derive a distinct deterministic Linux/arm64 slot device_id (for legacy user_id too!).
        let mut minimal_hdrs = HeaderMap::new();
        minimal_hdrs.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.321 (external, cli)"));
        minimal_hdrs.insert("x-berth-exec-os", HeaderValue::from_static("Linux"));
        minimal_hdrs.insert("x-berth-exec-arch", HeaderValue::from_static("arm64"));
        let legacy_body = br#"{"model":"claude-opus-5-5","metadata":{"user_id":"user_deadbeef_account_0000_session_144d2ca6-29f0-46df-9d92-1487a6888e60"},"messages":[{"role":"user","content":"Hello"}]}"#;
        let out_min = prepare_landing_http_request(
            Method::POST,
            "https://api.anthropic.com/v1/messages",
            &minimal_hdrs,
            Bytes::from_static(legacy_body),
            &dummy_claims("anthropic"),
            Some(&cred),
            false,
        )
        .unwrap();
        assert_eq!(out_min.headers.get("x-stainless-os").unwrap(), "Linux");
        assert_eq!(out_min.headers.get("x-stainless-arch").unwrap(), "arm64");
        assert!(out_min.headers.get("x-berth-exec-os").is_none());
        assert!(out_min.headers.get("x-berth-exec-arch").is_none());
        let linux_slot = derive_slot_claude_device_id(
            "4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e",
            cred.cage_identity.as_ref(),
            Some("Linux"),
            Some("arm64"),
        );
        assert_ne!(linux_slot, win_slot);
        assert!(std::str::from_utf8(&out_min.body).unwrap().contains(&format!("user_{linux_slot}_account_")));
    }

    #[test]
    fn codex_oauth_converges_device_id_aligns_sandbox_and_strips_failover_turn_state() {
        let mut client_hdrs = HeaderMap::new();
        client_hdrs.insert("originator", HeaderValue::from_static("codex_exec"));
        client_hdrs.insert("user-agent", HeaderValue::from_static("codex_exec/0.172.0 (Mac OS 27.0.1; arm64) unknown"));
        client_hdrs.insert("chatgpt-account-id", HeaderValue::from_static("spoofed-acct"));
        client_hdrs.insert("x-codex-turn-state", HeaderValue::from_static("acct-a-turn-state"));
        client_hdrs.insert(
            "x-codex-turn-metadata",
            HeaderValue::from_static(r#"{"installation_id":"local-mac-id","sandbox":"seatbelt","agent_name":"/root","session_id":"sess-1"}"#),
        );

        let body = br#"{"model":"gpt-6.2-sol","stream":true,"prompt_cache_key":"sess-1","client_metadata":{"session_id":"sess-1","x-codex-installation-id":"local-mac-id","x-codex-turn-metadata":"{\"installation_id\":\"local-mac-id\",\"sandbox\":\"seatbelt\",\"agent_name\":\"/root\"}"}}"#;

        let mut cred_hdrs = HashMap::new();
        cred_hdrs.insert("Authorization".into(), "Bearer oa-tok".into());
        cred_hdrs.insert("Chatgpt-Account-Id".into(), "real-acct-24".into());

        let cred = UpstreamCredentialDto {
            account_id: 24,
            platform: "openai".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs,
            base_url: "https://chatgpt.com/backend-api/codex".into(),
            expires_at_unix: 9999999999,
            cage_identity: Some(CageIdentityDto {
                client_os: "MacOS".into(),
                client_arch: "arm64".into(),
                client_app_version: "0.146.0".into(),
                originator: "codex_cli_rs".into(),
                accept_language: "en-US,en;q=0.9".into(),
                oai_language: "en-US".into(),
                codex_installation_id: "6878c0a3-a067-423e-9c9f-aebd007eb6a6".into(),
                codex_fingerprint_mode: "device".into(),
                ..Default::default()
            }),
        };

        let out = prepare_landing_http_request(
            Method::POST,
            "https://chatgpt.com/backend-api/codex/responses",
            &client_hdrs,
            Bytes::from_static(body),
            &dummy_claims("openai"),
            Some(&cred),
            true,
        )
        .unwrap();

        assert_eq!(out.headers.get("chatgpt-account-id").unwrap(), "real-acct-24");
        assert!(out.headers.get("x-codex-turn-state").is_none());
        assert_eq!(out.headers.get("originator").unwrap(), "codex_exec");
        assert_eq!(out.headers.get("version").unwrap(), "0.172.0");
        // Primary MacOS/arm64 preserves exact base codex_installation_id.
        assert!(out.headers.get("user-agent").unwrap().to_str().unwrap().contains("Mac OS 27.0.1; arm64"));
        assert_eq!(
            out.headers.get("x-codex-installation-id").unwrap(),
            "6878c0a3-a067-423e-9c9f-aebd007eb6a6"
        );
        let tm = out.headers.get("x-codex-turn-metadata").unwrap().to_str().unwrap();
        assert!(tm.contains("6878c0a3-a067-423e-9c9f-aebd007eb6a6"));
        assert!(tm.contains("seatbelt"));
        assert!(!tm.contains("/root"));

        let out_str = std::str::from_utf8(&out.body).unwrap();
        assert!(out_str.contains("6878c0a3-a067-423e-9c9f-aebd007eb6a6"));
        assert!(out_str.contains(r#""prompt_cache_key":"sess-1""#));
        assert!(out_str.contains(r#""store":false"#));

        // Linux ARM64 Micro-VM execution aligns to Ubuntu/arm64 + linux-sandbox and derives a distinct
        // deterministic RFC 4122 UUID installation_id consistently across HTTP AND WebSocket handshake!
        let mut vm_hdrs = HeaderMap::new();
        vm_hdrs.insert("originator", HeaderValue::from_static("codex_cli_rs"));
        vm_hdrs.insert("user-agent", HeaderValue::from_static("codex_cli_rs/0.172.0 (Ubuntu 24.04; aarch64) xterm-256color"));
        vm_hdrs.insert(
            "x-codex-turn-metadata",
            HeaderValue::from_static(r#"{"installation_id":"vm-id","sandbox":"linux-sandbox"}"#),
        );
        let out_vm = prepare_landing_http_request(
            Method::POST,
            "https://chatgpt.com/backend-api/codex/responses",
            &vm_hdrs,
            Bytes::from_static(body),
            &dummy_claims("openai"),
            Some(&cred),
            false,
        )
        .unwrap();
        let vm_iid = out_vm.headers.get("x-codex-installation-id").unwrap().to_str().unwrap();
        assert_ne!(vm_iid, "6878c0a3-a067-423e-9c9f-aebd007eb6a6");
        let parsed_uuid = Uuid::parse_str(vm_iid).expect("derived slot id must be valid UUID");
        assert_eq!(parsed_uuid.get_version_num(), 4);
        assert!(out_vm.headers.get("user-agent").unwrap().to_str().unwrap().contains("Ubuntu 24.04; arm64"));
        assert!(out_vm.headers.get("x-codex-turn-metadata").unwrap().to_str().unwrap().contains("linux-sandbox"));
        assert!(out_vm.headers.get("x-codex-turn-metadata").unwrap().to_str().unwrap().contains(vm_iid));
        assert!(std::str::from_utf8(&out_vm.body).unwrap().contains(vm_iid));

        let ws_hdrs = prepare_landing_ws_headers(&vm_hdrs, &dummy_claims("openai"), Some(&cred));
        assert_eq!(ws_hdrs.get("x-codex-installation-id").unwrap().to_str().unwrap(), vm_iid);
    }

    #[test]
    fn antigravity_oauth_bridges_v1beta_to_v1internal_and_unwraps_sse() {
        let mut client_hdrs = HeaderMap::new();
        client_hdrs.insert("x-goog-ext-525006001-bin", HeaderValue::from_static("gateway-leak"));
        client_hdrs.insert("x-berth-exec-os", HeaderValue::from_static("Linux"));
        client_hdrs.insert("x-berth-exec-arch", HeaderValue::from_static("arm64"));
        let mut cred_hdrs = HashMap::new();
        cred_hdrs.insert("Authorization".into(), "Bearer goog-tok".into());
        let cred = UpstreamCredentialDto {
            account_id: 25,
            platform: "antigravity".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs,
            base_url: "https://daily-cloudcode-pa.googleapis.com".into(),
            expires_at_unix: 9999999999,
            cage_identity: Some(CageIdentityDto {
                client_os: "Windows".into(),
                client_arch: "x64".into(),
                client_app_version: "2.23.0".into(),
                accept_language: "en-US,en;q=0.9".into(),
                antigravity_project_id: "aicode-consumers".into(),
                antigravity_plan_type: "Ultra".into(),
                ..Default::default()
            }),
        };

        let models_req = prepare_landing_http_request(
            Method::GET,
            "https://daily-cloudcode-pa.googleapis.com/v1beta/models?pageSize=1000",
            &client_hdrs,
            Bytes::new(),
            &dummy_claims("antigravity"),
            Some(&cred),
            false,
        )
        .unwrap();
        assert_eq!(models_req.agy_bridge, AntigravityBridgeMode::ModelsList);
        assert_eq!(models_req.method, Method::POST);
        assert_eq!(models_req.url, "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels");
        assert!(models_req.headers.get("x-goog-ext-525006001-bin").is_none());
        assert!(models_req.headers.get("x-berth-exec-os").is_none());
        assert_eq!(models_req.headers.get("user-agent").unwrap(), "antigravity/hub/2.23.0 linux/arm64");

        // Without X-Berth-Exec-* headers, falls back to Account Cage OS/arch.
        let empty_hdrs = HeaderMap::new();
        let fallback_req = prepare_landing_http_request(
            Method::GET,
            "https://daily-cloudcode-pa.googleapis.com/v1beta/models",
            &empty_hdrs,
            Bytes::new(),
            &dummy_claims("antigravity"),
            Some(&cred),
            false,
        )
        .unwrap();
        assert_eq!(fallback_req.headers.get("user-agent").unwrap(), "antigravity/hub/2.23.0 windows/amd64");

        let gen_req = prepare_landing_http_request(
            Method::POST,
            "https://daily-cloudcode-pa.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            &client_hdrs,
            Bytes::from_static(br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#),
            &dummy_claims("antigravity"),
            Some(&cred),
            false,
        )
        .unwrap();
        assert_eq!(gen_req.agy_bridge, AntigravityBridgeMode::StreamGenerate);
        assert_eq!(gen_req.url, "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse");
        let parsed_body: Value = serde_json::from_slice(&gen_req.body).unwrap();
        assert_eq!(parsed_body["project"], "aicode-consumers");
        assert_eq!(parsed_body["model"], "gemini-2.5-pro");
        assert_eq!(parsed_body["userAgent"], "antigravity");

        // Malformed JSON must fail visibly (400) rather than silently substituting `{}`!
        let bad_gen = prepare_landing_http_request(
            Method::POST,
            "https://daily-cloudcode-pa.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent",
            &client_hdrs,
            Bytes::from_static(b"{not-valid-json"),
            &dummy_claims("antigravity"),
            Some(&cred),
            false,
        );
        assert_eq!(bad_gen.unwrap_err().status_code(), 400);

        let mut unwrapper = AntigravitySseUnwrapper::default();
        let part1 = unwrapper.push_chunk(b"data: {\"response\":{\"cand");
        assert!(part1.is_empty());
        let part2 = unwrapper.push_chunk(b"idates\":[{\"index\":0}]}}\r\n\r\ndata: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"OK\"}]}}]}}\r\n\r\n");
        let out_sse = String::from_utf8(part2).unwrap();
        assert!(!out_sse.contains('\r'), "SSE must emit pure LF delimiters without mixed CRLF");
        assert_eq!(
            out_sse,
            "data: {\"candidates\":[{\"index\":0}]}\n\ndata: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"OK\"}]}}]}\n\n"
        );
    }

    #[test]
    fn gzip_request_decoding_and_claude_billing_fp_resync_work_strictly() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let plain = br#"{"contents":[{"role":"user","parts":[{"text":"gzipped ok"}]}]}"#;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        let gz = enc.finish().unwrap();

        let mut hdrs = HeaderMap::new();
        hdrs.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let decoded = decode_request_body_if_encoded(&hdrs, Bytes::from(gz.clone()), 1024).unwrap();
        assert_eq!(decoded.as_ref(), plain);

        // Oversize expanded gzip is rejected with 413.
        let too_small = decode_request_body_if_encoded(&hdrs, Bytes::from(gz), 8);
        assert_eq!(too_small.unwrap_err().status_code(), 413);

        // Stacked or unsupported Content-Encoding is rejected with 415.
        let mut stacked = HeaderMap::new();
        stacked.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("gzip, gzip"));
        assert_eq!(
            decode_request_body_if_encoded(&stacked, Bytes::from_static(b"abc"), 1024)
                .unwrap_err()
                .status_code(),
            415
        );
        let mut br = HeaderMap::new();
        br.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(
            decode_request_body_if_encoded(&br, Bytes::from_static(b"abc"), 1024)
                .unwrap_err()
                .status_code(),
            415
        );

        // Billing header resyncs stale 3-hex fp even when version matches, and is no-op once synced.
        let stale = br#"{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.321.000; cc_entrypoint=cli;"}],"messages":[{"role":"user","content":"Hello world this is a long test message"}]}"#;
        let expected_fp = compute_claude_code_fingerprint(stale, "2.1.321");
        assert_ne!(expected_fp, "000");
        let fixed = sync_claude_billing_header_surgical(stale, "2.1.321").expect("must resync stale fp");
        assert!(std::str::from_utf8(&fixed).unwrap().contains(&format!("cc_version=2.1.321.{expected_fp}")));
        assert!(
            sync_claude_billing_header_surgical(&fixed, "2.1.321").is_none(),
            "already-synced billing header must remain byte-identical"
        );
    }

    #[test]
    fn adversarial_gzip_multimember_trailing_garbage_empty_and_identity_limits() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        // Concatenated two-member gzip stream spanning JSON across member boundary.
        let part_a = br#"{"contents":[{"role":"user","#;
        let part_b = br#""parts":[{"text":"multi-member ok"}]}]}"#;
        let mut e1 = GzEncoder::new(Vec::new(), Compression::default());
        e1.write_all(part_a).unwrap();
        let mut combined = e1.finish().unwrap();
        let mut e2 = GzEncoder::new(Vec::new(), Compression::default());
        e2.write_all(part_b).unwrap();
        combined.extend_from_slice(&e2.finish().unwrap());

        let mut gz_hdrs = HeaderMap::new();
        gz_hdrs.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let decoded = decode_request_body_if_encoded(&gz_hdrs, Bytes::from(combined.clone()), 1024).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(part_a);
        expected.extend_from_slice(part_b);
        assert_eq!(decoded.as_ref(), expected.as_slice());

        // Cumulative multi-member size exceeding limit -> 413.
        assert_eq!(
            decode_request_body_if_encoded(&gz_hdrs, Bytes::from(combined.clone()), expected.len() - 1)
                .unwrap_err()
                .status_code(),
            413
        );
        // Exact boundary -> OK.
        assert!(decode_request_body_if_encoded(&gz_hdrs, Bytes::from(combined.clone()), expected.len()).is_ok());

        // Trailing garbage after a valid gzip member -> 400 (never silent truncation!).
        let mut corrupt = combined;
        corrupt.extend_from_slice(b"NOT_GZIP_TRAILING_GARBAGE");
        assert_eq!(
            decode_request_body_if_encoded(&gz_hdrs, Bytes::from(corrupt), 1024)
                .unwrap_err()
                .status_code(),
            400
        );

        // Empty wire payload with Content-Encoding: gzip -> 400.
        assert_eq!(
            decode_request_body_if_encoded(&gz_hdrs, Bytes::new(), 1024)
                .unwrap_err()
                .status_code(),
            400
        );

        // Identity / absent encoding respects max_decoded_bytes -> 413 on overflow.
        let empty_hdrs = HeaderMap::new();
        assert_eq!(
            decode_request_body_if_encoded(&empty_hdrs, Bytes::from_static(b"123456789"), 8)
                .unwrap_err()
                .status_code(),
            413
        );
    }

    #[test]
    fn adversarial_four_os_slots_ws_frames_duplicate_json_keys_and_direct_v1internal() {
        let base_claude_dev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let base_codex_iid = "11111111-2222-4333-8444-555555555555";
        let cage = CageIdentityDto {
            client_os: "MacOS".into(),
            client_arch: "arm64".into(),
            client_app_version: "2.1.330".into(),
            claude_device_id: base_claude_dev.into(),
            claude_account_uuid: "acct-uuid-99".into(),
            codex_installation_id: base_codex_iid.into(),
            codex_fingerprint_mode: "device".into(),
            ..Default::default()
        };

        // All 4 OS/arch pairs produce deterministic, distinct slots; primary preserves base ID.
        let matrix = [
            ("MacOS", "arm64", true),
            ("Linux", "arm64", false),
            ("Linux", "x64", false),
            ("Windows", "x64", false),
        ];
        let mut claude_ids = std::collections::HashSet::new();
        let mut codex_ids = std::collections::HashSet::new();
        for (os, arch, is_primary) in matrix {
            let c_id = derive_slot_claude_device_id(base_claude_dev, Some(&cage), Some(os), Some(arch));
            let o_id = derive_slot_codex_installation_id(base_codex_iid, Some(&cage), Some(os), Some(arch));
            if is_primary {
                assert_eq!(c_id, base_claude_dev);
                assert_eq!(o_id, base_codex_iid);
            } else {
                assert_ne!(c_id, base_claude_dev);
                assert_ne!(o_id, base_codex_iid);
            }
            assert!(claude_ids.insert(c_id), "duplicate Claude slot for {os}/{arch}");
            assert!(codex_ids.insert(o_id), "duplicate Codex slot for {os}/{arch}");
        }

        // Unrecognized Linux distro display name still maps to Linux slot (never falls back to MacOS primary!).
        let mut cred_hdrs = HashMap::new();
        cred_hdrs.insert("Authorization".into(), "Bearer tok".into());
        let codex_cred = UpstreamCredentialDto {
            account_id: 24,
            platform: "openai".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs.clone(),
            base_url: "https://chatgpt.com/backend-api/codex".into(),
            expires_at_unix: 9999999999,
            cage_identity: Some(cage.clone()),
        };
        let mut custom_linux_hdrs = HeaderMap::new();
        custom_linux_hdrs.insert("x-berth-exec-os", HeaderValue::from_static("Linux"));
        custom_linux_hdrs.insert("x-berth-exec-os-version", HeaderValue::from_static("NixOS 25.05"));
        custom_linux_hdrs.insert("x-berth-exec-arch", HeaderValue::from_static("arm64"));
        let (ws_hdrs, ws_ctx) =
            prepare_landing_ws_session(&custom_linux_hdrs, &dummy_claims("openai"), Some(&codex_cred));
        let ws_ctx = ws_ctx.expect("codex oauth WS must return normalization context");
        assert_eq!(ws_ctx.sandbox, "linux-sandbox");
        assert_ne!(ws_ctx.install_id, base_codex_iid);
        assert_eq!(
            ws_hdrs.get("x-codex-installation-id").unwrap().to_str().unwrap(),
            ws_ctx.install_id
        );

        // Codex WS `response.create` frame normalization: single valid `client_metadata` normalizes
        // installation_id, sandbox, and scrubs malformed turn-metadata / path-like agent_name.
        let ws_frame = br#"{"type":"response.create","client_metadata":{"x-codex-installation-id":"local-2","x-codex-turn-metadata":"{\"sandbox\":\"seatbelt\",\"agent_name\":\"/Users/me/proj\"}"}}"#;
        let normalized_ws = normalize_codex_ws_client_frame(ws_frame, &ws_ctx)
            .expect("valid ws frame must succeed")
            .expect("ws frame must normalize");
        let normalized_str = std::str::from_utf8(&normalized_ws).unwrap();
        assert!(!normalized_str.contains("local-2"));
        assert!(!normalized_str.contains("seatbelt"));
        assert!(!normalized_str.contains("/Users/me/proj"));
        assert_eq!(normalized_str.matches(&ws_ctx.install_id).count(), 2);

        // Duplicate `client_metadata` or non-object `client_metadata` MUST fail closed with 400!
        let dup_ws_frame = br#"{"type":"response.create","client_metadata":{"x-codex-installation-id":"a"},"client_metadata":{"x-codex-installation-id":"b"}}"#;
        assert_eq!(
            normalize_codex_ws_client_frame(dup_ws_frame, &ws_ctx)
                .unwrap_err()
                .status_code(),
            400
        );
        let bad_cm_frame = br#"{"type":"response.create","client_metadata":"not-an-object"}"#;
        assert_eq!(
            normalize_codex_ws_client_frame(bad_cm_frame, &ws_ctx)
                .unwrap_err()
                .status_code(),
            400
        );

        // Non-UTF-8 `x-codex-turn-metadata` header MUST be scrubbed (never forwarded raw!).
        let mut raw_tm_hdrs = HeaderMap::new();
        raw_tm_hdrs.insert(
            "x-codex-turn-metadata",
            HeaderValue::from_bytes(&[0xFF, 0xFE, b'{']).unwrap(),
        );
        let prep_codex = prepare_landing_http_request(
            Method::POST,
            "https://chatgpt.com/backend-api/codex/responses",
            &raw_tm_hdrs,
            Bytes::from_static(br#"{"input":"hi"}"#),
            &dummy_claims("openai"),
            Some(&codex_cred),
            false,
        )
        .unwrap();
        assert!(!prep_codex.headers.contains_key("x-codex-turn-metadata"));

        // Claude duplicate `metadata.user_id` or duplicate `metadata` keys MUST fail closed with 400!
        let dup_claude = br#"{"metadata":{"user_id":"user_deadbeef_account_old_session_sess-1","user_id":"{\"device_id\":\"raw-local-dev\",\"account_uuid\":\"old\",\"session_id\":\"sess-2\"}"},"messages":[]}"#;
        assert_eq!(
            rewrite_claude_metadata_user_id_surgical(
                dup_claude,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "acct-uuid-99",
                1,
                26,
            )
            .unwrap_err()
            .status_code(),
            400
        );
        let dup_meta = br#"{"metadata":{"user_id":"user_deadbeef_account_old_session_sess-1"},"metadata":{"user_id":"user_deadbeef_account_old_session_sess-2"}}"#;
        assert_eq!(
            rewrite_claude_metadata_user_id_surgical(
                dup_meta,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "acct-uuid-99",
                1,
                26,
            )
            .unwrap_err()
            .status_code(),
            400
        );
        // Unnormalizable `metadata.user_id` must also fail closed with 400!
        let bad_uid = br#"{"metadata":{"user_id":"opaque-unrecognized-id"},"messages":[]}"#;
        assert_eq!(
            rewrite_claude_metadata_user_id_surgical(
                bad_uid,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "acct-uuid-99",
                1,
                26,
            )
            .unwrap_err()
            .status_code(),
            400
        );

        // Malformed JSON before `client_metadata` MUST fail closed with 400 (never look absent!).
        let malformed_cm = br#"{"broken": [1,2 "client_metadata":{"x-codex-installation-id":"leak"}}"#;
        assert_eq!(
            normalize_codex_ws_client_frame(malformed_cm, &ws_ctx)
                .unwrap_err()
                .status_code(),
            400
        );

        // Blank or non-string present Claude `session_id` MUST fail closed with 400!
        for bad_sess_body in [
            br#"{"metadata":{"user_id":"{\"device_id\":\"d\",\"account_uuid\":\"a\",\"session_id\":\"\"}"},"messages":[]}"#.as_slice(),
            br#"{"metadata":{"user_id":"{\"device_id\":\"d\",\"account_uuid\":\"a\",\"session_id\":123}"},"messages":[]}"#.as_slice(),
        ] {
            assert_eq!(
                rewrite_claude_metadata_user_id_surgical(
                    bad_sess_body,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "acct-uuid-99",
                    1,
                    26,
                )
                .unwrap_err()
                .status_code(),
                400
            );
        }

        // Unresolved duplicate `x-stainless-os` headers must not survive when unresolvable.
        let mut bad_stainless_hdrs = HeaderMap::new();
        bad_stainless_hdrs.append("x-stainless-os", HeaderValue::from_static("WeirdOS1"));
        bad_stainless_hdrs.append("x-stainless-os", HeaderValue::from_static("WeirdOS2"));
        let empty_cage_cred = UpstreamCredentialDto {
            account_id: 26,
            platform: "anthropic".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs.clone(),
            base_url: "https://api.anthropic.com".into(),
            expires_at_unix: 9999999999,
            cage_identity: None,
        };
        let prep_claude = prepare_landing_http_request(
            Method::POST,
            "https://api.anthropic.com/v1/messages",
            &bad_stainless_hdrs,
            Bytes::from_static(br#"{"messages":[]}"#),
            &dummy_claims("anthropic"),
            Some(&empty_cage_cred),
            false,
        )
        .unwrap();
        assert!(!prep_claude.headers.contains_key("x-stainless-os"));

        // Direct `/v1internal:*` rejects malformed JSON or non-object JSON with 400!
        let agy_cred = UpstreamCredentialDto {
            account_id: 25,
            platform: "antigravity".into(),
            account_type: "oauth".into(),
            headers: cred_hdrs,
            base_url: "https://daily-cloudcode-pa.googleapis.com".into(),
            expires_at_unix: 9999999999,
            cage_identity: Some(cage),
        };
        for bad_body in [b"{bad".as_slice(), b"[1,2,3]".as_slice(), b"\"scalar\"".as_slice(), b"".as_slice()] {
            let err = prepare_landing_http_request(
                Method::POST,
                "https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent",
                &HeaderMap::new(),
                Bytes::from_static(bad_body),
                &dummy_claims("antigravity"),
                Some(&agy_cred),
                false,
            )
            .unwrap_err();
            assert_eq!(err.status_code(), 400);
        }
    }
}
