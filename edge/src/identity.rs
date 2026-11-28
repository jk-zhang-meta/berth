//! Strict per-platform outbound header allowlists, Cage identity convergence,
//! byte-preserving surgical JSON body normalization, and Google Antigravity
//! Gemini-REST <-> Cloud Code `v1internal` wire bridging on Landing Edge nodes.

use std::collections::HashMap;

use bytes::Bytes;
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
const BERTH_SESSION_UUID_NS: Uuid = Uuid::from_bytes([
    0x6b, 0x1e, 0x9f, 0x41, 0x7c, 0x2d, 0x4a, 0x8b, 0x91, 0x5c, 0x3e, 0x77, 0xa2, 0xd4, 0x56, 0x09,
]);

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
) -> PreparedUpstreamRequest {
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
            prepare_anthropic_oauth_http(method, up_url, client_headers, body, claims, cred, cage)
        }
        ("openai" | "codex", "oauth") => prepare_openai_codex_oauth_http(
            method,
            up_url,
            client_headers,
            body,
            claims,
            cred,
            cage,
            is_failover_retry,
        ),
        ("antigravity", "oauth") => {
            prepare_antigravity_oauth_http(method, up_url, client_headers, body, claims, cred, cage)
        }
        _ => prepare_generic_allowlisted_http(method, up_url, client_headers, body, claims, cred),
    }
}

/// Builds strictly allowlisted, Cage-converged WebSocket upgrade headers for Landing execution.
pub fn prepare_landing_ws_headers(
    client_headers: &HeaderMap,
    claims: &SessionLeaseClaims,
    cred: Option<&UpstreamCredentialDto>,
) -> HeaderMap {
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
        let mut h = prepared.headers;
        // Preserve RFC 6455 subprotocol header if the client requested one.
        if let Some(proto) = client_headers.get("sec-websocket-protocol") {
            h.insert(
                HeaderName::from_static("sec-websocket-protocol"),
                proto.clone(),
            );
        }
        return h;
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
    dst
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
) -> PreparedUpstreamRequest {
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
    // Preserve genuine client-sent x-stainless-* headers; only backfill missing fields
    // from Berth's internal X-Berth-Exec-* hint and then Account Cage defaults.
    let exec_hint = resolve_exec_os_hint(client_headers);
    insert_header_str(&mut dst, "x-stainless-lang", "js");
    if !dst.contains_key("x-stainless-os") {
        if let Some(os) = exec_hint.os_family {
            insert_header_str(&mut dst, "x-stainless-os", os);
        } else if let Some(c) = cage.filter(|c| !c.client_os.is_empty()) {
            insert_header_str(&mut dst, "x-stainless-os", &c.client_os);
        }
    }
    if !dst.contains_key("x-stainless-arch") {
        if let Some(arch) = exec_hint.arch {
            insert_header_str(&mut dst, "x-stainless-arch", arch);
        } else if let Some(c) = cage.filter(|c| !c.client_arch.is_empty()) {
            insert_header_str(&mut dst, "x-stainless-arch", &c.client_arch);
        }
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
    // 1) metadata.user_id: inject Cage device_id + real OAuth account_uuid + account-scoped session_id
    // 2) sync X-Claude-Code-Session-Id header to the exact same session_id
    // 3) sync system[0] x-anthropic-billing-header cc_version ONLY if version differs from final_ua
    if !body.is_empty() && method == Method::POST {
        let mut raw = body.to_vec();
        if let Some(c) = cage {
            if !c.claude_device_id.is_empty() || !c.claude_account_uuid.is_empty() {
                let (patched, synced_session) = rewrite_claude_metadata_user_id_surgical(
                    &raw,
                    &c.claude_device_id,
                    &c.claude_account_uuid,
                    claims.api_key_id,
                    claims.account_id,
                );
                if let Some(new_raw) = patched {
                    raw = new_raw;
                }
                if let Some(sid) = synced_session {
                    if dst.contains_key("x-claude-code-session-id") {
                        insert_header_str(&mut dst, "x-claude-code-session-id", &sid);
                    }
                }
            }
        }
        if let Some(new_raw) = sync_claude_billing_header_surgical(&raw, &effective_ver) {
            raw = new_raw;
        }
        body = Bytes::from(raw);
    }

    PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    }
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
) -> PreparedUpstreamRequest {
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
    let (codex_os, codex_arch) = resolve_codex_os_arch(&client_ua, client_headers, cage);
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
    let install_id = cage
        .map(|c| c.codex_installation_id.trim())
        .filter(|s| !s.is_empty());
    if fp_mode != "off" {
        if let Some(iid) = install_id {
            insert_header_str(&mut dst, "x-codex-installation-id", iid);
            let exec_sandbox = codex_sandbox_for_os(&codex_os);
            if let Some(raw_tm) = dst
                .get("x-codex-turn-metadata")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                if let Some(rewritten_tm) =
                    rewrite_codex_turn_metadata_json(&raw_tm, iid, exec_sandbox)
                {
                    insert_header_str(&mut dst, "x-codex-turn-metadata", &rewritten_tm);
                }
            }
            if !body.is_empty() && method == Method::POST {
                let mut raw = body.to_vec();
                if let Some(patched) =
                    rewrite_codex_body_client_metadata_surgical(&raw, iid, exec_sandbox)
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

    PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    }
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
) -> PreparedUpstreamRequest {
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
        return PreparedUpstreamRequest {
            method,
            url: up_url.to_string(),
            headers: dst,
            body,
            agy_bridge: AntigravityBridgeMode::None,
        };
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
        return PreparedUpstreamRequest {
            method: Method::POST,
            url: format!("{origin}/v1internal:fetchAvailableModels"),
            headers: dst,
            body: req_body,
            agy_bridge: AntigravityBridgeMode::ModelsList,
        };
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
                let wrapped = wrap_gemini_body_for_v1internal(&body, &model, project_id);
                return PreparedUpstreamRequest {
                    method: Method::POST,
                    url: target_url,
                    headers: dst,
                    body: Bytes::from(wrapped),
                    agy_bridge: if is_stream {
                        AntigravityBridgeMode::StreamGenerate
                    } else {
                        AntigravityBridgeMode::UnaryGenerate
                    },
                };
            }
        }
    }

    // Direct /v1internal:* passthrough with hardened headers.
    PreparedUpstreamRequest {
        method,
        url: up_url.to_string(),
        headers: dst,
        body,
        agy_bridge: AntigravityBridgeMode::None,
    }
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

fn wrap_gemini_body_for_v1internal(raw: &[u8], model: &str, project_id: &str) -> Vec<u8> {
    let mut inner = serde_json::from_slice::<Value>(raw).unwrap_or_else(|_| Value::Object(Map::new()));
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
    serde_json::to_vec(&Value::Object(envelope)).unwrap_or_else(|_| raw.to_vec())
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
    let first_text = extract_first_claude_user_text(body);
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

fn extract_first_claude_user_text(body: &[u8]) -> String {
    let Ok(val) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let Some(msgs) = val.get("messages").and_then(Value::as_array) else {
        return String::new();
    };
    for msg in msgs {
        if msg.get("role").and_then(Value::as_str) != Some("user") {
            continue;
        }
        if let Some(s) = msg.get("content").and_then(Value::as_str) {
            return s.to_string();
        }
        if let Some(arr) = msg.get("content").and_then(Value::as_array) {
            for blk in arr {
                if blk.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = blk.get("text").and_then(Value::as_str) {
                        return t.to_string();
                    }
                }
            }
        }
        break;
    }
    String::new()
}

/// Surgically rewrites `metadata.user_id` string value in-place without re-serializing
/// any other part of the JSON body. Returns `(patched_body_if_changed, final_session_id)`.
pub fn rewrite_claude_metadata_user_id_surgical(
    body: &[u8],
    cage_device_id: &str,
    account_uuid: &str,
    api_key_id: i64,
    account_id: i64,
) -> (Option<Vec<u8>>, Option<String>) {
    let Some((meta_start, meta_end)) = find_top_level_field_value_span(body, "metadata") else {
        return (None, None);
    };
    let meta_slice = &body[meta_start..meta_end];
    let Some((uid_rel_start, uid_rel_end)) = find_top_level_field_value_span(meta_slice, "user_id")
    else {
        return (None, None);
    };
    let uid_start = meta_start + uid_rel_start;
    let uid_end = meta_start + uid_rel_end;
    let Ok(raw_uid) = serde_json::from_slice::<String>(&body[uid_start..uid_end]) else {
        return (None, None);
    };

    let (new_uid, final_session) = if raw_uid.trim_start().starts_with('{') {
        // New JSON-encoded metadata.user_id format (Claude Code 2.1.x):
        // `{"device_id":"...","account_uuid":"...","session_id":"..."}`
        let Ok(mut obj) = serde_json::from_str::<Map<String, Value>>(&raw_uid) else {
            return (None, None);
        };
        let orig_session = obj
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let scoped_session = if orig_session.is_empty() {
            String::new()
        } else {
            isolate_session_uuid("claude", api_key_id, account_id, &orig_session)
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
        (ordered, sid_opt)
    } else if let Some(rest) = raw_uid.strip_prefix("user_") {
        // Legacy format: `user_<64hex>_account_<uuid>_session_<uuid>`
        let Some((orig_dev, after_acct)) = rest.split_once("_account_") else {
            return (None, None);
        };
        let Some((orig_acct, orig_sess)) = after_acct.split_once("_session_") else {
            return (None, None);
        };
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
        (format!("user_{dev}_account_{acct}_session_{sess}"), Some(sess))
    } else {
        return (None, None);
    };

    if new_uid == raw_uid {
        return (None, final_session);
    }
    let Ok(encoded) = serde_json::to_vec(&new_uid) else {
        return (None, final_session);
    };
    let mut out = Vec::with_capacity(body.len() + encoded.len());
    out.extend_from_slice(&body[..uid_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&body[uid_end..]);
    (Some(out), final_session)
}

/// Surgically updates `cc_version=X.Y.Z.{fp}` in `system[0]`'s `x-anthropic-billing-header`
/// text block ONLY when the version differs from `target_version`. Never touches `system[1..]`
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
    let (cur_ver, has_fp) = split_cc_version_and_fp(cur_token);
    if cur_ver == target_version {
        return None; // Already synced -> keep 100% byte-identical!
    }

    let replacement = if has_fp {
        let fp = compute_claude_code_fingerprint(body, target_version);
        format!("{target_version}.{fp}")
    } else {
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

fn split_cc_version_and_fp(token: &str) -> (&str, bool) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 4
        && parts[3].len() == 3
        && parts[3].bytes().all(|b| b.is_ascii_hexdigit())
    {
        let ver_len = token.len() - 4;
        (&token[..ver_len], true)
    } else {
        (token, false)
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
) -> (String, String) {
    // 1) Real execution CLI User-Agent (matches prompt body `<environment_context>` & shell).
    if let Some((os_str, arch_str)) = parse_codex_ua_os_arch(client_ua) {
        return (os_str, arch_str);
    }
    // 2) Authoritative internal execution-OS hint from Berth CageShim (e.g. macOS Seatbelt
    //    vs Apple Silicon ARM64 Linux Micro-VM vs WSL bwrap).
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
        return (os_str, arch_str);
    }
    // 3) Fallback to Account Cage defaults when no client OS signal is present.
    cage_codex_os_arch(cage)
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

/// Surgically updates ONLY the `client_metadata` JSON object value in a Codex request body
/// (`x-codex-installation-id` + embedded `x-codex-turn-metadata`), leaving `input`, `tools`,
/// `prompt_cache_key`, `reasoning`, etc. 100% byte-identical.
pub fn rewrite_codex_body_client_metadata_surgical(
    body: &[u8],
    install_id: &str,
    cage_sandbox: &str,
) -> Option<Vec<u8>> {
    let (cm_start, cm_end) = find_top_level_field_value_span(body, "client_metadata")?;
    let mut cm_obj: Map<String, Value> = serde_json::from_slice(&body[cm_start..cm_end]).ok()?;
    cm_obj.insert(
        "x-codex-installation-id".to_string(),
        Value::String(install_id.to_string()),
    );
    if let Some(tm_raw) = cm_obj
        .get("x-codex-turn-metadata")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        if let Some(rewritten) = rewrite_codex_turn_metadata_json(&tm_raw, install_id, cage_sandbox)
        {
            cm_obj.insert(
                "x-codex-turn-metadata".to_string(),
                Value::String(rewritten),
            );
        }
    }
    let encoded = serde_json::to_vec(&Value::Object(cm_obj)).ok()?;
    let mut out = Vec::with_capacity(body.len() + encoded.len());
    out.extend_from_slice(&body[..cm_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&body[cm_end..]);
    Some(out)
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

/// Finds the exact `(value_start, value_end)` byte span of a top-level JSON object key.
fn find_top_level_field_value_span(b: &[u8], target_key: &str) -> Option<(usize, usize)> {
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(b, i + 1);
    while i < b.len() {
        if b[i] == b'}' {
            return None;
        }
        let key_end = skip_json_string(b, i)?;
        let key_str = serde_json::from_slice::<String>(&b[i..key_end]).ok()?;
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        let val_start = skip_ws(b, i + 1);
        let val_end = skip_json_value(b, val_start)?;
        if key_str == target_key {
            return Some((val_start, val_end));
        }
        i = skip_ws(b, val_end);
        match b.get(i) {
            Some(&b',') => i = skip_ws(b, i + 1),
            Some(&b'}') => return None,
            _ => return None,
        }
    }
    None
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
        );

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
        assert!(out_str.contains("4937ce527342c18de8a9da49d7dd77527e65c334407f92245fef2413b6aac79e"));
        assert!(out_str.contains("03be3d17-1731-44d3-9c30-13f93416e404"));
        let expected_fp = compute_claude_code_fingerprint(body, "2.1.321");
        assert!(out_str.contains(&format!("cc_version=2.1.321.{expected_fp}")));
        // Header X-Claude-Code-Session-Id synced to rewritten session_id.
        let hdr_sid = out.headers.get("x-claude-code-session-id").unwrap().to_str().unwrap();
        assert_ne!(hdr_sid, "144d2ca6-29f0-46df-9d92-1487a6888e60");
        assert!(out_str.contains(hdr_sid));

        // When client omits x-stainless-os/arch, X-Berth-Exec-OS/Arch backfill cleanly without leaking x-berth-* upstream.
        let mut minimal_hdrs = HeaderMap::new();
        minimal_hdrs.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.321 (external, cli)"));
        minimal_hdrs.insert("x-berth-exec-os", HeaderValue::from_static("Linux"));
        minimal_hdrs.insert("x-berth-exec-arch", HeaderValue::from_static("arm64"));
        let out_min = prepare_landing_http_request(
            Method::POST,
            "https://api.anthropic.com/v1/messages",
            &minimal_hdrs,
            Bytes::from_static(body),
            &dummy_claims("anthropic"),
            Some(&cred),
            false,
        );
        assert_eq!(out_min.headers.get("x-stainless-os").unwrap(), "Linux");
        assert_eq!(out_min.headers.get("x-stainless-arch").unwrap(), "arm64");
        assert!(out_min.headers.get("x-berth-exec-os").is_none());
        assert!(out_min.headers.get("x-berth-exec-arch").is_none());
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
                client_os: "Windows".into(),
                client_arch: "x64".into(),
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
        );

        assert_eq!(out.headers.get("chatgpt-account-id").unwrap(), "real-acct-24");
        assert!(out.headers.get("x-codex-turn-state").is_none());
        assert_eq!(out.headers.get("originator").unwrap(), "codex_exec");
        assert_eq!(out.headers.get("version").unwrap(), "0.172.0");
        // Aligns User-Agent OS/arch and turn-metadata sandbox to real client execution OS (Mac OS 27.0.1; arm64 -> seatbelt),
        // eliminating contradiction with prompt body while still converging installation_id to Cage!
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

        // Linux ARM64 Micro-VM execution aligns to Ubuntu/arm64 + linux-sandbox.
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
        );
        assert!(out_vm.headers.get("user-agent").unwrap().to_str().unwrap().contains("Ubuntu 24.04; arm64"));
        assert!(out_vm.headers.get("x-codex-turn-metadata").unwrap().to_str().unwrap().contains("linux-sandbox"));
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
        );
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
        );
        assert_eq!(fallback_req.headers.get("user-agent").unwrap(), "antigravity/hub/2.23.0 windows/amd64");

        let gen_req = prepare_landing_http_request(
            Method::POST,
            "https://daily-cloudcode-pa.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            &client_hdrs,
            Bytes::from_static(br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#),
            &dummy_claims("antigravity"),
            Some(&cred),
            false,
        );
        assert_eq!(gen_req.agy_bridge, AntigravityBridgeMode::StreamGenerate);
        assert_eq!(gen_req.url, "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse");
        let parsed_body: Value = serde_json::from_slice(&gen_req.body).unwrap();
        assert_eq!(parsed_body["project"], "aicode-consumers");
        assert_eq!(parsed_body["model"], "gemini-2.5-pro");
        assert_eq!(parsed_body["userAgent"], "antigravity");

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
}
