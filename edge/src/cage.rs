use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rustls::ClientConfig;
use rustls::client::ClientSessionMemoryCache;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use url::Url;

use crate::proto::{SessionLeaseClaims, compute_websocket_accept};
use crate::ssrf::{CompatSsrfGuard, SsrfError, build_default_root_store};

pub const MAX_OAUTH_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct OAuthHttpResult {
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

fn has_secret_headers(headers: &HeaderMap) -> bool {
    headers.keys().any(|k| {
        matches!(
            k.as_str().to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "x-api-key" | "proxy-authorization"
        )
    })
}

fn build_no_resumption_tls_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe TLS versions")
        .with_root_certificates(build_default_root_store())
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error(transparent)]
    Ssrf(#[from] SsrfError),
    #[error("landing cage: {0}")]
    Http(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AccountCageKey {
    account_id: i64,
    cage_epoch: i64,
}

/// Protocol-level antidetect Account Cage executor on Landing nodes:
/// - Strict IPv4-only SSRF-guarded direct dialing (zero IPv6, zero private/IMDS IPs)
/// - Isolated per-(account_id, cage_epoch) TLS `ClientConfig` + `ClientSessionMemoryCache`
///   so TLS session tickets/PSKs NEVER cross account boundaries
/// - Monotonic `cage_epoch` bump atomically wipes previous account TLS session cache
/// - Geo-aligned `Accept-Language` derived from `SessionLeaseClaims.cohort_locale`
pub struct LandingCageExecutor {
    guard: Arc<CompatSsrfGuard>,
    state: Mutex<CagePoolState>,
}

struct CagePoolState {
    account_epoch: HashMap<i64, i64>,
    tls_configs: HashMap<AccountCageKey, Arc<ClientConfig>>,
}

impl LandingCageExecutor {
    pub fn new(guard: Arc<CompatSsrfGuard>) -> Arc<Self> {
        Arc::new(Self {
            guard,
            state: Mutex::new(CagePoolState {
                account_epoch: HashMap::new(),
                tls_configs: HashMap::new(),
            }),
        })
    }

    pub fn guard(&self) -> &Arc<CompatSsrfGuard> {
        &self.guard
    }

    pub fn evict_account(&self, account_id: i64) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.tls_configs.retain(|k, _| k.account_id != account_id);
    }

    fn tls_config_for(&self, account_id: i64, cage_epoch: i64) -> Arc<ClientConfig> {
        // Never share TLS session tickets across unassociated / OAuth signup calls (account_id <= 0).
        if account_id <= 0 {
            return build_no_resumption_tls_config();
        }
        let key = AccountCageKey {
            account_id,
            cage_epoch,
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&prev) = st.account_epoch.get(&account_id) {
            if cage_epoch > prev {
                st.tls_configs.retain(|k, _| k.account_id != account_id);
            }
        }
        let cur = st.account_epoch.entry(account_id).or_insert(0);
        if cage_epoch > *cur {
            *cur = cage_epoch;
        }
        if let Some(cfg) = st.tls_configs.get(&key) {
            return Arc::clone(cfg);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe TLS versions")
            .with_root_certificates(build_default_root_store())
            .with_no_client_auth();
        // Isolated per-account TLS session resumption cache!
        cfg.resumption = rustls::client::Resumption::store(Arc::new(
            ClientSessionMemoryCache::new(16),
        ));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let arc = Arc::new(cfg);
        st.tls_configs.insert(key, Arc::clone(&arc));
        arc
    }

    /// Executes an SSRF-guarded HTTP/SSE request with strict HTTPS enforcement and optional
    /// same-origin-guarded redirect following (never forwards secrets across origins).
    pub async fn do_http(
        &self,
        method: Method,
        raw_url: &str,
        headers: HeaderMap,
        body: Bytes,
        lease: Option<&SessionLeaseClaims>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        let (account_id, cage_epoch, locale) = match lease {
            Some(l) => (l.account_id, l.cage_epoch, l.cohort_locale.as_str()),
            None => (0, 0, ""),
        };
        self.do_http_inner(method, raw_url, headers, body, account_id, cage_epoch, locale, true)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_http_inner(
        &self,
        method: Method,
        raw_url: &str,
        headers: HeaderMap,
        body: Bytes,
        account_id: i64,
        cage_epoch: i64,
        locale: &str,
        follow_redirects: bool,
    ) -> Result<Response<Incoming>, UpstreamError> {
        let mut cur_url = raw_url.to_string();
        let mut cur_method = method;
        let mut cur_body = body;
        let carries_secrets = has_secret_headers(&headers);
        let mut initial_origin: Option<(String, String, u16)> = None;

        let max_hops = if follow_redirects { 5 } else { 0 };
        for redirects in 0..=max_hops {
            let (host, port, _is_test) = self.guard.validate_http_url(&cur_url)?;
            let parsed = Url::parse(&cur_url)
                .map_err(|e| UpstreamError::Http(format!("invalid url: {e}")))?;
            let scheme_lc = parsed.scheme().to_ascii_lowercase();
            let is_https = scheme_lc == "https";
            let cur_origin = (scheme_lc, host.clone(), port);
            if let Some(ref orig) = initial_origin {
                if carries_secrets && orig != &cur_origin {
                    return Err(UpstreamError::Http(format!(
                        "blocked cross-origin redirect for credential-bearing request: {}:{} -> {}:{}",
                        orig.1, orig.2, cur_origin.1, cur_origin.2
                    )));
                }
            } else {
                initial_origin = Some(cur_origin);
            }

            let path_and_query = match parsed.query() {
                Some(q) => format!("{}?{q}", parsed.path()),
                None => parsed.path().to_string(),
            };
            let uri: Uri = path_and_query
                .parse()
                .map_err(|e| UpstreamError::Http(format!("invalid path `{path_and_query}`: {e}")))?;

            let mut req_builder = Request::builder().method(cur_method.clone()).uri(uri);
            let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            req_builder = req_builder.header(http::header::HOST, host_header);
            if !headers.contains_key(http::header::ACCEPT_LANGUAGE) && !locale.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&accept_language_for_locale(locale)) {
                    req_builder = req_builder.header(http::header::ACCEPT_LANGUAGE, val);
                }
            }
            for (k, v) in &headers {
                let lk = k.as_str().to_ascii_lowercase();
                if matches!(
                    lk.as_str(),
                    "host" | "connection" | "transfer-encoding" | "content-length" | "upgrade"
                ) {
                    continue;
                }
                req_builder = req_builder.header(k.clone(), v.clone());
            }
            let req = req_builder
                .body(Full::new(cur_body.clone()))
                .map_err(|e| UpstreamError::Http(format!("build upstream req: {e}")))?;

            let resp = if is_https {
                let tls_cfg = self.tls_config_for(account_id, cage_epoch);
                let tls_stream = self.guard.dial_validated_tls(&host, port, tls_cfg).await?;
                send_http1_over_io(tls_stream, req).await?
            } else {
                let tcp = self.guard.dial_validated_tcp(&host, port).await?;
                send_http1_over_io(tcp, req).await?
            };

            let status = resp.status();
            if follow_redirects && status.is_redirection() {
                if let Some(loc) = resp.headers().get(http::header::LOCATION) {
                    if redirects == max_hops {
                        return Err(UpstreamError::Http("too many upstream redirects".into()));
                    }
                    let loc_str = loc
                        .to_str()
                        .map_err(|_| UpstreamError::Http("non-utf8 redirect Location".into()))?;
                    let next_url = parsed
                        .join(loc_str)
                        .map_err(|e| UpstreamError::Http(format!("bad redirect url: {e}")))?;
                    let (next_host, next_port, _) = self.guard.validate_http_url(next_url.as_str())?;
                    let next_origin = (next_url.scheme().to_ascii_lowercase(), next_host, next_port);
                    if carries_secrets && initial_origin.as_ref() != Some(&next_origin) {
                        return Err(UpstreamError::Http(format!(
                            "blocked cross-origin redirect for credential-bearing request to {}:{}",
                            next_origin.1, next_origin.2
                        )));
                    }
                    cur_url = next_url.to_string();
                    if matches!(
                        status,
                        http::StatusCode::MOVED_PERMANENTLY
                            | http::StatusCode::FOUND
                            | http::StatusCode::SEE_OTHER
                    ) && cur_method != Method::GET
                        && cur_method != Method::HEAD
                    {
                        cur_method = Method::GET;
                        cur_body = Bytes::new();
                    }
                    continue;
                }
            }
            return Ok(resp);
        }
        Err(UpstreamError::Http("too many upstream redirects".into()))
    }

    /// Executes an SSRF-guarded OAuth/refresh HTTP request under a single end-to-end deadline,
    /// streaming response frames up to `MAX_OAUTH_RESPONSE_BYTES` and preserving exact raw bytes
    /// and multi-valued response headers (including `Set-Cookie` and `Location`).
    pub async fn do_oauth_http(
        &self,
        method: Method,
        raw_url: &str,
        headers: HeaderMap,
        body: Bytes,
        account_id: i64,
        follow_redirects: bool,
    ) -> Result<OAuthHttpResult, UpstreamError> {
        let fut = async {
            let resp = self
                .do_http_inner(
                    method,
                    raw_url,
                    headers,
                    body,
                    account_id,
                    0,
                    "",
                    follow_redirects,
                )
                .await?;
            let status = resp.status().as_u16();
            let mut resp_headers: HashMap<String, Vec<String>> = HashMap::new();
            for (k, v) in resp.headers() {
                if let Ok(vs) = v.to_str() {
                    resp_headers
                        .entry(k.as_str().to_string())
                        .or_default()
                        .push(vs.to_string());
                }
            }
            let mut body_stream = resp.into_body();
            let mut out = Vec::new();
            while let Some(frame_res) = body_stream.frame().await {
                let frame = frame_res
                    .map_err(|e| UpstreamError::Http(format!("read OAuth response frame: {e}")))?;
                if let Some(data) = frame.data_ref() {
                    if out.len().saturating_add(data.len()) > MAX_OAUTH_RESPONSE_BYTES {
                        return Err(UpstreamError::Http(format!(
                            "upstream OAuth response body exceeds {} bytes",
                            MAX_OAUTH_RESPONSE_BYTES
                        )));
                    }
                    out.extend_from_slice(data);
                }
            }
            Ok(OAuthHttpResult {
                status,
                headers: resp_headers,
                body: out,
            })
        };
        tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .map_err(|_| UpstreamError::Http("upstream OAuth request timed out".into()))?
    }

    /// Dials an RFC 6455 WebSocket connection over an SSRF-guarded IPv4 TCP/TLS stream.
    pub async fn dial_websocket(
        &self,
        target_url: &str,
        headers: &HeaderMap,
        lease: Option<&SessionLeaseClaims>,
    ) -> Result<BoxedWsStream, UpstreamError> {
        let (host, port, _is_test) = self.guard.validate_ws_url(target_url)?;
        let parsed = Url::parse(target_url)
            .map_err(|e| UpstreamError::Http(format!("invalid ws url: {e}")))?;
        let is_tls = parsed.scheme().eq_ignore_ascii_case("wss");
        let (account_id, cage_epoch) = match lease {
            Some(l) => (l.account_id, l.cage_epoch),
            None => (0, 0),
        };
        let stream: BoxedWsIo = if is_tls {
            let tls_cfg = self.tls_config_for(account_id, cage_epoch);
            let tls = self.guard.dial_validated_tls(&host, port, tls_cfg).await?;
            Box::new(tls)
        } else {
            let tcp = self.guard.dial_validated_tcp(&host, port).await?;
            Box::new(tcp)
        };

        let mut key_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let sec_key = STANDARD.encode(key_bytes);

        let path = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => {
                if parsed.path().is_empty() {
                    "/".to_string()
                } else {
                    parsed.path().to_string()
                }
            }
        };
        let host_hdr = if (is_tls && port == 443) || (!is_tls && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };

        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {sec_key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        for (k, v) in headers {
            let lk = k.as_str().to_ascii_lowercase();
            if lk == "host"
                || lk == "upgrade"
                || lk == "connection"
                || lk.starts_with("sec-websocket-")
            {
                continue;
            }
            if let Ok(vs) = v.to_str() {
                req.push_str(&format!("{}: {vs}\r\n", k.as_str()));
            }
        }
        req.push_str("\r\n");

        let mut br = BufReader::new(stream);
        br.get_mut()
            .write_all(req.as_bytes())
            .await
            .map_err(|e| UpstreamError::Http(format!("ws handshake write: {e}")))?;
        br.get_mut()
            .flush()
            .await
            .map_err(|e| UpstreamError::Http(format!("ws handshake flush: {e}")))?;

        let mut status_line = String::new();
        br.read_line(&mut status_line)
            .await
            .map_err(|e| UpstreamError::Http(format!("ws status read: {e}")))?;
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let mut accept_hdr = String::new();
        loop {
            let mut line = String::new();
            let n = br
                .read_line(&mut line)
                .await
                .map_err(|e| UpstreamError::Http(format!("ws header read: {e}")))?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                    accept_hdr = v.trim().to_string();
                }
            }
        }
        if status_code != 101 {
            return Err(UpstreamError::Http(format!(
                "upstream ws upgrade rejected with status {status_code}"
            )));
        }
        if accept_hdr != compute_websocket_accept(&sec_key) {
            return Err(UpstreamError::Http(
                "upstream ws invalid Sec-WebSocket-Accept".into(),
            ));
        }
        Ok(br)
    }
}

pub trait WsIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl WsIo for TcpStream {}
impl WsIo for TlsStream<TcpStream> {}
pub type BoxedWsIo = Box<dyn WsIo>;
pub type BoxedWsStream = BufReader<BoxedWsIo>;

async fn send_http1_over_io<IO>(
    io: IO,
    req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, UpstreamError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| UpstreamError::Http(format!("http1 handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| UpstreamError::Http(format!("http1 request: {e}")))
}

pub fn accept_language_for_locale(locale: &str) -> String {
    let mut l = locale.trim().to_string();
    if let Some(idx) = l.find(['.', '@']) {
        l.truncate(idx);
    }
    l = l.replace('_', "-");
    if l.is_empty() || l.eq_ignore_ascii_case("C") || l.eq_ignore_ascii_case("POSIX") {
        return "en-US,en;q=0.9".to_string();
    }
    if let Some((lang_raw, region_raw)) = l.split_once('-') {
        let lang = lang_raw.to_ascii_lowercase();
        if !region_raw.is_empty() {
            let tag = format!("{lang}-{}", region_raw.to_ascii_uppercase());
            if lang == "en" {
                return format!("{tag},en;q=0.9");
            }
            return format!("{tag},{lang};q=0.9,en-US;q=0.8,en;q=0.7");
        }
    }
    let lang = l.to_ascii_lowercase();
    if lang == "en" {
        "en-US,en;q=0.9".to_string()
    } else {
        format!("{lang},en-US;q=0.8,en;q=0.7")
    }
}

pub fn apply_credential_headers(dst: &mut HeaderMap, headers: &HashMap<String, String>) {
    for (k, raw_v) in headers {
        let v = raw_v.trim();
        if k.is_empty() || v.is_empty() {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else {
            continue;
        };
        if k.eq_ignore_ascii_case("anthropic-beta") {
            if let Some(existing) = dst.get(&name).and_then(|hv| hv.to_str().ok()) {
                let existing = existing.trim();
                if !existing.is_empty() {
                    let mut merged: Vec<String> = Vec::new();
                    for tok in existing.split(',').chain(v.split(',')) {
                        let t = tok.trim();
                        if !t.is_empty() && !merged.iter().any(|m| m == t) {
                            merged.push(t.to_string());
                        }
                    }
                    if let Ok(hv) = HeaderValue::from_str(&merged.join(",")) {
                        dst.insert(name, hv);
                    }
                    continue;
                }
            }
        }
        if let Ok(hv) = HeaderValue::from_str(v) {
            dst.insert(name, hv);
        }
    }
}

pub fn rewrite_url_for_credential_base(raw_up_url: &str, raw_base_url: &str) -> String {
    let raw_base = raw_base_url.trim();
    if raw_base.is_empty() {
        return raw_up_url.to_string();
    }
    let (Ok(orig), Ok(base)) = (Url::parse(raw_up_url), Url::parse(raw_base)) else {
        return raw_up_url.to_string();
    };
    let Some(base_host) = base.host_str() else {
        return raw_up_url.to_string();
    };
    let mut scheme = if base.scheme().is_empty() {
        orig.scheme().to_string()
    } else {
        base.scheme().to_string()
    };
    match orig.scheme().to_ascii_lowercase().as_str() {
        "wss" => scheme = "wss".into(),
        "ws" => {
            scheme = if base.scheme().eq_ignore_ascii_case("https") {
                "wss".into()
            } else {
                "ws".into()
            };
        }
        _ => {}
    }

    let base_path = base.path().trim_end_matches('/');
    let orig_path = if orig.path().is_empty() {
        "/"
    } else {
        orig.path()
    };
    let final_path = if !base_path.is_empty() {
        if orig_path == base_path || orig_path.starts_with(&format!("{base_path}/")) {
            orig_path.to_string()
        } else if base_path.starts_with("/backend-api/codex") {
            let trimmed = orig_path.strip_prefix("/v1").unwrap_or(orig_path);
            let trimmed = if trimmed.is_empty() || !trimmed.starts_with('/') {
                format!("/{}", trimmed.trim_start_matches('/'))
            } else {
                trimmed.to_string()
            };
            format!("{base_path}{trimmed}")
        } else if base_path.ends_with("/v1")
            && (orig_path == "/v1" || orig_path.starts_with("/v1/"))
        {
            format!("{base_path}{}", orig_path.strip_prefix("/v1").unwrap_or(""))
        } else if orig_path.starts_with('/') {
            format!("{base_path}{orig_path}")
        } else {
            format!("{base_path}/{orig_path}")
        }
    } else {
        orig_path.to_string()
    };

    let host_port = match base.port() {
        Some(p) => format!("{base_host}:{p}"),
        None => base_host.to_string(),
    };
    match orig.query() {
        Some(q) => format!("{scheme}://{host_port}{final_path}?{q}"),
        None => format!("{scheme}://{host_port}{final_path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_and_url_rewrite_match_go_behavior() {
        assert_eq!(accept_language_for_locale("en_SG.UTF-8"), "en-SG,en;q=0.9");
        assert_eq!(
            accept_language_for_locale("ja_JP.UTF-8"),
            "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"
        );
        assert_eq!(
            rewrite_url_for_credential_base(
                "https://api.openai.com/v1/responses?stream=1",
                "https://chatgpt.com/backend-api/codex"
            ),
            "https://chatgpt.com/backend-api/codex/responses?stream=1"
        );
    }
}
