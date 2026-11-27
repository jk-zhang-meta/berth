use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
    SslVersion,
};
use boring::x509::X509;
use boring::x509::store::X509StoreBuilder;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rand::RngCore;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tokio_boring::client::{AsTarget, Connector as BoringConnector, Target as BoringTarget};
use url::Url;

use crate::proto::{SessionLeaseClaims, compute_websocket_accept};
use crate::ssrf::{CompatSsrfGuard, SsrfError};

pub const MAX_OAUTH_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

// Modern Chrome / Bun BoringSSL cipher list (TLS 1.3 + TLS 1.2 AEAD suites).
const BORING_CIPHER_LIST: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
const BORING_CURVES_PQ: &str = "X25519MLKEM768:X25519:P-256:P-384";
const BORING_CURVES_CLASSIC: &str = "X25519:P-256:P-384";
const BORING_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

const ALPN_H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
const ALPN_HTTP1_ONLY: &[u8] = b"\x08http/1.1";

#[derive(Debug, Clone)]
pub struct OAuthHttpResult {
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

struct OwnedTarget {
    host: String,
    port: u16,
}

impl AsTarget for OwnedTarget {
    fn as_target(&self) -> BoringTarget<'_> {
        BoringTarget::new(&self.host, self.port)
    }
}

struct BrotliCertDecompressor;

impl CertificateCompressor for BrotliCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut cursor = io::Cursor::new(input);
        brotli::BrotliDecompress(&mut cursor, output)
            .map_err(|e| io::Error::other(format!("brotli cert decompress: {e}")))
    }
}

fn has_secret_headers(headers: &HeaderMap) -> bool {
    headers.keys().any(|k| {
        matches!(
            k.as_str().to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "x-api-key" | "x-goog-api-key" | "proxy-authorization"
        )
    })
}

fn build_boring_connector(
    alpn: &[u8],
    session_cache_capacity: usize,
) -> Result<Arc<BoringConnector<OwnedTarget>>, UpstreamError> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| UpstreamError::Http(format!("boring ssl builder: {e}")))?;

    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| UpstreamError::Http(format!("boring min tls: {e}")))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| UpstreamError::Http(format!("boring max tls: {e}")))?;

    // Authentic Chrome / Bun BoringSSL ClientHello fingerprint features:
    // GREASE, TLS extension permutation, Brotli cert compression, OCSP stapling, SCT,
    // modern AEAD cipher list, PQ hybrid curves (fallback to classic), and ALPN.
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    let _ = builder.add_certificate_compression_algorithm(BrotliCertDecompressor);

    builder
        .set_cipher_list(BORING_CIPHER_LIST)
        .map_err(|e| UpstreamError::Http(format!("boring ciphers: {e}")))?;
    if builder.set_curves_list(BORING_CURVES_PQ).is_err() {
        builder
            .set_curves_list(BORING_CURVES_CLASSIC)
            .map_err(|e| UpstreamError::Http(format!("boring curves: {e}")))?;
    }
    builder
        .set_sigalgs_list(BORING_SIGALGS)
        .map_err(|e| UpstreamError::Http(format!("boring sigalgs: {e}")))?;
    builder
        .set_alpn_protos(alpn)
        .map_err(|e| UpstreamError::Http(format!("boring alpn: {e}")))?;

    // Load bundled Mozilla roots (webpki-root-certs) so verification never depends on host CA paths.
    let mut store = X509StoreBuilder::new()
        .map_err(|e| UpstreamError::Http(format!("boring root store: {e}")))?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            let _ = store.add_cert(cert);
        }
    }
    builder.set_cert_store(store.build());

    let connector = BoringConnector::with_session_cache_capacity(builder, session_cache_capacity)
        .map_err(|e| UpstreamError::Http(format!("boring connector: {e}")))?;
    Ok(Arc::new(connector))
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct H2PoolKey {
    account_id: i64,
    cage_epoch: i64,
    host: String,
    port: u16,
}

struct CageTlsPair {
    http: Arc<BoringConnector<OwnedTarget>>,
    ws: Arc<BoringConnector<OwnedTarget>>,
}

/// Protocol-level antidetect Account Cage executor on Landing nodes:
/// - Strict IPv4-only SSRF-guarded direct dialing (zero IPv6, zero private/IMDS IPs)
/// - Authentic BoringSSL TLS ClientHello (GREASE, extension permutation, Brotli cert
///   compression, OCSP/SCT, X25519MLKEM768/X25519, ALPN `h2` + `http/1.1`)
/// - Isolated per-(account_id, cage_epoch) BoringSSL TLS session cache AND persistent
///   multiplexed HTTP/2 connection pool so tickets/sockets NEVER cross account boundaries
/// - Monotonic `cage_epoch` bump atomically wipes previous TLS sessions AND H2 connections
/// - Geo-aligned `Accept-Language` derived from `SessionLeaseClaims.cohort_locale`
pub struct LandingCageExecutor {
    guard: Arc<CompatSsrfGuard>,
    state: Mutex<CagePoolState>,
}

struct CagePoolState {
    account_epoch: HashMap<i64, i64>,
    tls_connectors: HashMap<AccountCageKey, Arc<CageTlsPair>>,
    h2_senders: HashMap<H2PoolKey, hyper::client::conn::http2::SendRequest<Full<Bytes>>>,
}

impl LandingCageExecutor {
    pub fn new(guard: Arc<CompatSsrfGuard>) -> Arc<Self> {
        Arc::new(Self {
            guard,
            state: Mutex::new(CagePoolState {
                account_epoch: HashMap::new(),
                tls_connectors: HashMap::new(),
                h2_senders: HashMap::new(),
            }),
        })
    }

    pub fn guard(&self) -> &Arc<CompatSsrfGuard> {
        &self.guard
    }

    pub fn evict_account(&self, account_id: i64) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.tls_connectors.retain(|k, _| k.account_id != account_id);
        st.h2_senders.retain(|k, _| k.account_id != account_id);
    }

    fn connectors_for(
        &self,
        account_id: i64,
        cage_epoch: i64,
    ) -> Result<Arc<CageTlsPair>, UpstreamError> {
        // Never share TLS session tickets across unassociated / OAuth signup calls.
        if account_id <= 0 || cage_epoch <= 0 {
            return Ok(Arc::new(CageTlsPair {
                http: build_boring_connector(ALPN_H2_HTTP1, 0)?,
                ws: build_boring_connector(ALPN_HTTP1_ONLY, 0)?,
            }));
        }
        let key = AccountCageKey {
            account_id,
            cage_epoch,
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&prev) = st.account_epoch.get(&account_id) {
            if cage_epoch < prev {
                return Err(UpstreamError::Http(format!(
                    "stale cage_epoch {cage_epoch} < current {prev} for account {account_id}"
                )));
            }
            if cage_epoch > prev {
                st.tls_connectors.retain(|k, _| k.account_id != account_id);
                st.h2_senders.retain(|k, _| k.account_id != account_id);
            }
        }
        let cur = st.account_epoch.entry(account_id).or_insert(0);
        if cage_epoch > *cur {
            *cur = cage_epoch;
        }
        if let Some(pair) = st.tls_connectors.get(&key) {
            return Ok(Arc::clone(pair));
        }
        let pair = Arc::new(CageTlsPair {
            http: build_boring_connector(ALPN_H2_HTTP1, 16)?,
            ws: build_boring_connector(ALPN_HTTP1_ONLY, 16)?,
        });
        st.tls_connectors.insert(key, Arc::clone(&pair));
        Ok(pair)
    }

    fn get_pooled_h2(
        &self,
        account_id: i64,
        cage_epoch: i64,
        host: &str,
        port: u16,
    ) -> Option<hyper::client::conn::http2::SendRequest<Full<Bytes>>> {
        if account_id <= 0 || cage_epoch <= 0 {
            return None;
        }
        let key = H2PoolKey {
            account_id,
            cage_epoch,
            host: host.to_string(),
            port,
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sender) = st.h2_senders.get(&key) {
            if !sender.is_closed() {
                return Some(sender.clone());
            }
            st.h2_senders.remove(&key);
        }
        None
    }

    fn put_pooled_h2(
        &self,
        account_id: i64,
        cage_epoch: i64,
        host: &str,
        port: u16,
        sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    ) {
        if account_id <= 0 || cage_epoch <= 0 || sender.is_closed() {
            return;
        }
        let key = H2PoolKey {
            account_id,
            cage_epoch,
            host: host.to_string(),
            port,
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.account_epoch.get(&account_id).copied().unwrap_or(0) > cage_epoch {
            return; // Cage epoch advanced while dialing; never insert stale connection.
        }
        st.h2_senders.insert(key, sender);
    }

    fn remove_pooled_h2(&self, account_id: i64, cage_epoch: i64, host: &str, port: u16) {
        if account_id <= 0 || cage_epoch <= 0 {
            return;
        }
        let key = H2PoolKey {
            account_id,
            cage_epoch,
            host: host.to_string(),
            port,
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.h2_senders.remove(&key);
    }

    async fn dial_validated_boring_tls(
        &self,
        host: &str,
        port: u16,
        connector: &BoringConnector<OwnedTarget>,
    ) -> Result<SslStream<TcpStream>, UpstreamError> {
        let tcp = self.guard.dial_validated_tcp(host, port).await?;
        let target = OwnedTarget {
            host: host.to_string(),
            port,
        };
        tokio::time::timeout(Duration::from_secs(15), connector.connect(&target, tcp))
            .await
            .map_err(|_| UpstreamError::Http(format!("TLS handshake timeout {host}:{port}")))?
            .map_err(|e| UpstreamError::Http(format!("TLS handshake {host}:{port}: {e}")))
    }

    /// Executes an SSRF-guarded HTTP/2 (with HTTP/1.1 fallback) request over BoringSSL
    /// with strict HTTPS enforcement and same-origin-guarded redirect following.
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
        self.do_http_inner(
            method, raw_url, headers, body, account_id, cage_epoch, locale, true,
        )
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
            let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
                host.clone()
            } else {
                format!("{host}:{port}")
            };

            let resp = if is_https {
                // Ensure cage_epoch monotonicity is enforced BEFORE touching any pooled H2 socket!
                let pair = self.connectors_for(account_id, cage_epoch)?;
                let h2_uri: Uri = format!("https://{host_header}{path_and_query}")
                    .parse()
                    .map_err(|e| UpstreamError::Http(format!("invalid h2 uri: {e}")))?;

                // 1) Fast path: reuse live multiplexed HTTP/2 connection bound strictly to this Account Cage.
                let mut pooled_resp = None;
                if let Some(mut sender) = self.get_pooled_h2(account_id, cage_epoch, &host, port) {
                    if sender.ready().await.is_ok() {
                        let req_h2 = build_hyper_request(
                            cur_method.clone(),
                            h2_uri.clone(),
                            None,
                            &headers,
                            cur_body.clone(),
                            account_id,
                            locale,
                            true,
                        )?;
                        match sender.send_request(req_h2).await {
                            Ok(r) => pooled_resp = Some(r),
                            Err(_) => {
                                self.remove_pooled_h2(account_id, cage_epoch, &host, port);
                            }
                        }
                    } else {
                        self.remove_pooled_h2(account_id, cage_epoch, &host, port);
                    }
                }

                if let Some(r) = pooled_resp {
                    r
                } else {
                    // 2) Dial validated IPv4 TCP + BoringSSL TLS with ALPN ["h2", "http/1.1"].
                    let tls_stream = self
                        .dial_validated_boring_tls(&host, port, &pair.http)
                        .await?;
                    let negotiated_h2 = tls_stream.ssl().selected_alpn_protocol() == Some(b"h2");
                    if negotiated_h2 {
                        let mut sender = handshake_http2_over_io(tls_stream).await?;
                        if sender.ready().await.is_err() {
                            return Err(UpstreamError::Http("http2 sender closed after handshake".into()));
                        }
                        self.put_pooled_h2(account_id, cage_epoch, &host, port, sender.clone());
                        let req_h2 = build_hyper_request(
                            cur_method.clone(),
                            h2_uri,
                            None,
                            &headers,
                            cur_body.clone(),
                            account_id,
                            locale,
                            true,
                        )?;
                        sender
                            .send_request(req_h2)
                            .await
                            .map_err(|e| UpstreamError::Http(format!("http2 request: {e}")))?
                    } else {
                        let h1_uri: Uri = path_and_query
                            .parse()
                            .map_err(|e| UpstreamError::Http(format!("invalid path `{path_and_query}`: {e}")))?;
                        let req_h1 = build_hyper_request(
                            cur_method.clone(),
                            h1_uri,
                            Some(&host_header),
                            &headers,
                            cur_body.clone(),
                            account_id,
                            locale,
                            false,
                        )?;
                        send_http1_over_io(tls_stream, req_h1).await?
                    }
                }
            } else {
                let tcp = self.guard.dial_validated_tcp(&host, port).await?;
                let h1_uri: Uri = path_and_query
                    .parse()
                    .map_err(|e| UpstreamError::Http(format!("invalid path `{path_and_query}`: {e}")))?;
                let req_h1 = build_hyper_request(
                    cur_method.clone(),
                    h1_uri,
                    Some(&host_header),
                    &headers,
                    cur_body.clone(),
                    account_id,
                    locale,
                    false,
                )?;
                send_http1_over_io(tcp, req_h1).await?
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
                    let (next_host, next_port, _) =
                        self.guard.validate_http_url(next_url.as_str())?;
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

    /// Executes an SSRF-guarded OAuth/refresh/quota HTTP request over the account's exact
    /// BoringSSL + HTTP/2 Cage session pool (or no-resumption pool when `account_id <= 0`),
    /// preserving exact raw bytes and multi-valued response headers.
    #[allow(clippy::too_many_arguments)]
    pub async fn do_oauth_http(
        &self,
        method: Method,
        raw_url: &str,
        headers: HeaderMap,
        body: Bytes,
        account_id: i64,
        cage_epoch: i64,
        locale: &str,
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
                    cage_epoch,
                    locale,
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

    /// Dials an RFC 6455 WebSocket connection over an SSRF-guarded IPv4 TCP + BoringSSL stream
    /// (negotiating `http/1.1` ALPN strictly for RFC 6455 `101 Switching Protocols`).
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
        let (account_id, cage_epoch, locale) = match lease {
            Some(l) => (l.account_id, l.cage_epoch, l.cohort_locale.as_str()),
            None => (0, 0, ""),
        };
        let stream: BoxedWsIo = if is_tls {
            let pair = self.connectors_for(account_id, cage_epoch)?;
            let tls = self.dial_validated_boring_tls(&host, port, &pair.ws).await?;
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
        let has_accept_lang = headers.contains_key(http::header::ACCEPT_LANGUAGE);
        if !has_accept_lang && !locale.is_empty() {
            req.push_str(&format!(
                "Accept-Language: {}\r\n",
                accept_language_for_locale(locale)
            ));
        }
        for (k, v) in headers {
            let lk = k.as_str().to_ascii_lowercase();
            if lk == "host"
                || lk == "upgrade"
                || lk == "connection"
                || lk.starts_with("sec-websocket-")
            {
                if lk != "sec-websocket-protocol" {
                    continue;
                }
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
impl WsIo for SslStream<TcpStream> {}
pub type BoxedWsIo = Box<dyn WsIo>;
pub type BoxedWsStream = BufReader<BoxedWsIo>;

#[allow(clippy::too_many_arguments)]
fn build_hyper_request(
    method: Method,
    uri: Uri,
    host_header: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    account_id: i64,
    locale: &str,
    is_h2: bool,
) -> Result<Request<Full<Bytes>>, UpstreamError> {
    let mut req_builder = Request::builder().method(method).uri(uri);
    if is_h2 {
        req_builder = req_builder.version(http::Version::HTTP_2);
    } else if let Some(host_h) = host_header {
        req_builder = req_builder.header(http::header::HOST, host_h);
    }

    let has_accept_lang = headers.contains_key(http::header::ACCEPT_LANGUAGE);
    let enforce_accept_lang = !has_accept_lang && (account_id > 0 || !locale.is_empty()) && !locale.is_empty();
    if enforce_accept_lang {
        if let Ok(val) = HeaderValue::from_str(&accept_language_for_locale(locale)) {
            req_builder = req_builder.header(http::header::ACCEPT_LANGUAGE, val);
        }
    }
    for (k, v) in headers {
        let lk = k.as_str().to_ascii_lowercase();
        // RFC 9113 §8.2.2 forbids connection-specific headers on HTTP/2; also strip hop-by-hop on H1.
        if matches!(
            lk.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "upgrade"
                | "te"
        ) {
            continue;
        }
        req_builder = req_builder.header(k.clone(), v.clone());
    }
    req_builder
        .body(Full::new(body))
        .map_err(|e| UpstreamError::Http(format!("build upstream req: {e}")))
}

async fn handshake_http2_over_io<IO>(
    io: IO,
) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, UpstreamError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .initial_stream_window_size(6_291_456)
        .initial_connection_window_size(15_728_640)
        .max_header_list_size(262_144)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true);

    let (sender, conn) = builder
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| UpstreamError::Http(format!("http2 handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

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
    rewrite_url_for_credential_base_strict(raw_up_url, raw_base_url)
        .unwrap_or_else(|_| raw_up_url.to_string())
}

/// Fail-closed URL rewrite against Central's authoritative credential base_url (S-5).
/// Returns an error if `raw_base_url` is non-empty yet malformed or lacks a host so
/// credentials are NEVER sent to a caller-supplied fallback origin.
pub fn rewrite_url_for_credential_base_strict(
    raw_up_url: &str,
    raw_base_url: &str,
) -> Result<String, UpstreamError> {
    let raw_base = raw_base_url.trim();
    if raw_base.is_empty() {
        return Ok(raw_up_url.to_string());
    }
    let orig = Url::parse(raw_up_url)
        .map_err(|e| UpstreamError::Http(format!("invalid upstream target url: {e}")))?;
    let base = Url::parse(raw_base)
        .map_err(|e| UpstreamError::Http(format!("invalid credential base_url: {e}")))?;
    let Some(base_host) = base.host_str().filter(|h| !h.is_empty()) else {
        return Err(UpstreamError::Http("credential base_url missing host".into()));
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
    Ok(match orig.query() {
        Some(q) => format!("{scheme}://{host_port}{final_path}?{q}"),
        None => format!("{scheme}://{host_port}{final_path}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_url_rewrite_and_boring_cage_isolation() {
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
        // S-5: strict rewrite fails closed on malformed base_url and treats x-goog-api-key as secret.
        assert!(
            rewrite_url_for_credential_base_strict(
                "https://api.openai.com/v1/responses",
                "://bad-url"
            )
            .is_err()
        );
        let mut h = HeaderMap::new();
        h.insert("x-goog-api-key", HeaderValue::from_static("AIza-secret"));
        assert!(has_secret_headers(&h));

        // C-9: LandingCageExecutor builds BoringSSL connectors and rejects stale cage_epoch regression.
        let exec = LandingCageExecutor::new(Arc::new(CompatSsrfGuard::new(&[], &[])));
        assert!(exec.connectors_for(23, 3).is_ok());
        assert!(exec.connectors_for(23, 2).is_err());
        assert!(exec.connectors_for(23, 4).is_ok());
        // No-resumption connector builds cleanly for unassociated OAuth signup.
        assert!(exec.connectors_for(0, 0).is_ok());
    }
}
