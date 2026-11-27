use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::Stream;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::Service;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, watch};
use tracing::{info, warn};

use crate::admission::{AdmissionError, AdmissionGate, AdmittedStream};
use crate::cage::{LandingCageExecutor, rewrite_url_for_credential_base_strict};
use crate::central::{CentralClient, CredentialError, UpstreamCredentialDto};
use crate::config::{
    Config, ROLE_COMPAT, ROLE_INGRESS_RELAY, ROLE_LANDING, ROLE_TRANSIT, normalize_listen_addr,
};
use crate::identity::{
    AntigravityBridgeMode, AntigravitySseUnwrapper, is_blocked_upstream_response_header,
    prepare_landing_http_request, prepare_landing_ws_headers,
    transform_v1internal_models_response, unwrap_v1internal_unary_response,
};
use crate::proto::{
    DEFAULT_MAX_WS_FRAME_BYTES, HEADER_ACCOUNT_ID, HEADER_CAGE_COHORT,
    HEADER_CONNECT_TARGET, HEADER_HOP_INDEX, HEADER_LANDING_NODE, HEADER_LEASE, HEADER_ROUTE,
    HEADER_UPSTREAM_METHOD, HEADER_UPSTREAM_URL, RouteHop, SessionLeaseClaims, TUNNEL_CONNECT_PATH,
    TUNNEL_EXECUTE_PATH, TUNNEL_WS_BRIDGE_PATH, UsageReceipt, WS_CLOSE_CAGE_REBIND, WS_OP_CLOSE,
    compute_websocket_accept, decode_route_header, encode_route_header, encode_ws_h2_frame,
    now_unix, read_rfc6455_frame, verify_lease, write_rfc6455_close, write_rfc6455_frame,
};
use crate::reverse_tunnel::{EdgeBody, ReverseTunnelHub};
use crate::ssrf::CompatSsrfGuard;
use crate::usage_extract::{ExtractedUsage, UsageStreamSniffer, extract_request_meta};
use crate::wal::OutboxWal;

struct MpscFrameStream {
    rx: mpsc::Receiver<Result<Frame<Bytes>, hyper::Error>>,
}

impl Stream for MpscFrameStream {
    type Item = Result<Frame<Bytes>, hyper::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

fn channel_body(rx: mpsc::Receiver<Result<Frame<Bytes>, hyper::Error>>) -> EdgeBody {
    StreamBody::new(MpscFrameStream { rx }).boxed()
}

fn full_body(bytes: impl Into<Bytes>) -> EdgeBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn text_response(status: u16, msg: impl Into<String>) -> Response<EdgeBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(msg.into()))
        .unwrap()
}

fn json_response(status: u16, val: &serde_json::Value) -> Response<EdgeBody> {
    let raw = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(raw))
        .unwrap()
}

fn admission_error_response(err: &AdmissionError) -> Response<EdgeBody> {
    let (status, code) = err.http_status_and_code();
    json_response(
        status,
        &serde_json::json!({
            "error": {
                "code": code,
                "message": err.to_string(),
            }
        }),
    )
}

#[derive(Clone)]
struct CachedCred {
    cred: UpstreamCredentialDto,
    expires_at: Instant,
}

pub struct EdgeServer {
    cfg: Config,
    central: Option<Arc<CentralClient>>,
    gate: Arc<AdmissionGate>,
    outbox: Option<Arc<OutboxWal>>,
    rev_hub: Option<Arc<ReverseTunnelHub>>,
    upstream: Arc<LandingCageExecutor>,
    ssrf_guard: Arc<CompatSsrfGuard>,
    h2c_client: LegacyClient<HttpConnector, EdgeBody>,
    roles: RwLock<Vec<String>>,
    creds: RwLock<HashMap<String, CachedCred>>,
    conn_sem: Arc<Semaphore>,
    oauth_sem: Arc<Semaphore>,
    oauth_inflight: Mutex<HashSet<String>>,
}

impl EdgeServer {
    pub fn new(
        cfg: Config,
        central: Option<Arc<CentralClient>>,
        gate: Arc<AdmissionGate>,
        outbox: Option<Arc<OutboxWal>>,
        rev_hub: Option<Arc<ReverseTunnelHub>>,
        upstream: Arc<LandingCageExecutor>,
        ssrf_guard: Arc<CompatSsrfGuard>,
    ) -> Arc<Self> {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_secs(10)));
        let h2c_client = LegacyClient::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .http2_only(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(20)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .build(connector);
        let initial_roles = cfg.roles.clone();
        let conn_limit = (cfg.max_concurrent_streams as usize).saturating_mul(4).max(256);
        Arc::new(Self {
            cfg,
            central,
            gate,
            outbox,
            rev_hub,
            upstream,
            ssrf_guard,
            h2c_client,
            roles: RwLock::new(initial_roles),
            creds: RwLock::new(HashMap::new()),
            conn_sem: Arc::new(Semaphore::new(conn_limit)),
            oauth_sem: Arc::new(Semaphore::new(8)),
            oauth_inflight: Mutex::new(HashSet::new()),
        })
    }

    pub fn gate(&self) -> &Arc<AdmissionGate> {
        &self.gate
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|r| r == role)
    }

    pub fn roles(&self) -> Vec<String> {
        self.roles.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn apply_runtime_roles(&self, next: Vec<String>) -> bool {
        let mut cleaned = Vec::with_capacity(next.len());
        for r in next {
            let trimmed = r.trim();
            if !trimmed.is_empty() && !cleaned.iter().any(|x| x == trimmed) {
                cleaned.push(trimmed.to_string());
            }
        }
        if cleaned.is_empty() {
            return false;
        }
        let mut guard = self.roles.write().unwrap_or_else(|e| e.into_inner());
        if *guard != cleaned {
            *guard = cleaned;
            true
        } else {
            false
        }
    }

    pub fn service(self: &Arc<Self>) -> EdgeHttpService {
        EdgeHttpService {
            server: Arc::clone(self),
        }
    }

    pub async fn listen_and_serve(
        self: Arc<Self>,
        listen_addr: &str,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let bind_addr = normalize_listen_addr(listen_addr);
        let listener = TcpListener::bind(&bind_addr).await?;
        info!(
            "berth-edge[{}] data-plane listening on {} roles={:?} (pure Rust HTTP/1.1+h2c)",
            self.cfg.node_name,
            listener.local_addr()?,
            self.roles()
        );
        let max_streams = self.cfg.max_concurrent_streams;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return Ok(()); }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, _peer)) => {
                            let Ok(permit) = Arc::clone(&self.conn_sem).try_acquire_owned() else {
                                warn!("berth-edge[{}] connection intake limit reached; shedding", self.cfg.node_name);
                                drop(stream);
                                continue;
                            };
                            let _ = stream.set_nodelay(true);
                            let svc = self.service();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let mut builder = AutoServerBuilder::new(TokioExecutor::new());
                                builder.http2().max_concurrent_streams(max_streams);
                                let _ = builder
                                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                                    .await;
                            });
                        }
                        Err(e) => warn!("data-plane accept error: {e}"),
                    }
                }
            }
        }
    }

    pub async fn handle_request(self: Arc<Self>, req: Request<Incoming>) -> Response<EdgeBody> {
        let path = req.uri().path().to_string();
        if req.method() == Method::CONNECT {
            return self.handle_ingress_client(req).await;
        }
        match path.as_str() {
            "/healthz" => self.handle_healthz(),
            TUNNEL_EXECUTE_PATH => self.handle_tunnel_execute(req).await,
            TUNNEL_WS_BRIDGE_PATH => self.handle_tunnel_ws_bridge(req).await,
            TUNNEL_CONNECT_PATH => self.handle_tunnel_connect(req).await,
            _ => self.handle_ingress_client(req).await,
        }
    }

    fn handle_healthz(&self) -> Response<EdgeBody> {
        json_response(
            200,
            &serde_json::json!({
                "status": "ok",
                "node_id": self.cfg.node_id,
                "node_name": self.cfg.node_name,
                "roles": self.roles(),
                "active_streams": self.gate.active_stream_count(),
                "runtime": "rust",
            }),
        )
    }

    // ---------- Ingress Client Entry ----------

    async fn handle_ingress_client(self: Arc<Self>, req: Request<Incoming>) -> Response<EdgeBody> {
        let lease_token = extract_bearer_lease(req.headers());
        if lease_token.is_empty() {
            return text_response(401, "missing session lease token");
        }
        let admitted = match self.gate.admit(&lease_token, 0).await {
            Ok(a) => a,
            Err(e) => return admission_error_response(&e),
        };
        let route = admitted.claims().route_chain.clone();
        if !route.is_empty()
            && route[0].node_id != self.cfg.node_id
            && !self.has_role(ROLE_INGRESS_RELAY)
        {
            return text_response(403, "node is not authorized entry hop for this lease");
        }

        if req.method() == Method::CONNECT {
            let connect_target = header_str(req.headers(), HEADER_CONNECT_TARGET)
                .filter(|s| !s.is_empty())
                .or_else(|| req.uri().authority().map(|a| a.to_string()))
                .or_else(|| header_str(req.headers(), "host"))
                .unwrap_or_default();
            if connect_target.is_empty() {
                return text_response(400, "missing CONNECT target host:port");
            }
            return self
                .handle_ingress_connect(req, admitted, lease_token, connect_target)
                .await;
        }

        let target_url = match header_str(req.headers(), HEADER_UPSTREAM_URL).filter(|s| !s.is_empty())
        {
            Some(u) => u,
            None => {
                let req_path = req.uri().path();
                let base = if !self.cfg.default_upstream_base_url.trim().is_empty() {
                    self.cfg
                        .default_upstream_base_url
                        .trim()
                        .trim_end_matches('/')
                        .to_string()
                } else {
                    default_provider_base_url(&admitted.claims().platform, req_path).to_string()
                };
                if base.is_empty() {
                    return text_response(400, "missing upstream target url");
                }
                let pq = req
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");
                format!("{base}{pq}")
            }
        };

        if is_websocket_upgrade(req.headers()) {
            return self
                .handle_ingress_ws(req, admitted, lease_token, target_url)
                .await;
        }

        self.handle_ingress_http(req, admitted, lease_token, target_url)
            .await
    }

    async fn handle_ingress_http(
        self: Arc<Self>,
        req: Request<Incoming>,
        admitted: AdmittedStream,
        lease_token: String,
        target_url: String,
    ) -> Response<EdgeBody> {
        let method = req.method().as_str().to_string();
        let headers = req.headers().clone();
        let body_bytes = match tokio::time::timeout(
            Duration::from_secs(30),
            collect_capped(req.into_body(), 16 * 1024 * 1024),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return text_response(400, format!("failed reading request body: {e}")),
            Err(_) => return text_response(408, "request body read timed out"),
        };

        let mut cur_lease_token = lease_token;
        let mut cur_claims = admitted.claims().clone();
        let mut cur_route = cur_claims.route_chain.clone();
        let mut cur_admitted = admitted;
        let mut cur_headers = headers;

        for attempt in 0..2 {
            // Single-hop direct landing optimization!
            if cur_route.len() <= 1
                && (cur_route.is_empty() || cur_route[0].node_id == self.cfg.node_id)
                && (self.has_role(ROLE_LANDING) || self.has_role(ROLE_COMPAT))
            {
                let resp = self
                    .clone()
                    .execute_landing_http_inner(
                        &cur_lease_token,
                        &method,
                        &target_url,
                        &cur_headers,
                        body_bytes.clone(),
                        attempt > 0,
                    )
                    .await;
                if attempt == 0
                    && matches!(resp.status().as_u16(), 429 | 529)
                    && self.central.is_some()
                {
                    if let Some(alt) = self
                        .try_precommit_failover(&cur_claims, resp.status().as_u16())
                        .await
                    {
                        match alt {
                            FailoverAction::Switched { token, route, claims } => {
                                cur_lease_token = token;
                                cur_route = route;
                                if let Some(c) = claims {
                                    cur_claims = c;
                                }
                                // Strip account-scoped Codex turn state before retrying on a different account.
                                cur_headers.remove("x-codex-turn-state");
                                continue;
                            }
                            FailoverAction::RebindRequired(rebind_resp) => return rebind_resp,
                        }
                    }
                }
                return resp;
            }

            let resp = match self
                .next_hop_dispatch(
                    &cur_route,
                    0,
                    TUNNEL_EXECUTE_PATH,
                    &cur_lease_token,
                    &method,
                    &target_url,
                    &cur_headers,
                    full_body(body_bytes.clone()),
                )
                .await
            {
                Ok(r) => r,
                Err(e) => return text_response(502, format!("tunnel dispatch failed: {e}")),
            };

            let status = resp.status();
            if attempt == 0
                && matches!(status.as_u16(), 429 | 529)
                && self.central.is_some()
            {
                if let Some(alt) = self
                    .try_precommit_failover(&cur_claims, status.as_u16())
                    .await
                {
                    match alt {
                        FailoverAction::Switched { token, route, claims } => {
                            drop(resp);
                            // Re-admit switched lease so stream cancellation watches the NEW lease!
                            let next_admitted = match self.gate.admit(&token, 0).await {
                                Ok(a) => a,
                                Err(e) => return admission_error_response(&e),
                            };
                            cur_admitted = next_admitted;
                            cur_lease_token = token;
                            cur_route = route;
                            if let Some(c) = claims {
                                cur_claims = c;
                            }
                            cur_headers.remove("x-codex-turn-state");
                            continue;
                        }
                        FailoverAction::RebindRequired(rebind_resp) => {
                            drop(resp);
                            return rebind_resp;
                        }
                    }
                }
                // Failover unavailable: preserve real provider 429/529 response (including Retry-After!).
                return stream_incoming_with_revocation(resp, cur_admitted);
            }

            return stream_incoming_with_revocation(resp, cur_admitted);
        }
        text_response(502, "tunnel dispatch exhausted retries")
    }

    async fn try_precommit_failover(
        &self,
        claims: &SessionLeaseClaims,
        status_code: u16,
    ) -> Option<FailoverAction> {
        let central = self.central.as_ref()?;
        let (fo_code, fo_res) = central
            .request_failover(&claims.lease_id, claims.account_id, status_code, &[])
            .await
            .ok()?;
        let res = fo_res?;
        if res.action == "switched" {
            if let Some(lease) = res.lease {
                if !lease.token.is_empty() {
                    let next_claims = self
                        .gate
                        .central_pub_key()
                        .and_then(|pk| verify_lease(pk, &lease.token, now_unix()).ok());
                    return Some(FailoverAction::Switched {
                        token: lease.token,
                        route: lease.route_chain,
                        claims: next_claims,
                    });
                }
            }
        }
        if fo_code == 409 || res.action == "cage_rebind_required" {
            let mut resp = json_response(
                409,
                &serde_json::json!({
                    "error": {
                        "code": "cage_rebind_required",
                        "message": res.message,
                        "recommended_cohort": res.recommended_cohort,
                    }
                }),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-berth-action"),
                HeaderValue::from_static("cage_rebind_required"),
            );
            return Some(FailoverAction::RebindRequired(resp));
        }
        None
    }

    // ---------- Ingress Transparent CONNECT Tunnel ----------

    async fn handle_ingress_connect(
        self: Arc<Self>,
        req: Request<Incoming>,
        admitted: AdmittedStream,
        lease_token: String,
        connect_target: String,
    ) -> Response<EdgeBody> {
        let route = admitted.claims().route_chain.clone();
        let headers = req.headers().clone();

        // Single-hop self-landing CONNECT directly (re-admit with local landing node_id so
        // per-grant concurrency and RPM caps are strictly enforced before dialing).
        if route.len() <= 1
            && (route.is_empty() || route[0].node_id == self.cfg.node_id)
            && (self.has_role(ROLE_LANDING) || self.has_role(ROLE_COMPAT))
        {
            drop(admitted);
            let landing_admitted = match self.gate.admit(&lease_token, self.cfg.node_id).await {
                Ok(a) => a,
                Err(e) => return admission_error_response(&e),
            };
            let target_conn = match self.ssrf_guard.dial_validated_public_tcp(&connect_target).await {
                Ok((c, _)) => c,
                Err(e) => {
                    let sc = if e.is_policy_forbidden() { 403 } else { 502 };
                    self.record_receipt(landing_admitted.claims(), 0, 0, sc, 0, Duration::ZERO);
                    return text_response(sc, format!("connect dial error: {e}"));
                }
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let start = Instant::now();
                let Ok(upgraded) = hyper::upgrade::on(req).await else {
                    return;
                };
                let (in_b, out_b) = splice_upgraded_with_target(
                    TokioIo::new(upgraded),
                    target_conn,
                    &landing_admitted,
                )
                .await;
                me.record_receipt(landing_admitted.claims(), in_b, out_b, 200, 0, start.elapsed());
            });
            return Response::builder()
                .status(StatusCode::OK)
                .body(full_body(Bytes::new()))
                .unwrap();
        }

        let (up_tx, up_rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
        let bridge_resp = match self
            .next_hop_dispatch(
                &route,
                0,
                TUNNEL_CONNECT_PATH,
                &lease_token,
                "CONNECT",
                &connect_target,
                &headers,
                channel_body(up_rx),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return text_response(502, format!("connect tunnel failed: {e}")),
        };

        if bridge_resp.status() != StatusCode::OK {
            let status = bridge_resp.status().as_u16();
            let err_body = collect_capped(bridge_resp.into_body(), 4096)
                .await
                .unwrap_or_default();
            return text_response(status, String::from_utf8_lossy(&err_body).into_owned());
        }

        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                return;
            };
            let (mut client_r, mut client_w) = tokio::io::split(TokioIo::new(upgraded));
            let mut cancel_rx = admitted.cancel_receiver();
            let mut down_body = bridge_resp.into_body();

            let c2u = async {
                let mut buf = [0u8; 32 * 1024];
                loop {
                    match client_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if up_tx
                                .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..n]))))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                drop(up_tx);
            };
            let u2c = async {
                while let Some(frame_res) = down_body.frame().await {
                    let Ok(frame) = frame_res else { break };
                    if let Some(data) = frame.data_ref() {
                        if !data.is_empty() && client_w.write_all(data).await.is_err() {
                            break;
                        }
                    }
                }
                let _ = client_w.shutdown().await;
            };

            tokio::select! {
                _ = wait_revoked(&mut cancel_rx) => {}
                _ = async { tokio::join!(c2u, u2c) } => {}
            }
            drop(admitted);
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(full_body(Bytes::new()))
            .unwrap()
    }

    // ---------- Ingress WebSocket Upgrade ----------

    async fn handle_ingress_ws(
        self: Arc<Self>,
        req: Request<Incoming>,
        admitted: AdmittedStream,
        lease_token: String,
        target_url: String,
    ) -> Response<EdgeBody> {
        let Some(sec_key) = header_str(req.headers(), "sec-websocket-key").filter(|s| !s.is_empty())
        else {
            return text_response(400, "missing Sec-WebSocket-Key");
        };
        let route = admitted.claims().route_chain.clone();
        let headers = req.headers().clone();

        // Single-hop self-landing WebSocket route: bridge directly to upstream after landing admission!
        if route.len() <= 1
            && (route.is_empty() || route[0].node_id == self.cfg.node_id)
            && (self.has_role(ROLE_LANDING) || self.has_role(ROLE_COMPAT))
        {
            drop(admitted);
            let start = Instant::now();
            let landing_admitted = match self.gate.admit(&lease_token, self.cfg.node_id).await {
                Ok(a) => a,
                Err(e) => return admission_error_response(&e),
            };
            let claims = landing_admitted.claims().clone();
            let mut up_url = target_url;
            let cred = match self.resolve_upstream_credential(&claims).await {
                Ok(c) => c,
                Err(e) => {
                    let sc = match e {
                        CredentialError::Forbidden(_) => 403,
                        CredentialError::Unavailable(_) => 502,
                    };
                    self.record_receipt(&claims, 0, 0, sc, 0, start.elapsed());
                    return text_response(sc, e.to_string());
                }
            };
            if let Some(ref c) = cred {
                if !c.headers.is_empty() && c.base_url.trim().is_empty() {
                    self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
                    return text_response(403, "upstream credential missing authoritative base_url");
                }
                if !c.base_url.is_empty() {
                    match rewrite_url_for_credential_base_strict(&up_url, &c.base_url) {
                        Ok(rewritten) => up_url = rewritten,
                        Err(e) => {
                            self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
                            return text_response(403, format!("invalid upstream credential base_url: {e}"));
                        }
                    }
                }
            }
            let up_headers = prepare_landing_ws_headers(&headers, &claims, cred.as_ref());
            let up_ws = match self
                .upstream
                .dial_websocket(&up_url, &up_headers, Some(&claims))
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let sc = match &e {
                        crate::cage::UpstreamError::Ssrf(se) if se.is_policy_forbidden() => 403,
                        _ => 502,
                    };
                    self.record_receipt(&claims, 0, 0, sc, 0, start.elapsed());
                    return text_response(sc, format!("upstream ws error: {e}"));
                }
            };
            let accept = compute_websocket_accept(&sec_key);
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let Ok(upgraded) = hyper::upgrade::on(req).await else {
                    return;
                };
                let (client_r, client_w) = tokio::io::split(TokioIo::new(upgraded));
                let client_w = tokio::sync::Mutex::new(client_w);
                let mut client_br = BufReader::new(client_r);
                let (ws_r, mut ws_w) = tokio::io::split(up_ws);
                let mut ws_br = BufReader::new(ws_r);
                let mut cancel_rx = landing_admitted.cancel_receiver();
                let in_b = AtomicI64::new(0);
                let out_b = AtomicI64::new(0);
                let ttft_ms = AtomicI64::new(0);
                let sniffer = Mutex::new(UsageStreamSniffer::new_ws(extract_request_meta(&up_url, &[])));

                let c2u = async {
                    loop {
                        let Ok((op, payload)) =
                            read_rfc6455_frame(&mut client_br, DEFAULT_MAX_WS_FRAME_BYTES).await
                        else {
                            break;
                        };
                        if !payload.is_empty() && (op & 0x0F) != WS_OP_CLOSE {
                            if landing_admitted.pre_debit(payload.len() as i64).await.is_err() {
                                let mut cw = client_w.lock().await;
                                let _ = write_rfc6455_close(
                                    &mut *cw,
                                    WS_CLOSE_CAGE_REBIND,
                                    "landing_grant_exhausted",
                                    false,
                                )
                                .await;
                                break;
                            }
                            in_b.fetch_add(payload.len() as i64, Ordering::Relaxed);
                            if (op & 0x0F) == 1 {
                                sniffer
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .feed_ws_client_text(&payload);
                            }
                        }
                        if write_rfc6455_frame(&mut ws_w, op, &payload, true).await.is_err() {
                            break;
                        }
                        if (op & 0x0F) == WS_OP_CLOSE {
                            break;
                        }
                    }
                };
                let u2c = async {
                    loop {
                        let Ok((op, payload)) =
                            read_rfc6455_frame(&mut ws_br, DEFAULT_MAX_WS_FRAME_BYTES).await
                        else {
                            break;
                        };
                        if !payload.is_empty() && (op & 0x0F) != WS_OP_CLOSE {
                            if ttft_ms.load(Ordering::Relaxed) == 0 {
                                let _ = ttft_ms.compare_exchange(
                                    0,
                                    (start.elapsed().as_millis() as i64).max(1),
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                );
                            }
                            if landing_admitted.pre_debit(payload.len() as i64).await.is_err() {
                                let mut cw = client_w.lock().await;
                                let _ = write_rfc6455_close(
                                    &mut *cw,
                                    WS_CLOSE_CAGE_REBIND,
                                    "landing_grant_exhausted",
                                    false,
                                )
                                .await;
                                break;
                            }
                            out_b.fetch_add(payload.len() as i64, Ordering::Relaxed);
                            if (op & 0x0F) == 1 {
                                sniffer
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .feed_ws_server_text(&payload);
                            }
                        }
                        let write_res = {
                            let mut cw = client_w.lock().await;
                            write_rfc6455_frame(&mut *cw, op, &payload, false).await
                        };
                        if write_res.is_err() {
                            break;
                        }
                        if (op & 0x0F) == WS_OP_CLOSE {
                            break;
                        }
                    }
                };
                let mut revoked = false;
                tokio::select! {
                    _ = wait_revoked(&mut cancel_rx) => {
                        revoked = true;
                    }
                    _ = async { tokio::join!(c2u, u2c) } => {}
                }
                if revoked {
                    let mut cw = client_w.lock().await;
                    let _ = write_rfc6455_close(&mut *cw, WS_CLOSE_CAGE_REBIND, "stream_revoked", false).await;
                    let _ = write_rfc6455_close(&mut ws_w, WS_CLOSE_CAGE_REBIND, "stream_revoked", true).await;
                }
                let extracted = sniffer.into_inner().unwrap_or_else(|e| e.into_inner()).finish();
                me.record_receipt_with_usage(
                    &claims,
                    in_b.load(Ordering::Relaxed),
                    out_b.load(Ordering::Relaxed),
                    101,
                    ttft_ms.load(Ordering::Relaxed),
                    start.elapsed(),
                    Some(extracted),
                );
                drop(landing_admitted);
            });
            return Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::UPGRADE, "websocket")
                .header(http::header::CONNECTION, "Upgrade")
                .header("Sec-WebSocket-Accept", accept)
                .body(full_body(Bytes::new()))
                .unwrap();
        }

        let (up_tx, up_rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
        let bridge_resp = match self
            .next_hop_dispatch(
                &route,
                0,
                TUNNEL_WS_BRIDGE_PATH,
                &lease_token,
                "GET",
                &target_url,
                &headers,
                channel_body(up_rx),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return text_response(502, format!("ws bridge failed: {e}")),
        };
        if bridge_resp.status() != StatusCode::OK {
            let status = bridge_resp.status().as_u16();
            let err_body = collect_capped(bridge_resp.into_body(), 4096)
                .await
                .unwrap_or_default();
            return text_response(status, String::from_utf8_lossy(&err_body).into_owned());
        }

        let accept = compute_websocket_accept(&sec_key);
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else {
                return;
            };
            let (client_r, mut client_w) = tokio::io::split(TokioIo::new(upgraded));
            let mut client_br = BufReader::new(client_r);
            let mut cancel_rx = admitted.cancel_receiver();
            let mut down_reader = IncomingFrameReader::new(bridge_resp.into_body());

            let c2u = async {
                loop {
                    let Ok((op, payload)) =
                        read_rfc6455_frame(&mut client_br, DEFAULT_MAX_WS_FRAME_BYTES).await
                    else {
                        break;
                    };
                    let raw = encode_ws_h2_frame(op, &payload);
                    if up_tx.send(Ok(Frame::data(Bytes::from(raw)))).await.is_err() {
                        break;
                    }
                    if (op & 0x0F) == WS_OP_CLOSE {
                        break;
                    }
                }
                drop(up_tx);
            };
            let u2c = async {
                loop {
                    let Ok((op, payload)) = down_reader.read_ws_h2_frame().await else {
                        break;
                    };
                    if write_rfc6455_frame(&mut client_w, op, &payload, false)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if (op & 0x0F) == WS_OP_CLOSE {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = wait_revoked(&mut cancel_rx) => {
                    let _ = write_rfc6455_close(&mut client_w, WS_CLOSE_CAGE_REBIND, "stream_revoked", false).await;
                }
                _ = c2u => {}
                _ = u2c => {}
            }
            drop(admitted);
        });

        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONNECTION, "Upgrade")
            .header("Sec-WebSocket-Accept", accept)
            .body(full_body(Bytes::new()))
            .unwrap()
    }

    // ---------- Multi-Hop Tunnel Dispatch ----------

    #[allow(clippy::too_many_arguments)]
    async fn next_hop_dispatch(
        &self,
        route: &[RouteHop],
        cur_hop_idx: usize,
        path: &str,
        lease_token: &str,
        method: &str,
        target: &str,
        orig_headers: &HeaderMap,
        body: EdgeBody,
    ) -> anyhow::Result<Response<Incoming>> {
        let next_idx = cur_hop_idx + 1;
        if route.is_empty() || next_idx >= route.len() {
            anyhow::bail!("no next hop in route (len={}, cur={cur_hop_idx})", route.len());
        }
        let next_hop = &route[next_idx];
        let route_hdr = encode_route_header(route)?;
        let req_uri_str = if next_hop.link_class == "reverse_tunnel" {
            format!("http://node-{}.edge.internal{path}", next_hop.node_id)
        } else {
            format!("http://{}{path}", next_hop.addr)
        };
        let uri: Uri = req_uri_str.parse()?;

        let mut builder = Request::builder().method(Method::POST).uri(uri);
        let conn_nominated = connection_nominated_headers(orig_headers);
        for (k, v) in orig_headers {
            let lk = k.as_str().to_ascii_lowercase();
            if is_hop_by_hop(&lk)
                || lk.starts_with("x-berth-")
                || conn_nominated.contains(lk.as_str())
            {
                continue;
            }
            builder = builder.header(k.clone(), v.clone());
        }
        builder = builder
            .header(HEADER_ROUTE, route_hdr)
            .header(HEADER_HOP_INDEX, next_idx.to_string())
            .header(HEADER_LEASE, lease_token)
            .header(HEADER_UPSTREAM_METHOD, method);
        if path == TUNNEL_CONNECT_PATH {
            builder = builder.header(HEADER_CONNECT_TARGET, target);
        } else {
            builder = builder.header(HEADER_UPSTREAM_URL, target);
        }

        let fwd_req = builder.body(body)?;
        if next_hop.link_class == "reverse_tunnel" {
            let hub = self
                .rev_hub
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("reverse tunnel hub unavailable"))?;
            Ok(hub.round_trip(next_hop.node_id, fwd_req).await?)
        } else {
            Ok(self.h2c_client.request(fwd_req).await?)
        }
    }

    // ---------- Authenticated Tunnel Route Verification ----------

    async fn authenticate_tunnel_hop(
        &self,
        headers: &HeaderMap,
    ) -> Result<(AdmittedStream, String, Vec<RouteHop>, usize), Response<EdgeBody>> {
        let (hdr_route, hop_idx) = parse_route_and_hop(headers)?;
        let lease_token = single_bearer_lease(headers)?;
        if lease_token.is_empty() {
            return Err(text_response(401, "missing session lease token"));
        }
        let is_landing_hop = hop_idx == hdr_route.len() - 1;
        let expected_landing = if is_landing_hop { self.cfg.node_id } else { 0 };
        let admitted = self
            .gate
            .admit(&lease_token, expected_landing)
            .await
            .map_err(|e| admission_error_response(&e))?;
        let signed_route = admitted.claims().route_chain.clone();
        if signed_route.is_empty() || signed_route != hdr_route {
            return Err(text_response(
                403,
                "tunnel route header conflicts with signed lease route",
            ));
        }
        if hop_idx >= signed_route.len() || signed_route[hop_idx].node_id != self.cfg.node_id {
            return Err(text_response(403, "route hop node mismatch"));
        }
        if !is_landing_hop
            && !self.has_role(ROLE_TRANSIT)
            && !self.has_role(ROLE_INGRESS_RELAY)
        {
            return Err(text_response(403, "transit/ingress role not enabled"));
        }
        if is_landing_hop && !self.has_role(ROLE_LANDING) && !self.has_role(ROLE_COMPAT) {
            return Err(text_response(403, "landing/compat role not enabled"));
        }
        Ok((admitted, lease_token, signed_route, hop_idx))
    }

    // ---------- /edge/v1/execute (Transit + Landing) ----------

    async fn handle_tunnel_execute(self: Arc<Self>, req: Request<Incoming>) -> Response<EdgeBody> {
        let headers = req.headers().clone();
        let (admitted, lease_tok, signed_route, hop_idx) =
            match self.authenticate_tunnel_hop(&headers).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        let up_method = match single_header_opt(&headers, HEADER_UPSTREAM_METHOD) {
            Ok(Some(m)) if !m.is_empty() => m,
            Ok(_) => "POST".into(),
            Err(resp) => return resp,
        };
        let up_url = match single_header_opt(&headers, HEADER_UPSTREAM_URL) {
            Ok(Some(u)) if !u.is_empty() => u,
            Ok(_) => return text_response(400, "missing X-Berth-Upstream-URL"),
            Err(resp) => return resp,
        };

        if hop_idx < signed_route.len() - 1 {
            let body = req.into_body().boxed();
            return match self
                .next_hop_dispatch(
                    &signed_route,
                    hop_idx,
                    TUNNEL_EXECUTE_PATH,
                    &lease_tok,
                    &up_method,
                    &up_url,
                    &headers,
                    body,
                )
                .await
            {
                Ok(resp) => stream_incoming_with_revocation(resp, admitted),
                Err(e) => text_response(502, format!("transit hop failed: {e}")),
            };
        }

        // Landing hop: already authenticated & admitted BEFORE reading request body!
        let body_bytes = match tokio::time::timeout(
            Duration::from_secs(30),
            collect_capped(req.into_body(), 16 * 1024 * 1024),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return text_response(400, format!("failed reading request stream: {e}")),
            Err(_) => return text_response(408, "request stream read timed out"),
        };
        self.execute_landing_http_admitted(admitted, &up_method, &up_url, &headers, body_bytes, false)
            .await
    }

    async fn execute_landing_http_inner(
        self: Arc<Self>,
        lease_token: &str,
        up_method_str: &str,
        raw_up_url: &str,
        orig_headers: &HeaderMap,
        body_bytes: Bytes,
        is_failover_retry: bool,
    ) -> Response<EdgeBody> {
        if !self.has_role(ROLE_LANDING) && !self.has_role(ROLE_COMPAT) {
            return text_response(403, "landing/compat role not enabled");
        }
        let admitted = match self.gate.admit(lease_token, self.cfg.node_id).await {
            Ok(a) => a,
            Err(e) => return admission_error_response(&e),
        };
        self.execute_landing_http_admitted(
            admitted,
            up_method_str,
            raw_up_url,
            orig_headers,
            body_bytes,
            is_failover_retry,
        )
        .await
    }

    async fn execute_landing_http_admitted(
        self: Arc<Self>,
        admitted: AdmittedStream,
        up_method_str: &str,
        raw_up_url: &str,
        orig_headers: &HeaderMap,
        body_bytes: Bytes,
        is_failover_retry: bool,
    ) -> Response<EdgeBody> {
        let start = Instant::now();
        let claims = admitted.claims().clone();

        // Pre-debit ingress bytes BEFORE contacting upstream (and fail closed on 0-byte GETs if grant is exhausted)!
        let mut ingress_bytes = 0i64;
        if body_bytes.is_empty() {
            if let Err(e) = admitted.ensure_grant_capacity().await {
                self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
                return admission_error_response(&e);
            }
        }
        let chunk_sz = (self.cfg.pre_debit_chunk_size.min(32 * 1024) as usize).max(1024);
        for chunk in body_bytes.chunks(chunk_sz) {
            if let Err(e) = admitted.pre_debit(chunk.len() as i64).await {
                self.record_receipt(&claims, ingress_bytes, 0, 403, 0, start.elapsed());
                return admission_error_response(&e);
            }
            ingress_bytes += chunk.len() as i64;
        }

        let cred = match self.resolve_upstream_credential(&claims).await {
            Ok(c) => c,
            Err(e) => {
                let (sc, code) = match e {
                    CredentialError::Forbidden(_) => (403, "upstream_credential_forbidden"),
                    CredentialError::Unavailable(_) => (502, "upstream_credential_unavailable"),
                };
                self.record_receipt(&claims, ingress_bytes, 0, sc, 0, start.elapsed());
                return json_response(
                    sc,
                    &serde_json::json!({ "error": { "code": code, "message": e.to_string() } }),
                );
            }
        };

        let mut up_url = raw_up_url.to_string();
        if let Some(ref c) = cred {
            if !c.headers.is_empty() && c.base_url.trim().is_empty() {
                self.record_receipt(&claims, ingress_bytes, 0, 403, 0, start.elapsed());
                return text_response(403, "upstream credential missing authoritative base_url");
            }
            if !c.base_url.is_empty() {
                match rewrite_url_for_credential_base_strict(&up_url, &c.base_url) {
                    Ok(rewritten) => up_url = rewritten,
                    Err(e) => {
                        self.record_receipt(&claims, ingress_bytes, 0, 403, 0, start.elapsed());
                        return text_response(403, format!("invalid upstream credential base_url: {e}"));
                    }
                }
            }
        }

        let req_meta = extract_request_meta(&up_url, &body_bytes);
        let raw_method = Method::from_bytes(up_method_str.as_bytes()).unwrap_or(Method::POST);
        let prepared = prepare_landing_http_request(
            raw_method,
            &up_url,
            orig_headers,
            body_bytes,
            &claims,
            cred.as_ref(),
            is_failover_retry,
        );
        let agy_bridge = prepared.agy_bridge;

        let up_resp = match self
            .upstream
            .do_http(
                prepared.method,
                &prepared.url,
                prepared.headers,
                prepared.body,
                Some(&claims),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let sc = match &e {
                    crate::cage::UpstreamError::Ssrf(se) if se.is_policy_forbidden() => 403,
                    _ => 502,
                };
                self.record_receipt(&claims, ingress_bytes, 0, sc, 0, start.elapsed());
                return text_response(sc, format!("upstream error: {e}"));
            }
        };

        let status = up_resp.status();
        if status == StatusCode::UNAUTHORIZED && cred.is_some() {
            self.evict_upstream_credential(&claims.lease_id, claims.account_id);
        }

        let is_sse = up_resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));
        let content_encoding = up_resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let is_compressed = content_encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|s| !s.eq_ignore_ascii_case("identity"));

        // Non-streaming Antigravity v1internal bridge transformations (ModelsList / UnaryGenerate).
        if status.is_success()
            && !is_compressed
            && matches!(
                agy_bridge,
                AntigravityBridgeMode::ModelsList | AntigravityBridgeMode::UnaryGenerate
            )
        {
            let raw_body = match collect_capped(up_resp.into_body(), 16 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    self.record_receipt(&claims, ingress_bytes, 0, 502, 0, start.elapsed());
                    return text_response(502, format!("read upstream response failed: {e}"));
                }
            };
            let transformed = match agy_bridge {
                AntigravityBridgeMode::ModelsList => transform_v1internal_models_response(&raw_body),
                AntigravityBridgeMode::UnaryGenerate => unwrap_v1internal_unary_response(&raw_body),
                _ => raw_body.to_vec(),
            };
            if let Err(e) = admitted.pre_debit(transformed.len() as i64).await {
                self.record_receipt(&claims, ingress_bytes, 0, 403, 0, start.elapsed());
                return admission_error_response(&e);
            }
            let mut sniffer = UsageStreamSniffer::new_http(req_meta, false, None);
            sniffer.feed_http_chunk(&transformed);
            let extracted = sniffer.finish();
            let ttft_ms = (start.elapsed().as_millis() as i64).max(1);
            self.record_receipt_with_usage(
                &claims,
                ingress_bytes,
                transformed.len() as i64,
                status.as_u16(),
                ttft_ms,
                start.elapsed(),
                Some(extracted),
            );
            return Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header(HEADER_ACCOUNT_ID, claims.account_id.to_string())
                .header(HEADER_LANDING_NODE, self.cfg.node_name.clone())
                .header(
                    HEADER_CAGE_COHORT,
                    format!(
                        "{}:{}:{}",
                        claims.platform, claims.cohort_country_code, claims.cohort_timezone
                    ),
                )
                .body(full_body(transformed))
                .unwrap();
        }

        let mut resp_builder = Response::builder().status(status);
        for (k, v) in up_resp.headers() {
            // Strip hop-by-hop AND any upstream-spoofed `x-berth-*` control headers!
            if !is_hop_by_hop(k.as_str()) && !is_blocked_upstream_response_header(k.as_str()) {
                resp_builder = resp_builder.header(k.clone(), v.clone());
            }
        }
        resp_builder = resp_builder
            .header(HEADER_ACCOUNT_ID, claims.account_id.to_string())
            .header(HEADER_LANDING_NODE, self.cfg.node_name.clone())
            .header(
                HEADER_CAGE_COHORT,
                format!(
                    "{}:{}:{}",
                    claims.platform, claims.cohort_country_code, claims.cohort_timezone
                ),
            );

        let unwrap_agy_sse =
            status.is_success() && !is_compressed && agy_bridge == AntigravityBridgeMode::StreamGenerate;

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
        let me = Arc::clone(&self);
        tokio::spawn(async move {
            let mut body = up_resp.into_body();
            let mut egress_bytes = 0i64;
            let mut ttft_ms = 0i64;
            let mut cancel_rx = admitted.cancel_receiver();
            let mut sniffer =
                UsageStreamSniffer::new_http(req_meta, is_sse, content_encoding.as_deref());
            let mut agy_unwrapper = unwrap_agy_sse.then(AntigravitySseUnwrapper::default);

            loop {
                tokio::select! {
                    _ = wait_revoked(&mut cancel_rx) => {
                        // Never append plaintext SSE error bytes into a compressed stream!
                        if is_sse && !is_compressed {
                            let _ = tx.send(Ok(Frame::data(Bytes::from_static(
                                b"event: error\ndata: {\"code\":\"cage_rebind_required\",\"reason\":\"stream_revoked\"}\n\n"
                            )))).await;
                        }
                        break;
                    }
                    frame_opt = body.frame() => {
                        match frame_opt {
                            Some(Ok(frame)) => {
                                if let Some(data) = frame.data_ref() {
                                    if data.is_empty() {
                                        continue;
                                    }
                                    let out_chunk: Bytes = if let Some(ref mut unwrapper) = agy_unwrapper {
                                        let unwrapped = unwrapper.push_chunk(data);
                                        if unwrapped.is_empty() {
                                            continue;
                                        }
                                        Bytes::from(unwrapped)
                                    } else {
                                        data.clone()
                                    };
                                    if ttft_ms == 0 {
                                        ttft_ms = (start.elapsed().as_millis() as i64).max(1);
                                    }
                                    sniffer.feed_http_chunk(&out_chunk);
                                    match admitted.pre_debit_up_to(out_chunk.len() as i64).await {
                                        Ok(allowed) => {
                                            let n = (allowed as usize).min(out_chunk.len());
                                            if n > 0 {
                                                if tx.send(Ok(Frame::data(out_chunk.slice(..n)))).await.is_err() {
                                                    break;
                                                }
                                                egress_bytes += n as i64;
                                            }
                                            if n < out_chunk.len() {
                                                if is_sse && !is_compressed {
                                                    let _ = tx.send(Ok(Frame::data(Bytes::from_static(
                                                        b"event: error\ndata: {\"code\":\"landing_grant_exhausted\"}\n\n"
                                                    )))).await;
                                                }
                                                break;
                                            }
                                        }
                                        Err(_) => {
                                            if is_sse && !is_compressed {
                                                let _ = tx.send(Ok(Frame::data(Bytes::from_static(
                                                    b"event: error\ndata: {\"code\":\"landing_grant_exhausted\"}\n\n"
                                                )))).await;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            Some(Err(_)) | None => {
                                if let Some(ref mut unwrapper) = agy_unwrapper {
                                    let tail = unwrapper.finish();
                                    if !tail.is_empty() {
                                        sniffer.feed_http_chunk(&tail);
                                        if let Ok(allowed) = admitted.pre_debit_up_to(tail.len() as i64).await {
                                            let n = (allowed as usize).min(tail.len());
                                            if n > 0 {
                                                let _ = tx.send(Ok(Frame::data(Bytes::from(tail[..n].to_vec())))).await;
                                                egress_bytes += n as i64;
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            let extracted = sniffer.finish();
            me.record_receipt_with_usage(
                &claims,
                ingress_bytes,
                egress_bytes,
                status.as_u16(),
                ttft_ms,
                start.elapsed(),
                Some(extracted),
            );
            drop(admitted);
        });

        resp_builder.body(channel_body(rx)).unwrap()
    }

    // ---------- /edge/v1/connect (Transit + Landing) ----------

    async fn handle_tunnel_connect(self: Arc<Self>, req: Request<Incoming>) -> Response<EdgeBody> {
        let headers = req.headers().clone();
        let (admitted, lease_tok, signed_route, hop_idx) =
            match self.authenticate_tunnel_hop(&headers).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        let connect_target = match single_header_opt(&headers, HEADER_CONNECT_TARGET) {
            Ok(Some(t)) if !t.is_empty() => t,
            Ok(_) => return text_response(400, "missing X-Berth-Connect-Target"),
            Err(resp) => return resp,
        };
        if hop_idx < signed_route.len() - 1 {
            return match self
                .next_hop_dispatch(
                    &signed_route,
                    hop_idx,
                    TUNNEL_CONNECT_PATH,
                    &lease_tok,
                    "CONNECT",
                    &connect_target,
                    &headers,
                    req.into_body().boxed(),
                )
                .await
            {
                Ok(resp) => stream_incoming_with_revocation(resp, admitted),
                Err(e) => text_response(502, format!("transit connect hop failed: {e}")),
            };
        }

        let start = Instant::now();
        let claims = admitted.claims().clone();
        if let Err(e) = admitted.ensure_grant_capacity().await {
            self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
            return admission_error_response(&e);
        }

        let target_conn = match self.ssrf_guard.dial_validated_public_tcp(&connect_target).await {
            Ok((c, _)) => c,
            Err(e) => {
                let sc = if e.is_policy_forbidden() { 403 } else { 502 };
                self.record_receipt(&claims, 0, 0, sc, 0, start.elapsed());
                return text_response(sc, format!("connect dial error: {e}"));
            }
        };

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
        let me = Arc::clone(&self);
        let mut req_body = req.into_body();
        let chunk_sz = (self.cfg.pre_debit_chunk_size.min(32 * 1024) as usize).max(4096);

        tokio::spawn(async move {
            let (mut target_r, mut target_w) = target_conn.into_split();
            let mut cancel_rx = admitted.cancel_receiver();
            let ingress_bytes = AtomicI64::new(0);
            let egress_bytes = AtomicI64::new(0);

            let c2t = async {
                while let Some(frame_res) = req_body.frame().await {
                    let Ok(frame) = frame_res else { break };
                    if let Some(data) = frame.data_ref() {
                        if data.is_empty() {
                            continue;
                        }
                        if admitted.pre_debit(data.len() as i64).await.is_err() {
                            break;
                        }
                        if target_w.write_all(data).await.is_err() {
                            break;
                        }
                        ingress_bytes.fetch_add(data.len() as i64, Ordering::Relaxed);
                    }
                }
                let _ = target_w.shutdown().await;
            };

            let t2c = async {
                let mut buf = vec![0u8; chunk_sz];
                loop {
                    match target_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => match admitted.pre_debit_up_to(n as i64).await {
                            Ok(allowed) => {
                                let k = (allowed as usize).min(n);
                                if k > 0 {
                                    if tx
                                        .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..k]))))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    egress_bytes.fetch_add(k as i64, Ordering::Relaxed);
                                }
                                if k < n {
                                    break;
                                }
                            }
                            Err(_) => break,
                        },
                    }
                }
            };

            tokio::select! {
                _ = wait_revoked(&mut cancel_rx) => {}
                _ = async { tokio::join!(c2t, t2c) } => {}
            }
            me.record_receipt(
                &claims,
                ingress_bytes.load(Ordering::Relaxed),
                egress_bytes.load(Ordering::Relaxed),
                200,
                0,
                start.elapsed(),
            );
            drop(admitted);
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(channel_body(rx))
            .unwrap()
    }

    // ---------- /edge/v1/ws-bridge (Transit + Landing) ----------

    async fn handle_tunnel_ws_bridge(self: Arc<Self>, req: Request<Incoming>) -> Response<EdgeBody> {
        let headers = req.headers().clone();
        let (admitted, lease_tok, signed_route, hop_idx) =
            match self.authenticate_tunnel_hop(&headers).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        let mut up_url = match single_header_opt(&headers, HEADER_UPSTREAM_URL) {
            Ok(Some(u)) if !u.is_empty() => u,
            Ok(_) => return text_response(400, "missing X-Berth-Upstream-URL"),
            Err(resp) => return resp,
        };
        if hop_idx < signed_route.len() - 1 {
            return match self
                .next_hop_dispatch(
                    &signed_route,
                    hop_idx,
                    TUNNEL_WS_BRIDGE_PATH,
                    &lease_tok,
                    "GET",
                    &up_url,
                    &headers,
                    req.into_body().boxed(),
                )
                .await
            {
                Ok(resp) => stream_incoming_with_revocation_mode(resp, admitted, true),
                Err(e) => text_response(502, format!("transit ws hop failed: {e}")),
            };
        }

        let start = Instant::now();
        let claims = admitted.claims().clone();
        if let Err(e) = admitted.ensure_grant_capacity().await {
            self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
            return admission_error_response(&e);
        }

        let cred = match self.resolve_upstream_credential(&claims).await {
            Ok(c) => c,
            Err(e) => {
                let sc = match e {
                    CredentialError::Forbidden(_) => 403,
                    CredentialError::Unavailable(_) => 502,
                };
                self.record_receipt(&claims, 0, 0, sc, 0, start.elapsed());
                return text_response(sc, e.to_string());
            }
        };
        if let Some(ref c) = cred {
            if !c.headers.is_empty() && c.base_url.trim().is_empty() {
                self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
                return text_response(403, "upstream credential missing authoritative base_url");
            }
            if !c.base_url.is_empty() {
                match rewrite_url_for_credential_base_strict(&up_url, &c.base_url) {
                    Ok(rewritten) => up_url = rewritten,
                    Err(e) => {
                        self.record_receipt(&claims, 0, 0, 403, 0, start.elapsed());
                        return text_response(403, format!("invalid upstream credential base_url: {e}"));
                    }
                }
            }
        }
        let up_headers = prepare_landing_ws_headers(&headers, &claims, cred.as_ref());

        let up_ws = match self
            .upstream
            .dial_websocket(&up_url, &up_headers, Some(&claims))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let sc = match &e {
                    crate::cage::UpstreamError::Ssrf(se) if se.is_policy_forbidden() => 403,
                    _ => 502,
                };
                self.record_receipt(&claims, 0, 0, sc, 0, start.elapsed());
                return text_response(sc, format!("upstream ws error: {e}"));
            }
        };

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
        let me = Arc::clone(&self);
        let mut in_reader = IncomingFrameReader::new(req.into_body());

        tokio::spawn(async move {
            let (ws_r, mut ws_w) = tokio::io::split(up_ws);
            let mut ws_br = BufReader::new(ws_r);
            let mut cancel_rx = admitted.cancel_receiver();
            let in_b = AtomicI64::new(0);
            let out_b = AtomicI64::new(0);
            let ttft_ms = AtomicI64::new(0);
            let sniffer = Mutex::new(UsageStreamSniffer::new_ws(extract_request_meta(&up_url, &[])));

            let c2u = async {
                loop {
                    let Ok((op, payload)) = in_reader.read_ws_h2_frame().await else {
                        break;
                    };
                    if !payload.is_empty() && (op & 0x0F) != WS_OP_CLOSE {
                        if admitted.pre_debit(payload.len() as i64).await.is_err() {
                            let mut close_p = WS_CLOSE_CAGE_REBIND.to_be_bytes().to_vec();
                            close_p.extend_from_slice(b"landing_grant_exhausted");
                            let _ = tx
                                .send(Ok(Frame::data(Bytes::from(encode_ws_h2_frame(
                                    0x80 | WS_OP_CLOSE,
                                    &close_p,
                                )))))
                                .await;
                            break;
                        }
                        in_b.fetch_add(payload.len() as i64, Ordering::Relaxed);
                        if (op & 0x0F) == 1 {
                            sniffer
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .feed_ws_client_text(&payload);
                        }
                    }
                    if write_rfc6455_frame(&mut ws_w, op, &payload, true)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if (op & 0x0F) == WS_OP_CLOSE {
                        break;
                    }
                }
            };

            let u2c = async {
                loop {
                    let Ok((op, payload)) =
                        read_rfc6455_frame(&mut ws_br, DEFAULT_MAX_WS_FRAME_BYTES).await
                    else {
                        break;
                    };
                    if !payload.is_empty() && (op & 0x0F) != WS_OP_CLOSE {
                        if ttft_ms.load(Ordering::Relaxed) == 0 {
                            let _ = ttft_ms.compare_exchange(
                                0,
                                (start.elapsed().as_millis() as i64).max(1),
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            );
                        }
                        if admitted.pre_debit(payload.len() as i64).await.is_err() {
                            let mut close_p = WS_CLOSE_CAGE_REBIND.to_be_bytes().to_vec();
                            close_p.extend_from_slice(b"landing_grant_exhausted");
                            let _ = tx
                                .send(Ok(Frame::data(Bytes::from(encode_ws_h2_frame(
                                    0x80 | WS_OP_CLOSE,
                                    &close_p,
                                )))))
                                .await;
                            break;
                        }
                        out_b.fetch_add(payload.len() as i64, Ordering::Relaxed);
                        if (op & 0x0F) == 1 {
                            sniffer
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .feed_ws_server_text(&payload);
                        }
                    }
                    if tx
                        .send(Ok(Frame::data(Bytes::from(encode_ws_h2_frame(
                            op, &payload,
                        )))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if (op & 0x0F) == WS_OP_CLOSE {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = wait_revoked(&mut cancel_rx) => {
                    let mut close_p = WS_CLOSE_CAGE_REBIND.to_be_bytes().to_vec();
                    close_p.extend_from_slice(b"stream_revoked");
                    let _ = tx.send(Ok(Frame::data(Bytes::from(encode_ws_h2_frame(0x80 | WS_OP_CLOSE, &close_p))))).await;
                    let _ = write_rfc6455_close(&mut ws_w, WS_CLOSE_CAGE_REBIND, "stream_revoked", true).await;
                }
                _ = async { tokio::join!(c2u, u2c) } => {}
            }
            let extracted = sniffer.into_inner().unwrap_or_else(|e| e.into_inner()).finish();
            me.record_receipt_with_usage(
                &claims,
                in_b.load(Ordering::Relaxed),
                out_b.load(Ordering::Relaxed),
                101,
                ttft_ms.load(Ordering::Relaxed),
                start.elapsed(),
                Some(extracted),
            );
            drop(admitted);
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(channel_body(rx))
            .unwrap()
    }

    // ---------- Landing OAuth Long-Poll Worker ----------

    pub async fn run_oauth_task_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let Some(central) = self.central.clone() else {
            return;
        };
        let mut backoff = Duration::from_secs(1);
        loop {
            if *shutdown.borrow() {
                return;
            }
            if !self.has_role(ROLE_LANDING) && !self.has_role(ROLE_COMPAT) {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
                }
            }
            let poll_res = tokio::select! {
                _ = shutdown.changed() => return,
                r = central.poll_oauth_tasks(15) => r,
            };
            match poll_res {
                Ok(tasks) => {
                    backoff = Duration::from_secs(1);
                    for task in tasks {
                        // Local belt-and-suspenders dedup alongside Central's atomic single-claim.
                        {
                            let mut set = self.oauth_inflight.lock().unwrap_or_else(|e| e.into_inner());
                            if !set.insert(task.task_id.clone()) {
                                continue;
                            }
                        }
                        let Ok(permit) = Arc::clone(&self.oauth_sem).acquire_owned().await else {
                            self.oauth_inflight
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&task.task_id);
                            continue;
                        };
                        let me = Arc::clone(&self);
                        let central_c = Arc::clone(&central);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let tid = task.task_id.clone();
                            me.execute_single_oauth_task(&central_c, task).await;
                            me.oauth_inflight
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&tid);
                        });
                    }
                }
                Err(e) => {
                    warn!("berth-edge[{}] oauth long-poll error: {e}", self.cfg.node_name);
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep(backoff) => {
                            backoff = (backoff * 2).min(Duration::from_secs(15));
                        }
                    }
                }
            }
        }
    }

    async fn report_oauth_completion(
        &self,
        central: &CentralClient,
        task_id: &str,
        claim_id: &str,
        status_code: u16,
        resp_headers: &HashMap<String, Vec<String>>,
        resp_body_b64: &str,
        resp_body: &str,
        err_msg: &str,
    ) {
        // Retry delivery of the already-computed result without ever re-executing the provider POST!
        for attempt in 0..3 {
            match central
                .complete_oauth_task(
                    task_id,
                    claim_id,
                    status_code,
                    resp_headers,
                    resp_body_b64,
                    resp_body,
                    err_msg,
                )
                .await
            {
                Ok(()) => return,
                Err(e) => {
                    warn!(
                        "berth-edge[{}] complete_oauth_task {task_id} attempt {} failed: {e}",
                        self.cfg.node_name,
                        attempt + 1
                    );
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(300 * (attempt as u64 + 1))).await;
                    }
                }
            }
        }
    }

    async fn execute_single_oauth_task(
        &self,
        central: &CentralClient,
        task: crate::central::OAuthTaskDto,
    ) {
        let empty_hdrs: HashMap<String, Vec<String>> = HashMap::new();
        if task.kind == "health_probe" {
            self.report_oauth_completion(
                central,
                &task.task_id,
                &task.claim_id,
                200,
                &empty_hdrs,
                "",
                "ok",
                "",
            )
            .await;
            return;
        }
        if let Err(e) = self.ssrf_guard.validate_http_url(&task.target_url) {
            warn!(
                "berth-edge[{}] blocked OAuth task {} target {}: {e}",
                self.cfg.node_name, task.task_id, task.target_url
            );
            self.report_oauth_completion(
                central,
                &task.task_id,
                &task.claim_id,
                403,
                &empty_hdrs,
                "",
                "",
                &e.to_string(),
            )
            .await;
            return;
        }
        let body = if task.body_base64.is_empty() {
            Bytes::new()
        } else {
            match STANDARD.decode(task.body_base64.trim()) {
                Ok(b) => Bytes::from(b),
                Err(e) => {
                    self.report_oauth_completion(
                        central,
                        &task.task_id,
                        &task.claim_id,
                        0,
                        &empty_hdrs,
                        "",
                        "",
                        &format!("invalid base64: {e}"),
                    )
                    .await;
                    return;
                }
            }
        };
        let method = if task.method.trim().is_empty() {
            Method::POST
        } else {
            Method::from_bytes(task.method.trim().as_bytes()).unwrap_or(Method::POST)
        };
        let mut headers = HeaderMap::new();
        for (k, v) in &task.headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.insert(hn, hv);
            }
        }
        match self
            .upstream
            .do_oauth_http(
                method,
                &task.target_url,
                headers,
                body,
                task.account_id,
                task.cage_epoch,
                &task.accept_language,
                task.follow_redirects,
            )
            .await
        {
            Ok(res) => {
                info!(
                    "berth-edge[{}] executed OAuth task {} -> status={} bytes={}",
                    self.cfg.node_name,
                    task.task_id,
                    res.status,
                    res.body.len()
                );
                let b64 = STANDARD.encode(&res.body);
                self.report_oauth_completion(
                    central,
                    &task.task_id,
                    &task.claim_id,
                    res.status,
                    &res.headers,
                    &b64,
                    "",
                    "",
                )
                .await;
            }
            Err(e) => {
                warn!(
                    "berth-edge[{}] OAuth task {} failed: {e}",
                    self.cfg.node_name, task.task_id
                );
                self.report_oauth_completion(
                    central,
                    &task.task_id,
                    &task.claim_id,
                    0,
                    &empty_hdrs,
                    "",
                    "",
                    &e.to_string(),
                )
                .await;
            }
        }
    }

    // ---------- Ephemeral RAM-only Upstream Credential Cache ----------

    async fn resolve_upstream_credential(
        &self,
        claims: &SessionLeaseClaims,
    ) -> Result<Option<UpstreamCredentialDto>, CredentialError> {
        let Some(central) = &self.central else {
            return Ok(None);
        };
        if claims.lease_id.is_empty() || claims.account_id <= 0 {
            return Ok(None);
        }
        let key = format!("{}:{}", claims.lease_id, claims.account_id);
        let now = Instant::now();
        {
            let map = self.creds.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = map.get(&key) {
                if now < entry.expires_at {
                    return Ok(Some(entry.cred.clone()));
                }
            }
        }
        let cred = central
            .fetch_upstream_credential(&claims.lease_id, claims.account_id)
            .await?;
        let Some(cred) = cred else {
            return Ok(None);
        };
        let mut ttl = Duration::from_secs(90);
        if cred.expires_at_unix > 0 {
            let rem = cred.expires_at_unix - now_unix();
            if rem <= 0 {
                // Fail closed: NEVER dial upstream with an already-expired credential envelope!
                return Err(CredentialError::Unavailable(
                    "upstream credential envelope already expired".into(),
                ));
            }
            ttl = ttl.min(Duration::from_secs(rem as u64));
        }
        let mut map = self.creds.write().unwrap_or_else(|e| e.into_inner());
        if map.len() > 256 {
            map.retain(|_, v| now < v.expires_at);
        }
        map.insert(
            key,
            CachedCred {
                cred: cred.clone(),
                expires_at: now + ttl,
            },
        );
        Ok(Some(cred))
    }

    fn evict_upstream_credential(&self, lease_id: &str, account_id: i64) {
        let key = format!("{lease_id}:{account_id}");
        self.creds
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    fn record_receipt(
        &self,
        claims: &SessionLeaseClaims,
        in_b: i64,
        out_b: i64,
        status_code: u16,
        ttft_ms: i64,
        dur: Duration,
    ) {
        self.record_receipt_with_usage(claims, in_b, out_b, status_code, ttft_ms, dur, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_receipt_with_usage(
        &self,
        claims: &SessionLeaseClaims,
        in_b: i64,
        out_b: i64,
        status_code: u16,
        ttft_ms: i64,
        dur: Duration,
        usage: Option<ExtractedUsage>,
    ) {
        let Some(outbox) = &self.outbox else {
            return;
        };
        let u = usage.unwrap_or_default();
        let req_count = u.request_count.max(1);
        let mut rb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut rb);
        let _ = outbox.append(UsageReceipt {
            receipt_id: format!("rcpt-{}", hex::encode(rb)),
            node_id: self.cfg.node_id,
            lease_id: claims.lease_id.clone(),
            grant_id: claims.grant_id,
            user_id: claims.user_id,
            api_key_id: claims.api_key_id,
            account_id: claims.account_id,
            work_session_id: claims.work_session_id,
            platform: claims.platform.clone(),
            model: u.model,
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cache_creation_tokens: u.cache_creation_tokens,
            cache_read_tokens: u.cache_read_tokens,
            stream: u.stream,
            ingress_bytes: in_b,
            egress_bytes: out_b,
            total_bytes: in_b + out_b,
            request_count: req_count,
            status_code: status_code as i32,
            ttft_ms,
            duration_ms: dur.as_millis() as i64,
            created_at: now_unix(),
        });
    }
}

enum FailoverAction {
    Switched {
        token: String,
        route: Vec<RouteHop>,
        claims: Option<SessionLeaseClaims>,
    },
    RebindRequired(Response<EdgeBody>),
}

#[derive(Clone)]
pub struct EdgeHttpService {
    server: Arc<EdgeServer>,
}

impl Service<Request<Incoming>> for EdgeHttpService {
    type Response = Response<EdgeBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let srv = Arc::clone(&self.server);
        Box::pin(async move { Ok(srv.handle_request(req).await) })
    }
}

// ---------- Helpers ----------

async fn wait_revoked(rx: &mut watch::Receiver<Option<String>>) {
    if rx.borrow().is_some() {
        return;
    }
    while rx.changed().await.is_ok() {
        if rx.borrow().is_some() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

fn extract_bearer_lease(headers: &HeaderMap) -> String {
    if let Some(tok) = header_str(headers, HEADER_LEASE).filter(|s| !s.is_empty()) {
        return tok;
    }
    if let Some(auth) = header_str(headers, "authorization") {
        if auth.len() >= 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            return auth[7..].trim().to_string();
        }
    }
    String::new()
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_ws = header_str(headers, "upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let conn_upgrade = header_str(headers, "connection").is_some_and(|v| {
        v.split(',')
            .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
    });
    upgrade_ws && conn_upgrade
}

fn single_header_opt(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, Response<EdgeBody>> {
    let mut iter = headers.get_all(name).iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(text_response(400, format!("duplicate control header {name}")));
    }
    let val = first
        .to_str()
        .map_err(|_| text_response(400, format!("invalid UTF-8 in header {name}")))?;
    Ok(Some(val.trim().to_string()))
}

fn single_bearer_lease(headers: &HeaderMap) -> Result<String, Response<EdgeBody>> {
    if let Some(tok) = single_header_opt(headers, HEADER_LEASE)? {
        if !tok.is_empty() {
            return Ok(tok);
        }
    }
    if let Some(auth) = single_header_opt(headers, "authorization")? {
        if auth.len() >= 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            return Ok(auth[7..].trim().to_string());
        }
    }
    Ok(String::new())
}

fn connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut set = HashSet::new();
    for v in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            for tok in s.split(',') {
                let t = tok.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    set.insert(t);
                }
            }
        }
    }
    set
}

fn parse_route_and_hop(headers: &HeaderMap) -> Result<(Vec<RouteHop>, usize), Response<EdgeBody>> {
    let route_raw = single_header_opt(headers, HEADER_ROUTE)?.unwrap_or_default();
    let route = decode_route_header(&route_raw)
        .map_err(|_| text_response(400, "invalid X-Berth-Route header"))?;
    if route.is_empty() {
        return Err(text_response(400, "empty X-Berth-Route header"));
    }
    let hop_idx = single_header_opt(headers, HEADER_HOP_INDEX)?
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| text_response(400, "invalid X-Berth-Hop-Index header"))?;
    if hop_idx >= route.len() {
        return Err(text_response(400, "X-Berth-Hop-Index out of bounds"));
    }
    Ok((route, hop_idx))
}

fn default_provider_base_url(platform: &str, req_path: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "openai" | "codex" => {
            if req_path.starts_with("/backend-api/") {
                "https://chatgpt.com"
            } else {
                "https://api.openai.com"
            }
        }
        "anthropic" | "claude" => "https://api.anthropic.com",
        "antigravity" | "gemini" => {
            if req_path.starts_with("/v1internal") {
                "https://cloudcode-pa.googleapis.com"
            } else {
                "https://generativelanguage.googleapis.com"
            }
        }
        "xai" | "grok" => "https://api.x.ai",
        _ => "",
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn stream_incoming_with_revocation(
    resp: Response<Incoming>,
    admitted: AdmittedStream,
) -> Response<EdgeBody> {
    stream_incoming_with_revocation_mode(resp, admitted, false)
}

fn stream_incoming_with_revocation_mode(
    resp: Response<Incoming>,
    admitted: AdmittedStream,
    is_ws_bridge: bool,
) -> Response<EdgeBody> {
    let status = resp.status();
    let is_sse = !is_ws_bridge
        && resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));
    let is_compressed = resp
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some_and(|s| !s.eq_ignore_ascii_case("identity"));
    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        if !is_hop_by_hop(k.as_str()) {
            builder = builder.header(k.clone(), v.clone());
        }
    }
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
    tokio::spawn(async move {
        let mut body = resp.into_body();
        let mut cancel_rx = admitted.cancel_receiver();
        loop {
            tokio::select! {
                _ = wait_revoked(&mut cancel_rx) => {
                    if is_ws_bridge {
                        let mut close_p = WS_CLOSE_CAGE_REBIND.to_be_bytes().to_vec();
                        close_p.extend_from_slice(b"stream_revoked");
                        let _ = tx.send(Ok(Frame::data(Bytes::from(encode_ws_h2_frame(
                            0x80 | WS_OP_CLOSE,
                            &close_p,
                        ))))).await;
                    } else if is_sse && !is_compressed {
                        let _ = tx.send(Ok(Frame::data(Bytes::from_static(
                            b"event: error\ndata: {\"code\":\"cage_rebind_required\",\"reason\":\"stream_revoked\"}\n\n"
                        )))).await;
                    }
                    break;
                }
                frame_opt = body.frame() => {
                    match frame_opt {
                        Some(Ok(frame)) => {
                            if tx.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }
        drop(admitted);
    });
    builder.body(channel_body(rx)).unwrap()
}

async fn collect_capped(mut body: Incoming, max_bytes: usize) -> anyhow::Result<Bytes> {
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > max_bytes {
                anyhow::bail!("request body exceeds limit ({max_bytes} bytes)");
            }
            out.extend_from_slice(data);
        }
    }
    Ok(Bytes::from(out))
}

async fn splice_upgraded_with_target(
    upgraded: TokioIo<hyper::upgrade::Upgraded>,
    target: tokio::net::TcpStream,
    admitted: &AdmittedStream,
) -> (i64, i64) {
    let (mut cr, mut cw) = tokio::io::split(upgraded);
    let (mut tr, mut tw) = target.into_split();
    let mut cancel_rx = admitted.cancel_receiver();
    let in_bytes = AtomicI64::new(0);
    let out_bytes = AtomicI64::new(0);

    let c2t = async {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if admitted.pre_debit(n as i64).await.is_err() {
                        break;
                    }
                    if tw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    in_bytes.fetch_add(n as i64, Ordering::Relaxed);
                }
            }
        }
        let _ = tw.shutdown().await;
    };
    let t2c = async {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match tr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => match admitted.pre_debit_up_to(n as i64).await {
                    Ok(allowed) => {
                        let k = (allowed as usize).min(n);
                        if k > 0 {
                            if cw.write_all(&buf[..k]).await.is_err() {
                                break;
                            }
                            out_bytes.fetch_add(k as i64, Ordering::Relaxed);
                        }
                        if k < n {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
        let _ = cw.shutdown().await;
    };

    tokio::select! {
        _ = wait_revoked(&mut cancel_rx) => {}
        _ = async { tokio::join!(c2t, t2c) } => {}
    }
    (
        in_bytes.load(Ordering::Relaxed),
        out_bytes.load(Ordering::Relaxed),
    )
}

struct IncomingFrameReader {
    body: Incoming,
    buf: Vec<u8>,
}

impl IncomingFrameReader {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buf: Vec::new(),
        }
    }

    async fn read_exact(&mut self, n: usize) -> anyhow::Result<Vec<u8>> {
        while self.buf.len() < n {
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        self.buf.extend_from_slice(data);
                    }
                }
                Some(Err(e)) => return Err(e.into()),
                None => anyhow::bail!("unexpected EOF"),
            }
        }
        let rest = self.buf.split_off(n);
        let out = std::mem::replace(&mut self.buf, rest);
        Ok(out)
    }

    async fn read_ws_h2_frame(&mut self) -> anyhow::Result<(u8, Vec<u8>)> {
        let hdr = self.read_exact(5).await?;
        let op = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > DEFAULT_MAX_WS_FRAME_BYTES {
            anyhow::bail!("ws-over-h2 frame too large: {len}");
        }
        let payload = if len == 0 {
            Vec::new()
        } else {
            self.read_exact(len).await?
        };
        Ok((op, payload))
    }
}
