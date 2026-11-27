use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper::service::Service;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, watch};
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::config::normalize_listen_addr;
use crate::proto::{NonceGuard, now_unix};

pub type EdgeBody = BoxBody<Bytes, hyper::Error>;

const BRT2_MAGIC: &[u8; 4] = b"BRT2";
const BRT2_VERSION: u8 = 2;
const BRT2_CLIENT_HELLO_LEN: usize = 4 + 1 + 8 + 8 + 8 + 16 + 32 + 64; // 141 bytes
const BRT2_SERVER_HELLO_LEN: usize = 4 + 1 + 8 + 32 + 64; // 109 bytes
const BRT2_MAX_RECORD_PLAIN: usize = 16 * 1024;
const BRT2_TAG_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum ReverseTunnelError {
    #[error("edgeproto: reverse tunnel generation is stale (got {got} <= active {active})")]
    StaleGeneration { got: u64, active: u64 },
    #[error("edgeproto: reverse tunnel unavailable for node {0}")]
    Unavailable(i64),
    #[error("edgeproto: reverse tunnel h2 error: {0}")]
    Http2(String),
    #[error("edgeproto: reverse tunnel handshake error: {0}")]
    Handshake(String),
}

// ---------- Mutually-Authenticated Forward-Secret BRT2 AEAD Stream ----------

fn derive_brt2_keys(
    shared: &[u8; 32],
    client_hello: &[u8],
    server_hello: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut th = Sha256::new();
    th.update(client_hello);
    th.update(server_hello);
    let transcript = th.finalize();

    let mut c2s = Sha256::new();
    c2s.update(b"brt2-c2s-v2");
    c2s.update(shared);
    c2s.update(transcript);

    let mut s2c = Sha256::new();
    s2c.update(b"brt2-s2c-v2");
    s2c.update(shared);
    s2c.update(transcript);

    (c2s.finalize().into(), s2c.finalize().into())
}

fn make_nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    n
}

struct Brt2AeadStream {
    io: TcpStream,
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_seq: u64,
    rx_seq: u64,
    read_wire: Vec<u8>,
    read_plain: Vec<u8>,
    read_plain_pos: usize,
    write_wire: Vec<u8>,
    write_wire_pos: usize,
}

impl Brt2AeadStream {
    fn new(io: TcpStream, tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self {
            io,
            tx_cipher: ChaCha20Poly1305::new(Key::from_slice(&tx_key)),
            rx_cipher: ChaCha20Poly1305::new(Key::from_slice(&rx_key)),
            tx_seq: 0,
            rx_seq: 0,
            read_wire: Vec::with_capacity(4096),
            read_plain: Vec::new(),
            read_plain_pos: 0,
            write_wire: Vec::new(),
            write_wire_pos: 0,
        }
    }

    fn flush_write_wire(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_wire_pos < this.write_wire.len() {
            let n = match Pin::new(&mut this.io)
                .poll_write(cx, &this.write_wire[this.write_wire_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "brt2 underlying write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
            };
            this.write_wire_pos += n;
        }
        this.write_wire.clear();
        this.write_wire_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Brt2AeadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.read_plain_pos < this.read_plain.len() {
                let avail = &this.read_plain[this.read_plain_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_plain_pos += n;
                if this.read_plain_pos >= this.read_plain.len() {
                    this.read_plain.clear();
                    this.read_plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Determine how many wire bytes we need next.
            let target_len = if this.read_wire.len() < 2 {
                2
            } else {
                let plain_len = u16::from_be_bytes([this.read_wire[0], this.read_wire[1]]) as usize;
                if plain_len == 0 || plain_len > BRT2_MAX_RECORD_PLAIN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("brt2 invalid record length {plain_len}"),
                    )));
                }
                2 + plain_len + BRT2_TAG_LEN
            };

            if this.read_wire.len() >= target_len && target_len > 2 {
                if this.rx_seq == u64::MAX {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "brt2 rx sequence exhausted",
                    )));
                }
                let aad = [this.read_wire[0], this.read_wire[1]];
                let plain_len = u16::from_be_bytes(aad) as usize;
                let tag_start = 2 + plain_len;
                let mut payload = this.read_wire[2..tag_start].to_vec();
                let tag = *Tag::from_slice(&this.read_wire[tag_start..tag_start + BRT2_TAG_LEN]);
                let nonce_bytes = make_nonce(this.rx_seq);
                let nonce = Nonce::from_slice(&nonce_bytes);
                if this
                    .rx_cipher
                    .decrypt_in_place_detached(nonce, &aad, &mut payload, &tag)
                    .is_err()
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "brt2 AEAD tag verification failed",
                    )));
                }
                this.rx_seq += 1;
                this.read_wire.drain(..target_len);
                this.read_plain = payload;
                this.read_plain_pos = 0;
                continue;
            }

            let need = target_len - this.read_wire.len();
            let mut tmp = [0u8; 4096];
            let cap = need.min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..cap]);
            match Pin::new(&mut this.io).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let got = rb.filled().len();
                    if got == 0 {
                        if this.read_wire.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "brt2 truncated AEAD frame",
                        )));
                    }
                    this.read_wire.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl AsyncWrite for Brt2AeadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Pending = self.as_mut().flush_write_wire(cx)? {
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        if this.tx_seq == u64::MAX {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "brt2 tx sequence exhausted",
            )));
        }
        let chunk_len = buf.len().min(BRT2_MAX_RECORD_PLAIN);
        let aad = (chunk_len as u16).to_be_bytes();
        let mut payload = buf[..chunk_len].to_vec();
        let nonce_bytes = make_nonce(this.tx_seq);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = this
            .tx_cipher
            .encrypt_in_place_detached(nonce, &aad, &mut payload)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "brt2 AEAD encrypt failed"))?;
        this.tx_seq += 1;

        this.write_wire.clear();
        this.write_wire.reserve(2 + chunk_len + BRT2_TAG_LEN);
        this.write_wire.extend_from_slice(&aad);
        this.write_wire.extend_from_slice(&payload);
        this.write_wire.extend_from_slice(tag.as_slice());
        this.write_wire_pos = 0;

        // Best-effort immediate flush; any remainder is flushed on subsequent write/flush.
        let _ = self.as_mut().flush_write_wire(cx)?;
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Pending = self.as_mut().flush_write_wire(cx)? {
            return Poll::Pending;
        }
        Pin::new(&mut self.as_mut().get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Pending = self.as_mut().flush_write_wire(cx)? {
            return Poll::Pending;
        }
        Pin::new(&mut self.as_mut().get_mut().io).poll_shutdown(cx)
    }
}

struct TunnelEntry {
    generation: u64,
    sender: SendRequest<EdgeBody>,
    closed: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
}

/// Generation-fenced, mutually-authenticated X25519+Ed25519+ChaCha20-Poly1305 (`BRT2`)
/// single-H2-mux reverse-tunnel hub running on Transit nodes.
pub struct ReverseTunnelHub {
    hub_node_id: i64,
    hub_priv_key: SigningKey,
    peer_keys: RwLock<HashMap<i64, VerifyingKey>>,
    nonce_guard: NonceGuard,
    tunnels: RwLock<HashMap<i64, TunnelEntry>>,
    handshake_wait: Duration,
}

impl ReverseTunnelHub {
    pub fn new(
        hub_node_id: i64,
        hub_priv_key: SigningKey,
        peer_keys: HashMap<i64, VerifyingKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            hub_node_id,
            hub_priv_key,
            peer_keys: RwLock::new(peer_keys),
            nonce_guard: NonceGuard::default_guard(),
            tunnels: RwLock::new(HashMap::new()),
            handshake_wait: Duration::from_secs(10),
        })
    }

    pub fn update_peer_keys(&self, updates: HashMap<i64, VerifyingKey>) {
        if updates.is_empty() {
            return;
        }
        let mut map = self.peer_keys.write().unwrap_or_else(|e| e.into_inner());
        for (id, pk) in updates {
            map.insert(id, pk);
        }
    }

    pub fn connected_node_ids(&self) -> Vec<i64> {
        let map = self.tunnels.read().unwrap_or_else(|e| e.into_inner());
        let mut ids: Vec<i64> = map
            .iter()
            .filter(|(_, e)| !e.closed.load(Ordering::Acquire))
            .map(|(&id, _)| id)
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn active_generation(&self, node_id: i64) -> u64 {
        let map = self.tunnels.read().unwrap_or_else(|e| e.into_inner());
        map.get(&node_id)
            .filter(|e| !e.closed.load(Ordering::Acquire))
            .map(|e| e.generation)
            .unwrap_or(0)
    }

    pub async fn round_trip(
        &self,
        node_id: i64,
        req: Request<EdgeBody>,
    ) -> Result<Response<Incoming>, ReverseTunnelError> {
        let (mut sender, gen_id, closed) = {
            let map = self.tunnels.read().unwrap_or_else(|e| e.into_inner());
            match map.get(&node_id) {
                Some(e) if !e.closed.load(Ordering::Acquire) => {
                    (e.sender.clone(), e.generation, Arc::clone(&e.closed))
                }
                _ => return Err(ReverseTunnelError::Unavailable(node_id)),
            }
        };
        if sender.ready().await.is_err() {
            closed.store(true, Ordering::Release);
            self.unregister(node_id, gen_id);
            return Err(ReverseTunnelError::Unavailable(node_id));
        }
        match sender.send_request(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                if e.is_closed() {
                    closed.store(true, Ordering::Release);
                    self.unregister(node_id, gen_id);
                }
                Err(ReverseTunnelError::Http2(e.to_string()))
            }
        }
    }

    pub fn unregister(&self, node_id: i64, generation: u64) {
        let mut map = self.tunnels.write().unwrap_or_else(|e| e.into_inner());
        if let Some(cur) = map.get(&node_id) {
            if cur.generation == generation {
                cur.closed.store(true, Ordering::Release);
                cur.close_notify.notify_waiters();
                map.remove(&node_id);
                info!("reverse_tunnel unregistered node_id={node_id} gen={generation}");
            }
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
            "reverse_tunnel BRT2 encrypted hub listening on {}",
            listener.local_addr()?
        );
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        let mut map = self.tunnels.write().unwrap_or_else(|e| e.into_inner());
                        for (_, e) in map.drain() {
                            e.closed.store(true, Ordering::Release);
                            e.close_notify.notify_waiters();
                        }
                        return Ok(());
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((conn, peer)) => {
                            let me = Arc::clone(&self);
                            tokio::spawn(async move {
                                me.accept_one(conn, peer).await;
                            });
                        }
                        Err(e) => warn!("reverse_tunnel accept error: {e}"),
                    }
                }
            }
        }
    }

    async fn handshake_server(
        &self,
        conn: &mut TcpStream,
    ) -> Result<(i64, u64, [u8; 32], [u8; 32]), ReverseTunnelError> {
        let mut ch = [0u8; BRT2_CLIENT_HELLO_LEN];
        conn.read_exact(&mut ch)
            .await
            .map_err(|e| ReverseTunnelError::Handshake(format!("read client hello: {e}")))?;
        if &ch[0..4] != BRT2_MAGIC || ch[4] != BRT2_VERSION {
            return Err(ReverseTunnelError::Handshake(
                "invalid BRT2 magic/version (plaintext BRT1 rejected)".into(),
            ));
        }
        let node_id = i64::from_be_bytes(ch[5..13].try_into().unwrap());
        let generation = u64::from_be_bytes(ch[13..21].try_into().unwrap());
        let ts_unix = i64::from_be_bytes(ch[21..29].try_into().unwrap());
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&ch[29..45]);
        let mut c_pub_bytes = [0u8; 32];
        c_pub_bytes.copy_from_slice(&ch[45..77]);
        let sig = Signature::from_slice(&ch[77..141])
            .map_err(|_| ReverseTunnelError::Handshake("malformed client ed25519 sig".into()))?;
        if node_id <= 0 || generation == 0 {
            return Err(ReverseTunnelError::Handshake("invalid node_id or generation".into()));
        }

        let peer_vk = {
            let map = self.peer_keys.read().unwrap_or_else(|e| e.into_inner());
            map.get(&node_id).copied()
        }
        .ok_or_else(|| ReverseTunnelError::Handshake(format!("unknown peer node_id={node_id}")))?;

        peer_vk
            .verify(&ch[..77], &sig)
            .map_err(|_| ReverseTunnelError::Handshake("client ed25519 signature invalid".into()))?;
        self.nonce_guard
            .check_and_record(node_id, nonce, ts_unix, now_unix())
            .map_err(|e| ReverseTunnelError::Handshake(e.to_string()))?;

        // Generate ephemeral X25519 keypair and sign server hello bound to client hello hash.
        let mut sk_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
        let s_sk = X25519StaticSecret::from(sk_bytes);
        let s_pk = X25519PublicKey::from(&s_sk);
        let shared = s_sk.diffie_hellman(&X25519PublicKey::from(c_pub_bytes));
        if shared.to_bytes().iter().all(|&b| b == 0) {
            return Err(ReverseTunnelError::Handshake("all-zero X25519 shared secret".into()));
        }

        let ch_hash = Sha256::digest(&ch);
        let mut sign_input = Vec::with_capacity(11 + 32 + 8 + 32);
        sign_input.extend_from_slice(b"BRT2-HUB-v2");
        sign_input.extend_from_slice(&ch_hash);
        sign_input.extend_from_slice(&self.hub_node_id.to_be_bytes());
        sign_input.extend_from_slice(s_pk.as_bytes());
        let hub_sig = self.hub_priv_key.sign(&sign_input);

        let mut sh = [0u8; BRT2_SERVER_HELLO_LEN];
        sh[0..4].copy_from_slice(BRT2_MAGIC);
        sh[4] = BRT2_VERSION;
        sh[5..13].copy_from_slice(&self.hub_node_id.to_be_bytes());
        sh[13..45].copy_from_slice(s_pk.as_bytes());
        sh[45..109].copy_from_slice(&hub_sig.to_bytes());
        conn.write_all(&sh)
            .await
            .map_err(|e| ReverseTunnelError::Handshake(format!("write server hello: {e}")))?;
        conn.flush()
            .await
            .map_err(|e| ReverseTunnelError::Handshake(format!("flush server hello: {e}")))?;

        let (c2s_key, s2c_key) = derive_brt2_keys(shared.as_bytes(), &ch, &sh);
        // Hub sends with s2c_key and receives with c2s_key.
        Ok((node_id, generation, s2c_key, c2s_key))
    }

    async fn accept_one(self: Arc<Self>, mut conn: TcpStream, peer: std::net::SocketAddr) {
        let _ = conn.set_nodelay(true);
        let (node_id, generation, tx_key, rx_key) = match tokio::time::timeout(
            self.handshake_wait,
            self.handshake_server(&mut conn),
        )
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                warn!("reverse_tunnel rejected {peer}: {e}");
                return;
            }
            Err(_) => {
                warn!("reverse_tunnel BRT2 handshake timeout from {peer}");
                return;
            }
        };

        let aead_stream = Brt2AeadStream::new(conn, tx_key, rx_key);
        let mut h2_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        h2_builder
            .timer(TokioTimer::new())
            .keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        let (sender, h2_conn) = match h2_builder.handshake(TokioIo::new(aead_stream)).await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("reverse_tunnel H2 handshake failed for node {node_id}: {e}");
                return;
            }
        };

        let closed = Arc::new(AtomicBool::new(false));
        let close_notify = Arc::new(Notify::new());
        {
            let mut map = self.tunnels.write().unwrap_or_else(|e| e.into_inner());
            if let Some(cur) = map.get(&node_id) {
                if generation <= cur.generation {
                    warn!(
                        "reverse_tunnel stale gen for node {node_id}: got {generation} <= active {}",
                        cur.generation
                    );
                    return;
                }
                cur.closed.store(true, Ordering::Release);
                cur.close_notify.notify_waiters();
            }
            map.insert(
                node_id,
                TunnelEntry {
                    generation,
                    sender,
                    closed: Arc::clone(&closed),
                    close_notify: Arc::clone(&close_notify),
                },
            );
        }

        info!(
            "reverse_tunnel BRT2 encrypted session connected node_id={node_id} gen={generation} peer={peer}"
        );

        let me = Arc::clone(&self);
        // Latch cancellation before entering select so a concurrent replacement cannot miss notify_waiters().
        let notified = close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !closed.load(Ordering::Acquire) {
            tokio::select! {
                res = h2_conn => {
                    if let Err(e) = res {
                        warn!("reverse_tunnel H2 conn ended node_id={node_id}: {e}");
                    }
                }
                _ = notified => {}
            }
        }
        closed.store(true, Ordering::Release);
        me.unregister(node_id, generation);
    }
}

/// Outbound mutually-authenticated encrypted (`BRT2`) reverse-tunnel client running on
/// NAT/home Landing nodes (e.g. `legend-sg`, `houston-vm100`).
pub struct ReverseTunnelClient {
    node_id: i64,
    priv_key: SigningKey,
    hub_addr: String,
    peer_keys: RwLock<HashMap<i64, VerifyingKey>>,
    generation: AtomicU64,
    connected: AtomicBool,
}

impl ReverseTunnelClient {
    pub fn new(
        node_id: i64,
        priv_key: SigningKey,
        hub_addr: String,
        peer_keys: HashMap<i64, VerifyingKey>,
    ) -> Arc<Self> {
        // Seed initial generation from current unix milliseconds so restarts ALWAYS
        // produce a strictly higher generation than any previous process run!
        let seed_gen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
            .max(1);
        Arc::new(Self {
            node_id,
            priv_key,
            hub_addr,
            peer_keys: RwLock::new(peer_keys),
            generation: AtomicU64::new(seed_gen),
            connected: AtomicBool::new(false),
        })
    }

    pub fn update_peer_keys(&self, updates: HashMap<i64, VerifyingKey>) {
        if updates.is_empty() {
            return;
        }
        let mut map = self.peer_keys.write().unwrap_or_else(|e| e.into_inner());
        for (id, pk) in updates {
            map.insert(id, pk);
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub async fn run<S>(
        self: Arc<Self>,
        service: S,
        mut shutdown: watch::Receiver<bool>,
    ) where
        S: Service<Request<Incoming>, Response = Response<EdgeBody>, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let base_backoff = Duration::from_millis(200);
        let max_backoff = Duration::from_secs(10);
        let mut backoff = base_backoff;

        loop {
            if *shutdown.borrow() {
                return;
            }
            match self.connect_once(service.clone(), shutdown.clone()).await {
                Ok(()) => backoff = base_backoff,
                Err(e) => {
                    warn!("reverse_tunnel dial {} error: {e}", self.hub_addr);
                }
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
                _ = tokio::time::sleep(backoff) => {
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    async fn connect_once<S>(
        &self,
        service: S,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()>
    where
        S: Service<Request<Incoming>, Response = Response<EdgeBody>, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        // Fail closed until we hold at least one authenticated hub public key (from config or Central HTTPS heartbeat).
        if self
            .peer_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            anyhow::bail!("waiting for peer public keys before BRT2 dial");
        }

        let mut conn = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&self.hub_addr),
        )
        .await??;
        let _ = conn.set_nodelay(true);

        let gen_id = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let mut sk_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk_bytes);
        let c_sk = X25519StaticSecret::from(sk_bytes);
        let c_pk = X25519PublicKey::from(&c_sk);
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ts = now_unix();

        let mut ch = [0u8; BRT2_CLIENT_HELLO_LEN];
        ch[0..4].copy_from_slice(BRT2_MAGIC);
        ch[4] = BRT2_VERSION;
        ch[5..13].copy_from_slice(&self.node_id.to_be_bytes());
        ch[13..21].copy_from_slice(&gen_id.to_be_bytes());
        ch[21..29].copy_from_slice(&ts.to_be_bytes());
        ch[29..45].copy_from_slice(&nonce);
        ch[45..77].copy_from_slice(c_pk.as_bytes());
        let c_sig = self.priv_key.sign(&ch[..77]);
        ch[77..141].copy_from_slice(&c_sig.to_bytes());

        tokio::time::timeout(Duration::from_secs(10), async {
            conn.write_all(&ch).await?;
            conn.flush().await
        })
        .await??;

        let mut sh = [0u8; BRT2_SERVER_HELLO_LEN];
        tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut sh)).await??;
        if &sh[0..4] != BRT2_MAGIC || sh[4] != BRT2_VERSION {
            anyhow::bail!("invalid BRT2 server hello magic/version");
        }
        let hub_node_id = i64::from_be_bytes(sh[5..13].try_into().unwrap());
        let mut s_pub_bytes = [0u8; 32];
        s_pub_bytes.copy_from_slice(&sh[13..45]);
        let hub_sig = Signature::from_slice(&sh[45..109])
            .map_err(|_| anyhow::anyhow!("malformed hub ed25519 signature"))?;

        let hub_vk = {
            let map = self.peer_keys.read().unwrap_or_else(|e| e.into_inner());
            map.get(&hub_node_id).copied()
        }
        .ok_or_else(|| anyhow::anyhow!("untrusted BRT2 hub node_id={hub_node_id}"))?;

        let ch_hash = Sha256::digest(&ch);
        let mut sign_input = Vec::with_capacity(11 + 32 + 8 + 32);
        sign_input.extend_from_slice(b"BRT2-HUB-v2");
        sign_input.extend_from_slice(&ch_hash);
        sign_input.extend_from_slice(&hub_node_id.to_be_bytes());
        sign_input.extend_from_slice(&s_pub_bytes);
        hub_vk
            .verify(&sign_input, &hub_sig)
            .map_err(|_| anyhow::anyhow!("BRT2 hub ed25519 signature verification failed"))?;

        let shared = c_sk.diffie_hellman(&X25519PublicKey::from(s_pub_bytes));
        if shared.to_bytes().iter().all(|&b| b == 0) {
            anyhow::bail!("all-zero X25519 shared secret");
        }
        let (c2s_key, s2c_key) = derive_brt2_keys(shared.as_bytes(), &ch, &sh);
        // Client sends with c2s_key and receives with s2c_key.
        let aead_stream = Brt2AeadStream::new(conn, c2s_key, s2c_key);

        self.connected.store(true, Ordering::Release);
        info!(
            "reverse_tunnel BRT2 encrypted session established to {} (hub_node_id={} node_id={} gen={})",
            self.hub_addr, hub_node_id, self.node_id, gen_id
        );

        let mut h2_srv = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        h2_srv
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10));

        let conn_fut = h2_srv.serve_connection(TokioIo::new(aead_stream), service);
        tokio::select! {
            res = conn_fut => {
                self.connected.store(false, Ordering::Release);
                if let Err(e) = res {
                    return Err(anyhow::anyhow!("h2 serve ended: {e}"));
                }
            }
            _ = shutdown.changed() => {
                self.connected.store(false, Ordering::Release);
            }
        }
        Ok(())
    }
}
