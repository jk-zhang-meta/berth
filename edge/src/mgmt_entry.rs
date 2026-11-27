use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::normalize_listen_addr;
use crate::proto::{encode_bhe1, now_unix};

const DEFAULT_MAX_CONNS: usize = 1024;
const DEFAULT_MAX_PER_SOURCE: usize = 32;
const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

pub struct MgmtEntryProxy {
    node_id: i64,
    priv_key: SigningKey,
    central_target: String,
    max_conns: usize,
    max_per_source: usize,
    dial_timeout: Duration,
    idle_timeout: Duration,
    active_total: AtomicUsize,
    per_source: Mutex<HashMap<IpAddr, usize>>,
}

impl MgmtEntryProxy {
    pub fn new(node_id: i64, priv_key: SigningKey, central_target: String) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            priv_key,
            central_target,
            max_conns: DEFAULT_MAX_CONNS,
            max_per_source: DEFAULT_MAX_PER_SOURCE,
            dial_timeout: DEFAULT_DIAL_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            active_total: AtomicUsize::new(0),
            per_source: Mutex::new(HashMap::new()),
        })
    }

    fn acquire_slot(&self, ip: IpAddr) -> bool {
        if self.active_total.fetch_add(1, Ordering::AcqRel) + 1 > self.max_conns {
            self.active_total.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        let mut map = self.per_source.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert(0);
        if *entry >= self.max_per_source {
            self.active_total.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        *entry += 1;
        true
    }

    fn release_slot(&self, ip: IpAddr) {
        {
            let mut map = self.per_source.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = map.get_mut(&ip) {
                if *c <= 1 {
                    map.remove(&ip);
                } else {
                    *c -= 1;
                }
            }
        }
        self.active_total.fetch_sub(1, Ordering::AcqRel);
    }

    pub async fn listen_and_serve(
        self: Arc<Self>,
        listen_addr: &str,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let bind_addr = normalize_listen_addr(listen_addr);
        let listener = TcpListener::bind(&bind_addr).await?;
        info!(
            "mgmt_entry BHE1 listening on {} -> {}",
            listener.local_addr()?,
            self.central_target
        );
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return Ok(()); }
                }
                res = listener.accept() => {
                    match res {
                        Ok((conn, peer)) => {
                            let me = Arc::clone(&self);
                            let stop = shutdown.clone();
                            tokio::spawn(async move {
                                me.handle_conn(conn, peer.ip(), stop).await;
                            });
                        }
                        Err(e) => warn!("mgmt_entry accept error: {e}"),
                    }
                }
            }
        }
    }

    async fn handle_conn(
        &self,
        mut client: TcpStream,
        peer_ip: IpAddr,
        mut shutdown: watch::Receiver<bool>,
    ) {
        if !self.acquire_slot(peer_ip) {
            return;
        }
        let _guard = SlotGuard {
            proxy: self,
            ip: peer_ip,
        };
        let _ = client.set_nodelay(true);

        let Ok(Ok(mut upstream)) = tokio::time::timeout(
            self.dial_timeout,
            TcpStream::connect(&self.central_target),
        )
        .await
        else {
            return;
        };
        let _ = upstream.set_nodelay(true);

        let Ok(preface) = encode_bhe1(&self.priv_key, self.node_id, peer_ip, now_unix()) else {
            return;
        };
        if upstream.write_all(&preface).await.is_err() {
            return;
        }

        let (mut cr, mut cw) = client.split();
        let (mut ur, mut uw) = upstream.split();
        let idle = self.idle_timeout;

        let c2u = async {
            let mut buf = [0u8; 32 * 1024];
            loop {
                match tokio::time::timeout(idle, cr.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => {
                        if tokio::time::timeout(idle, uw.write_all(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = uw.shutdown().await;
        };
        let u2c = async {
            let mut buf = [0u8; 32 * 1024];
            loop {
                match tokio::time::timeout(idle, ur.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => {
                        if tokio::time::timeout(idle, cw.write_all(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = cw.shutdown().await;
        };

        tokio::select! {
            _ = shutdown.changed() => {}
            _ = async { tokio::join!(c2u, u2c) } => {}
        }
    }
}

struct SlotGuard<'a> {
    proxy: &'a MgmtEntryProxy,
    ip: IpAddr,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.proxy.release_slot(self.ip);
    }
}
