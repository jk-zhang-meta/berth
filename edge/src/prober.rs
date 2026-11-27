use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore, watch};

use crate::proto::now_unix;
use crate::reverse_tunnel::{EdgeBody, ReverseTunnelHub};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub node_id: i64,
    #[serde(default)]
    pub node_name: String,
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredPeerLink {
    pub target_node_id: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_name: String,
    pub reachable: bool,
    pub rtt_ms: i32,
    pub link_class: String, // direct | reverse_tunnel
    pub measured_at_unix: i64,
}

struct ProberState {
    targets: Vec<ProbeTarget>,
    measured: HashMap<i64, MeasuredPeerLink>,
}

pub struct PeerProber {
    self_node_id: i64,
    rev_hub: Option<Arc<ReverseTunnelHub>>,
    http: Client,
    interval: Duration,
    state: RwLock<ProberState>,
    kick: Notify,
}

impl PeerProber {
    pub fn new(
        self_node_id: i64,
        rev_hub: Option<Arc<ReverseTunnelHub>>,
        interval: Duration,
    ) -> Arc<Self> {
        let interval = if interval.is_zero() {
            Duration::from_secs(20)
        } else {
            interval
        };
        let http = Client::builder()
            .timeout(Duration::from_millis(2500))
            .pool_max_idle_per_host(0)
            .build()
            .expect("prober http client");
        Arc::new(Self {
            self_node_id,
            rev_hub,
            http,
            interval,
            state: RwLock::new(ProberState {
                targets: Vec::new(),
                measured: HashMap::new(),
            }),
            kick: Notify::new(),
        })
    }

    pub fn update_targets(&self, targets: Vec<ProbeTarget>) {
        let mut clean = Vec::with_capacity(targets.len());
        let mut seen = HashSet::new();
        for t in targets {
            let addr = t
                .addr
                .trim()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('/')
                .to_string();
            if t.node_id <= 0 || t.node_id == self.self_node_id || addr.is_empty() {
                continue;
            }
            if !seen.insert(t.node_id) {
                continue;
            }
            clean.push(ProbeTarget {
                node_id: t.node_id,
                node_name: t.node_name,
                addr,
            });
        }

        let should_kick = {
            let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
            let had = !st.targets.is_empty();
            st.targets = clean;
            st.measured
                .retain(|id, m| m.link_class == "reverse_tunnel" || seen.contains(id));
            !had && !st.targets.is_empty()
        };
        if should_kick {
            self.kick.notify_one();
        }
    }

    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
                _ = self.kick.notified() => {
                    self.probe_once().await;
                }
                _ = ticker.tick() => {
                    self.probe_once().await;
                }
            }
        }
    }

    pub async fn probe_once(self: &Arc<Self>) {
        let targets = {
            self.state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .targets
                .clone()
        };
        let rev_peers = self
            .rev_hub
            .as_ref()
            .map(|h| h.connected_node_ids())
            .unwrap_or_default();

        let sem = Arc::new(Semaphore::new(8));
        let mut handles = Vec::new();

        for t in targets {
            let me = Arc::clone(self);
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                let (ok, rtt) = me.probe_direct(&t.addr).await;
                me.record_sample(t.node_id, &t.node_name, "direct", ok, rtt);
            }));
        }

        let rev_set: HashSet<i64> = rev_peers.iter().copied().collect();
        for peer_id in rev_peers {
            let me = Arc::clone(self);
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                let (ok, rtt) = me.probe_reverse_tunnel(peer_id).await;
                me.record_sample(peer_id, "", "reverse_tunnel", ok, rtt);
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        st.measured
            .retain(|id, m| m.link_class != "reverse_tunnel" || rev_set.contains(id));
    }

    async fn probe_direct(&self, addr: &str) -> (bool, i32) {
        let url = format!("http://{addr}/healthz");
        let start = Instant::now();
        match self.http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                // Drop body immediately after status check so a stalled peer cannot hold the probe.
                drop(resp);
                let ms = (start.elapsed().as_millis() as i32).max(1);
                (true, ms)
            }
            _ => (false, 0),
        }
    }

    async fn probe_reverse_tunnel(&self, node_id: i64) -> (bool, i32) {
        let Some(hub) = &self.rev_hub else {
            return (false, 0);
        };
        let uri = format!("http://node-{node_id}.edge.internal/healthz");
        let body: EdgeBody = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        let Ok(req) = Request::builder().method("GET").uri(uri).body(body) else {
            return (false, 0);
        };
        let start = Instant::now();
        match tokio::time::timeout(Duration::from_millis(2500), hub.round_trip(node_id, req)).await
        {
            Ok(Ok(resp)) if resp.status().is_success() => {
                // Drop body immediately after status verification so a slow peer can never stall rounds.
                drop(resp);
                let ms = (start.elapsed().as_millis() as i32).max(1);
                (true, ms)
            }
            _ => (false, 0),
        }
    }

    fn record_sample(
        &self,
        target_id: i64,
        target_name: &str,
        link_class: &str,
        reachable: bool,
        sample_ms: i32,
    ) {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        let prev = st.measured.get(&target_id);
        let rtt = if reachable {
            if let Some(p) = prev.filter(|p| p.reachable && p.rtt_ms > 0) {
                ((p.rtt_ms * 7 + sample_ms * 3) / 10).max(1)
            } else {
                sample_ms
            }
        } else {
            sample_ms
        };
        let name = if target_name.is_empty() {
            prev.map(|p| p.target_name.clone()).unwrap_or_default()
        } else {
            target_name.to_string()
        };
        st.measured.insert(
            target_id,
            MeasuredPeerLink {
                target_node_id: target_id,
                target_name: name,
                reachable,
                rtt_ms: rtt,
                link_class: link_class.to_string(),
                measured_at_unix: now_unix(),
            },
        );
    }

    pub fn snapshot(&self) -> (Vec<MeasuredPeerLink>, Vec<i64>) {
        let mut links: Vec<MeasuredPeerLink> = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .measured
            .values()
            .cloned()
            .collect();
        links.sort_by_key(|l| l.target_node_id);
        let live_rev = self
            .rev_hub
            .as_ref()
            .map(|h| h.connected_node_ids())
            .unwrap_or_default();
        (links, live_rev)
    }
}
