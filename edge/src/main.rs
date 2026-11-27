#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

use berth_edge::VERSION;
use berth_edge::admission::{AdmissionGate, SliceRefiller, SnapshotRefresher};
use berth_edge::cage::LandingCageExecutor;
use berth_edge::central::{CentralClient, HeartbeatReport};
use berth_edge::config::{
    Config, ROLE_MGMT_ENTRY, load_node_private_key, parse_ed25519_public_key,
};
use berth_edge::mgmt_entry::MgmtEntryProxy;
use berth_edge::prober::PeerProber;
use berth_edge::reverse_tunnel::{ReverseTunnelClient, ReverseTunnelHub};
use berth_edge::server::EdgeServer;
use berth_edge::ssrf::CompatSsrfGuard;
use berth_edge::wal::{GrantWal, OutboxWal, WalError};

#[derive(Parser, Debug)]
#[command(name = "berth-edge", disable_version_flag = true)]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long = "node-id", default_value_t = 0)]
    node_id: i64,
    #[arg(long = "node-name", default_value = "")]
    node_name: String,
    #[arg(long, default_value = "")]
    roles: String,
    #[arg(long, default_value = "")]
    listen: String,
    #[arg(long = "central-url", default_value = "")]
    central_url: String,
    #[arg(long = "central-pubkey", default_value = "")]
    central_pubkey: String,
    #[arg(long = "mgmt-entry-listen", default_value = "")]
    mgmt_entry_listen: String,
    #[arg(long = "mgmt-central-target", default_value = "")]
    mgmt_central_target: String,
    #[arg(long = "reverse-tunnel-hub", default_value = "")]
    reverse_tunnel_hub: String,
    #[arg(long = "reverse-tunnel-dial", default_value = "")]
    reverse_tunnel_dial: String,
    #[arg(long = "wal-dir", default_value = "")]
    wal_dir: String,
    #[arg(long)]
    version: bool,
}

fn compute_self_sha256() -> String {
    let Ok(exe) = std::env::current_exe() else {
        return String::new();
    };
    let resolved = std::fs::canonicalize(&exe).unwrap_or(exe);
    let Ok(raw) = std::fs::read(&resolved) else {
        return String::new();
    };
    hex::encode(Sha256::digest(&raw))
}

fn runtime_arch_pair() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{arch}")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.version {
        let commit = option_env!("BERTH_EDGE_COMMIT").unwrap_or("rust");
        println!("berth-edge {VERSION} (commit: {commit})");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut cfg = match cli.config {
        Some(path) => Config::load(&path)?,
        None => Config::default(),
    };
    if cli.node_id > 0 {
        cfg.node_id = cli.node_id;
    }
    if !cli.node_name.is_empty() {
        cfg.node_name = cli.node_name;
    }
    if !cli.roles.is_empty() {
        cfg.roles = cli
            .roles
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if !cli.listen.is_empty() {
        cfg.listen_addr = cli.listen;
    }
    if !cli.central_url.is_empty() {
        cfg.central_url = cli.central_url;
    }
    if !cli.central_pubkey.is_empty() {
        cfg.central_pubkey = cli.central_pubkey;
    }
    if !cli.mgmt_entry_listen.is_empty() {
        cfg.mgmt_entry_listen_addr = cli.mgmt_entry_listen;
    }
    if !cli.mgmt_central_target.is_empty() {
        cfg.mgmt_central_target = cli.mgmt_central_target;
    }
    if !cli.reverse_tunnel_hub.is_empty() {
        cfg.reverse_tunnel_hub_addr = cli.reverse_tunnel_hub;
    }
    if !cli.reverse_tunnel_dial.is_empty() {
        cfg.reverse_tunnel_dial_addr = cli.reverse_tunnel_dial;
    }
    if !cli.wal_dir.is_empty() {
        cfg.wal_dir = cli.wal_dir;
    }
    cfg.apply_defaults();

    if cfg.node_id <= 0 {
        bail!("berth-edge: --node-id or config.node_id is required");
    }
    if cfg.roles.is_empty() {
        bail!("berth-edge: at least one role is required");
    }

    let node_priv = load_node_private_key(&cfg).context("load node private key")?;
    let central_pub = if !cfg.central_pubkey.trim().is_empty() {
        Some(parse_ed25519_public_key(&cfg.central_pubkey).context("parse central_pubkey")?)
    } else {
        None
    };

    let wal_dir = if cfg.wal_dir.trim().is_empty() {
        std::env::temp_dir().join(format!("berth-edge-{}", cfg.node_id))
    } else {
        PathBuf::from(&cfg.wal_dir)
    };
    let grant_wal = Arc::new(
        GrantWal::open(wal_dir.join("grant_wal.jsonl")).context("open grant WAL")?,
    );
    let outbox_wal = Arc::new(
        OutboxWal::open(wal_dir.join("outbox_wal.jsonl")).context("open outbox WAL")?,
    );

    let central = if !cfg.central_url.trim().is_empty() {
        Some(Arc::new(CentralClient::new(
            &cfg.central_url,
            cfg.node_id,
            node_priv.clone(),
        )?))
    } else {
        None
    };

    let mut initial_peer_keys = HashMap::new();
    for (&id, raw) in &cfg.peer_public_keys {
        if let Ok(pk) = parse_ed25519_public_key(raw) {
            initial_peer_keys.insert(id, pk);
        }
    }

    let rev_hub = if !cfg.reverse_tunnel_hub_addr.trim().is_empty() {
        Some(ReverseTunnelHub::new(
            cfg.node_id,
            node_priv.clone(),
            initial_peer_keys.clone(),
        ))
    } else {
        None
    };

    let rev_client = if !cfg.reverse_tunnel_dial_addr.trim().is_empty() {
        Some(ReverseTunnelClient::new(
            cfg.node_id,
            node_priv.clone(),
            cfg.reverse_tunnel_dial_addr.clone(),
            initial_peer_keys,
        ))
    } else {
        None
    };

    let ssrf_guard = Arc::new(CompatSsrfGuard::new(
        &cfg.allowed_upstream_hosts,
        &cfg.test_allow_loopback_hosts,
    ));
    let landing_exec = LandingCageExecutor::new(Arc::clone(&ssrf_guard));

    let refiller: Option<SliceRefiller> = central.as_ref().map(|c| {
        let cc = Arc::clone(c);
        Arc::new(move |grant_id: i64, want: i64| {
            let cc = Arc::clone(&cc);
            async move {
                cc.request_grant_slice(grant_id, want)
                    .await
                    .map_err(|_| WalError::GrantSliceExhausted {
                        grant_id,
                        need: want,
                        rem: 0,
                    })
            }
            .boxed()
        }) as SliceRefiller
    });

    let gate = AdmissionGate::new(
        central_pub,
        Some(Arc::clone(&grant_wal)),
        refiller,
        cfg.grant_slice_bytes,
        cfg.grant_low_watermark,
    );
    if let Some(c) = &central {
        let cc = Arc::clone(c);
        let refresher: SnapshotRefresher = Arc::new(move || {
            let cc = Arc::clone(&cc);
            async move { cc.heartbeat_snapshot().await }.boxed()
        });
        gate.set_snapshot_refresher(refresher);
    }

    let srv = EdgeServer::new(
        cfg.clone(),
        central.clone(),
        Arc::clone(&gate),
        Some(Arc::clone(&outbox_wal)),
        rev_hub.clone(),
        landing_exec,
        ssrf_guard,
    );

    let prober = PeerProber::new(cfg.node_id, rev_hub.clone(), Duration::from_secs(20));
    let self_sha256 = compute_self_sha256();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut tasks = Vec::new();

    // 1. Freshness watchdog (500ms fail-closed revocation enforcement).
    {
        let g = Arc::clone(&gate);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            g.run_freshness_watchdog(rx, Duration::from_millis(500)).await;
        }));
    }

    // 2. FR-125 PeerProber.
    if central.is_some() {
        let p = Arc::clone(&prober);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            p.run(rx).await;
        }));
    }

    // 3. Heartbeat + revocation snapshot + dynamic roles + BRT2 peer keys sync.
    if let Some(cc) = central.clone() {
        let srv_c = Arc::clone(&srv);
        let prober_c = Arc::clone(&prober);
        let hub_c = rev_hub.clone();
        let client_c = rev_client.clone();
        let node_name = cfg.node_name.clone();
        let hb_interval = cfg.heartbeat_duration();
        let sha_c = self_sha256.clone();
        let mut rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let commit = option_env!("BERTH_EDGE_COMMIT").unwrap_or("rust");
            let agent_version = format!("{VERSION}-{commit}");
            let arch = runtime_arch_pair();
            let mut ticker = tokio::time::interval(hb_interval);
            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        if *rx.borrow() { return; }
                    }
                    _ = ticker.tick() => {
                        let (links, live_rev) = prober_c.snapshot();
                        let report = HeartbeatReport {
                            status: "active".into(),
                            agent_version: agent_version.clone(),
                            agent_arch: arch.clone(),
                            agent_sha256: sha_c.clone(),
                            measured_links: Some(links),
                            live_reverse_tunnels: Some(live_rev),
                        };
                        match cc.heartbeat_full(&report).await {
                            Ok(res) => {
                                if let Err(e) = srv_c.gate().update_snapshot(res.revocation_snapshot) {
                                    warn!("berth-edge[{node_name}] snapshot update warning: {e}");
                                }
                                if !res.probe_targets.is_empty() {
                                    prober_c.update_targets(res.probe_targets);
                                }
                                if !res.peer_public_keys.is_empty() {
                                    let mut parsed = HashMap::new();
                                    for (id, raw) in res.peer_public_keys {
                                        if let Ok(pk) = parse_ed25519_public_key(&raw) {
                                            parsed.insert(id, pk);
                                        }
                                    }
                                    if let Some(ref h) = hub_c {
                                        h.update_peer_keys(parsed.clone());
                                    }
                                    if let Some(ref c) = client_c {
                                        c.update_peer_keys(parsed);
                                    }
                                }
                                if !res.node_roles.is_empty() {
                                    let prev = srv_c.roles();
                                    if srv_c.apply_runtime_roles(res.node_roles) {
                                        info!("berth-edge[{node_name}] runtime roles updated: {prev:?} -> {:?}", srv_c.roles());
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("berth-edge[{node_name}] heartbeat failed: {e}");
                            }
                        }
                    }
                }
            }
        }));
    }

    // 4. Dedicated Landing OAuth task long-poll worker (instant sub-second wakeup!).
    if central.is_some() {
        let srv_c = Arc::clone(&srv);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            srv_c.run_oauth_task_loop(rx).await;
        }));
    }

    // 5. Durable OutboxWAL flusher.
    if let Some(cc) = central.clone() {
        let ob = Arc::clone(&outbox_wal);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            ob.run_flusher(
                rx,
                Duration::from_millis(500),
                Duration::from_secs(30),
                move |batch| {
                    let cc = Arc::clone(&cc);
                    async move { cc.flush_usage_outbox(batch).await }
                },
            )
            .await;
        }));
    }

    // 6. BHE1 Management-Entry TCP proxy.
    if cfg.has_role(ROLE_MGMT_ENTRY) && !cfg.mgmt_central_target.trim().is_empty() {
        let proxy = MgmtEntryProxy::new(
            cfg.node_id,
            node_priv.clone(),
            cfg.mgmt_central_target.clone(),
        );
        let listen = cfg.mgmt_entry_listen_addr.clone();
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = proxy.listen_and_serve(&listen, rx).await {
                warn!("mgmt_entry stopped: {e}");
            }
        }));
    }

    // 7. Reverse-Tunnel Hub (Transit role).
    if let Some(hub) = rev_hub {
        let listen = cfg.reverse_tunnel_hub_addr.clone();
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = hub.listen_and_serve(&listen, rx).await {
                warn!("reverse_tunnel hub stopped: {e}");
            }
        }));
    }

    // 8. Reverse-Tunnel Outbound Client (NAT Landing role, BRT2 mutually-authenticated AEAD).
    if let Some(client) = rev_client {
        let svc = srv.service();
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            client.run(svc, rx).await;
        }));
    }

    // 9. Primary HTTP/1.1 + HTTP/2 (h2c) data-plane listener.
    if !cfg.listen_addr.trim().is_empty() {
        let srv_c = Arc::clone(&srv);
        let listen = cfg.listen_addr.clone();
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = srv_c.listen_and_serve(&listen, rx).await {
                warn!("data-plane listener stopped: {e}");
            }
        }));
    }

    info!(
        "berth-edge[{}] started (id={}, roles={:?}, version={VERSION})",
        cfg.node_name, cfg.node_id, cfg.roles
    );

    wait_for_shutdown_signal().await;
    info!("berth-edge[{}] shutting down...", cfg.node_name);
    let _ = shutdown_tx.send(true);

    if let Some(cc) = central {
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            outbox_wal.flush_once(100, move |batch| {
                let cc = Arc::clone(&cc);
                async move { cc.flush_usage_outbox(batch).await }
            }),
        )
        .await;
    }

    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
    }
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
