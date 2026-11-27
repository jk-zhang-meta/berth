#![forbid(unsafe_code)]

//! `berth-vault` — Standalone Pure-Rust Cloud Session Vault Daemon for Berth.
//!
//! Zero Go code. Runs alongside Berth Central on `isvoro-hk`, fronted by Nginx
//! on `/api/v1/berth/vault/*` and `/api/v1/admin/berth/vault/*`.

mod auth;
mod db;
mod routes;
mod storage;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;

use crate::auth::AuthClient;
use crate::db::VaultDb;
use crate::routes::{AppState, build_router};
use crate::storage::BlobStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "berth_vault=info,tower_http=info".into()),
        )
        .init();

    let bind_addr: SocketAddr = std::env::var("VAULT_BIND")
        .unwrap_or_else(|_| "127.0.0.1:18440".into())
        .parse()
        .context("parse VAULT_BIND")?;

    let storage_root = PathBuf::from(
        std::env::var("VAULT_STORAGE_ROOT")
            .unwrap_or_else(|_| "/opt/berth/data/session-vault".into()),
    );
    let central_url = std::env::var("VAULT_CENTRAL_URL")
        .unwrap_or_else(|_| "http://172.18.0.6:8080".into());

    let pg_host = std::env::var("VAULT_PG_HOST").unwrap_or_else(|_| "172.18.0.5".into());
    let pg_port: u16 = std::env::var("VAULT_PG_PORT")
        .unwrap_or_else(|_| "5432".into())
        .parse()
        .context("parse VAULT_PG_PORT")?;
    let pg_user = std::env::var("VAULT_PG_USER").unwrap_or_else(|_| "berth".into());
    let pg_db = std::env::var("VAULT_PG_DB").unwrap_or_else(|_| "berth".into());
    let pg_password = std::env::var("VAULT_PG_PASSWORD")
        .context("VAULT_PG_PASSWORD environment variable is required")?;

    let mut cfg = Config::new();
    cfg.host = Some(pg_host);
    cfg.port = Some(pg_port);
    cfg.user = Some(pg_user);
    cfg.dbname = Some(pg_db);
    cfg.password = Some(pg_password);
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    let pool = cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .context("create postgres pool")?;

    let db = VaultDb::new(pool.clone());
    db.verify_schema_ready()
        .await
        .context("verify migration 259 schema")?;

    let blobs = BlobStore::new(storage_root.clone())?;
    let auth = AuthClient::new(central_url.clone(), pool)?;

    // Periodic background sweeper for orphaned `.incoming/*.tmp` staging files.
    let sweep_blobs = blobs.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            sweep_blobs.sweep_stale_incoming(Duration::from_secs(900)).await;
        }
    });

    let state = AppState {
        auth,
        db,
        blobs,
        user_upload_limits: Arc::new(Mutex::new(HashMap::new())),
        blob_locks: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = build_router(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;
    tracing::info!(
        %bind_addr,
        storage_root = %storage_root.display(),
        central_url = %central_url,
        "berth-vault pure-Rust daemon listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("berth-vault shutting down cleanly");
}
