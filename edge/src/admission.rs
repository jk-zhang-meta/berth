use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use futures_util::future::BoxFuture;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::config::{DEFAULT_GRANT_LOW_WATERMARK, DEFAULT_GRANT_SLICE_BYTES};
use crate::proto::{
    ProtoError, RevocationSnapshot, SessionLeaseClaims, now_unix, verify_lease,
    verify_revocation_snapshot,
};
use crate::wal::{GrantWal, WalError};

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("edge: landing grant concurrency limit exceeded")]
    GrantConcurrencyLimit,
    #[error("edge: landing grant RPM limit exceeded")]
    GrantRpmLimit,
    #[error("edge: lease landing_node_id ({lease}) does not match self ({self_id})")]
    LandingNodeMismatch { lease: i64, self_id: i64 },
    #[error("edge: active stream terminated: {0}")]
    StreamRevoked(String),
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error(transparent)]
    Wal(#[from] WalError),
}

impl AdmissionError {
    pub fn http_status_and_code(&self) -> (u16, &'static str) {
        match self {
            Self::Wal(WalError::GrantSliceExhausted { .. })
            | Self::Wal(WalError::GrantExpired)
            | Self::Wal(WalError::GrantRevoked) => (403, "landing_grant_exhausted"),
            Self::GrantConcurrencyLimit | Self::GrantRpmLimit => (429, "landing_grant_rate_limited"),
            Self::Proto(ProtoError::LeaseRevoked)
            | Self::Proto(ProtoError::GrantRevoked)
            | Self::Proto(ProtoError::ApiKeyRevoked)
            | Self::Proto(ProtoError::CageEpochStale)
            | Self::LandingNodeMismatch { .. } => (403, "lease_revoked"),
            Self::Proto(ProtoError::RevocationSnapshotMissing)
            | Self::Proto(ProtoError::RevocationSnapshotStale)
            | Self::Proto(ProtoError::RevocationSnapshotBehind) => (503, "revocation_snapshot_stale"),
            _ => (401, "lease_unauthorized"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GrantLimits {
    pub max_concurrency: usize,
    pub max_rpm: usize,
}

pub type SliceRefiller = Arc<
    dyn Fn(i64, i64) -> BoxFuture<'static, Result<(String, i64, i64), WalError>> + Send + Sync,
>;

pub type SnapshotRefresher = Arc<
    dyn Fn() -> BoxFuture<'static, anyhow::Result<RevocationSnapshot>> + Send + Sync,
>;

struct RpmWindow {
    timestamps: Vec<Instant>,
}

impl RpmWindow {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    fn allow(&mut self, limit: usize, now: Instant) -> bool {
        if limit == 0 {
            return true;
        }
        self.timestamps
            .retain(|&t| now.saturating_duration_since(t) < Duration::from_secs(60));
        if self.timestamps.len() >= limit {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

struct ActiveStreamEntry {
    claims: SessionLeaseClaims,
    cancel_tx: watch::Sender<Option<String>>,
}

struct GateState {
    snapshot: Option<RevocationSnapshot>,
    grant_limits: HashMap<i64, GrantLimits>,
    grant_inflight: HashMap<i64, usize>,
    grant_rpm: HashMap<i64, RpmWindow>,
    active_streams: HashMap<u64, ActiveStreamEntry>,
}

pub struct AdmissionGate {
    central_pub_key: Option<VerifyingKey>,
    wal: Option<Arc<GrantWal>>,
    refiller: Option<SliceRefiller>,
    snap_refresher: RwLock<Option<SnapshotRefresher>>,
    snap_refresh_mu: AsyncMutex<()>,
    refill_locks: Mutex<HashMap<i64, Arc<AsyncMutex<()>>>>,
    slice_bytes: i64,
    low_watermark: i64,
    state: RwLock<GateState>,
    next_stream_id: AtomicU64,
}

impl AdmissionGate {
    pub fn new(
        central_pub_key: Option<VerifyingKey>,
        wal: Option<Arc<GrantWal>>,
        refiller: Option<SliceRefiller>,
        slice_bytes: i64,
        low_watermark: i64,
    ) -> Arc<Self> {
        let slice_bytes = if slice_bytes > 0 {
            slice_bytes
        } else {
            DEFAULT_GRANT_SLICE_BYTES
        };
        let low_watermark = if low_watermark > 0 {
            low_watermark
        } else {
            DEFAULT_GRANT_LOW_WATERMARK.min(slice_bytes / 4).max(1)
        };
        Arc::new(Self {
            central_pub_key,
            wal,
            refiller,
            snap_refresher: RwLock::new(None),
            snap_refresh_mu: AsyncMutex::new(()),
            refill_locks: Mutex::new(HashMap::new()),
            slice_bytes,
            low_watermark,
            state: RwLock::new(GateState {
                snapshot: None,
                grant_limits: HashMap::new(),
                grant_inflight: HashMap::new(),
                grant_rpm: HashMap::new(),
                active_streams: HashMap::new(),
            }),
            next_stream_id: AtomicU64::new(1),
        })
    }

    pub fn central_pub_key(&self) -> Option<&VerifyingKey> {
        self.central_pub_key.as_ref()
    }

    pub fn set_snapshot_refresher(&self, refresher: SnapshotRefresher) {
        *self.snap_refresher.write().unwrap_or_else(|e| e.into_inner()) = Some(refresher);
    }

    pub fn set_grant_limits(&self, grant_id: i64, limits: GrantLimits) {
        self.state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .grant_limits
            .insert(grant_id, limits);
    }

    pub fn active_stream_count(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .active_streams
            .len()
    }

    pub fn update_snapshot(&self, snap: RevocationSnapshot) -> Result<(), AdmissionError> {
        let now = now_unix();
        let pub_key = self
            .central_pub_key
            .as_ref()
            .ok_or(ProtoError::RevocationSnapshotInvalid)?;
        verify_revocation_snapshot(pub_key, &snap, now)?;

        let mut to_terminate = Vec::new();
        {
            let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
            if let Some(cur) = &st.snapshot {
                if snap.seq < cur.seq {
                    return Err(AdmissionError::Proto(ProtoError::RevocationSnapshotBehind));
                }
            }
            for entry in st.active_streams.values() {
                if let Err(reason) = snap.is_authorized(&entry.claims, now) {
                    to_terminate.push((entry.cancel_tx.clone(), reason.to_string()));
                }
            }
            st.snapshot = Some(snap.clone());
        }

        if let Some(wal) = &self.wal {
            for &gid in &snap.revoked_grant_ids {
                let _ = wal.revoke_grant(gid);
            }
        }
        for (tx, reason) in to_terminate {
            let _ = tx.send(Some(reason));
        }
        Ok(())
    }

    pub fn sweep_freshness(&self) -> usize {
        let now = now_unix();
        let mut to_terminate = Vec::new();
        {
            let st = self.state.read().unwrap_or_else(|e| e.into_inner());
            for entry in st.active_streams.values() {
                let auth = match &st.snapshot {
                    Some(snap) => snap.is_authorized(&entry.claims, now),
                    None => Err(ProtoError::RevocationSnapshotMissing),
                };
                if let Err(reason) = auth {
                    to_terminate.push((entry.cancel_tx.clone(), reason.to_string()));
                }
            }
        }
        let count = to_terminate.len();
        for (tx, reason) in to_terminate {
            let _ = tx.send(Some(reason));
        }
        count
    }

    pub async fn run_freshness_watchdog(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
        interval: Duration,
    ) {
        let interval = if interval.is_zero() {
            Duration::from_millis(500)
        } else {
            interval
        };
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
                _ = ticker.tick() => {
                    self.sweep_freshness();
                }
            }
        }
    }

    fn grant_refill_lock(&self, grant_id: i64) -> Arc<AsyncMutex<()>> {
        let mut map = self.refill_locks.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(grant_id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    async fn ensure_slice_capacity(&self, grant_id: i64, min_needed: i64) -> Result<(), WalError> {
        let Some(wal) = &self.wal else {
            return Ok(());
        };
        if grant_id <= 0 {
            return Ok(());
        }
        let threshold = self.low_watermark.max(min_needed);
        if !wal.needs_refill(grant_id, threshold) {
            return Ok(());
        }
        let Some(refiller) = &self.refiller else {
            return Ok(());
        };
        let lock = self.grant_refill_lock(grant_id);
        let _guard = lock.lock().await;
        if !wal.needs_refill(grant_id, threshold) {
            return Ok(());
        }
        let want = self.slice_bytes.max(min_needed);
        let (slice_id, granted, exp_unix) = refiller(grant_id, want).await?;
        if granted <= 0 {
            return Err(WalError::GrantSliceExhausted {
                grant_id,
                need: min_needed,
                rem: wal.remaining(grant_id),
            });
        }
        wal.add_slice(&slice_id, grant_id, granted, exp_unix)
    }

    pub async fn admit(
        self: &Arc<Self>,
        lease_token: &str,
        expected_landing_node_id: i64,
    ) -> Result<AdmittedStream, AdmissionError> {
        let now = now_unix();
        let pub_key = self
            .central_pub_key
            .as_ref()
            .ok_or(ProtoError::LeaseSignatureInvalid)?;
        let claims = verify_lease(pub_key, lease_token, now)?;
        if expected_landing_node_id > 0 && claims.landing_node_id != expected_landing_node_id {
            return Err(AdmissionError::LandingNodeMismatch {
                lease: claims.landing_node_id,
                self_id: expected_landing_node_id,
            });
        }

        let needs_refresh = {
            let st = self.state.read().unwrap_or_else(|e| e.into_inner());
            match &st.snapshot {
                Some(snap) => matches!(
                    snap.is_authorized(&claims, now),
                    Err(ProtoError::RevocationSnapshotBehind)
                ),
                None => true,
            }
        };

        if needs_refresh {
            let refresher = self
                .snap_refresher
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(refresher) = refresher {
                let _guard = self.snap_refresh_mu.lock().await;
                let still_behind = {
                    let st = self.state.read().unwrap_or_else(|e| e.into_inner());
                    st.snapshot
                        .as_ref()
                        .is_none_or(|s| s.seq < claims.rev_seq || now_unix() >= s.valid_until)
                };
                if still_behind {
                    if let Ok(fresh) = refresher().await {
                        let _ = self.update_snapshot(fresh);
                    }
                }
            }
        }

        let now_after = now_unix();
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        let auth_res = match &st.snapshot {
            Some(snap) => snap.is_authorized(&claims, now_after),
            None => Err(ProtoError::RevocationSnapshotMissing),
        };
        auth_res?;

        let is_landing = expected_landing_node_id > 0;
        let mut counted_inflight = false;
        if is_landing && claims.grant_id > 0 {
            let lim = st
                .grant_limits
                .get(&claims.grant_id)
                .copied()
                .unwrap_or_default();
            if lim.max_concurrency > 0 {
                let cur = st.grant_inflight.get(&claims.grant_id).copied().unwrap_or(0);
                if cur >= lim.max_concurrency {
                    return Err(AdmissionError::GrantConcurrencyLimit);
                }
            }
            if lim.max_rpm > 0 {
                let win = st
                    .grant_rpm
                    .entry(claims.grant_id)
                    .or_insert_with(RpmWindow::new);
                if !win.allow(lim.max_rpm, Instant::now()) {
                    return Err(AdmissionError::GrantRpmLimit);
                }
            }
            *st.grant_inflight.entry(claims.grant_id).or_insert(0) += 1;
            counted_inflight = true;
        }

        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (cancel_tx, cancel_rx) = watch::channel(None);
        st.active_streams.insert(
            stream_id,
            ActiveStreamEntry {
                claims: claims.clone(),
                cancel_tx,
            },
        );
        Ok(AdmittedStream {
            gate: Arc::clone(self),
            stream_id,
            claims,
            counted_inflight,
            cancel_rx,
        })
    }
}

pub struct AdmittedStream {
    gate: Arc<AdmissionGate>,
    stream_id: u64,
    claims: SessionLeaseClaims,
    counted_inflight: bool,
    cancel_rx: watch::Receiver<Option<String>>,
}

impl AdmittedStream {
    pub fn claims(&self) -> &SessionLeaseClaims {
        &self.claims
    }

    pub fn is_revoked(&self) -> Option<String> {
        self.cancel_rx.borrow().clone()
    }

    pub fn cancel_receiver(&self) -> watch::Receiver<Option<String>> {
        self.cancel_rx.clone()
    }

    pub async fn ensure_grant_capacity(&self) -> Result<(), AdmissionError> {
        if self.gate.wal.is_none() || self.claims.grant_id <= 0 {
            return Ok(());
        }
        if let Some(reason) = self.is_revoked() {
            return Err(AdmissionError::StreamRevoked(reason));
        }
        let wal = self.gate.wal.as_ref().unwrap();
        if wal.remaining(self.claims.grant_id) > 0 {
            return Ok(());
        }
        self.gate
            .ensure_slice_capacity(self.claims.grant_id, 1)
            .await?;
        if wal.remaining(self.claims.grant_id) <= 0 {
            return Err(AdmissionError::Wal(WalError::GrantSliceExhausted {
                grant_id: self.claims.grant_id,
                need: 1,
                rem: 0,
            }));
        }
        Ok(())
    }

    pub async fn pre_debit(&self, chunk_bytes: i64) -> Result<(), AdmissionError> {
        if self.gate.wal.is_none() || self.claims.grant_id <= 0 || chunk_bytes <= 0 {
            return Ok(());
        }
        if let Some(reason) = self.is_revoked() {
            return Err(AdmissionError::StreamRevoked(reason));
        }
        let wal = self.gate.wal.as_ref().unwrap();
        match wal.pre_debit(self.claims.grant_id, chunk_bytes, now_unix()) {
            Ok(_) => {
                if wal.needs_refill(self.claims.grant_id, self.gate.low_watermark) {
                    let _ = self
                        .gate
                        .ensure_slice_capacity(self.claims.grant_id, chunk_bytes)
                        .await;
                }
                Ok(())
            }
            Err(WalError::GrantSliceExhausted { .. }) => {
                self.gate
                    .ensure_slice_capacity(self.claims.grant_id, chunk_bytes)
                    .await?;
                wal.pre_debit(self.claims.grant_id, chunk_bytes, now_unix())?;
                Ok(())
            }
            Err(e) => Err(AdmissionError::Wal(e)),
        }
    }

    pub async fn pre_debit_up_to(&self, want_bytes: i64) -> Result<i64, AdmissionError> {
        if self.gate.wal.is_none() || self.claims.grant_id <= 0 || want_bytes <= 0 {
            return Ok(want_bytes);
        }
        if let Some(reason) = self.is_revoked() {
            return Err(AdmissionError::StreamRevoked(reason));
        }
        let wal = self.gate.wal.as_ref().unwrap();
        if wal.needs_refill(self.claims.grant_id, self.gate.low_watermark) {
            let _ = self
                .gate
                .ensure_slice_capacity(self.claims.grant_id, want_bytes)
                .await;
        }
        match wal.pre_debit_up_to(self.claims.grant_id, want_bytes, now_unix()) {
            Ok((admitted, _)) => Ok(admitted),
            Err(WalError::GrantSliceExhausted { .. }) => {
                if self
                    .gate
                    .ensure_slice_capacity(self.claims.grant_id, want_bytes)
                    .await
                    .is_ok()
                {
                    let (admitted, _) =
                        wal.pre_debit_up_to(self.claims.grant_id, want_bytes, now_unix())?;
                    return Ok(admitted);
                }
                Err(AdmissionError::Wal(WalError::GrantSliceExhausted {
                    grant_id: self.claims.grant_id,
                    need: want_bytes,
                    rem: 0,
                }))
            }
            Err(e) => Err(AdmissionError::Wal(e)),
        }
    }
}

impl Drop for AdmittedStream {
    fn drop(&mut self) {
        let mut st = self.gate.state.write().unwrap_or_else(|e| e.into_inner());
        st.active_streams.remove(&self.stream_id);
        if self.counted_inflight && self.claims.grant_id > 0 {
            if let Some(cur) = st.grant_inflight.get_mut(&self.claims.grant_id) {
                if *cur <= 1 {
                    st.grant_inflight.remove(&self.claims.grant_id);
                } else {
                    *cur -= 1;
                }
            }
        }
    }
}
