use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Notify;

use crate::proto::{UsageReceipt, now_unix};

#[derive(Debug, Error)]
pub enum WalError {
    #[error("edgeproto: grant byte slice exhausted: grant={grant_id} need={need} rem={rem}")]
    GrantSliceExhausted { grant_id: i64, need: i64, rem: i64 },
    #[error("edgeproto: landing grant expired")]
    GrantExpired,
    #[error("edgeproto: landing grant revoked")]
    GrantRevoked,
    #[error("edgeproto: invalid byte amount")]
    InvalidAmount,
    #[error("edgeproto: wal io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("edgeproto: wal json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("edgeproto: wal interior corruption at byte offset {0}: {1}")]
    Corrupted(u64, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantWalRecord {
    op: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    slice_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    debit_id: String,
    #[serde(default)]
    grant_id: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    expires_at_unix: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    revoked: bool,
    #[serde(default)]
    ts: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[derive(Debug, Default, Clone)]
struct GrantState {
    remaining: i64,
    consumed: i64,
    expires_at_unix: i64,
    revoked: bool,
}

struct GrantWalInner {
    file: Option<File>,
    grants: HashMap<i64, GrantState>,
    seen_slices: HashSet<String>,
    record_count: usize,
}

pub struct GrantWal {
    path: PathBuf,
    inner: Mutex<GrantWalInner>,
}

/// Reads newline-delimited JSON records safely:
/// - Fails closed on any I/O error or interior malformed newline-terminated record.
/// - Repairs ONLY a demonstrably torn tail at EOF (missing trailing `\n`) by truncating
///   the file to the last verified newline boundary before opening for append.
fn replay_jsonl_verified<T, F>(path: &Path, mut on_record: F) -> Result<(), WalError>
where
    T: serde::de::DeserializeOwned,
    F: FnMut(T),
{
    if !path.exists() {
        return Ok(());
    }
    let f = File::open(path)?;
    let file_len = f.metadata()?.len();
    let mut reader = BufReader::new(f);
    let mut valid_offset: u64 = 0;
    let mut buf = Vec::new();
    let mut needs_truncate = false;

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        let ends_with_nl = buf.ends_with(b"\n");
        let trimmed = std::str::from_utf8(&buf)
            .map(|s| s.trim())
            .map_err(|e| (e.to_string(), ends_with_nl));

        match trimmed {
            Ok("") => {
                if ends_with_nl {
                    valid_offset += n as u64;
                } else {
                    needs_truncate = true;
                    break;
                }
            }
            Ok(line) => match serde_json::from_str::<T>(line) {
                Ok(rec) => {
                    if !ends_with_nl {
                        // Valid JSON without trailing newline at EOF — truncate to avoid
                        // concatenating the next record onto the same line.
                        needs_truncate = true;
                        break;
                    }
                    on_record(rec);
                    valid_offset += n as u64;
                }
                Err(e) => {
                    if !ends_with_nl && valid_offset + (n as u64) == file_len {
                        // Demonstrable torn tail from crash mid-write at EOF: truncate cleanly.
                        needs_truncate = true;
                        break;
                    }
                    return Err(WalError::Corrupted(valid_offset, e.to_string()));
                }
            },
            Err((msg, true)) => {
                return Err(WalError::Corrupted(valid_offset, msg));
            }
            Err((msg, false)) => {
                if valid_offset + (n as u64) == file_len {
                    needs_truncate = true;
                    break;
                }
                return Err(WalError::Corrupted(valid_offset, msg));
            }
        }
    }
    drop(reader);

    if needs_truncate {
        let wf = OpenOptions::new().write(true).open(path)?;
        wf.set_len(valid_offset)?;
        wf.sync_all()?;
    }
    Ok(())
}

impl GrantWal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut inner = GrantWalInner {
            file: None,
            grants: HashMap::new(),
            seen_slices: HashSet::new(),
            record_count: 0,
        };
        replay_jsonl_verified::<GrantWalRecord, _>(&path, |rec| {
            apply_grant_record(&mut inner, &rec);
            inner.record_count += 1;
        })?;
        inner.file = Some(open_append_0600(&path)?);
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    pub fn add_slice(
        &self,
        slice_id: &str,
        grant_id: i64,
        bytes: i64,
        expires_at_unix: i64,
    ) -> Result<(), WalError> {
        if slice_id.is_empty() || grant_id <= 0 || bytes < 0 {
            return Err(WalError::InvalidAmount);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.seen_slices.contains(slice_id) {
            return Ok(());
        }
        if inner.grants.get(&grant_id).is_some_and(|st| st.revoked) {
            return Err(WalError::GrantRevoked);
        }
        let rec = GrantWalRecord {
            op: "slice_granted".into(),
            slice_id: slice_id.to_string(),
            debit_id: String::new(),
            grant_id,
            bytes,
            expires_at_unix,
            revoked: false,
            ts: now_unix(),
        };
        append_durable(&mut inner.file, &rec)?;
        inner.record_count += 1;
        apply_grant_record(&mut inner, &rec);
        Ok(())
    }

    pub fn pre_debit(
        &self,
        grant_id: i64,
        chunk_bytes: i64,
        now_secs: i64,
    ) -> Result<String, WalError> {
        if grant_id <= 0 || chunk_bytes <= 0 {
            return Err(WalError::InvalidAmount);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let st = inner.grants.entry(grant_id).or_default();
        if st.revoked {
            return Err(WalError::GrantRevoked);
        }
        if st.expires_at_unix > 0 && now_secs >= st.expires_at_unix {
            return Err(WalError::GrantExpired);
        }
        if st.remaining < chunk_bytes {
            return Err(WalError::GrantSliceExhausted {
                grant_id,
                need: chunk_bytes,
                rem: st.remaining,
            });
        }
        let debit_id = random_hex_12();
        let rec = GrantWalRecord {
            op: "pre_debit".into(),
            slice_id: String::new(),
            debit_id: debit_id.clone(),
            grant_id,
            bytes: chunk_bytes,
            expires_at_unix: 0,
            revoked: false,
            ts: now_secs,
        };
        append_durable(&mut inner.file, &rec)?;
        inner.record_count += 1;
        apply_grant_record(&mut inner, &rec);
        Ok(debit_id)
    }

    pub fn pre_debit_up_to(
        &self,
        grant_id: i64,
        want_bytes: i64,
        now_secs: i64,
    ) -> Result<(i64, String), WalError> {
        if grant_id <= 0 || want_bytes <= 0 {
            return Err(WalError::InvalidAmount);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let st = inner.grants.entry(grant_id).or_default();
        if st.revoked {
            return Err(WalError::GrantRevoked);
        }
        if st.expires_at_unix > 0 && now_secs >= st.expires_at_unix {
            return Err(WalError::GrantExpired);
        }
        if st.remaining <= 0 {
            return Err(WalError::GrantSliceExhausted {
                grant_id,
                need: want_bytes,
                rem: 0,
            });
        }
        let admit = want_bytes.min(st.remaining);
        let debit_id = random_hex_12();
        let rec = GrantWalRecord {
            op: "pre_debit".into(),
            slice_id: String::new(),
            debit_id: debit_id.clone(),
            grant_id,
            bytes: admit,
            expires_at_unix: 0,
            revoked: false,
            ts: now_secs,
        };
        append_durable(&mut inner.file, &rec)?;
        inner.record_count += 1;
        apply_grant_record(&mut inner, &rec);
        Ok((admit, debit_id))
    }

    pub fn revoke_grant(&self, grant_id: i64) -> Result<(), WalError> {
        if grant_id <= 0 {
            return Err(WalError::InvalidAmount);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let rec = GrantWalRecord {
            op: "revoke_grant".into(),
            slice_id: String::new(),
            debit_id: String::new(),
            grant_id,
            bytes: 0,
            expires_at_unix: 0,
            revoked: true,
            ts: now_unix(),
        };
        append_durable(&mut inner.file, &rec)?;
        inner.record_count += 1;
        apply_grant_record(&mut inner, &rec);
        Ok(())
    }

    pub fn remaining(&self, grant_id: i64) -> i64 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .grants
            .get(&grant_id)
            .filter(|st| !st.revoked)
            .map(|st| st.remaining)
            .unwrap_or(0)
    }

    pub fn needs_refill(&self, grant_id: i64, low_watermark: i64) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.grants.get(&grant_id) {
            None => true,
            Some(st) if st.revoked => false,
            Some(st) => st.remaining <= low_watermark,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn apply_grant_record(inner: &mut GrantWalInner, rec: &GrantWalRecord) {
    let st = inner.grants.entry(rec.grant_id).or_default();
    match rec.op.as_str() {
        "slice_granted" => {
            if !rec.slice_id.is_empty() && !inner.seen_slices.insert(rec.slice_id.clone()) {
                return;
            }
            if rec.bytes > 0 {
                st.remaining += rec.bytes;
            }
            if rec.expires_at_unix > 0 {
                st.expires_at_unix = rec.expires_at_unix;
            }
        }
        "pre_debit" => {
            if rec.bytes > 0 {
                st.remaining = (st.remaining - rec.bytes).max(0);
                st.consumed += rec.bytes;
            }
        }
        "refund_unused" => {
            if rec.bytes > 0 {
                st.remaining += rec.bytes;
                st.consumed = (st.consumed - rec.bytes).max(0);
            }
        }
        "revoke_grant" => {
            st.revoked = true;
            st.remaining = 0;
        }
        "snapshot_state" => {
            if !rec.slice_id.is_empty() {
                inner.seen_slices.insert(rec.slice_id.clone());
            } else {
                st.remaining = rec.bytes;
                st.expires_at_unix = rec.expires_at_unix;
                st.revoked = rec.revoked;
            }
        }
        _ => {}
    }
}

// ---------- Durable OutboxWAL ----------

#[derive(Debug, Serialize, Deserialize)]
struct OutboxEntry {
    op: String, // "put" | "ack"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<UsageReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ack_ids: Vec<String>,
}

struct OutboxInner {
    file: Option<File>,
    pending: HashMap<String, UsageReceipt>,
    order: Vec<String>,
    acked_count: usize,
}

pub struct OutboxWal {
    path: PathBuf,
    compact_hint: usize,
    inner: Mutex<OutboxInner>,
    notify: Notify,
}

impl OutboxWal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut inner = OutboxInner {
            file: None,
            pending: HashMap::new(),
            order: Vec::new(),
            acked_count: 0,
        };
        replay_jsonl_verified::<OutboxEntry, _>(&path, |ent| match ent.op.as_str() {
            "put" => {
                if let Some(r) = ent.receipt {
                    if !r.receipt_id.is_empty() {
                        if !inner.pending.contains_key(&r.receipt_id) {
                            inner.order.push(r.receipt_id.clone());
                        }
                        inner.pending.insert(r.receipt_id.clone(), r);
                    }
                }
            }
            "ack" => {
                for id in ent.ack_ids {
                    if inner.pending.remove(&id).is_some() {
                        inner.acked_count += 1;
                    }
                }
            }
            _ => {}
        })?;
        inner.order.retain(|id| inner.pending.contains_key(id));
        inner.file = Some(open_append_0600(&path)?);
        Ok(Self {
            path,
            compact_hint: 64,
            inner: Mutex::new(inner),
            notify: Notify::new(),
        })
    }

    pub fn append(&self, mut receipt: UsageReceipt) -> Result<(), WalError> {
        if receipt.receipt_id.is_empty() {
            return Err(WalError::InvalidAmount);
        }
        if receipt.created_at == 0 {
            receipt.created_at = now_unix();
        }
        if receipt.total_bytes == 0 && (receipt.ingress_bytes > 0 || receipt.egress_bytes > 0) {
            receipt.total_bytes = receipt.ingress_bytes + receipt.egress_bytes;
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.pending.contains_key(&receipt.receipt_id) {
                return Ok(());
            }
            let ent = OutboxEntry {
                op: "put".into(),
                receipt: Some(receipt.clone()),
                ack_ids: Vec::new(),
            };
            append_durable(&mut inner.file, &ent)?;
            inner.order.push(receipt.receipt_id.clone());
            inner.pending.insert(receipt.receipt_id.clone(), receipt);
        }
        self.notify.notify_one();
        Ok(())
    }

    pub fn pending(&self) -> Vec<UsageReceipt> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .order
            .iter()
            .filter_map(|id| inner.pending.get(id).cloned())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).pending.len()
    }

    pub fn ack(&self, ids: &[String]) -> Result<(), WalError> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let matched: Vec<String> = ids
            .iter()
            .filter(|id| inner.pending.contains_key(id.as_str()))
            .cloned()
            .collect();
        if matched.is_empty() {
            return Ok(());
        }
        let ent = OutboxEntry {
            op: "ack".into(),
            receipt: None,
            ack_ids: matched.clone(),
        };
        append_durable(&mut inner.file, &ent)?;
        for id in &matched {
            if inner.pending.remove(id).is_some() {
                inner.acked_count += 1;
            }
        }
        let OutboxInner {
            ref mut order,
            ref pending,
            ..
        } = *inner;
        order.retain(|id| pending.contains_key(id));
        if inner.acked_count >= self.compact_hint || inner.pending.is_empty() {
            self.compact_locked(&mut inner)?;
        }
        Ok(())
    }

    fn compact_locked(&self, inner: &mut OutboxInner) -> Result<(), WalError> {
        let tmp_path = PathBuf::from(format!("{}.compact.tmp", self.path.display()));
        {
            let mut tmp = open_trunc_0600(&tmp_path)?;
            for id in &inner.order {
                if let Some(r) = inner.pending.get(id) {
                    let ent = OutboxEntry {
                        op: "put".into(),
                        receipt: Some(r.clone()),
                        ack_ids: Vec::new(),
                    };
                    let mut raw = serde_json::to_vec(&ent)?;
                    raw.push(b'\n');
                    tmp.write_all(&raw)?;
                }
            }
            tmp.sync_all()?;
        }
        inner.file = None;
        fs::rename(&tmp_path, &self.path)?;
        inner.file = Some(open_append_0600(&self.path)?);
        inner.acked_count = 0;
        Ok(())
    }

    pub async fn flush_once<F, Fut>(&self, max_batch: usize, sender: F) -> anyhow::Result<usize>
    where
        F: Fn(Vec<UsageReceipt>) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<String>>>,
    {
        let max_batch = if max_batch == 0 { 100 } else { max_batch };
        let pending = self.pending();
        if pending.is_empty() {
            return Ok(0);
        }
        let mut flushed = 0usize;
        for chunk in pending.chunks(max_batch) {
            let acked = sender(chunk.to_vec()).await?;
            if !acked.is_empty() {
                self.ack(&acked)?;
                flushed += acked.len();
            }
        }
        Ok(flushed)
    }

    pub async fn run_flusher<F, Fut>(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        base_backoff: Duration,
        max_backoff: Duration,
        sender: F,
    ) where
        F: Fn(Vec<UsageReceipt>) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<String>>>,
    {
        let mut backoff = base_backoff.max(Duration::from_millis(200));
        let max_backoff = max_backoff.max(backoff);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(backoff) => {}
            }
            if self.pending_count() > 0 {
                match self.flush_once(100, &sender).await {
                    Ok(_) => backoff = base_backoff,
                    Err(_) => backoff = (backoff * 2).min(max_backoff),
                }
            } else {
                backoff = base_backoff;
            }
        }
    }
}

fn append_durable<T: Serialize>(file: &mut Option<File>, rec: &T) -> Result<(), WalError> {
    let f = file
        .as_mut()
        .ok_or_else(|| WalError::Io(std::io::Error::other("WAL closed")))?;
    let mut raw = serde_json::to_vec(rec)?;
    raw.push(b'\n');
    f.write_all(&raw)?;
    f.sync_all()?;
    Ok(())
}

fn open_append_0600(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn open_trunc_0600(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn random_hex_12() -> String {
    let mut b = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
