//! Safe per-user content-addressed blob storage for `berth-vault`.
//!
//! All paths are derived strictly from `(user_id, sha256)` beneath `root`:
//! `<root>/u_<user_id>/<sha[0..2]>/<sha>.bhv1`
//! Client-supplied paths are never trusted and uploaded blobs are never decompressed on the server.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

#[derive(Debug)]
pub struct StagedBlob {
    pub temp_path: PathBuf,
    pub stored_bytes: i64,
    pub sha256: String,
}

impl Drop for StagedBlob {
    fn drop(&mut self) {
        if self.temp_path.exists() {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

#[derive(Debug)]
pub enum StageError {
    EmptyBody,
    TooLarge { limit: i64 },
    HashMismatch { expected: String, actual: String },
    Io(String),
}

impl BlobStore {
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("create vault storage root {}", root.display()))?;
        std::fs::create_dir_all(root.join(".incoming"))
            .context("create vault .incoming staging directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(
                root.join(".incoming"),
                std::fs::Permissions::from_mode(0o700),
            );
        }
        Ok(Self { root })
    }

    /// Deterministically derives the physical blob path from integer `user_id` and
    /// strictly validated 64-hex lowercase `sha256`.
    pub fn blob_path(&self, user_id: i64, sha256: &str) -> Result<PathBuf> {
        if user_id <= 0 {
            bail!("invalid user_id");
        }
        if !is_valid_sha256(sha256) {
            bail!("invalid sha256 digest");
        }
        Ok(self
            .root
            .join(format!("u_{user_id}"))
            .join(&sha256[..2])
            .join(format!("{sha256}.bhv1")))
    }

    /// Streams an axum request body directly to a private staging file on the same
    /// filesystem, hashing SHA-256 on the fly and enforcing `max_bytes` strictly.
    pub async fn stage_body(
        &self,
        body: axum::body::Body,
        max_bytes: i64,
        expected_sha256: Option<&str>,
    ) -> Result<StagedBlob, StageError> {
        let tmp_path = self
            .root
            .join(".incoming")
            .join(format!("{}.tmp", Uuid::now_v7()));

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await
            .map_err(|e| StageError::Io(format!("create staging file: {e}")))?;

        let mut hasher = Sha256::new();
        let mut total: i64 = 0;
        let mut stream = body.into_data_stream();

        while let Some(chunk_res) = stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path).await;
                    return Err(StageError::Io(format!("read upload stream: {e}")));
                }
            };
            let len = chunk.len() as i64;
            if total.saturating_add(len) > max_bytes {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(StageError::TooLarge { limit: max_bytes });
            }
            if let Err(e) = file.write_all(&chunk).await {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(StageError::Io(format!("write staging file: {e}")));
            }
            hasher.update(&chunk);
            total += len;
        }

        if let Err(e) = file.sync_all().await {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(StageError::Io(format!("fsync staging file: {e}")));
        }
        drop(file);

        if total == 0 {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(StageError::EmptyBody);
        }

        let actual = hex::encode(hasher.finalize());
        if let Some(expected) = expected_sha256 {
            if actual != expected {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(StageError::HashMismatch {
                    expected: expected.to_string(),
                    actual,
                });
            }
        }

        Ok(StagedBlob {
            temp_path: tmp_path,
            stored_bytes: total,
            sha256: actual,
        })
    }

    /// Publishes a staged blob atomically into `<root>/u_<user_id>/<sha[0..2]>/<sha>.bhv1`.
    pub async fn publish(&self, user_id: i64, mut staged: StagedBlob) -> Result<PathBuf> {
        let dest = self.blob_path(user_id, &staged.sha256)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&staged.temp_path, std::fs::Permissions::from_mode(0o600))
                .await;
        }
        if dest.exists() {
            // Identical content already stored for this user — remove redundant staging file.
            let _ = fs::remove_file(&staged.temp_path).await;
        } else {
            fs::rename(&staged.temp_path, &dest).await?;
        }
        // Clear temp_path so Drop does not remove anything further.
        staged.temp_path = PathBuf::new();
        Ok(dest)
    }

    /// Removes a user blob file (called only after DB confirms zero remaining active references).
    pub async fn remove_blob(&self, user_id: i64, sha256: &str) {
        if let Ok(path) = self.blob_path(user_id, sha256) {
            let _ = fs::remove_file(path).await;
        }
    }

    /// Opens a user blob for streaming download.
    pub async fn open_blob(&self, user_id: i64, sha256: &str) -> Result<fs::File> {
        let path = self.blob_path(user_id, sha256)?;
        Ok(fs::File::open(path).await?)
    }

    /// Sweeps stale temporary staging files older than `max_age`.
    pub async fn sweep_stale_incoming(&self, max_age: std::time::Duration) {
        let incoming = self.root.join(".incoming");
        let Ok(mut rd) = fs::read_dir(&incoming).await else {
            return;
        };
        let now = std::time::SystemTime::now();
        while let Ok(Some(entry)) = rd.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                if let Ok(modified) = meta.modified() {
                    if now.duration_since(modified).unwrap_or_default() > max_age {
                        let _ = fs::remove_file(entry.path()).await;
                    }
                }
            }
        }
    }
}

pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_path_is_strictly_server_derived_and_rejects_traversal() {
        let tmp = std::env::temp_dir().join(format!("berth-vault-test-{}", Uuid::now_v7()));
        let store = BlobStore::new(tmp.clone()).unwrap();
        let valid_sha = "a".repeat(64);
        let p = store.blob_path(42, &valid_sha).unwrap();
        assert!(p.starts_with(&tmp));
        assert!(p.ends_with(format!("u_42/aa/{valid_sha}.bhv1")));

        assert!(store.blob_path(0, &valid_sha).is_err());
        assert!(store.blob_path(42, "../etc/passwd").is_err());
        assert!(store.blob_path(42, &"A".repeat(64)).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
