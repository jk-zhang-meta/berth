//! PostgreSQL data access layer for `berth-vault`:
//! - Atomic counter-row quota reservation (`berth_user_vault_usage`) — zero DB locks held over HTTP streaming.
//! - Immutable snapshot records + digest-bound tombstones + monotonic `change_seq` for multi-device sync.
//! - Encrypted metadata confidentiality enforced in code AND SQL CHECK constraint.
//! - Admin quota overrides with mandatory audit logging (`berth_vault_admin_audit`).

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_QUOTA_BYTES: i64 = 1024 * 1024 * 1024; // 1 GiB
pub const DEFAULT_MAX_ITEM_BYTES: i64 = 100 * 1024 * 1024; // 100 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    pub default_quota_bytes: i64,
    pub max_item_bytes: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserVaultQuota {
    pub user_id: i64,
    pub used_bytes: i64,
    pub reserved_bytes: i64,
    pub quota_bytes: i64,
    pub remaining_bytes: i64,
    pub max_item_bytes: i64,
    pub item_count: i64,
    pub has_custom_quota: bool,
    pub default_quota_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserVaultUsage {
    pub user_id: i64,
    pub email: String,
    pub username: String,
    pub used_bytes: i64,
    pub reserved_bytes: i64,
    pub item_count: i64,
    pub custom_quota_bytes: Option<i64>,
    pub effective_quota_bytes: i64,
    pub notes: String,
    pub last_uploaded_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSessionItem {
    pub id: i64,
    pub change_seq: i64,
    pub vault_id: String,
    pub user_id: i64,
    pub logical_id: String,
    pub revision: i32,
    pub parent_vault_id: Option<String>,
    pub provider: String,
    pub source_session_id: String,
    pub title: String,
    pub description: String,
    pub workspace_hint: String,
    pub git_repo: String,
    pub git_branch: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_meta_b64: Option<String>,
    pub message_count: i32,
    pub raw_bytes: i64,
    pub stored_bytes: i64,
    pub sha256: String,
    pub encoding: String,
    pub encrypted: bool,
    pub redacted: bool,
    pub redacted_count: i32,
    pub schema_version: i32,
    pub pinned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub tombstone_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadMeta {
    pub logical_id: String,
    #[serde(default)]
    pub parent_vault_id: Option<String>,
    pub provider: String,
    #[serde(default)]
    pub source_session_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub workspace_hint: String,
    #[serde(default)]
    pub git_repo: String,
    #[serde(default)]
    pub git_branch: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub sealed_meta_b64: Option<String>,
    #[serde(default)]
    pub message_count: i32,
    #[serde(default)]
    pub raw_bytes: i64,
    #[serde(default = "default_encoding")]
    pub encoding: String,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default = "default_true")]
    pub redacted: bool,
    #[serde(default)]
    pub redacted_count: i32,
    #[serde(default = "default_schema_version")]
    pub schema_version: i32,
    #[serde(default)]
    pub pinned: bool,
}

fn default_encoding() -> String {
    "zstd".to_string()
}
fn default_true() -> bool {
    true
}
fn default_schema_version() -> i32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatchMeta {
    pub title: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub pinned: Option<bool>,
    pub sealed_meta_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaExceededDetail {
    pub used_bytes: i64,
    pub reserved_bytes: i64,
    pub quota_bytes: i64,
    pub item_bytes: i64,
    pub projected_bytes: i64,
}

#[derive(Debug)]
pub enum DbError {
    NotFound,
    InvalidInput(String),
    QuotaExceeded(QuotaExceededDetail),
    ItemTooLarge { item_bytes: i64, max_item_bytes: i64 },
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct VaultDb {
    pool: Pool,
}

impl VaultDb {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Fails closed at startup if migration 259 tables are absent.
    pub async fn verify_schema_ready(&self) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        for table in [
            "berth_session_vault_settings",
            "berth_user_vault_quotas",
            "berth_user_vault_usage",
            "berth_session_vault_items",
            "berth_vault_admin_audit",
        ] {
            let exists: bool = client
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)",
                    &[&table],
                )
                .await?
                .get(0);
            if !exists {
                anyhow::bail!("missing required table `{table}` — apply migration 259_berth_session_vault.sql first");
            }
        }
        Ok(())
    }

    pub async fn get_settings(&self) -> Result<VaultSettings, DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let row = client
            .query_opt(
                "SELECT default_quota_bytes, max_item_bytes, updated_at FROM berth_session_vault_settings WHERE id = 1",
                &[],
            )
            .await
            .map_err(map_pg_err)?;
        match row {
            Some(r) => Ok(VaultSettings {
                default_quota_bytes: r.get(0),
                max_item_bytes: r.get(1),
                updated_at: r.get(2),
            }),
            None => Ok(VaultSettings {
                default_quota_bytes: DEFAULT_QUOTA_BYTES,
                max_item_bytes: DEFAULT_MAX_ITEM_BYTES,
                updated_at: Utc::now(),
            }),
        }
    }

    pub async fn update_settings(
        &self,
        admin_user_id: i64,
        default_quota_bytes: i64,
        max_item_bytes: i64,
    ) -> Result<VaultSettings, DbError> {
        if default_quota_bytes < 0 || max_item_bytes <= 0 {
            return Err(DbError::InvalidInput(
                "default_quota_bytes must be >= 0 and max_item_bytes > 0".into(),
            ));
        }
        let mut client = self.pool.get().await.map_err(map_pool_err)?;
        let tx = client.transaction().await.map_err(map_pg_err)?;
        let old_quota: Option<i64> = tx
            .query_opt(
                "SELECT default_quota_bytes FROM berth_session_vault_settings WHERE id = 1",
                &[],
            )
            .await
            .map_err(map_pg_err)?
            .map(|r| r.get(0));

        let row = tx
            .query_one(
                "INSERT INTO berth_session_vault_settings (id, default_quota_bytes, max_item_bytes, updated_at) \
                 VALUES (1, $1, $2, NOW()) \
                 ON CONFLICT (id) DO UPDATE \
                 SET default_quota_bytes = EXCLUDED.default_quota_bytes, \
                     max_item_bytes = EXCLUDED.max_item_bytes, \
                     updated_at = NOW() \
                 RETURNING default_quota_bytes, max_item_bytes, updated_at",
                &[&default_quota_bytes, &max_item_bytes],
            )
            .await
            .map_err(map_pg_err)?;

        tx.execute(
            "INSERT INTO berth_vault_admin_audit (admin_user_id, target_user_id, action, old_quota_bytes, new_quota_bytes, notes) \
             VALUES ($1, NULL, 'update_global_settings', $2, $3, $4)",
            &[
                &admin_user_id,
                &old_quota,
                &Some(default_quota_bytes),
                &format!("max_item_bytes={max_item_bytes}"),
            ],
        )
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        Ok(VaultSettings {
            default_quota_bytes: row.get(0),
            max_item_bytes: row.get(1),
            updated_at: row.get(2),
        })
    }

    pub async fn get_user_quota(&self, user_id: i64) -> Result<UserVaultQuota, DbError> {
        let settings = self.get_settings().await?;
        let client = self.pool.get().await.map_err(map_pool_err)?;

        let custom = client
            .query_opt(
                "SELECT quota_bytes, notes FROM berth_user_vault_quotas WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(map_pg_err)?;

        let usage = client
            .query_opt(
                "SELECT used_bytes, reserved_bytes, item_count FROM berth_user_vault_usage WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(map_pg_err)?;

        let (used_bytes, reserved_bytes, item_count) = match usage {
            Some(r) => (r.get::<_, i64>(0), r.get::<_, i64>(1), i64::from(r.get::<_, i32>(2))),
            None => (0, 0, 0),
        };
        let (effective, has_custom, notes) = match custom {
            Some(r) => (r.get::<_, i64>(0), true, r.get::<_, String>(1)),
            None => (settings.default_quota_bytes, false, String::new()),
        };
        let remaining = (effective - used_bytes - reserved_bytes).max(0);
        Ok(UserVaultQuota {
            user_id,
            used_bytes,
            reserved_bytes,
            quota_bytes: effective,
            remaining_bytes: remaining,
            max_item_bytes: settings.max_item_bytes,
            item_count,
            has_custom_quota: has_custom,
            default_quota_bytes: settings.default_quota_bytes,
            notes,
        })
    }

    /// Atomically reserves `reserve_bytes` in `berth_user_vault_usage` before reading the upload body.
    pub async fn reserve_quota(&self, user_id: i64, reserve_bytes: i64) -> Result<i64, DbError> {
        if reserve_bytes <= 0 {
            return Err(DbError::InvalidInput("Content-Length must be > 0".into()));
        }
        let settings = self.get_settings().await?;
        if reserve_bytes > settings.max_item_bytes {
            return Err(DbError::ItemTooLarge {
                item_bytes: reserve_bytes,
                max_item_bytes: settings.max_item_bytes,
            });
        }

        let mut client = self.pool.get().await.map_err(map_pool_err)?;
        let tx = client.transaction().await.map_err(map_pg_err)?;

        tx.execute(
            "INSERT INTO berth_user_vault_usage (user_id, used_bytes, reserved_bytes, item_count, updated_at) \
             VALUES ($1, 0, 0, 0, NOW()) ON CONFLICT (user_id) DO NOTHING",
            &[&user_id],
        )
        .await
        .map_err(map_pg_err)?;

        let effective_quota: i64 = tx
            .query_one(
                "SELECT COALESCE(\
                    (SELECT quota_bytes FROM berth_user_vault_quotas WHERE user_id = $1),\
                    (SELECT default_quota_bytes FROM berth_session_vault_settings WHERE id = 1),\
                    $2\
                 )",
                &[&user_id, &DEFAULT_QUOTA_BYTES],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);

        const MAX_USER_VAULT_ITEMS: i32 = 10_000;
        let updated = tx
            .query_opt(
                "UPDATE berth_user_vault_usage \
                 SET reserved_bytes = reserved_bytes + $2, updated_at = NOW() \
                 WHERE user_id = $1 \
                   AND item_count < $4 \
                   AND used_bytes + reserved_bytes + $2 <= $3 \
                 RETURNING used_bytes",
                &[&user_id, &reserve_bytes, &effective_quota, &MAX_USER_VAULT_ITEMS],
            )
            .await
            .map_err(map_pg_err)?;

        if updated.is_none() {
            let cur = tx
                .query_one(
                    "SELECT used_bytes, reserved_bytes, item_count FROM berth_user_vault_usage WHERE user_id = $1",
                    &[&user_id],
                )
                .await
                .map_err(map_pg_err)?;
            let used: i64 = cur.get(0);
            let reserved: i64 = cur.get(1);
            let count: i32 = cur.get(2);
            tx.rollback().await.ok();
            if count >= MAX_USER_VAULT_ITEMS {
                return Err(DbError::InvalidInput(format!(
                    "vault item count limit reached ({MAX_USER_VAULT_ITEMS} live items)"
                )));
            }
            return Err(DbError::QuotaExceeded(QuotaExceededDetail {
                used_bytes: used,
                reserved_bytes: reserved,
                quota_bytes: effective_quota,
                item_bytes: reserve_bytes,
                projected_bytes: used + reserved + reserve_bytes,
            }));
        }

        tx.commit().await.map_err(map_pg_err)?;
        Ok(reserve_bytes)
    }

    /// Reads the user's quota summary using an existing transaction (avoiding a second pool
    /// checkout and preventing post-commit read failures from triggering duplicate releases).
    async fn query_user_quota_tx(
        tx: &tokio_postgres::Transaction<'_>,
        user_id: i64,
    ) -> Result<UserVaultQuota, DbError> {
        let settings_row = tx
            .query_opt(
                "SELECT default_quota_bytes, max_item_bytes FROM berth_session_vault_settings WHERE id = 1",
                &[],
            )
            .await
            .map_err(map_pg_err)?;
        let (default_quota_bytes, max_item_bytes) = match settings_row {
            Some(r) => (r.get::<_, i64>(0), r.get::<_, i64>(1)),
            None => (DEFAULT_QUOTA_BYTES, DEFAULT_MAX_ITEM_BYTES),
        };
        let custom = tx
            .query_opt(
                "SELECT quota_bytes, notes FROM berth_user_vault_quotas WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(map_pg_err)?;
        let usage = tx
            .query_opt(
                "SELECT used_bytes, reserved_bytes, item_count FROM berth_user_vault_usage WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(map_pg_err)?;
        let (used_bytes, reserved_bytes, item_count) = match usage {
            Some(r) => (r.get::<_, i64>(0), r.get::<_, i64>(1), i64::from(r.get::<_, i32>(2))),
            None => (0, 0, 0),
        };
        let (effective, has_custom, notes) = match custom {
            Some(r) => (r.get::<_, i64>(0), true, r.get::<_, String>(1)),
            None => (default_quota_bytes, false, String::new()),
        };
        let remaining = (effective - used_bytes - reserved_bytes).max(0);
        Ok(UserVaultQuota {
            user_id,
            used_bytes,
            reserved_bytes,
            quota_bytes: effective,
            remaining_bytes: remaining,
            max_item_bytes,
            item_count,
            has_custom_quota: has_custom,
            default_quota_bytes,
            notes,
        })
    }

    pub async fn get_session_sha256(
        &self,
        user_id: i64,
        vault_id: &str,
    ) -> Result<Option<String>, DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let row = client
            .query_opt(
                "SELECT sha256 FROM berth_session_vault_items \
                 WHERE user_id = $1 AND vault_id = $2 AND deleted_at IS NULL",
                &[&user_id, &vault_id],
            )
            .await
            .map_err(map_pg_err)?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    pub async fn has_live_blob_ref(&self, user_id: i64, sha256: &str) -> Result<bool, DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let cnt: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM berth_session_vault_items \
                 WHERE user_id = $1 AND sha256 = $2 AND deleted_at IS NULL",
                &[&user_id, &sha256],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);
        Ok(cnt > 0)
    }

    /// Releases an in-flight quota reservation on upload error or abort.
    pub async fn release_reservation(&self, user_id: i64, reserved_bytes: i64) {
        if reserved_bytes <= 0 {
            return;
        }
        if let Ok(client) = self.pool.get().await {
            let _ = client
                .execute(
                    "UPDATE berth_user_vault_usage \
                     SET reserved_bytes = GREATEST(0, reserved_bytes - $2), updated_at = NOW() \
                     WHERE user_id = $1",
                    &[&user_id, &reserved_bytes],
                )
                .await;
        }
    }

    /// Commits an immutable snapshot record (idempotent on live `(user_id, logical_id, sha256)`,
    /// reviving tombstoned duplicates cleanly) and converts the reservation into `used_bytes`
    /// atomically within a single serialized transaction.
    pub async fn commit_snapshot(
        &self,
        user_id: i64,
        meta: NormalizedUploadMeta,
        stored_bytes: i64,
        sha256: &str,
        reserved_bytes: i64,
    ) -> Result<(VaultSessionItem, UserVaultQuota), DbError> {
        let mut client = self.pool.get().await.map_err(map_pool_err)?;
        let tx = client.transaction().await.map_err(map_pg_err)?;

        // Serialize blob publication vs concurrent last-reference deletion for (user_id, sha256).
        let lock_key = format!("berth_vault_blob:{user_id}:{sha256}");
        tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&lock_key])
            .await
            .map_err(map_pg_err)?;

        // Check existing row for (user_id, logical_id, sha256).
        let existing = tx
            .query_opt(
                &format!(
                    "SELECT {} FROM berth_session_vault_items \
                     WHERE user_id = $1 AND logical_id = $2 AND sha256 = $3 \
                     FOR UPDATE",
                    ITEM_COLUMNS
                ),
                &[&user_id, &meta.logical_id, &sha256],
            )
            .await
            .map_err(map_pg_err)?;

        let tags_json = serde_json::Value::Array(
            meta.tags
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        );
        let raw_bytes = if meta.raw_bytes > 0 {
            meta.raw_bytes
        } else {
            stored_bytes
        };

        if let Some(row) = existing {
            let item = row_to_item(&row);
            if item.deleted_at.is_none() {
                // Truly idempotent live duplicate: release reservation without charging again.
                tx.execute(
                    "UPDATE berth_user_vault_usage \
                     SET reserved_bytes = GREATEST(0, reserved_bytes - $2), updated_at = NOW() \
                     WHERE user_id = $1",
                    &[&user_id, &reserved_bytes],
                )
                .await
                .map_err(map_pg_err)?;
                let quota = Self::query_user_quota_tx(&tx, user_id).await?;
                tx.commit().await.map_err(map_pg_err)?;
                return Ok((item, quota));
            }
            // Previously tombstoned digest is being explicitly re-uploaded: revive row & re-charge quota.
            let revived_row = tx
                .query_one(
                    &format!(
                        "UPDATE berth_session_vault_items \
                         SET deleted_at = NULL, \
                             tombstone_sha256 = NULL, \
                             provider = $3, \
                             source_session_id = $4, \
                             title = $5, \
                             description = $6, \
                             workspace_hint = $7, \
                             git_repo = $8, \
                             git_branch = $9, \
                             tags = $10, \
                             sealed_meta = $11, \
                             message_count = $12, \
                             raw_bytes = $13, \
                             stored_bytes = $14, \
                             encoding = $15, \
                             encrypted = $16, \
                             redacted = $17, \
                             redacted_count = $18, \
                             schema_version = $19, \
                             pinned = $20, \
                             change_seq = nextval('berth_vault_change_seq'), \
                             updated_at = NOW() \
                         WHERE user_id = $1 AND vault_id = $2 \
                         RETURNING {ITEM_COLUMNS}"
                    ),
                    &[
                        &user_id,
                        &item.vault_id,
                        &meta.provider,
                        &meta.source_session_id,
                        &meta.title,
                        &meta.description,
                        &meta.workspace_hint,
                        &meta.git_repo,
                        &meta.git_branch,
                        &tags_json,
                        &meta.sealed_meta,
                        &meta.message_count,
                        &raw_bytes,
                        &stored_bytes,
                        &meta.encoding,
                        &meta.encrypted,
                        &meta.redacted,
                        &meta.redacted_count,
                        &meta.schema_version,
                        &meta.pinned,
                    ],
                )
                .await
                .map_err(map_pg_err)?;

            tx.execute(
                "UPDATE berth_user_vault_usage \
                 SET used_bytes = used_bytes + $2, \
                     reserved_bytes = GREATEST(0, reserved_bytes - $3), \
                     item_count = item_count + 1, \
                     updated_at = NOW() \
                 WHERE user_id = $1",
                &[&user_id, &stored_bytes, &reserved_bytes],
            )
            .await
            .map_err(map_pg_err)?;

            let revived = row_to_item(&revived_row);
            let quota = Self::query_user_quota_tx(&tx, user_id).await?;
            tx.commit().await.map_err(map_pg_err)?;
            return Ok((revived, quota));
        }

        let next_rev: i32 = tx
            .query_one(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM berth_session_vault_items WHERE user_id = $1 AND logical_id = $2",
                &[&user_id, &meta.logical_id],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);

        let vault_id = format!("vlt_{}", Uuid::now_v7().simple());

        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO berth_session_vault_items (\
                        vault_id, user_id, logical_id, revision, parent_vault_id,\
                        provider, source_session_id, title, description, workspace_hint,\
                        git_repo, git_branch, tags, sealed_meta, message_count,\
                        raw_bytes, stored_bytes, sha256, encoding, encrypted,\
                        redacted, redacted_count, schema_version, pinned\
                     ) VALUES (\
                        $1, $2, $3, $4, $5,\
                        $6, $7, $8, $9, $10,\
                        $11, $12, $13, $14, $15,\
                        $16, $17, $18, $19, $20,\
                        $21, $22, $23, $24\
                     ) RETURNING {ITEM_COLUMNS}"
                ),
                &[
                    &vault_id,
                    &user_id,
                    &meta.logical_id,
                    &next_rev,
                    &meta.parent_vault_id,
                    &meta.provider,
                    &meta.source_session_id,
                    &meta.title,
                    &meta.description,
                    &meta.workspace_hint,
                    &meta.git_repo,
                    &meta.git_branch,
                    &tags_json,
                    &meta.sealed_meta,
                    &meta.message_count,
                    &raw_bytes,
                    &stored_bytes,
                    &sha256,
                    &meta.encoding,
                    &meta.encrypted,
                    &meta.redacted,
                    &meta.redacted_count,
                    &meta.schema_version,
                    &meta.pinned,
                ],
            )
            .await
            .map_err(map_pg_err)?;

        tx.execute(
            "UPDATE berth_user_vault_usage \
             SET used_bytes = used_bytes + $2, \
                 reserved_bytes = GREATEST(0, reserved_bytes - $3), \
                 item_count = item_count + 1, \
                 updated_at = NOW() \
             WHERE user_id = $1",
            &[&user_id, &stored_bytes, &reserved_bytes],
        )
        .await
        .map_err(map_pg_err)?;

        let item = row_to_item(&row);
        let quota = Self::query_user_quota_tx(&tx, user_id).await?;
        tx.commit().await.map_err(map_pg_err)?;
        Ok((item, quota))
    }

    pub async fn list_sessions(
        &self,
        user_id: i64,
        provider: Option<&str>,
        query: Option<&str>,
        pinned_only: bool,
        include_deleted: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<VaultSessionItem>, i64), DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let limit = limit.clamp(1, 200);
        let offset = offset.max(0);
        let provider_filter = provider.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
        let like_pattern = query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|q| format!("%{q}%"));

        let total: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM berth_session_vault_items \
                 WHERE user_id = $1 \
                   AND ($2::boolean OR deleted_at IS NULL) \
                   AND ($3::text IS NULL OR provider = $3) \
                   AND (NOT $4::boolean OR pinned = TRUE) \
                   AND ($5::text IS NULL OR title ILIKE $5 OR description ILIKE $5 OR workspace_hint ILIKE $5 OR source_session_id ILIKE $5 OR logical_id ILIKE $5)",
                &[&user_id, &include_deleted, &provider_filter, &pinned_only, &like_pattern],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);

        let rows = client
            .query(
                &format!(
                    "SELECT {ITEM_COLUMNS} FROM berth_session_vault_items \
                     WHERE user_id = $1 \
                       AND ($2::boolean OR deleted_at IS NULL) \
                       AND ($3::text IS NULL OR provider = $3) \
                       AND (NOT $4::boolean OR pinned = TRUE) \
                       AND ($5::text IS NULL OR title ILIKE $5 OR description ILIKE $5 OR workspace_hint ILIKE $5 OR source_session_id ILIKE $5 OR logical_id ILIKE $5) \
                     ORDER BY pinned DESC, updated_at DESC \
                     LIMIT $6 OFFSET $7"
                ),
                &[
                    &user_id,
                    &include_deleted,
                    &provider_filter,
                    &pinned_only,
                    &like_pattern,
                    &limit,
                    &offset,
                ],
            )
            .await
            .map_err(map_pg_err)?;

        Ok((rows.iter().map(row_to_item).collect(), total))
    }

    pub async fn list_changes(
        &self,
        user_id: i64,
        since_seq: i64,
        limit: i64,
    ) -> Result<(Vec<VaultSessionItem>, i64), DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let limit = limit.clamp(1, 500);
        let rows = client
            .query(
                &format!(
                    "SELECT {ITEM_COLUMNS} FROM berth_session_vault_items \
                     WHERE user_id = $1 AND change_seq > $2 \
                     ORDER BY change_seq ASC \
                     LIMIT $3"
                ),
                &[&user_id, &since_seq, &limit],
            )
            .await
            .map_err(map_pg_err)?;
        let items: Vec<VaultSessionItem> = rows.iter().map(row_to_item).collect();
        let next_seq = items.last().map(|i| i.change_seq).unwrap_or(since_seq);
        Ok((items, next_seq))
    }

    pub async fn get_session(&self, user_id: i64, vault_id: &str) -> Result<VaultSessionItem, DbError> {
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT {ITEM_COLUMNS} FROM berth_session_vault_items \
                     WHERE user_id = $1 AND vault_id = $2 AND deleted_at IS NULL"
                ),
                &[&user_id, &vault_id],
            )
            .await
            .map_err(map_pg_err)?;
        row.map(|r| row_to_item(&r)).ok_or(DbError::NotFound)
    }

    pub async fn patch_session(
        &self,
        user_id: i64,
        vault_id: &str,
        patch: PatchMeta,
    ) -> Result<VaultSessionItem, DbError> {
        let current = self.get_session(user_id, vault_id).await?;
        let mut title = current.title.clone();
        let mut description = current.description.clone();
        let mut tags = current.tags.clone();
        let mut pinned = current.pinned;
        let mut sealed_meta = current
            .sealed_meta_b64
            .as_deref()
            .and_then(|b| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b).ok());

        if current.encrypted {
            if patch.title.is_some() || patch.description.is_some() || patch.tags.is_some() {
                return Err(DbError::InvalidInput(
                    "encrypted sessions cannot store plaintext title/description/tags; update sealed_meta_b64 or pinned instead".into(),
                ));
            }
        } else {
            if let Some(t) = patch.title {
                let t = truncate_chars(t.trim(), 240);
                if !t.is_empty() {
                    title = t;
                }
            }
            if let Some(d) = patch.description {
                description = truncate_chars(d.trim(), 2000);
            }
            if let Some(ts) = patch.tags {
                tags = sanitize_tags(ts);
            }
        }
        if let Some(p) = patch.pinned {
            pinned = p;
        }
        if let Some(b64) = patch.sealed_meta_b64 {
            let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
                .map_err(|_| DbError::InvalidInput("invalid base64 sealed_meta_b64".into()))?;
            if decoded.len() > 64 * 1024 {
                return Err(DbError::InvalidInput("sealed_meta exceeds 64 KiB".into()));
            }
            sealed_meta = Some(decoded);
        }

        let tags_json = serde_json::Value::Array(
            tags.into_iter().map(serde_json::Value::String).collect(),
        );
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let row = client
            .query_opt(
                &format!(
                    "UPDATE berth_session_vault_items \
                     SET title = $3, description = $4, tags = $5, pinned = $6, sealed_meta = $7, \
                         change_seq = nextval('berth_vault_change_seq'), updated_at = NOW() \
                     WHERE user_id = $1 AND vault_id = $2 AND deleted_at IS NULL \
                     RETURNING {ITEM_COLUMNS}"
                ),
                &[&user_id, &vault_id, &title, &description, &tags_json, &pinned, &sealed_meta],
            )
            .await
            .map_err(map_pg_err)?;
        row.map(|r| row_to_item(&r)).ok_or(DbError::NotFound)
    }

    /// Marks an item as tombstoned (preserving digest-bound tombstone for multi-device sync),
    /// compacts metadata fields, frees quota immediately, and returns `(updated_quota, Option<orphan_sha256_to_unlink>)`.
    pub async fn tombstone_session(
        &self,
        user_id: i64,
        vault_id: &str,
    ) -> Result<(UserVaultQuota, Option<String>), DbError> {
        let mut client = self.pool.get().await.map_err(map_pool_err)?;
        let tx = client.transaction().await.map_err(map_pg_err)?;

        let cur = tx
            .query_opt(
                "SELECT stored_bytes, sha256 FROM berth_session_vault_items \
                 WHERE user_id = $1 AND vault_id = $2 AND deleted_at IS NULL \
                 FOR UPDATE",
                &[&user_id, &vault_id],
            )
            .await
            .map_err(map_pg_err)?;

        let Some(cur) = cur else {
            return Err(DbError::NotFound);
        };
        let stored_bytes: i64 = cur.get(0);
        let sha256: String = cur.get(1);

        // Serialize last-reference deletion against concurrent upload of the same (user_id, sha256).
        let lock_key = format!("berth_vault_blob:{user_id}:{sha256}");
        tx.execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&lock_key])
            .await
            .map_err(map_pg_err)?;

        tx.execute(
            "UPDATE berth_session_vault_items \
             SET deleted_at = NOW(), \
                 tombstone_sha256 = sha256, \
                 sealed_meta = NULL, \
                 title = '', \
                 description = '', \
                 workspace_hint = '', \
                 git_repo = '', \
                 git_branch = '', \
                 tags = '[]'::jsonb, \
                 source_session_id = '', \
                 pinned = FALSE, \
                 change_seq = nextval('berth_vault_change_seq'), \
                 updated_at = NOW() \
             WHERE user_id = $1 AND vault_id = $2 AND deleted_at IS NULL",
            &[&user_id, &vault_id],
        )
        .await
        .map_err(map_pg_err)?;

        tx.execute(
            "UPDATE berth_user_vault_usage \
             SET used_bytes = GREATEST(0, used_bytes - $2), \
                 item_count = GREATEST(0, item_count - 1), \
                 updated_at = NOW() \
             WHERE user_id = $1",
            &[&user_id, &stored_bytes],
        )
        .await
        .map_err(map_pg_err)?;

        let remaining_refs: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM berth_session_vault_items \
                 WHERE user_id = $1 AND sha256 = $2 AND deleted_at IS NULL",
                &[&user_id, &sha256],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);

        let quota = Self::query_user_quota_tx(&tx, user_id).await?;
        tx.commit().await.map_err(map_pg_err)?;
        let orphan_sha = (remaining_refs == 0).then_some(sha256);
        Ok((quota, orphan_sha))
    }

    pub async fn list_admin_user_usage(
        &self,
        query: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AdminUserVaultUsage>, i64), DbError> {
        let settings = self.get_settings().await?;
        let client = self.pool.get().await.map_err(map_pool_err)?;
        let limit = limit.clamp(1, 200);
        let offset = offset.max(0);
        let like = query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|q| format!("%{q}%"));

        let total: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM users \
                 WHERE deleted_at IS NULL \
                   AND ($1::text IS NULL OR email ILIKE $1 OR username ILIKE $1)",
                &[&like],
            )
            .await
            .map_err(map_pg_err)?
            .get(0);

        let rows = client
            .query(
                "SELECT u.id, u.email, u.username, \
                        COALESCE(us.used_bytes, 0), COALESCE(us.reserved_bytes, 0), COALESCE(us.item_count, 0), \
                        q.quota_bytes, COALESCE(q.notes, ''), \
                        (SELECT MAX(updated_at) FROM berth_session_vault_items i WHERE i.user_id = u.id AND i.deleted_at IS NULL) \
                 FROM users u \
                 LEFT JOIN berth_user_vault_usage us ON us.user_id = u.id \
                 LEFT JOIN berth_user_vault_quotas q ON q.user_id = u.id \
                 WHERE u.deleted_at IS NULL \
                   AND ($1::text IS NULL OR u.email ILIKE $1 OR u.username ILIKE $1) \
                 ORDER BY COALESCE(us.used_bytes, 0) DESC, u.id ASC \
                 LIMIT $2 OFFSET $3",
                &[&like, &limit, &offset],
            )
            .await
            .map_err(map_pg_err)?;

        let out = rows
            .into_iter()
            .map(|r| {
                let custom: Option<i64> = r.get(6);
                let effective = custom.unwrap_or(settings.default_quota_bytes);
                AdminUserVaultUsage {
                    user_id: r.get(0),
                    email: r.get(1),
                    username: r.get(2),
                    used_bytes: r.get(3),
                    reserved_bytes: r.get(4),
                    item_count: i64::from(r.get::<_, i32>(5)),
                    custom_quota_bytes: custom,
                    effective_quota_bytes: effective,
                    notes: r.get(7),
                    last_uploaded_at: r.get(8),
                }
            })
            .collect();
        Ok((out, total))
    }

    pub async fn set_user_quota_override(
        &self,
        admin_user_id: i64,
        target_user_id: i64,
        quota_bytes: Option<i64>,
        notes: &str,
    ) -> Result<UserVaultQuota, DbError> {
        if target_user_id <= 0 {
            return Err(DbError::InvalidInput("invalid target user_id".into()));
        }
        if let Some(q) = quota_bytes {
            if q < 0 {
                return Err(DbError::InvalidInput("quota_bytes must be >= 0".into()));
            }
        }
        let clean_notes = truncate_chars(notes.trim(), 500);
        let mut client = self.pool.get().await.map_err(map_pool_err)?;
        let tx = client.transaction().await.map_err(map_pg_err)?;

        let old_quota: Option<i64> = tx
            .query_opt(
                "SELECT quota_bytes FROM berth_user_vault_quotas WHERE user_id = $1",
                &[&target_user_id],
            )
            .await
            .map_err(map_pg_err)?
            .map(|r| r.get(0));

        match quota_bytes {
            Some(q) => {
                tx.execute(
                    "INSERT INTO berth_user_vault_quotas (user_id, quota_bytes, notes, updated_by, updated_at) \
                     VALUES ($1, $2, $3, $4, NOW()) \
                     ON CONFLICT (user_id) DO UPDATE \
                     SET quota_bytes = EXCLUDED.quota_bytes, \
                         notes = EXCLUDED.notes, \
                         updated_by = EXCLUDED.updated_by, \
                         updated_at = NOW()",
                    &[&target_user_id, &q, &clean_notes, &admin_user_id],
                )
                .await
                .map_err(map_pg_err)?;
            }
            None => {
                tx.execute(
                    "DELETE FROM berth_user_vault_quotas WHERE user_id = $1",
                    &[&target_user_id],
                )
                .await
                .map_err(map_pg_err)?;
            }
        }

        tx.execute(
            "INSERT INTO berth_vault_admin_audit (admin_user_id, target_user_id, action, old_quota_bytes, new_quota_bytes, notes) \
             VALUES ($1, $2, 'set_user_quota', $3, $4, $5)",
            &[&admin_user_id, &Some(target_user_id), &old_quota, &quota_bytes, &clean_notes],
        )
        .await
        .map_err(map_pg_err)?;

        tx.commit().await.map_err(map_pg_err)?;
        self.get_user_quota(target_user_id).await
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedUploadMeta {
    pub logical_id: String,
    pub parent_vault_id: Option<String>,
    pub provider: String,
    pub source_session_id: String,
    pub title: String,
    pub description: String,
    pub workspace_hint: String,
    pub git_repo: String,
    pub git_branch: String,
    pub tags: Vec<String>,
    pub sealed_meta: Option<Vec<u8>>,
    pub message_count: i32,
    pub raw_bytes: i64,
    pub encoding: String,
    pub encrypted: bool,
    pub redacted: bool,
    pub redacted_count: i32,
    pub schema_version: i32,
    pub pinned: bool,
}

pub fn normalize_upload_meta(meta: UploadMeta) -> Result<NormalizedUploadMeta, DbError> {
    let provider = meta.provider.trim().to_ascii_lowercase();
    if provider.is_empty()
        || provider.len() > 32
        || !provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return Err(DbError::InvalidInput(format!("invalid provider `{provider}`")));
    }

    let logical_id = meta.logical_id.trim().to_string();
    if logical_id.is_empty() || logical_id.len() > 128 || logical_id.bytes().any(|b| b < 0x20) {
        return Err(DbError::InvalidInput("logical_id must be 1..128 printable chars".into()));
    }

    let encoding = meta.encoding.trim().to_ascii_lowercase();
    if !matches!(encoding.as_str(), "zstd" | "gzip" | "none") {
        return Err(DbError::InvalidInput(format!("unsupported encoding `{encoding}`")));
    }

    let sealed_meta = match meta.sealed_meta_b64 {
        Some(ref b64) if !b64.trim().is_empty() => {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b64.trim(),
            )
            .map_err(|_| DbError::InvalidInput("invalid base64 sealed_meta_b64".into()))?;
            if decoded.len() > 64 * 1024 {
                return Err(DbError::InvalidInput("sealed_meta exceeds 64 KiB".into()));
            }
            Some(decoded)
        }
        _ => None,
    };

    // Enforce SQL-level E2EE metadata confidentiality: encrypted records NEVER persist plaintext labels.
    let (source_session_id, title, description, workspace_hint, git_repo, git_branch, tags) =
        if meta.encrypted {
            (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
            )
        } else {
            let sid = truncate_chars(meta.source_session_id.trim(), 192);
            let mut title = truncate_chars(meta.title.trim(), 240);
            if title.is_empty() {
                title = format!("{provider}/{}", truncate_chars(&logical_id, 48));
            }
            (
                sid,
                title,
                truncate_chars(meta.description.trim(), 2000),
                truncate_chars(meta.workspace_hint.trim(), 512),
                truncate_chars(meta.git_repo.trim(), 256),
                truncate_chars(meta.git_branch.trim(), 128),
                sanitize_tags(meta.tags),
            )
        };

    Ok(NormalizedUploadMeta {
        logical_id,
        parent_vault_id: meta.parent_vault_id.map(|s| truncate_chars(s.trim(), 64)).filter(|s| !s.is_empty()),
        provider,
        source_session_id,
        title,
        description,
        workspace_hint,
        git_repo,
        git_branch,
        tags,
        sealed_meta,
        message_count: meta.message_count.max(0),
        raw_bytes: meta.raw_bytes.max(0),
        encoding,
        encrypted: meta.encrypted,
        redacted: meta.redacted,
        redacted_count: meta.redacted_count.max(0),
        schema_version: meta.schema_version.max(1),
        pinned: meta.pinned,
    })
}

const ITEM_COLUMNS: &str = "\
    id, change_seq, vault_id, user_id, logical_id, revision, parent_vault_id,\
    provider, source_session_id, title, description, workspace_hint,\
    git_repo, git_branch, tags, sealed_meta, message_count,\
    raw_bytes, stored_bytes, sha256, encoding, encrypted,\
    redacted, redacted_count, schema_version, pinned,\
    created_at, updated_at, deleted_at, tombstone_sha256";

fn row_to_item(r: &tokio_postgres::Row) -> VaultSessionItem {
    let tags_val: serde_json::Value = r.get(14);
    let tags = tags_val
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let sealed: Option<Vec<u8>> = r.get(15);
    let sealed_meta_b64 = sealed.map(|b| {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
    });
    VaultSessionItem {
        id: r.get(0),
        change_seq: r.get(1),
        vault_id: r.get(2),
        user_id: r.get(3),
        logical_id: r.get(4),
        revision: r.get(5),
        parent_vault_id: r.get(6),
        provider: r.get(7),
        source_session_id: r.get(8),
        title: r.get(9),
        description: r.get(10),
        workspace_hint: r.get(11),
        git_repo: r.get(12),
        git_branch: r.get(13),
        tags,
        sealed_meta_b64,
        message_count: r.get(16),
        raw_bytes: r.get(17),
        stored_bytes: r.get(18),
        sha256: r.get(19),
        encoding: r.get(20),
        encrypted: r.get(21),
        redacted: r.get(22),
        redacted_count: r.get(23),
        schema_version: r.get(24),
        pinned: r.get(25),
        created_at: r.get(26),
        updated_at: r.get(27),
        deleted_at: r.get(28),
        tombstone_sha256: r.get(29),
    }
}

fn sanitize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for t in tags {
        let clean = truncate_chars(t.trim(), 48);
        if clean.is_empty() {
            continue;
        }
        let lower = clean.to_ascii_lowercase();
        if seen.insert(lower) {
            out.push(clean);
            if out.len() >= 16 {
                break;
            }
        }
    }
    out
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn map_pool_err(e: deadpool_postgres::PoolError) -> DbError {
    DbError::Internal(format!("db pool: {e}"))
}

fn map_pg_err(e: tokio_postgres::Error) -> DbError {
    DbError::Internal(format!("postgres: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_upload_meta_strips_all_plaintext_fields() {
        let meta = UploadMeta {
            logical_id: "sess-1".into(),
            parent_vault_id: None,
            provider: "claude-code".into(),
            source_session_id: "uuid-secret".into(),
            title: "Secret M&A Project".into(),
            description: "Confidential".into(),
            workspace_hint: "/Users/alice/secret-repo".into(),
            git_repo: "github.com/corp/secret".into(),
            git_branch: "feat/secret".into(),
            tags: vec!["finance".into()],
            sealed_meta_b64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"ciphertext",
            )),
            message_count: 10,
            raw_bytes: 1234,
            encoding: "zstd".into(),
            encrypted: true,
            redacted: true,
            redacted_count: 2,
            schema_version: 1,
            pinned: true,
        };
        let norm = normalize_upload_meta(meta).unwrap();
        assert!(norm.encrypted);
        assert!(norm.source_session_id.is_empty());
        assert!(norm.title.is_empty());
        assert!(norm.description.is_empty());
        assert!(norm.workspace_hint.is_empty());
        assert!(norm.git_repo.is_empty());
        assert!(norm.git_branch.is_empty());
        assert!(norm.tags.is_empty());
        assert!(norm.sealed_meta.is_some());
    }
}
