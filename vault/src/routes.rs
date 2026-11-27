//! Axum HTTP router for `berth-vault`.
//!
//! User/CLI endpoints (`/api/v1/berth/vault/*`):
//! - `GET  /quota`
//! - `GET  /sessions`
//! - `GET  /changes?since=<seq>`
//! - `PUT  /sessions` (requires Content-Length, X-Berth-Vault-Meta base64 JSON, X-Berth-Vault-SHA256)
//! - `GET  /sessions/{vault_id}` (binary blob stream, or `?meta_only=1` JSON)
//! - `PATCH /sessions/{vault_id}`
//! - `DELETE /sessions/{vault_id}` (tombstone + immediate quota release)
//!
//! Admin endpoints (`/api/v1/admin/berth/vault/*` — strictly Admin JWT only, never serves blobs):
//! - `GET /settings`
//! - `PUT /settings`
//! - `GET /users`
//! - `PUT /users/{user_id}/quota`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::{Mutex, Semaphore};
use tokio_util_stream::ReaderStream;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::{AuthClient, AuthError, extract_trusted_client_ip};
use crate::db::{DbError, PatchMeta, UploadMeta, VaultDb, normalize_upload_meta};
use crate::storage::{BlobStore, StageError, is_valid_sha256};

const HEADER_VAULT_META: &str = "x-berth-vault-meta";
const HEADER_VAULT_SHA256: &str = "x-berth-vault-sha256";
const HEADER_VAULT_ENCODING: &str = "x-berth-vault-encoding";
const MAX_UPLOADS_PER_USER: usize = 2;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthClient,
    pub db: VaultDb,
    pub blobs: BlobStore,
    pub user_upload_limits: Arc<Mutex<HashMap<i64, Arc<Semaphore>>>>,
    pub blob_locks: Arc<Mutex<HashMap<(i64, String), Arc<Mutex<()>>>>>,
}

/// Drop-safe single-settlement guard for an in-flight quota reservation.
/// Guarantees that even if a request future is cancelled by timeout/disconnect,
/// the reserved quota bytes are released at most once.
struct ReservationGuard {
    db: VaultDb,
    user_id: i64,
    bytes: i64,
}

impl ReservationGuard {
    fn new(db: VaultDb, user_id: i64, bytes: i64) -> Self {
        Self { db, user_id, bytes }
    }

    fn disarm(&mut self) {
        self.bytes = 0;
    }

    async fn release_now(&mut self) {
        let bytes = std::mem::take(&mut self.bytes);
        if bytes > 0 {
            self.db.release_reservation(self.user_id, bytes).await;
        }
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        let bytes = std::mem::take(&mut self.bytes);
        if bytes > 0 {
            let db = self.db.clone();
            let user_id = self.user_id;
            tokio::spawn(async move {
                db.release_reservation(user_id, bytes).await;
            });
        }
    }
}

impl AppState {
    async fn acquire_user_upload_slot(&self, user_id: i64) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = {
            let mut map = self.user_upload_limits.lock().await;
            map.entry(user_id)
                .or_insert_with(|| Arc::new(Semaphore::new(MAX_UPLOADS_PER_USER)))
                .clone()
        };
        sem.try_acquire_owned().ok()
    }

    async fn blob_lock(&self, user_id: i64, sha256: &str) -> Arc<Mutex<()>> {
        let mut map = self.blob_locks.lock().await;
        if map.len() > 4096 {
            map.retain(|_, v| Arc::strong_count(v) > 1);
        }
        map.entry((user_id, sha256.to_string()))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

pub fn build_router(state: AppState) -> Router {
    let sensitive = [
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderName::from_static("x-api-key"),
    ];
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/berth/vault/quota", get(get_my_quota))
        .route(
            "/api/v1/berth/vault/sessions",
            get(list_my_sessions).put(upload_session),
        )
        .route("/api/v1/berth/vault/changes", get(list_my_changes))
        .route(
            "/api/v1/berth/vault/sessions/{vault_id}",
            get(download_session)
                .patch(patch_session)
                .delete(delete_session),
        )
        .route(
            "/api/v1/admin/berth/vault/settings",
            get(admin_get_settings).put(admin_update_settings),
        )
        .route("/api/v1/admin/berth/vault/users", get(admin_list_users))
        .route(
            "/api/v1/admin/berth/vault/users/{user_id}/quota",
            put(admin_set_user_quota),
        )
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(120),
        ))
        .layer(SetSensitiveRequestHeadersLayer::new(sensitive))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    ok_json(serde_json::json!({ "status": "ok", "service": "berth-vault" }))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    provider: Option<String>,
    q: Option<String>,
    pinned: Option<String>,
    include_deleted: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Debug, Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    since: i64,
    #[serde(default = "default_changes_limit")]
    limit: i64,
}

fn default_changes_limit() -> i64 {
    200
}

#[derive(Debug, Deserialize)]
struct DownloadQuery {
    meta_only: Option<String>,
}

async fn get_my_quota(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    match state.db.get_user_quota(principal.user_id).await {
        Ok(q) => ok_json(q),
        Err(e) => db_err_response(e),
    }
}

async fn list_my_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    let pinned_only = matches!(q.pinned.as_deref(), Some("1" | "true" | "TRUE"));
    let include_deleted = matches!(q.include_deleted.as_deref(), Some("1" | "true" | "TRUE"));

    let (items, total) = match state
        .db
        .list_sessions(
            principal.user_id,
            q.provider.as_deref(),
            q.q.as_deref(),
            pinned_only,
            include_deleted,
            q.limit,
            q.offset,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return db_err_response(e),
    };
    let quota = match state.db.get_user_quota(principal.user_id).await {
        Ok(q) => q,
        Err(e) => return db_err_response(e),
    };
    ok_json(serde_json::json!({
        "items": items,
        "total": total,
        "quota": quota,
    }))
}

async fn list_my_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ChangesQuery>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    let (items, next_seq) = match state
        .db
        .list_changes(principal.user_id, q.since.max(0), q.limit)
        .await
    {
        Ok(v) => v,
        Err(e) => return db_err_response(e),
    };
    ok_json(serde_json::json!({
        "items": items,
        "next_seq": next_seq,
    }))
}

async fn upload_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };

    // Require Content-Length upfront so quota reservation happens BEFORE streaming any body bytes.
    let declared_len: i64 = match headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
    {
        Some(n) if n > 0 => n,
        _ => {
            return err_json(
                StatusCode::LENGTH_REQUIRED,
                "Content-Length header > 0 is required for vault uploads",
            );
        }
    };

    let raw_meta = match headers.get(HEADER_VAULT_META).and_then(|v| v.to_str().ok()) {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return err_json(StatusCode::BAD_REQUEST, "missing X-Berth-Vault-Meta header"),
    };
    let meta_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_meta)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_meta));
    let Ok(meta_bytes) = meta_bytes else {
        return err_json(StatusCode::BAD_REQUEST, "invalid base64 X-Berth-Vault-Meta");
    };
    let Ok(upload_meta) = serde_json::from_slice::<UploadMeta>(&meta_bytes) else {
        return err_json(StatusCode::BAD_REQUEST, "invalid JSON in X-Berth-Vault-Meta");
    };
    let norm_meta = match normalize_upload_meta(upload_meta) {
        Ok(m) => m,
        Err(e) => return db_err_response(e),
    };

    let expected_sha = headers
        .get(HEADER_VAULT_SHA256)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(ref sha) = expected_sha {
        if !is_valid_sha256(sha) {
            return err_json(StatusCode::BAD_REQUEST, "invalid X-Berth-Vault-SHA256 header");
        }
    }

    let Some(_permit) = state.acquire_user_upload_slot(principal.user_id).await else {
        return err_json(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent vault uploads for this user (max 2)",
        );
    };

    // Atomically reserve declared_len against user quota before streaming.
    // ReservationGuard guarantees single settlement even if the request is timed out / dropped.
    let reserved = match state.db.reserve_quota(principal.user_id, declared_len).await {
        Ok(n) => n,
        Err(e) => return db_err_response(e),
    };
    let mut res_guard = ReservationGuard::new(state.db.clone(), principal.user_id, reserved);

    // Stream body to staging file with exact declared_len cap (zero over-read possible).
    let staged = match state
        .blobs
        .stage_body(body, declared_len, expected_sha.as_deref())
        .await
    {
        Ok(s) => s,
        Err(StageError::EmptyBody) => {
            res_guard.release_now().await;
            return err_json(StatusCode::BAD_REQUEST, "empty upload body");
        }
        Err(StageError::TooLarge { limit }) => {
            res_guard.release_now().await;
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("upload body exceeded declared/max limit of {limit} bytes"),
            );
        }
        Err(StageError::HashMismatch { expected, actual }) => {
            res_guard.release_now().await;
            return err_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("SHA-256 mismatch: expected {expected}, got {actual}"),
            );
        }
        Err(StageError::Io(msg)) => {
            res_guard.release_now().await;
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, &msg);
        }
    };

    let stored_bytes = staged.stored_bytes;
    let sha256 = staged.sha256.clone();

    // Serialize filesystem publication & DB commit against concurrent deletion of the same digest.
    let blob_mutex = state.blob_lock(principal.user_id, &sha256).await;
    let _blob_guard = blob_mutex.lock().await;

    if let Err(e) = state.blobs.publish(principal.user_id, staged).await {
        res_guard.release_now().await;
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to publish blob: {e}"),
        );
    }

    match state
        .db
        .commit_snapshot(principal.user_id, norm_meta, stored_bytes, &sha256, reserved)
        .await
    {
        Ok((item, quota)) => {
            // SQL transaction already converted `reserved` into `used_bytes` (or released it on dedup).
            res_guard.disarm();
            ok_json(serde_json::json!({
                "item": item,
                "quota": quota,
            }))
        }
        Err(e) => {
            // SQL transaction rolled back; release reservation once and clean up orphaned blob if unreferenced.
            res_guard.release_now().await;
            if matches!(state.db.has_live_blob_ref(principal.user_id, &sha256).await, Ok(false)) {
                state.blobs.remove_blob(principal.user_id, &sha256).await;
            }
            db_err_response(e)
        }
    }
}

async fn download_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    let item = match state.db.get_session(principal.user_id, vault_id.trim()).await {
        Ok(i) => i,
        Err(e) => return db_err_response(e),
    };
    if matches!(q.meta_only.as_deref(), Some("1" | "true" | "TRUE")) {
        return ok_json(item);
    }

    let file = match state.blobs.open_blob(principal.user_id, &item.sha256).await {
        Ok(f) => f,
        Err(_) => return err_json(StatusCode::NOT_FOUND, "vault blob not found"),
    };

    let meta_json = serde_json::to_vec(&item).unwrap_or_default();
    let meta_b64 = base64::engine::general_purpose::STANDARD.encode(meta_json);
    let stream = ReaderStream::new(file);

    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&item.stored_bytes.to_string()) {
        h.insert(axum::http::header::CONTENT_LENGTH, v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta_b64) {
        h.insert(axum::http::HeaderName::from_static(HEADER_VAULT_META), v);
    }
    if let Ok(v) = HeaderValue::from_str(&item.sha256) {
        h.insert(axum::http::HeaderName::from_static(HEADER_VAULT_SHA256), v);
    }
    if let Ok(v) = HeaderValue::from_str(&item.encoding) {
        h.insert(axum::http::HeaderName::from_static(HEADER_VAULT_ENCODING), v);
    }
    resp
}

async fn patch_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
    Json(patch): Json<PatchMeta>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    match state
        .db
        .patch_session(principal.user_id, vault_id.trim(), patch)
        .await
    {
        Ok(updated) => ok_json(updated),
        Err(e) => db_err_response(e),
    }
}

async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let principal = match state.auth.authenticate_user(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    let sha_hint = match state
        .db
        .get_session_sha256(principal.user_id, vault_id.trim())
        .await
    {
        Ok(Some(sha)) => sha,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "session not found"),
        Err(e) => return db_err_response(e),
    };
    let blob_mutex = state.blob_lock(principal.user_id, &sha_hint).await;
    let _blob_guard = blob_mutex.lock().await;

    match state
        .db
        .tombstone_session(principal.user_id, vault_id.trim())
        .await
    {
        Ok((quota, orphan_sha)) => {
            if let Some(sha) = orphan_sha {
                state.blobs.remove_blob(principal.user_id, &sha).await;
            }
            ok_json(serde_json::json!({
                "deleted": true,
                "quota": quota,
            }))
        }
        Err(e) => db_err_response(e),
    }
}

// ---------- Admin Routes (Admin JWT Only, Zero Blob Reads) ----------

async fn admin_get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    if let Err(e) = state.auth.authenticate_admin(&headers, ip).await {
        return auth_err_response(e);
    }
    match state.db.get_settings().await {
        Ok(s) => ok_json(s),
        Err(e) => db_err_response(e),
    }
}

#[derive(Debug, Deserialize)]
struct AdminSettingsBody {
    default_quota_bytes: i64,
    max_item_bytes: i64,
}

async fn admin_update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminSettingsBody>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let admin = match state.auth.authenticate_admin(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    match state
        .db
        .update_settings(admin.user_id, body.default_quota_bytes, body.max_item_bytes)
        .await
    {
        Ok(s) => ok_json(s),
        Err(e) => db_err_response(e),
    }
}

#[derive(Debug, Deserialize)]
struct AdminUsersQuery {
    q: Option<String>,
    #[serde(default = "default_admin_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_admin_limit() -> i64 {
    50
}

async fn admin_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminUsersQuery>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    if let Err(e) = state.auth.authenticate_admin(&headers, ip).await {
        return auth_err_response(e);
    }
    let (items, total) = match state
        .db
        .list_admin_user_usage(q.q.as_deref(), q.limit, q.offset)
        .await
    {
        Ok(v) => v,
        Err(e) => return db_err_response(e),
    };
    let settings = match state.db.get_settings().await {
        Ok(s) => s,
        Err(e) => return db_err_response(e),
    };
    ok_json(serde_json::json!({
        "items": items,
        "total": total,
        "settings": settings,
    }))
}

#[derive(Debug, Deserialize)]
struct AdminSetQuotaBody {
    quota_bytes: Option<i64>,
    #[serde(default)]
    notes: String,
}

async fn admin_set_user_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_user_id): Path<i64>,
    Json(body): Json<AdminSetQuotaBody>,
) -> Response {
    let ip = extract_trusted_client_ip(&headers);
    let admin = match state.auth.authenticate_admin(&headers, ip).await {
        Ok(p) => p,
        Err(e) => return auth_err_response(e),
    };
    match state
        .db
        .set_user_quota_override(admin.user_id, target_user_id, body.quota_bytes, &body.notes)
        .await
    {
        Ok(quota) => ok_json(quota),
        Err(e) => db_err_response(e),
    }
}

// ---------- Helpers & Minimal Async File Stream ----------

fn ok_json<T: serde::Serialize>(data: T) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "code": 0,
            "message": "ok",
            "data": data,
        })),
    )
        .into_response()
}

fn err_json(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "code": status.as_u16(),
            "message": message,
        })),
    )
        .into_response()
}

fn auth_err_response(err: AuthError) -> Response {
    match err {
        AuthError::Unauthorized(m) => err_json(StatusCode::UNAUTHORIZED, &m),
        AuthError::Forbidden(m) => err_json(StatusCode::FORBIDDEN, &m),
        AuthError::UpstreamUnavailable(m) => err_json(StatusCode::BAD_GATEWAY, &m),
    }
}

fn db_err_response(err: DbError) -> Response {
    match err {
        DbError::NotFound => err_json(StatusCode::NOT_FOUND, "vault session not found"),
        DbError::InvalidInput(m) => err_json(StatusCode::BAD_REQUEST, &m),
        DbError::QuotaExceeded(detail) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "code": StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                "message": format!(
                    "session vault quota exceeded: projected {} bytes > quota {} bytes",
                    detail.projected_bytes, detail.quota_bytes
                ),
                "data": detail,
            })),
        )
            .into_response(),
        DbError::ItemTooLarge {
            item_bytes,
            max_item_bytes,
        } => err_json(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("upload {item_bytes} bytes exceeds maximum single-session limit {max_item_bytes} bytes"),
        ),
        DbError::Internal(m) => {
            tracing::error!("vault db error: {m}");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal vault error")
        }
    }
}

mod tokio_util_stream {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use axum::body::Bytes;
    use futures_util::Stream;
    use tokio::io::{AsyncRead, ReadBuf};

    pub struct ReaderStream<R> {
        reader: R,
        buf: Vec<u8>,
    }

    impl<R> ReaderStream<R> {
        pub fn new(reader: R) -> Self {
            Self {
                reader,
                buf: vec![0u8; 64 * 1024],
            }
        }
    }

    impl<R: AsyncRead + Unpin> Stream for ReaderStream<R> {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            let mut rb = ReadBuf::new(&mut this.buf);
            match Pin::new(&mut this.reader).poll_read(cx, &mut rb) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.buf[..n]))))
                    }
                }
            }
        }
    }
}
