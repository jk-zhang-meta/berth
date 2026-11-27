use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const LEASE_CLOCK_SKEW_SECONDS: i64 = 30;
pub const LEASE_TYPE_HEADER: &str = "berth-lease+jwt";
pub const LEASE_ALG_HEADER: &str = "EdDSA";

pub const HEADER_ROUTE: &str = "X-Berth-Route";
pub const HEADER_HOP_INDEX: &str = "X-Berth-Hop-Index";
pub const HEADER_LEASE: &str = "X-Berth-Lease";
pub const HEADER_REQUEST_ID: &str = "X-Berth-Request-ID";
pub const HEADER_OPERATION_ID: &str = "X-Berth-Operation-ID";
pub const HEADER_UPSTREAM_METHOD: &str = "X-Berth-Upstream-Method";
pub const HEADER_UPSTREAM_URL: &str = "X-Berth-Upstream-URL";
pub const HEADER_CONNECT_TARGET: &str = "X-Berth-Connect-Target";
pub const HEADER_ACCOUNT_ID: &str = "X-Berth-Account-ID";
pub const HEADER_LANDING_NODE: &str = "X-Berth-Landing-Node";
pub const HEADER_CAGE_COHORT: &str = "X-Berth-Cage-Cohort";
pub const HEADER_ACTION: &str = "X-Berth-Action";
pub const HEADER_SWITCH_REASON: &str = "X-Berth-Switch-Reason";
pub const HEADER_NODE_ID: &str = "X-Berth-Node-ID";
pub const HEADER_NODE_TIMESTAMP: &str = "X-Berth-Timestamp";
pub const HEADER_NODE_SIGNATURE: &str = "X-Berth-Signature";

pub const TUNNEL_EXECUTE_PATH: &str = "/edge/v1/execute";
pub const TUNNEL_WS_BRIDGE_PATH: &str = "/edge/v1/ws-bridge";
pub const TUNNEL_CONNECT_PATH: &str = "/edge/v1/connect";

pub const BHE1_MAGIC: &[u8; 4] = b"BHE1";
pub const BHE1_VERSION: u8 = 1;

pub const BRT1_MAGIC: &[u8; 4] = b"BRT1";
pub const BRT1_VERSION: u8 = 1;
pub const BRT1_FRAME_LEN: usize = 4 + 1 + 8 + 8 + 8 + 16 + 64; // 109 bytes

pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const WS_CLOSE_CAGE_REBIND: u16 = 4009;
pub const WS_CLOSE_NORMAL: u16 = 1000;

pub const WS_OP_TEXT: u8 = 0x1;
pub const WS_OP_BINARY: u8 = 0x2;
pub const WS_OP_CLOSE: u8 = 0x8;
pub const WS_OP_PING: u8 = 0x9;
pub const WS_OP_PONG: u8 = 0xA;

pub const DEFAULT_MAX_WS_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);
pub const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(90);
pub const DEFAULT_MAX_NONCES: usize = 100_000;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("edgeproto: invalid session lease: {0}")]
    LeaseInvalid(String),
    #[error("edgeproto: invalid lease signature")]
    LeaseSignatureInvalid,
    #[error("edgeproto: session lease expired")]
    LeaseExpired,
    #[error("edgeproto: session lease not yet valid")]
    LeaseNotYetValid,
    #[error("edgeproto: session lease revoked")]
    LeaseRevoked,
    #[error("edgeproto: landing grant revoked")]
    GrantRevoked,
    #[error("edgeproto: api key revoked")]
    ApiKeyRevoked,
    #[error("edgeproto: cage epoch is stale")]
    CageEpochStale,
    #[error("edgeproto: revocation snapshot missing")]
    RevocationSnapshotMissing,
    #[error("edgeproto: invalid revocation snapshot signature")]
    RevocationSnapshotInvalid,
    #[error("edgeproto: revocation snapshot stale or expired")]
    RevocationSnapshotStale,
    #[error("edgeproto: revocation snapshot sequence behind lease")]
    RevocationSnapshotBehind,
    #[error("edgeproto: invalid edge node request signature")]
    NodeAuthInvalid,
    #[error("edgeproto: invalid BHE1 attestation frame: {0}")]
    Bhe1InvalidFrame(String),
    #[error("edgeproto: clock skew exceeds limit ({0}s)")]
    ClockSkew(i64),
    #[error("edgeproto: nonce replay detected")]
    NonceReplay,
    #[error("edgeproto: invalid Ed25519 signature")]
    BadSignature,
    #[error("edgeproto: unknown peer node {0}")]
    UnknownNode(i64),
    #[error("edgeproto: invalid BRT1 reverse-tunnel frame: {0}")]
    Brt1InvalidFrame(String),
    #[error("edgeproto: ws-over-h2 frame exceeds max size ({0} > {1})")]
    WsFrameTooLarge(usize, usize),
    #[error("edgeproto: io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn key_id_from_public_key(pub_key: &VerifyingKey) -> String {
    let sum = Sha256::digest(pub_key.as_bytes());
    hex::encode(&sum[..8])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHop {
    pub node_id: i64,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub link_class: String, // direct | iplc | reverse_tunnel
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLeaseClaims {
    pub lease_id: String,
    pub jti: String,
    pub user_id: i64,
    #[serde(default)]
    pub api_key_id: i64,
    #[serde(default)]
    pub work_session_id: i64,
    #[serde(default)]
    pub platform: String,
    pub account_id: i64,
    #[serde(default)]
    pub cage_id: i64,
    #[serde(default)]
    pub cage_epoch: i64,
    #[serde(default)]
    pub grant_id: i64,
    #[serde(default)]
    pub ingress_node_id: i64,
    pub landing_node_id: i64,
    #[serde(default)]
    pub route_chain: Vec<RouteHop>,
    #[serde(default)]
    pub cohort_timezone: String,
    #[serde(default)]
    pub cohort_country_code: String,
    #[serde(default)]
    pub cohort_locale: String,
    #[serde(default)]
    pub rev_seq: i64,
    #[serde(default)]
    pub lease_epoch: i64,
    pub iat: i64,
    pub exp: i64,
}

impl SessionLeaseClaims {
    pub fn validate_bound_claims(&self) -> Result<(), ProtoError> {
        if self.lease_id.trim().is_empty() || self.jti.trim().is_empty() {
            return Err(ProtoError::LeaseInvalid("missing lease_id or jti".into()));
        }
        if self.user_id <= 0 || self.account_id <= 0 || self.landing_node_id <= 0 {
            return Err(ProtoError::LeaseInvalid(
                "missing bound principal/account/landing_node_id".into(),
            ));
        }
        if self.cage_epoch < 0 || self.rev_seq < 0 {
            return Err(ProtoError::LeaseInvalid(
                "negative cage_epoch or rev_seq".into(),
            ));
        }
        if self.iat <= 0 || self.exp <= self.iat {
            return Err(ProtoError::LeaseInvalid("invalid iat/exp timestamps".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LeaseJwsHeader {
    alg: String,
    typ: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kid: String,
}

pub fn sign_lease(
    priv_key: &SigningKey,
    kid: &str,
    claims: &SessionLeaseClaims,
) -> Result<String, ProtoError> {
    claims.validate_bound_claims()?;
    let kid = if kid.is_empty() {
        key_id_from_public_key(&priv_key.verifying_key())
    } else {
        kid.to_string()
    };
    let hdr = LeaseJwsHeader {
        alg: LEASE_ALG_HEADER.to_string(),
        typ: LEASE_TYPE_HEADER.to_string(),
        kid,
    };
    let hdr_bytes = serde_json::to_vec(&hdr)
        .map_err(|e| ProtoError::LeaseInvalid(e.to_string()))?;
    let payload_bytes = serde_json::to_vec(claims)
        .map_err(|e| ProtoError::LeaseInvalid(e.to_string()))?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&hdr_bytes),
        URL_SAFE_NO_PAD.encode(&payload_bytes)
    );
    let sig = priv_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

pub fn verify_lease(
    pub_key: &VerifyingKey,
    token: &str,
    now_unix_secs: i64,
) -> Result<SessionLeaseClaims, ProtoError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(ProtoError::LeaseInvalid("expected 3 JWS segments".into()));
    }
    let hdr_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| ProtoError::LeaseInvalid("invalid header base64url".into()))?;
    let hdr: LeaseJwsHeader = serde_json::from_slice(&hdr_bytes)
        .map_err(|_| ProtoError::LeaseInvalid("invalid header json".into()))?;
    if hdr.alg != LEASE_ALG_HEADER || hdr.typ != LEASE_TYPE_HEADER {
        return Err(ProtoError::LeaseInvalid("unexpected alg/typ".into()));
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| ProtoError::LeaseSignatureInvalid)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| ProtoError::LeaseSignatureInvalid)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    pub_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| ProtoError::LeaseSignatureInvalid)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| ProtoError::LeaseInvalid("invalid payload base64url".into()))?;
    let claims: SessionLeaseClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| ProtoError::LeaseInvalid(format!("invalid payload json: {e}")))?;
    claims.validate_bound_claims()?;

    if now_unix_secs >= claims.exp {
        return Err(ProtoError::LeaseExpired);
    }
    if now_unix_secs + LEASE_CLOCK_SKEW_SECONDS < claims.iat {
        return Err(ProtoError::LeaseNotYetValid);
    }
    Ok(claims)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationSnapshot {
    pub seq: i64,
    pub issued_at: i64,
    pub valid_until: i64,
    #[serde(default)]
    pub revoked_lease_ids: Vec<String>,
    #[serde(default)]
    pub revoked_grant_ids: Vec<i64>,
    #[serde(default)]
    pub revoked_api_key_ids: Vec<i64>,
    #[serde(default)]
    pub cage_min_epochs: BTreeMap<i64, i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kid: String,
    #[serde(default)]
    pub sig: String,
}

/// Exact Go `revocationSnapshotSignable` field order for 100% byte-identical canonical JSON!
/// Go's `encoding/json` sorts `map[int64]int64` keys lexicographically as decimal strings
/// (e.g., `"10"` before `"5"`), so we serialize `cage_min_epochs` via `BTreeMap<String, i64>`.
#[derive(Serialize)]
struct RevocationSnapshotSignable<'a> {
    seq: i64,
    issued_at: i64,
    valid_until: i64,
    revoked_lease_ids: &'a [String],
    revoked_grant_ids: &'a [i64],
    revoked_api_key_ids: &'a [i64],
    cage_min_epochs: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "str::is_empty")]
    kid: &'a str,
}

impl RevocationSnapshot {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        let cage_min_epochs_str: BTreeMap<String, i64> = self
            .cage_min_epochs
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        serde_json::to_vec(&RevocationSnapshotSignable {
            seq: self.seq,
            issued_at: self.issued_at,
            valid_until: self.valid_until,
            revoked_lease_ids: &self.revoked_lease_ids,
            revoked_grant_ids: &self.revoked_grant_ids,
            revoked_api_key_ids: &self.revoked_api_key_ids,
            cage_min_epochs: cage_min_epochs_str,
            kid: &self.kid,
        })
        .map_err(|_| ProtoError::RevocationSnapshotInvalid)
    }

    pub fn is_authorized(
        &self,
        lease: &SessionLeaseClaims,
        now_unix_secs: i64,
    ) -> Result<(), ProtoError> {
        if self.issued_at <= 0 || self.valid_until <= self.issued_at || now_unix_secs >= self.valid_until {
            return Err(ProtoError::RevocationSnapshotStale);
        }
        if now_unix_secs >= lease.exp {
            return Err(ProtoError::LeaseExpired);
        }
        if now_unix_secs + LEASE_CLOCK_SKEW_SECONDS < lease.iat {
            return Err(ProtoError::LeaseNotYetValid);
        }
        if lease.rev_seq > self.seq {
            return Err(ProtoError::RevocationSnapshotBehind);
        }
        if self.revoked_lease_ids.iter().any(|id| id == &lease.lease_id) {
            return Err(ProtoError::LeaseRevoked);
        }
        if lease.grant_id > 0 && self.revoked_grant_ids.contains(&lease.grant_id) {
            return Err(ProtoError::GrantRevoked);
        }
        if lease.api_key_id > 0 && self.revoked_api_key_ids.contains(&lease.api_key_id) {
            return Err(ProtoError::ApiKeyRevoked);
        }
        if lease.cage_id > 0 {
            if let Some(&min_epoch) = self.cage_min_epochs.get(&lease.cage_id) {
                if lease.cage_epoch < min_epoch {
                    return Err(ProtoError::CageEpochStale);
                }
            }
        }
        Ok(())
    }
}

pub fn sign_revocation_snapshot(
    priv_key: &SigningKey,
    kid: &str,
    snap: &mut RevocationSnapshot,
) -> Result<(), ProtoError> {
    if snap.seq < 0 || snap.issued_at <= 0 || snap.valid_until <= snap.issued_at {
        return Err(ProtoError::RevocationSnapshotInvalid);
    }
    snap.kid = if kid.is_empty() {
        key_id_from_public_key(&priv_key.verifying_key())
    } else {
        kid.to_string()
    };
    let payload = snap.canonical_bytes()?;
    let sig = priv_key.sign(&payload);
    snap.sig = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(())
}

pub fn verify_revocation_snapshot(
    pub_key: &VerifyingKey,
    snap: &RevocationSnapshot,
    now_unix_secs: i64,
) -> Result<(), ProtoError> {
    if snap.seq < 0 || snap.issued_at <= 0 || snap.valid_until <= snap.issued_at {
        return Err(ProtoError::RevocationSnapshotInvalid);
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(snap.sig.trim())
        .map_err(|_| ProtoError::RevocationSnapshotInvalid)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| ProtoError::RevocationSnapshotInvalid)?;
    let payload = snap.canonical_bytes()?;
    pub_key
        .verify(&payload, &sig)
        .map_err(|_| ProtoError::RevocationSnapshotInvalid)?;
    if now_unix_secs >= snap.valid_until {
        return Err(ProtoError::RevocationSnapshotStale);
    }
    if now_unix_secs + LEASE_CLOCK_SKEW_SECONDS < snap.issued_at {
        return Err(ProtoError::RevocationSnapshotInvalid);
    }
    Ok(())
}

pub fn node_request_sign_input(
    node_id: i64,
    method: &str,
    path_only: &str,
    ts: i64,
    body: &[u8],
) -> Vec<u8> {
    let body_sum = hex::encode(Sha256::digest(body));
    let clean_path = path_only.split('?').next().unwrap_or(path_only);
    format!(
        "berth-edge-req-v1\n{node_id}\n{}\n{clean_path}\n{ts}\n{body_sum}",
        method.to_ascii_uppercase()
    )
    .into_bytes()
}

pub fn sign_node_request(
    priv_key: &SigningKey,
    node_id: i64,
    method: &str,
    path_only: &str,
    ts: i64,
    body: &[u8],
) -> Result<String, ProtoError> {
    if node_id <= 0 {
        return Err(ProtoError::NodeAuthInvalid);
    }
    let msg = node_request_sign_input(node_id, method, path_only, ts, body);
    let sig = priv_key.sign(&msg);
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

pub fn verify_node_request(
    pub_key: &VerifyingKey,
    node_id: i64,
    method: &str,
    path_only: &str,
    ts: i64,
    body: &[u8],
    sig_b64: &str,
    now_unix_secs: i64,
) -> Result<(), ProtoError> {
    if node_id <= 0 {
        return Err(ProtoError::NodeAuthInvalid);
    }
    if (now_unix_secs - ts).abs() > LEASE_CLOCK_SKEW_SECONDS {
        return Err(ProtoError::NodeAuthInvalid);
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.trim())
        .map_err(|_| ProtoError::NodeAuthInvalid)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| ProtoError::NodeAuthInvalid)?;
    let msg = node_request_sign_input(node_id, method, path_only, ts, body);
    pub_key
        .verify(&msg, &sig)
        .map_err(|_| ProtoError::NodeAuthInvalid)
}

pub fn encode_route_header(hops: &[RouteHop]) -> Result<String, ProtoError> {
    let raw = serde_json::to_vec(hops)
        .map_err(|e| ProtoError::LeaseInvalid(format!("encode route: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

pub fn decode_route_header(val: &str) -> Result<Vec<RouteHop>, ProtoError> {
    let raw = URL_SAFE_NO_PAD
        .decode(val.trim())
        .map_err(|_| ProtoError::LeaseInvalid("invalid X-Berth-Route base64url".into()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| ProtoError::LeaseInvalid(format!("invalid X-Berth-Route json: {e}")))
}

// ---------- NonceGuard (Anti-Replay for BHE1 & BRT1) ----------

pub struct NonceGuard {
    max_skew_secs: i64,
    ttl_secs: i64,
    max_entries: usize,
    seen: Mutex<HashMap<(i64, [u8; 16]), i64>>,
}

impl NonceGuard {
    pub fn new(max_skew: Duration, ttl: Duration, max_entries: usize) -> Self {
        let max_skew_secs = max_skew.as_secs().max(1) as i64;
        let ttl_secs = (ttl.as_secs() as i64).max(max_skew_secs * 2);
        let max_entries = max_entries.max(1);
        Self {
            max_skew_secs,
            ttl_secs,
            max_entries,
            seen: Mutex::new(HashMap::with_capacity(256)),
        }
    }

    pub fn default_guard() -> Self {
        Self::new(DEFAULT_MAX_CLOCK_SKEW, DEFAULT_NONCE_TTL, DEFAULT_MAX_NONCES)
    }

    pub fn check_and_record(
        &self,
        scope_id: i64,
        nonce: [u8; 16],
        ts_unix: i64,
        now_unix_secs: i64,
    ) -> Result<(), ProtoError> {
        let skew = (now_unix_secs - ts_unix).abs();
        if skew > self.max_skew_secs {
            return Err(ProtoError::ClockSkew(skew));
        }
        let key = (scope_id, nonce);
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&exp) = map.get(&key) {
            if exp > now_unix_secs {
                return Err(ProtoError::NonceReplay);
            }
        }
        if map.len() >= self.max_entries {
            map.retain(|_, &mut exp| exp > now_unix_secs);
            if map.len() >= self.max_entries {
                // Fail closed while all slots hold live unexpired nonces (never evict live nonces).
                return Err(ProtoError::NonceReplay);
            }
        }
        map.insert(key, now_unix_secs + self.ttl_secs);
        Ok(())
    }
}

// ---------- BHE1 Management-Entry Binary Framing ----------

#[derive(Debug, Clone)]
pub struct Bhe1Attestation {
    pub version: u8,
    pub client_ip: IpAddr,
    pub entry_node_id: i64,
    pub timestamp_unix: i64,
    pub nonce: [u8; 16],
}

pub fn encode_bhe1(
    priv_key: &SigningKey,
    entry_node_id: i64,
    client_ip: IpAddr,
    now_unix_secs: i64,
) -> Result<Vec<u8>, ProtoError> {
    if entry_node_id <= 0 {
        return Err(ProtoError::Bhe1InvalidFrame("non-positive entry_node_id".into()));
    }
    let ip_bytes: Vec<u8> = match client_ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                mapped.octets().to_vec()
            } else {
                v6.octets().to_vec()
            }
        }
    };
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let total_len = 4 + 1 + 1 + ip_bytes.len() + 8 + 8 + 16 + 64;
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(BHE1_MAGIC);
    buf.push(BHE1_VERSION);
    buf.push(ip_bytes.len() as u8);
    buf.extend_from_slice(&ip_bytes);
    buf.extend_from_slice(&(entry_node_id as u64).to_be_bytes());
    buf.extend_from_slice(&(now_unix_secs as u64).to_be_bytes());
    buf.extend_from_slice(&nonce);
    let sig = priv_key.sign(&buf);
    buf.extend_from_slice(&sig.to_bytes());
    Ok(buf)
}

pub async fn read_and_verify_bhe1<R, F>(
    reader: &mut R,
    lookup_pub_key: F,
    guard: Option<&NonceGuard>,
    now_unix_secs: i64,
) -> Result<Bhe1Attestation, ProtoError>
where
    R: AsyncRead + Unpin,
    F: Fn(i64) -> Option<VerifyingKey>,
{
    let mut prefix = [0u8; 6];
    reader.read_exact(&mut prefix).await?;
    if &prefix[0..4] != BHE1_MAGIC {
        return Err(ProtoError::Bhe1InvalidFrame("bad magic".into()));
    }
    if prefix[4] != BHE1_VERSION {
        return Err(ProtoError::Bhe1InvalidFrame(format!("unsupported version {}", prefix[4])));
    }
    let ip_len = prefix[5] as usize;
    if ip_len != 4 && ip_len != 16 {
        return Err(ProtoError::Bhe1InvalidFrame(format!("invalid ip_len {ip_len}")));
    }
    let rest_len = ip_len + 8 + 8 + 16 + 64;
    let mut full = vec![0u8; 6 + rest_len];
    full[..6].copy_from_slice(&prefix);
    reader.read_exact(&mut full[6..]).await?;

    let mut off = 6;
    let client_ip = if ip_len == 4 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&full[off..off + 4]);
        IpAddr::from(b)
    } else {
        let mut b = [0u8; 16];
        b.copy_from_slice(&full[off..off + 16]);
        IpAddr::from(b)
    };
    off += ip_len;
    let entry_node_id = u64::from_be_bytes(full[off..off + 8].try_into().unwrap()) as i64;
    off += 8;
    if entry_node_id <= 0 {
        return Err(ProtoError::Bhe1InvalidFrame("non-positive entry_node_id".into()));
    }
    let ts_unix = u64::from_be_bytes(full[off..off + 8].try_into().unwrap()) as i64;
    off += 8;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&full[off..off + 16]);
    let signed_len = off + 16;

    let pub_key = lookup_pub_key(entry_node_id).ok_or(ProtoError::UnknownNode(entry_node_id))?;
    let sig = Signature::from_slice(&full[signed_len..]).map_err(|_| ProtoError::BadSignature)?;
    pub_key
        .verify(&full[..signed_len], &sig)
        .map_err(|_| ProtoError::BadSignature)?;
    if let Some(g) = guard {
        g.check_and_record(entry_node_id, nonce, ts_unix, now_unix_secs)?;
    }
    Ok(Bhe1Attestation {
        version: prefix[4],
        client_ip,
        entry_node_id,
        timestamp_unix: ts_unix,
        nonce,
    })
}

// ---------- BRT1 Reverse-Tunnel Binary Registration Frame (109 bytes) ----------

#[derive(Debug, Clone)]
pub struct ReverseTunnelReg {
    pub node_id: i64,
    pub generation: u64,
    pub timestamp_unix: i64,
    pub nonce: [u8; 16],
}

pub fn encode_brt1(
    priv_key: &SigningKey,
    node_id: i64,
    generation: u64,
    now_unix_secs: i64,
) -> Result<[u8; BRT1_FRAME_LEN], ProtoError> {
    if node_id <= 0 || generation == 0 {
        return Err(ProtoError::Brt1InvalidFrame("invalid node_id or generation".into()));
    }
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut buf = [0u8; BRT1_FRAME_LEN];
    buf[0..4].copy_from_slice(BRT1_MAGIC);
    buf[4] = BRT1_VERSION;
    buf[5..13].copy_from_slice(&(node_id as u64).to_be_bytes());
    buf[13..21].copy_from_slice(&generation.to_be_bytes());
    buf[21..29].copy_from_slice(&(now_unix_secs as u64).to_be_bytes());
    buf[29..45].copy_from_slice(&nonce);
    let sig = priv_key.sign(&buf[..45]);
    buf[45..].copy_from_slice(&sig.to_bytes());
    Ok(buf)
}

pub async fn read_and_verify_brt1<R, F>(
    reader: &mut R,
    lookup_pub_key: F,
    guard: Option<&NonceGuard>,
    now_unix_secs: i64,
) -> Result<ReverseTunnelReg, ProtoError>
where
    R: AsyncRead + Unpin,
    F: Fn(i64) -> Option<VerifyingKey>,
{
    let mut buf = [0u8; BRT1_FRAME_LEN];
    reader.read_exact(&mut buf).await?;
    if &buf[0..4] != BRT1_MAGIC || buf[4] != BRT1_VERSION {
        return Err(ProtoError::Brt1InvalidFrame("bad magic or version".into()));
    }
    let node_id = u64::from_be_bytes(buf[5..13].try_into().unwrap()) as i64;
    let generation = u64::from_be_bytes(buf[13..21].try_into().unwrap());
    let ts_unix = u64::from_be_bytes(buf[21..29].try_into().unwrap()) as i64;
    if node_id <= 0 || generation == 0 {
        return Err(ProtoError::Brt1InvalidFrame("non-positive node_id or zero generation".into()));
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&buf[29..45]);

    let pub_key = lookup_pub_key(node_id).ok_or(ProtoError::UnknownNode(node_id))?;
    let sig = Signature::from_slice(&buf[45..]).map_err(|_| ProtoError::BadSignature)?;
    pub_key
        .verify(&buf[..45], &sig)
        .map_err(|_| ProtoError::BadSignature)?;
    if let Some(g) = guard {
        g.check_and_record(node_id, nonce, ts_unix, now_unix_secs)?;
    }
    Ok(ReverseTunnelReg {
        node_id,
        generation,
        timestamp_unix: ts_unix,
        nonce,
    })
}

// ---------- UsageReceipt ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReceipt {
    pub receipt_id: String,
    pub node_id: i64,
    pub lease_id: String,
    pub grant_id: i64,
    pub user_id: i64,
    pub api_key_id: i64,
    pub account_id: i64,
    pub work_session_id: i64,
    pub platform: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub input_tokens: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub output_tokens: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub cache_creation_tokens: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub cache_read_tokens: i32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stream: bool,
    pub ingress_bytes: i64,
    pub egress_bytes: i64,
    pub total_bytes: i64,
    pub request_count: i32,
    pub status_code: i32,
    pub ttft_ms: i64,
    pub duration_ms: i64,
    pub created_at: i64,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

// ---------- WebSocket-over-H2 & RFC 6455 Framing ----------

pub fn compute_websocket_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.trim().as_bytes());
    h.update(WS_GUID.as_bytes());
    STANDARD.encode(h.finalize())
}

pub fn encode_ws_h2_frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(op);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Writes an RFC 6455 frame. Bit 7 (`0x80`) of `opcode_with_fin` carries the FIN bit;
/// if callers pass a bare opcode `<= 0x0F` from legacy code, FIN defaults to true unless
/// bit 6 (`0x40`, continuation-not-final marker) is set. Specifically:
/// `read_rfc6455_frame` encodes `(fin ? 0x80 : 0x40) | (opcode & 0x0F)` so FIN=0 is
/// unambiguously distinguished from legacy bare opcodes!
pub async fn write_rfc6455_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    opcode_with_fin: u8,
    payload: &[u8],
    masked: bool,
) -> Result<(), ProtoError> {
    let mut hdr = [0u8; 14];
    let fin_bit = if (opcode_with_fin & 0x40) != 0 && (opcode_with_fin & 0x80) == 0 {
        0x00
    } else {
        0x80
    };
    hdr[0] = fin_bit | (opcode_with_fin & 0x0F);
    let mask_bit = if masked { 0x80 } else { 0 };
    let n = payload.len();
    let mut pos = 2usize;
    if n < 126 {
        hdr[1] = mask_bit | (n as u8);
    } else if n <= 65535 {
        hdr[1] = mask_bit | 126;
        hdr[2..4].copy_from_slice(&(n as u16).to_be_bytes());
        pos = 4;
    } else {
        hdr[1] = mask_bit | 127;
        hdr[2..10].copy_from_slice(&(n as u64).to_be_bytes());
        pos = 10;
    }
    let mut mask_key = [0u8; 4];
    if masked {
        rand::rngs::OsRng.fill_bytes(&mut mask_key);
        hdr[pos..pos + 4].copy_from_slice(&mask_key);
        pos += 4;
    }
    w.write_all(&hdr[..pos]).await?;
    if n > 0 {
        if !masked {
            w.write_all(payload).await?;
        } else {
            let mut masked_buf = vec![0u8; n];
            for (i, &b) in payload.iter().enumerate() {
                masked_buf[i] = b ^ mask_key[i % 4];
            }
            w.write_all(&masked_buf).await?;
        }
    }
    w.flush().await?;
    Ok(())
}

pub async fn write_rfc6455_close<W: AsyncWrite + Unpin>(
    w: &mut W,
    code: u16,
    reason: &str,
    masked: bool,
) -> Result<(), ProtoError> {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    write_rfc6455_frame(w, 0x80 | WS_OP_CLOSE, &payload, masked).await
}

pub async fn read_rfc6455_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_payload: usize,
) -> Result<(u8, Vec<u8>), ProtoError> {
    let max_payload = if max_payload == 0 {
        DEFAULT_MAX_WS_FRAME_BYTES
    } else {
        max_payload
    };
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let opcode_with_fin = if fin { 0x80 | opcode } else { 0x40 | opcode };
    let masked = (hdr[1] & 0x80) != 0;
    let mut length = (hdr[1] & 0x7F) as u64;
    if length == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await?;
        length = u16::from_be_bytes(ext) as u64;
    } else if length == 127 {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await?;
        length = u64::from_be_bytes(ext);
    }
    if length > max_payload as u64 {
        return Err(ProtoError::WsFrameTooLarge(length as usize, max_payload));
    }
    let mut mask_key = [0u8; 4];
    if masked {
        r.read_exact(&mut mask_key).await?;
    }
    let mut payload = vec![0u8; length as usize];
    if !payload.is_empty() {
        r.read_exact(&mut payload).await?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask_key[i % 4];
            }
        }
    }
    Ok((opcode_with_fin, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn lease_and_revocation_roundtrip_and_canonical_json_matches_go() {
        let sk = test_key();
        let vk = sk.verifying_key();
        let now = 1_700_000_000;
        let claims = SessionLeaseClaims {
            lease_id: "lease-1".into(),
            jti: "jti-1".into(),
            user_id: 1,
            api_key_id: 26,
            work_session_id: 99,
            platform: "anthropic".into(),
            account_id: 22,
            cage_id: 5,
            cage_epoch: 2,
            grant_id: 3,
            ingress_node_id: 7,
            landing_node_id: 15,
            route_chain: vec![RouteHop {
                node_id: 15,
                node_name: "legend-sg".into(),
                role: "landing".into(),
                addr: "".into(),
                link_class: "reverse_tunnel".into(),
            }],
            cohort_timezone: "Asia/Singapore".into(),
            cohort_country_code: "SG".into(),
            cohort_locale: "en_SG.UTF-8".into(),
            rev_seq: 1,
            lease_epoch: 1,
            iat: now,
            exp: now + 300,
        };
        let tok = sign_lease(&sk, "", &claims).unwrap();
        let verified = verify_lease(&vk, &tok, now + 5).unwrap();
        assert_eq!(verified, claims);

        let mut snap = RevocationSnapshot {
            seq: 1,
            issued_at: now,
            valid_until: now + 60,
            revoked_lease_ids: vec![],
            revoked_grant_ids: vec![],
            revoked_api_key_ids: vec![],
            cage_min_epochs: BTreeMap::from([(5, 2), (10, 1)]),
            kid: String::new(),
            sig: String::new(),
        };
        sign_revocation_snapshot(&sk, "k1", &mut snap).unwrap();
        let canonical = String::from_utf8(snap.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            canonical,
            r#"{"seq":1,"issued_at":1700000000,"valid_until":1700000060,"revoked_lease_ids":[],"revoked_grant_ids":[],"revoked_api_key_ids":[],"cage_min_epochs":{"10":1,"5":2},"kid":"k1"}"#
        );
        verify_revocation_snapshot(&vk, &snap, now + 10).unwrap();
        snap.is_authorized(&verified, now + 10).unwrap();
    }

    #[test]
    fn node_request_signature_strips_query_like_go_central() {
        let sk = test_key();
        let vk = sk.verifying_key();
        let now = 1_700_000_000;
        let sig = sign_node_request(&sk, 15, "GET", "/api/v1/internal/edge/oauth-tasks?wait=15", now, b"").unwrap();
        verify_node_request(&vk, 15, "GET", "/api/v1/internal/edge/oauth-tasks", now, b"", &sig, now + 2).unwrap();
    }

    #[tokio::test]
    async fn bhe1_and_brt1_roundtrip_and_anti_replay() {
        let sk = test_key();
        let vk = sk.verifying_key();
        let now = 1_700_000_000;
        let guard = NonceGuard::default_guard();

        let frame = encode_bhe1(&sk, 1, "203.0.113.5".parse().unwrap(), now).unwrap();
        let mut cursor = std::io::Cursor::new(frame.clone());
        let att = read_and_verify_bhe1(&mut cursor, |id| (id == 1).then_some(vk), Some(&guard), now).await.unwrap();
        assert_eq!(att.client_ip.to_string(), "203.0.113.5");
        let mut cursor2 = std::io::Cursor::new(frame);
        assert!(matches!(
            read_and_verify_bhe1(&mut cursor2, |id| (id == 1).then_some(vk), Some(&guard), now).await,
            Err(ProtoError::NonceReplay)
        ));

        let brt = encode_brt1(&sk, 15, 42, now).unwrap();
        let mut c3 = std::io::Cursor::new(brt);
        let reg = read_and_verify_brt1(&mut c3, |id| (id == 15).then_some(vk), Some(&guard), now).await.unwrap();
        assert_eq!(reg.node_id, 15);
        assert_eq!(reg.generation, 42);
    }
}
