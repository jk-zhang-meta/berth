use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};

pub const ROLE_INGRESS_RELAY: &str = "ingress_relay";
pub const ROLE_TRANSIT: &str = "transit";
pub const ROLE_LANDING: &str = "landing";
pub const ROLE_COMPAT: &str = "compat";
pub const ROLE_MGMT_ENTRY: &str = "mgmt_entry";

pub const DEFAULT_GRANT_SLICE_BYTES: i64 = 16 * 1024 * 1024;
pub const DEFAULT_GRANT_LOW_WATERMARK: i64 = 4 * 1024 * 1024;
pub const DEFAULT_PRE_DEBIT_CHUNK_SIZE: i64 = 32 * 1024;
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub node_id: i64,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub central_url: String,
    #[serde(default)]
    pub central_pubkey: String,
    #[serde(default)]
    pub node_private_key: String,
    #[serde(default)]
    pub node_private_key_file: String,
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub mgmt_entry_listen_addr: String,
    #[serde(default)]
    pub mgmt_central_target: String,
    #[serde(default)]
    pub reverse_tunnel_hub_addr: String,
    #[serde(default)]
    pub reverse_tunnel_dial_addr: String,
    #[serde(default)]
    pub wal_dir: String,
    #[serde(default, deserialize_with = "deserialize_go_duration_opt")]
    pub heartbeat_interval: Option<Duration>,
    #[serde(default)]
    pub grant_slice_bytes: i64,
    #[serde(default)]
    pub grant_low_watermark: i64,
    #[serde(default)]
    pub pre_debit_chunk_size: i64,
    #[serde(default)]
    pub max_concurrent_streams: u32,
    #[serde(default)]
    pub allowed_upstream_hosts: Vec<String>,
    #[serde(default)]
    pub test_allow_loopback_hosts: Vec<String>,
    #[serde(default)]
    pub default_upstream_base_url: String,
    #[serde(default)]
    pub peer_public_keys: BTreeMap<i64, String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Config = serde_yaml::from_str(&raw)
            .with_context(|| format!("parse config {}", path.display()))?;
        cfg.apply_defaults();
        Ok(cfg)
    }

    pub fn apply_defaults(&mut self) {
        if self.heartbeat_interval.is_none()
            || self.heartbeat_interval == Some(Duration::ZERO)
        {
            self.heartbeat_interval = Some(Duration::from_secs(15));
        }
        if self.grant_slice_bytes <= 0 {
            self.grant_slice_bytes = DEFAULT_GRANT_SLICE_BYTES;
        }
        if self.grant_low_watermark <= 0 {
            self.grant_low_watermark =
                DEFAULT_GRANT_LOW_WATERMARK.min(self.grant_slice_bytes / 4).max(1);
        }
        if self.pre_debit_chunk_size <= 0 {
            self.pre_debit_chunk_size = DEFAULT_PRE_DEBIT_CHUNK_SIZE;
        }
        if self.max_concurrent_streams == 0 {
            self.max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;
        }
        if self.mgmt_entry_listen_addr.is_empty() && self.has_role(ROLE_MGMT_ENTRY) {
            self.mgmt_entry_listen_addr = ":18443".to_string();
        }
    }

    pub fn heartbeat_duration(&self) -> Duration {
        self.heartbeat_interval
            .filter(|d| !d.is_zero())
            .unwrap_or_else(|| Duration::from_secs(15))
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Normalizes Go-style listen addresses (`:19443`) into Rust socket addresses (`0.0.0.0:19443`).
pub fn normalize_listen_addr(addr: &str) -> String {
    let trimmed = addr.trim();
    if let Some(port) = trimmed.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        trimmed.to_string()
    }
}

pub fn parse_go_duration(raw: &str) -> Result<Duration> {
    let s = raw.trim();
    if s.is_empty() || s == "0" {
        return Ok(Duration::ZERO);
    }
    if let Ok(nanos) = s.parse::<u64>() {
        return Ok(Duration::from_nanos(nanos));
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total_nanos: u128 = 0;
    while i < bytes.len() {
        let num_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == num_start {
            bail!("invalid duration `{s}`");
        }
        let val: f64 = s[num_start..i]
            .parse()
            .with_context(|| format!("invalid number in duration `{s}`"))?;
        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &s[unit_start..i];
        let mult: f64 = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            _ => bail!("unsupported duration unit `{unit}` in `{s}`"),
        };
        if val < 0.0 {
            bail!("negative duration `{s}`");
        }
        total_nanos = total_nanos.saturating_add((val * mult) as u128);
    }
    Ok(Duration::from_nanos(total_nanos.min(u64::MAX as u128) as u64))
}

fn deserialize_go_duration_opt<'de, D>(deserializer: D) -> std::result::Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DurVal {
        Str(String),
        Num(u64),
    }

    let opt = Option::<DurVal>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(DurVal::Num(ns)) => Ok(Some(Duration::from_nanos(ns))),
        Some(DurVal::Str(s)) => {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                parse_go_duration(&s)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}

fn decode_flexible_bytes(raw: &str) -> Result<Vec<u8>> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty key material");
    }
    for dec in [
        URL_SAFE_NO_PAD.decode(s),
        URL_SAFE.decode(s),
        STANDARD.decode(s),
        hex::decode(s).map_err(|_| base64::DecodeError::InvalidByte(0, 0)),
    ] {
        if let Ok(bytes) = dec {
            return Ok(bytes);
        }
    }
    Err(anyhow!("unsupported key encoding (expected base64url, base64, or hex)"))
}

/// Decodes a 32-byte Ed25519 seed OR a 64-byte Go `ed25519.PrivateKey` (seed || pubkey).
pub fn parse_ed25519_private_key(raw: &str) -> Result<SigningKey> {
    let bytes = decode_flexible_bytes(raw)?;
    match bytes.len() {
        32 => {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("seed length"))?;
            Ok(SigningKey::from_bytes(&arr))
        }
        64 => {
            let seed: [u8; 32] = bytes[..32].try_into().map_err(|_| anyhow!("seed slice"))?;
            let key = SigningKey::from_bytes(&seed);
            if key.verifying_key().as_bytes() != &bytes[32..64] {
                bail!("ed25519 64-byte key public suffix does not match seed");
            }
            Ok(key)
        }
        n => bail!("invalid ed25519 private key length {n} (expected 32 or 64)"),
    }
}

/// Decodes a 32-byte Ed25519 public key from base64url, base64, or hex.
pub fn parse_ed25519_public_key(raw: &str) -> Result<VerifyingKey> {
    let bytes = decode_flexible_bytes(raw)?;
    if bytes.len() != 32 {
        bail!("invalid ed25519 public key length {} (expected 32)", bytes.len());
    }
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("pubkey length"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid ed25519 public key: {e}"))
}

pub fn load_node_private_key(cfg: &Config) -> Result<SigningKey> {
    if !cfg.node_private_key.trim().is_empty() {
        return parse_ed25519_private_key(&cfg.node_private_key);
    }
    if !cfg.node_private_key_file.trim().is_empty() {
        let raw = fs::read_to_string(&cfg.node_private_key_file)
            .with_context(|| format!("read node_private_key_file {}", cfg.node_private_key_file))?;
        return parse_ed25519_private_key(&raw);
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_go_yaml_config_and_durations() {
        let yaml = r#"
node_id: 7
node_name: hyonix-sg
roles:
  - ingress_relay
  - transit
central_url: https://berth.itachi.fans
wal_dir: /var/lib/berth-edge
heartbeat_interval: 15s
max_concurrent_streams: 256
listen_addr: ":19443"
reverse_tunnel_hub_addr: ":19445"
peer_public_keys:
  15: "dlHuxkob_kl4LRY7H4k3-7IQPXnn4qzS2AoOp8EeX2I"
"#;
        let mut cfg: Config = serde_yaml::from_str(yaml).unwrap();
        cfg.apply_defaults();
        assert_eq!(cfg.node_id, 7);
        assert_eq!(cfg.heartbeat_duration(), Duration::from_secs(15));
        assert_eq!(normalize_listen_addr(&cfg.listen_addr), "0.0.0.0:19443");
        assert!(parse_ed25519_public_key(&cfg.peer_public_keys[&15]).is_ok());
        assert_eq!(parse_go_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_go_duration("500ms").unwrap(), Duration::from_millis(500));
    }
}
