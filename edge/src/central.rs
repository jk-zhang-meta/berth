use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::DateTime;
use ed25519_dalek::SigningKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::prober::{MeasuredPeerLink, ProbeTarget};
use crate::proto::{
    HEADER_NODE_ID, HEADER_NODE_SIGNATURE, HEADER_NODE_TIMESTAMP, RevocationSnapshot, RouteHop,
    UsageReceipt, now_unix, sign_node_request,
};

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("edge: upstream credential forbidden (status {0})")]
    Forbidden(u16),
    #[error("edge: upstream credential unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatReport {
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub agent_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub agent_arch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub agent_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_links: Option<Vec<MeasuredPeerLink>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_reverse_tunnels: Option<Vec<i64>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrantLimitDto {
    pub grant_id: i64,
    #[serde(default)]
    pub max_concurrency: usize,
    #[serde(default)]
    pub max_rpm: usize,
}

#[derive(Debug, Clone)]
pub struct HeartbeatResult {
    pub revocation_snapshot: RevocationSnapshot,
    pub node_roles: Vec<String>,
    pub probe_targets: Vec<ProbeTarget>,
    pub peer_public_keys: Option<HashMap<i64, String>>,
    pub grant_limits: Option<Vec<GrantLimitDto>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTaskDto {
    pub task_id: String,
    #[serde(default)]
    pub node_id: i64,
    #[serde(default)]
    pub account_id: i64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub target_url: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body_base64: String,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub claim_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamCredentialDto {
    pub account_id: i64,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverCandidateDto {
    pub account_id: i64,
    pub cage_id: i64,
    pub cage_epoch: i64,
    pub grant_id: i64,
    pub landing_node_id: i64,
    pub cohort_timezone: String,
    pub cohort_country_code: String,
    pub cohort_locale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverLeaseDto {
    pub lease_id: String,
    pub token: String,
    #[serde(default)]
    pub route_chain: Vec<RouteHop>,
    #[serde(default)]
    pub account_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverResult {
    pub action: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub lease: Option<FailoverLeaseDto>,
    #[serde(default)]
    pub recommended_cohort: Option<serde_json::Value>,
}

pub struct CentralClient {
    base_url: String,
    node_id: i64,
    priv_key: SigningKey,
    http: Client,
    long_poll_http: Client,
}

impl CentralClient {
    pub fn new(base_url: &str, node_id: i64, priv_key: SigningKey) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("build central http client")?;
        let long_poll_http = Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .context("build central long-poll client")?;
        Ok(Self {
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            node_id,
            priv_key,
            http,
            long_poll_http,
        })
    }

    async fn do_signed_json(
        &self,
        client: &Client,
        method: reqwest::Method,
        path_with_query: &str,
        body_bytes: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        let ts = now_unix();
        // Central verifies against `c.Request.URL.Path` (path WITHOUT query string)!
        let sig = sign_node_request(
            &self.priv_key,
            self.node_id,
            method.as_str(),
            path_with_query,
            ts,
            &body_bytes,
        )?;
        let url = format!("{}{}", self.base_url, path_with_query);
        let mut req = client
            .request(method, &url)
            .header("Content-Type", "application/json")
            .header(HEADER_NODE_ID, self.node_id.to_string())
            .header(HEADER_NODE_TIMESTAMP, ts.to_string())
            .header(HEADER_NODE_SIGNATURE, sig);
        if !body_bytes.is_empty() {
            req = req.body(body_bytes);
        }
        let resp = req.send().await.with_context(|| format!("central request {url}"))?;
        let status = resp.status().as_u16();
        let raw = resp.bytes().await?.to_vec();
        Ok((status, raw))
    }

    pub async fn heartbeat_full(&self, report: &HeartbeatReport) -> Result<HeartbeatResult> {
        let body = serde_json::to_vec(report)?;
        let (code, raw) = self
            .do_signed_json(
                &self.http,
                reqwest::Method::POST,
                "/api/v1/internal/edge/heartbeat",
                body,
            )
            .await?;
        if code != 200 {
            bail!("heartbeat failed with status {code}");
        }
        #[derive(Deserialize)]
        struct NodeInfo {
            #[serde(default)]
            roles: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            node: Option<NodeInfo>,
            revocation_snapshot: Option<RevocationSnapshot>,
            #[serde(default)]
            probe_targets: Vec<ProbeTarget>,
            #[serde(default)]
            peer_public_keys: Option<HashMap<i64, String>>,
            #[serde(default)]
            grant_limits: Option<Vec<GrantLimitDto>>,
        }
        #[derive(Deserialize)]
        struct Env {
            data: Data,
        }
        let env: Env = serde_json::from_slice(&raw)?;
        let snap = env
            .data
            .revocation_snapshot
            .ok_or_else(|| anyhow::anyhow!("heartbeat missing revocation_snapshot"))?;
        let roles = env.data.node.map(|n| n.roles).unwrap_or_default();
        Ok(HeartbeatResult {
            revocation_snapshot: snap,
            node_roles: roles,
            probe_targets: env.data.probe_targets,
            peer_public_keys: env.data.peer_public_keys,
            grant_limits: env.data.grant_limits,
        })
    }

    pub async fn heartbeat_snapshot(&self) -> Result<RevocationSnapshot> {
        let report = HeartbeatReport {
            status: String::new(),
            agent_version: String::new(),
            agent_arch: String::new(),
            agent_sha256: String::new(),
            measured_links: None,
            live_reverse_tunnels: None,
        };
        Ok(self.heartbeat_full(&report).await?.revocation_snapshot)
    }

    pub async fn request_grant_slice(&self, grant_id: i64, want_bytes: i64) -> Result<(String, i64, i64)> {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let op_id = format!("slice-{}-{}-{}", self.node_id, grant_id, hex::encode(nonce));
        let body = serde_json::to_vec(&serde_json::json!({
            "grant_id": grant_id,
            "requested_bytes": want_bytes,
            "operation_id": op_id,
        }))?;
        let (code, raw) = self
            .do_signed_json(
                &self.http,
                reqwest::Method::POST,
                "/api/v1/internal/edge/grant-slice",
                body,
            )
            .await?;
        if code != 200 {
            bail!("grant-slice failed status {code}");
        }
        #[derive(Deserialize)]
        struct Data {
            slice_id: String,
            granted_bytes: i64,
            #[serde(default)]
            expires_at: Option<String>,
        }
        #[derive(Deserialize)]
        struct Env {
            data: Data,
        }
        let env: Env = serde_json::from_slice(&raw)?;
        let exp_unix = env
            .data
            .expires_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp())
            .unwrap_or(0);
        Ok((env.data.slice_id, env.data.granted_bytes, exp_unix))
    }

    pub async fn flush_usage_outbox(&self, batch: Vec<UsageReceipt>) -> Result<Vec<String>> {
        let body = serde_json::to_vec(&serde_json::json!({ "receipts": batch }))?;
        let (code, raw) = self
            .do_signed_json(
                &self.http,
                reqwest::Method::POST,
                "/api/v1/internal/edge/usage-outbox",
                body,
            )
            .await?;
        if code != 200 {
            bail!("usage-outbox flush failed status {code}");
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            acked_receipt_ids: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Env {
            data: Data,
        }
        let env: Env = serde_json::from_slice(&raw)?;
        Ok(env.data.acked_receipt_ids)
    }

    pub async fn request_failover(
        &self,
        lease_id: &str,
        failed_account_id: i64,
        status_code: u16,
        candidates: &[FailoverCandidateDto],
    ) -> Result<(u16, Option<FailoverResult>)> {
        let body = serde_json::to_vec(&serde_json::json!({
            "lease_id": lease_id,
            "failed_account_id": failed_account_id,
            "status_code": status_code,
            "candidates": candidates,
        }))?;
        let (code, raw) = self
            .do_signed_json(
                &self.http,
                reqwest::Method::POST,
                "/api/v1/internal/edge/failover",
                body,
            )
            .await?;
        #[derive(Deserialize)]
        struct Env {
            data: Option<FailoverResult>,
        }
        let env: Env = serde_json::from_slice(&raw)?;
        Ok((code, env.data))
    }

    /// Long-polls `/api/v1/internal/edge/oauth-tasks?wait=<wait_secs>` for instant Landing OAuth execution!
    pub async fn poll_oauth_tasks(&self, wait_secs: u64) -> Result<Vec<OAuthTaskDto>> {
        let path = if wait_secs > 0 {
            format!("/api/v1/internal/edge/oauth-tasks?wait={}", wait_secs.min(25))
        } else {
            "/api/v1/internal/edge/oauth-tasks".to_string()
        };
        let client = if wait_secs > 0 {
            &self.long_poll_http
        } else {
            &self.http
        };
        let (code, raw) = self
            .do_signed_json(client, reqwest::Method::GET, &path, Vec::new())
            .await?;
        if code != 200 {
            bail!("poll oauth tasks status {code}");
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            tasks: Vec<OAuthTaskDto>,
        }
        #[derive(Deserialize)]
        struct Env {
            data: Data,
        }
        let env: Env = serde_json::from_slice(&raw)?;
        Ok(env.data.tasks)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn complete_oauth_task(
        &self,
        task_id: &str,
        claim_id: &str,
        status_code: u16,
        resp_headers: &HashMap<String, Vec<String>>,
        resp_body_base64: &str,
        resp_body: &str,
        error_msg: &str,
    ) -> Result<()> {
        let body = serde_json::to_vec(&serde_json::json!({
            "claim_id": claim_id,
            "status_code": status_code,
            "resp_headers": resp_headers,
            "resp_body_base64": resp_body_base64,
            "resp_body": resp_body,
            "error": error_msg,
        }))?;
        let path = format!("/api/v1/internal/edge/oauth-tasks/{task_id}/complete");
        let (code, _) = self
            .do_signed_json(&self.http, reqwest::Method::POST, &path, body)
            .await?;
        if code != 200 {
            bail!("complete oauth task status {code}");
        }
        Ok(())
    }

    pub async fn fetch_upstream_credential(
        &self,
        lease_id: &str,
        account_id: i64,
    ) -> std::result::Result<Option<UpstreamCredentialDto>, CredentialError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "lease_id": lease_id,
            "account_id": account_id,
        }))
        .map_err(|e| CredentialError::Unavailable(e.to_string()))?;
        let (code, raw) = self
            .do_signed_json(
                &self.http,
                reqwest::Method::POST,
                "/api/v1/internal/edge/account-credential",
                body,
            )
            .await
            .map_err(|e| CredentialError::Unavailable(e.to_string()))?;
        if code == 204 {
            return Ok(None);
        }
        if code == 401 || code == 403 {
            return Err(CredentialError::Forbidden(code));
        }
        if code != 200 {
            return Err(CredentialError::Unavailable(format!("status {code}")));
        }
        #[derive(Deserialize)]
        struct Env {
            data: Option<UpstreamCredentialDto>,
        }
        let env: Env = serde_json::from_slice(&raw)
            .map_err(|e| CredentialError::Unavailable(e.to_string()))?;
        let cred = env
            .data
            .ok_or_else(|| CredentialError::Unavailable("empty upstream credential response".into()))?;
        Ok(Some(cred))
    }
}
