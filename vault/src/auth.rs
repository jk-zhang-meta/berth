//! Hardened dual authentication for `berth-vault`:
//! - User JWT: delegated per-request to fixed-origin Berth Central `/api/v1/auth/me`
//!   forwarding trusted client IP & User-Agent (avoids triggering Central session-binding revocation).
//! - User API key (`Bearer sk-...` or `x-api-key`): direct parameterized primary Postgres lookup
//!   verifying active non-deleted key & owner, expiry, and IP whitelist/blacklist.
//! - Admin routes: strictly Admin JWT only, re-verified live via Central `/api/v1/admin/system/version`.
//!   Ordinary API keys (even owned by an admin) are rejected on admin routes.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::HeaderMap;
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKind {
    Jwt,
    ApiKey { key_id: i64 },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthPrincipal {
    pub user_id: i64,
    pub email: String,
    pub username: String,
    pub is_admin: bool,
    pub kind: CredentialKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Unauthorized(String),
    Forbidden(String),
    UpstreamUnavailable(String),
}

#[derive(Debug, Clone)]
pub struct AuthClient {
    central_base_url: String,
    http: reqwest::Client,
    pool: Pool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExtractedCredential {
    Jwt(String),
    ApiKey(String),
}

#[derive(Debug, Deserialize)]
struct BerthEnvelope<T> {
    code: i64,
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct AuthMeData {
    id: i64,
    #[serde(default)]
    email: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    status: String,
}

impl AuthClient {
    pub fn new(central_base_url: String, pool: Pool) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self {
            central_base_url: central_base_url.trim_end_matches('/').to_string(),
            http,
            pool,
        })
    }

    /// Authenticates a user or CLI caller via either a Berth JWT or a Berth API key (`sk-...`).
    /// Rejects duplicate or mixed credentials before dispatch; never retries across authenticators.
    pub async fn authenticate_user(
        &self,
        headers: &HeaderMap,
        trusted_client_ip: Option<IpAddr>,
    ) -> Result<AuthPrincipal, AuthError> {
        let cred = extract_single_credential(headers)?;
        match cred {
            ExtractedCredential::Jwt(token) => {
                self.verify_jwt_via_central(&token, headers, trusted_client_ip)
                    .await
            }
            ExtractedCredential::ApiKey(api_key) => {
                self.verify_api_key_in_postgres(&api_key, trusted_client_ip)
                    .await
            }
        }
    }

    /// Authenticates a vault administrator. Strictly requires a live Admin JWT verified against
    /// BOTH `/api/v1/auth/me` AND `/api/v1/admin/system/version` (zero caching, API keys rejected).
    pub async fn authenticate_admin(
        &self,
        headers: &HeaderMap,
        trusted_client_ip: Option<IpAddr>,
    ) -> Result<AuthPrincipal, AuthError> {
        let cred = extract_single_credential(headers)?;
        let ExtractedCredential::Jwt(token) = cred else {
            return Err(AuthError::Forbidden(
                "admin vault endpoints require an admin JWT (API keys are not accepted)".into(),
            ));
        };
        let principal = self
            .verify_jwt_via_central(&token, headers, trusted_client_ip)
            .await?;
        if !principal.is_admin {
            return Err(AuthError::Forbidden("admin role required".into()));
        }

        // Exercise Berth Central's full admin middleware + compliance guard live.
        let url = format!("{}/api/v1/admin/system/version", self.central_base_url);
        let mut req = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {token}"));
        req = forward_session_binding_headers(req, headers, trusted_client_ip);

        let resp = req
            .send()
            .await
            .map_err(|e| AuthError::UpstreamUnavailable(format!("central admin check failed: {e}")))?;
        if resp.status().as_u16() == 401 {
            return Err(AuthError::Unauthorized("admin session unauthorized".into()));
        }
        if resp.status().as_u16() == 403 {
            return Err(AuthError::Forbidden("admin access denied by central".into()));
        }
        if !resp.status().is_success() {
            return Err(AuthError::UpstreamUnavailable(format!(
                "central admin check returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        Ok(principal)
    }

    async fn verify_jwt_via_central(
        &self,
        token: &str,
        headers: &HeaderMap,
        trusted_client_ip: Option<IpAddr>,
    ) -> Result<AuthPrincipal, AuthError> {
        let url = format!("{}/api/v1/auth/me", self.central_base_url);
        let mut req = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {token}"));
        req = forward_session_binding_headers(req, headers, trusted_client_ip);

        let resp = req
            .send()
            .await
            .map_err(|e| AuthError::UpstreamUnavailable(format!("central auth check failed: {e}")))?;

        let status = resp.status().as_u16();
        if status == 401 {
            return Err(AuthError::Unauthorized("invalid or expired JWT".into()));
        }
        if status == 403 {
            return Err(AuthError::Forbidden("account access denied".into()));
        }
        if !resp.status().is_success() {
            return Err(AuthError::UpstreamUnavailable(format!(
                "central auth/me returned HTTP {status}"
            )));
        }

        let env: BerthEnvelope<AuthMeData> = resp
            .json()
            .await
            .map_err(|e| AuthError::UpstreamUnavailable(format!("invalid auth/me JSON: {e}")))?;
        if env.code != 0 {
            return Err(AuthError::Unauthorized("central rejected JWT".into()));
        }
        let me = env
            .data
            .ok_or_else(|| AuthError::Unauthorized("missing user payload".into()))?;
        if me.id <= 0 {
            return Err(AuthError::Unauthorized("invalid user id".into()));
        }
        if !me.status.is_empty() && !me.status.eq_ignore_ascii_case("active") {
            return Err(AuthError::Forbidden("user account is not active".into()));
        }
        Ok(AuthPrincipal {
            user_id: me.id,
            email: me.email,
            username: me.username,
            is_admin: me.role.eq_ignore_ascii_case("admin"),
            kind: CredentialKind::Jwt,
        })
    }

    async fn verify_api_key_in_postgres(
        &self,
        api_key: &str,
        trusted_client_ip: Option<IpAddr>,
    ) -> Result<AuthPrincipal, AuthError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| AuthError::UpstreamUnavailable(format!("db pool error: {e}")))?;

        let row = client
            .query_opt(
                "SELECT k.id, k.user_id, k.status, k.expires_at, k.ip_whitelist, k.ip_blacklist, \
                        u.email, u.username, u.status \
                 FROM api_keys k \
                 JOIN users u ON u.id = k.user_id \
                 WHERE k.key = $1 \
                   AND k.deleted_at IS NULL \
                   AND u.deleted_at IS NULL",
                &[&api_key],
            )
            .await
            .map_err(|e| AuthError::UpstreamUnavailable(format!("api_keys lookup error: {e}")))?;

        let Some(row) = row else {
            return Err(AuthError::Unauthorized("invalid API key".into()));
        };

        let key_id: i64 = row.get(0);
        let user_id: i64 = row.get(1);
        let key_status: String = row.get(2);
        let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get(3);
        let ip_whitelist: Option<serde_json::Value> = row.get(4);
        let ip_blacklist: Option<serde_json::Value> = row.get(5);
        let email: String = row.get(6);
        let username: String = row.get(7);
        let user_status: String = row.get(8);

        if !key_status.eq_ignore_ascii_case("active") {
            return Err(AuthError::Forbidden("API key is not active".into()));
        }
        if !user_status.eq_ignore_ascii_case("active") {
            return Err(AuthError::Forbidden("user account is not active".into()));
        }
        if let Some(exp) = expires_at {
            if exp <= chrono::Utc::now() {
                return Err(AuthError::Unauthorized("API key has expired".into()));
            }
        }
        check_api_key_ip_rules(trusted_client_ip, ip_whitelist.as_ref(), ip_blacklist.as_ref())?;

        // Ordinary API keys are ALWAYS user-scoped (never admin), even if owned by an admin.
        Ok(AuthPrincipal {
            user_id,
            email,
            username,
            is_admin: false,
            kind: CredentialKind::ApiKey { key_id },
        })
    }
}

fn forward_session_binding_headers(
    mut req: reqwest::RequestBuilder,
    headers: &HeaderMap,
    trusted_client_ip: Option<IpAddr>,
) -> reqwest::RequestBuilder {
    if let Some(ua) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        if !ua.is_empty() {
            req = req.header("User-Agent", ua);
        }
    }
    if let Some(ip) = trusted_client_ip {
        let ip_str = ip.to_string();
        req = req.header("X-Real-IP", &ip_str);
        req = req.header("X-Forwarded-For", &ip_str);
    }
    req
}

/// Extracts the trusted client IP populated by Nginx (`X-Real-IP`).
pub fn extract_trusted_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
}

/// Parses exactly one credential from `Authorization` or `x-api-key`.
/// Rejects duplicate or mixed headers to prevent authenticator confusion.
pub(crate) fn extract_single_credential(headers: &HeaderMap) -> Result<ExtractedCredential, AuthError> {
    let auth_values: Vec<&str> = headers
        .get_all("authorization")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let api_key_values: Vec<&str> = headers
        .get_all("x-api-key")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if auth_values.len() > 1 || api_key_values.len() > 1 || (!auth_values.is_empty() && !api_key_values.is_empty()) {
        return Err(AuthError::Unauthorized(
            "duplicate or mixed authentication headers are forbidden".into(),
        ));
    }

    if let Some(raw) = api_key_values.first() {
        if !raw.starts_with("sk-") {
            return Err(AuthError::Unauthorized("invalid x-api-key format".into()));
        }
        return Ok(ExtractedCredential::ApiKey((*raw).to_string()));
    }

    if let Some(raw) = auth_values.first() {
        let Some(token) = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) else {
            return Err(AuthError::Unauthorized("Authorization header must use Bearer scheme".into()));
        };
        let token = token.trim();
        if token.is_empty() {
            return Err(AuthError::Unauthorized("empty Bearer token".into()));
        }
        if token.starts_with("sk-") {
            return Ok(ExtractedCredential::ApiKey(token.to_string()));
        }
        return Ok(ExtractedCredential::Jwt(token.to_string()));
    }

    Err(AuthError::Unauthorized("authentication required".into()))
}

pub(crate) fn check_api_key_ip_rules(
    client_ip: Option<IpAddr>,
    whitelist: Option<&serde_json::Value>,
    blacklist: Option<&serde_json::Value>,
) -> Result<(), AuthError> {
    let parse_rules = |val: Option<&serde_json::Value>| -> Vec<String> {
        val.and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };

    let wl = parse_rules(whitelist);
    let bl = parse_rules(blacklist);
    if wl.is_empty() && bl.is_empty() {
        return Ok(());
    }
    let Some(ip) = client_ip else {
        return Err(AuthError::Forbidden("client IP required by API key IP policy".into()));
    };
    if bl.iter().any(|rule| ip_matches_rule(ip, rule)) {
        return Err(AuthError::Forbidden("client IP blocked by API key blacklist".into()));
    }
    if !wl.is_empty() && !wl.iter().any(|rule| ip_matches_rule(ip, rule)) {
        return Err(AuthError::Forbidden("client IP not allowed by API key whitelist".into()));
    }
    Ok(())
}

fn ip_matches_rule(ip: IpAddr, rule: &str) -> bool {
    if let Ok(exact) = rule.parse::<IpAddr>() {
        return exact == ip;
    }
    if let Ok(net) = rule.parse::<IpNet>() {
        return net.contains(&ip);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn rejects_mixed_and_duplicate_credentials() {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("Bearer eyJ.abc.def"));
        h.insert("x-api-key", HeaderValue::from_static("sk-123456"));
        assert!(matches!(extract_single_credential(&h), Err(AuthError::Unauthorized(_))));

        let mut dup = HeaderMap::new();
        dup.append("authorization", HeaderValue::from_static("Bearer a"));
        dup.append("authorization", HeaderValue::from_static("Bearer b"));
        assert!(matches!(extract_single_credential(&dup), Err(AuthError::Unauthorized(_))));
    }

    #[test]
    fn distinguishes_jwt_and_sk_api_keys() {
        let mut h_jwt = HeaderMap::new();
        h_jwt.insert("authorization", HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.x.y"));
        assert_eq!(
            extract_single_credential(&h_jwt),
            Ok(ExtractedCredential::Jwt("eyJhbGciOiJIUzI1NiJ9.x.y".into()))
        );

        let mut h_key = HeaderMap::new();
        h_key.insert("authorization", HeaderValue::from_static("Bearer sk-berth-test"));
        assert_eq!(
            extract_single_credential(&h_key),
            Ok(ExtractedCredential::ApiKey("sk-berth-test".into()))
        );
    }

    #[test]
    fn enforces_cidr_and_exact_ip_rules() {
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let wl = serde_json::json!(["203.0.113.0/24"]);
        let bl = serde_json::json!(["203.0.113.42"]);
        assert!(check_api_key_ip_rules(Some(ip), Some(&wl), None).is_ok());
        assert!(check_api_key_ip_rules(Some(ip), Some(&wl), Some(&bl)).is_err());
        assert!(check_api_key_ip_rules(Some("198.51.100.1".parse().unwrap()), Some(&wl), None).is_err());
        assert!(check_api_key_ip_rules(None, Some(&wl), None).is_err());
    }
}
