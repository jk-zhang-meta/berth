use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

/// Legacy reference list of common provider HTTPS authorities.
/// By default, `CompatSsrfGuard` allows any public HTTPS/WSS domain (blocking private IPs,
/// IMDS, Tailscale/CGNAT, loopback, local domains, and non-HTTPS schemes) unless an operator
/// explicitly configures `extra_authorities` to opt into a strict allowlist.
#[allow(dead_code)]
pub const DEFAULT_ALLOWED_PROVIDER_AUTHORITIES: &[&str] = &[
    "api.openai.com:443",
    "chatgpt.com:443",
    "auth.openai.com:443",
    "api.anthropic.com:443",
    "console.anthropic.com:443",
    "platform.claude.com:443",
    "claude.ai:443",
    "claude.com:443",
    "statsig.anthropic.com:443",
    "generativelanguage.googleapis.com:443",
    "cloudcode-pa.googleapis.com:443",
    "daily-cloudcode-pa.googleapis.com:443",
    "oauth2.googleapis.com:443",
    "www.googleapis.com:443",
    "cloudresourcemanager.googleapis.com:443",
    "openidconnect.googleapis.com:443",
    "aiplatform.googleapis.com:443",
    "accounts.google.com:443",
    "api.x.ai:443",
    "us-east-1.api.x.ai:443",
    "us-west-2.api.x.ai:443",
    "eu-west-1.api.x.ai:443",
    "accounts.x.ai:443",
    "auth.x.ai:443",
];

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("edge: blocked non-https upstream scheme: {0}")]
    SchemeBlocked(String),
    #[error("edge: upstream authority or port not in allowlist: {0}")]
    AuthorityBlocked(String),
    #[error("edge: resolved upstream IP is not a public IPv4 address: {0}")]
    PrivateIpBlocked(String),
    #[error("edge: upstream URL must not contain userinfo")]
    UserInfoBlocked,
    #[error("edge: no public IPv4 address resolved for upstream host: {0}")]
    NoPublicIpv4Found(String),
    #[error("edge: dial error: {0}")]
    Dial(String),
}

impl SsrfError {
    pub fn is_policy_forbidden(&self) -> bool {
        matches!(
            self,
            Self::SchemeBlocked(_)
                | Self::AuthorityBlocked(_)
                | Self::PrivateIpBlocked(_)
                | Self::UserInfoBlocked
                | Self::NoPublicIpv4Found(_)
        )
    }
}

pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16 (IMDS),
    // 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,
    // 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4+, 240.0.0.0/4+
    if o[0] == 0
        || o[0] == 10
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224
    {
        return false;
    }
    true
}

fn is_blocked_local_domain(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() || h == "localhost" || !h.contains('.') {
        return true;
    }
    [
        ".localhost",
        ".local",
        ".internal",
        ".lan",
        ".home.arpa",
        ".localdomain",
    ]
    .iter()
    .any(|suf| h.ends_with(suf))
}

#[derive(Debug, Clone)]
pub struct CompatSsrfGuard {
    allowed_authorities: HashSet<String>,
    test_allow_loopback: HashSet<String>,
    dial_timeout: Duration,
}

impl CompatSsrfGuard {
    /// Creates an SSRF guard for outbound HTTPS/WSS requests and CONNECT tunnels.
    ///
    /// By default (`extra_authorities` empty), any public HTTPS/WSS domain is allowed while
    /// strictly enforcing anti-SSRF invariants (HTTPS/WSS only, no userinfo, no local/internal
    /// domains, no port 0/25, and single-resolve public IPv4 validation blocking RFC1918,
    /// loopback, CGNAT/Tailscale, cloud IMDS, and IPv6).
    ///
    /// If `extra_authorities` is non-empty, requests are additionally restricted to that
    /// explicit operator-configured authority allowlist.
    pub fn new(extra_authorities: &[String], test_allow_loopback: &[String]) -> Self {
        let mut allowed = HashSet::new();
        for raw in extra_authorities {
            let mut a = raw.trim().to_ascii_lowercase();
            if !a.is_empty() {
                if !a.contains(':') {
                    a.push_str(":443");
                }
                allowed.insert(a);
            }
        }
        let mut test_allowed = HashSet::new();
        for raw in test_allow_loopback {
            let a = raw.trim().to_ascii_lowercase();
            if !a.is_empty() {
                test_allowed.insert(a);
            }
        }
        Self {
            allowed_authorities: allowed,
            test_allow_loopback: test_allowed,
            dial_timeout: Duration::from_secs(15),
        }
    }

    pub fn is_test_allowed(&self, authority: &str) -> bool {
        self.test_allow_loopback.contains(&authority.to_ascii_lowercase())
    }

    pub fn validate_url(&self, raw_url: &str) -> Result<(String, u16, bool), SsrfError> {
        self.validate_http_url(raw_url)
    }

    /// Strict HTTP/HTTPS URL validator: production permits ONLY `https`; `http` is permitted
    /// exclusively for explicit `test_allow_loopback` authorities. Rejects `ws`/`wss`.
    pub fn validate_http_url(&self, raw_url: &str) -> Result<(String, u16, bool), SsrfError> {
        self.validate_url_with_schemes(raw_url, false)
    }

    /// Strict WebSocket URL validator: production permits ONLY `wss`; `ws` is permitted
    /// exclusively for explicit `test_allow_loopback` authorities. Rejects `http`/`https`.
    pub fn validate_ws_url(&self, raw_url: &str) -> Result<(String, u16, bool), SsrfError> {
        self.validate_url_with_schemes(raw_url, true)
    }

    fn validate_url_with_schemes(
        &self,
        raw_url: &str,
        websocket: bool,
    ) -> Result<(String, u16, bool), SsrfError> {
        let u = Url::parse(raw_url)
            .map_err(|e| SsrfError::AuthorityBlocked(format!("{raw_url}: {e}")))?;
        if !u.username().is_empty() || u.password().is_some() {
            return Err(SsrfError::UserInfoBlocked);
        }
        let scheme = u.scheme().to_ascii_lowercase();
        let host = u
            .host_str()
            .ok_or_else(|| SsrfError::AuthorityBlocked(raw_url.to_string()))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_ascii_lowercase();
        let port = match u.port() {
            Some(p) => p,
            None => match scheme.as_str() {
                "https" | "wss" => 443,
                "http" | "ws" => 80,
                _ => return Err(SsrfError::SchemeBlocked(scheme)),
            },
        };
        let authority = format!("{host}:{port}");
        if self.is_test_allowed(&authority) {
            let ok = if websocket {
                matches!(scheme.as_str(), "wss" | "ws")
            } else {
                matches!(scheme.as_str(), "https" | "http")
            };
            if !ok {
                return Err(SsrfError::SchemeBlocked(scheme));
            }
            return Ok((host, port, true));
        }
        let prod_ok = if websocket {
            scheme == "wss"
        } else {
            scheme == "https"
        };
        if !prod_ok {
            return Err(SsrfError::SchemeBlocked(scheme));
        }
        if port == 0 || port == 25 {
            return Err(SsrfError::AuthorityBlocked(format!("blocked port {port}")));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) if is_public_ipv4(v4) => {}
                other => return Err(SsrfError::PrivateIpBlocked(other.to_string())),
            }
        } else if is_blocked_local_domain(&host) {
            return Err(SsrfError::AuthorityBlocked(format!("local domain {host}")));
        }
        if !self.allowed_authorities.is_empty() && !self.allowed_authorities.contains(&authority) {
            return Err(SsrfError::AuthorityBlocked(authority));
        }
        Ok((host, port, false))
    }

    pub async fn resolve_and_validate_ipv4(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Ipv4Addr, SsrfError> {
        let host_lc = host.trim().to_ascii_lowercase();
        let authority = format!("{host_lc}:{port}");
        let test_ok = self.is_test_allowed(&authority);
        if !test_ok {
            if port == 0 || port == 25 {
                return Err(SsrfError::AuthorityBlocked(format!("blocked port {port}")));
            }
            if host_lc.parse::<IpAddr>().is_err() && is_blocked_local_domain(&host_lc) {
                return Err(SsrfError::AuthorityBlocked(format!("local domain {host_lc}")));
            }
            if !self.allowed_authorities.is_empty() && !self.allowed_authorities.contains(&authority) {
                return Err(SsrfError::AuthorityBlocked(authority));
            }
        }
        self.resolve_host_ipv4_inner(&host_lc, port, test_ok).await
    }

    async fn resolve_host_ipv4_inner(
        &self,
        host_lc: &str,
        port: u16,
        test_ok: bool,
    ) -> Result<Ipv4Addr, SsrfError> {
        if let Ok(ip) = host_lc.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) if test_ok && v4.is_loopback() => Ok(v4),
                IpAddr::V4(v4) if is_public_ipv4(v4) => Ok(v4),
                other => Err(SsrfError::PrivateIpBlocked(other.to_string())),
            };
        }
        let addrs = tokio::net::lookup_host((host_lc, port))
            .await
            .map_err(|e| SsrfError::Dial(format!("dns lookup {host_lc}: {e}")))?;
        let mut saw_private_or_v6 = false;
        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(v4) if test_ok && v4.is_loopback() => return Ok(v4),
                IpAddr::V4(v4) if is_public_ipv4(v4) => return Ok(v4),
                _ => saw_private_or_v6 = true,
            }
        }
        if saw_private_or_v6 {
            Err(SsrfError::PrivateIpBlocked(host_lc.to_string()))
        } else {
            Err(SsrfError::NoPublicIpv4Found(host_lc.to_string()))
        }
    }

    pub async fn dial_validated_tcp(&self, host: &str, port: u16) -> Result<TcpStream, SsrfError> {
        let ip = self.resolve_and_validate_ipv4(host, port).await?;
        let target = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let stream = tokio::time::timeout(self.dial_timeout, TcpStream::connect(target))
            .await
            .map_err(|_| SsrfError::Dial(format!("connect timeout to {host}:{port}")))?
            .map_err(|e| SsrfError::Dial(format!("connect {host}:{port}: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// Dials any validated public IPv4 host:port for lease-authorized `CONNECT` proxy tunneling.
    /// Blocks private/loopback/CGNAT/IMDS/IPv6, local domains, and SMTP port 25.
    pub async fn dial_validated_public_tcp(&self, addr: &str) -> Result<(TcpStream, String), SsrfError> {
        let (host, port) = split_host_port(addr.trim())
            .ok_or_else(|| SsrfError::AuthorityBlocked(format!("invalid connect target `{addr}`")))?;
        if port == 0 || port == 25 {
            return Err(SsrfError::AuthorityBlocked(format!("blocked connect port {port}")));
        }
        let host_lc = host.to_ascii_lowercase();
        let authority = format!("{host_lc}:{port}");
        let test_ok = self.is_test_allowed(&authority);
        if host_lc.parse::<IpAddr>().is_err() && !test_ok && is_blocked_local_domain(&host_lc) {
            return Err(SsrfError::AuthorityBlocked(format!("local domain {host_lc}")));
        }
        let ip = self.resolve_host_ipv4_inner(&host_lc, port, test_ok).await?;
        let target = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let stream = tokio::time::timeout(self.dial_timeout, TcpStream::connect(target))
            .await
            .map_err(|_| SsrfError::Dial(format!("connect timeout to {addr}")))?
            .map_err(|e| SsrfError::Dial(format!("connect {addr}: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok((stream, host_lc))
    }

    pub async fn dial_validated_tls(
        &self,
        host: &str,
        port: u16,
        tls_config: Arc<ClientConfig>,
    ) -> Result<TlsStream<TcpStream>, SsrfError> {
        let tcp = self.dial_validated_tcp(host, port).await?;
        let sni = ServerName::try_from(host.to_string())
            .map_err(|e| SsrfError::Dial(format!("invalid SNI `{host}`: {e}")))?;
        let connector = TlsConnector::from(tls_config);
        tokio::time::timeout(self.dial_timeout, connector.connect(sni, tcp))
            .await
            .map_err(|_| SsrfError::Dial(format!("TLS handshake timeout {host}:{port}")))?
            .map_err(|e| SsrfError::Dial(format!("TLS handshake {host}:{port}: {e}")))
    }
}

pub fn build_default_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let s = addr.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse::<u16>().ok()?;
        Some((h.to_string(), port))
    } else {
        let (h, p) = s.rsplit_once(':')?;
        if h.is_empty() || h.contains(':') {
            return None;
        }
        let port = p.parse::<u16>().ok()?;
        Some((h.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_allows_claude_oauth_and_blocks_private_and_imds() {
        let g = CompatSsrfGuard::new(&[], &[]);
        assert!(g.validate_url("https://platform.claude.com/v1/oauth/token").is_ok());
        assert!(g.validate_url("https://claude.ai/api/organizations").is_ok());
        assert!(g.validate_url("https://api.anthropic.com/v1/messages").is_ok());
        assert!(g.validate_url("https://api.openai.com/v1/responses").is_ok());
        assert!(g.validate_url("https://oauth2.googleapis.com/token").is_ok());
        assert!(g.validate_url("https://www.googleapis.com/oauth2/v2/userinfo").is_ok());
        assert!(g.validate_url("https://www.googleapis.com/drive/v3/about?fields=storageQuota").is_ok());
        assert!(g.validate_url("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist").is_ok());
        assert!(g.validate_url("https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist").is_ok());
        assert!(g.validate_url("https://cloudresourcemanager.googleapis.com/v1/projects").is_ok());
        assert!(g.validate_url("https://custom-relay.example.com/v1/messages").is_ok());
        assert!(g.validate_url("http://platform.claude.com/v1/oauth/token").is_err());
        assert!(g.validate_url("https://169.254.169.254/latest/meta-data").is_err());
        assert!(g.validate_url("https://127.0.0.1/admin").is_err());
        assert!(g.validate_url("https://10.0.0.1/internal").is_err());
        assert!(g.validate_url("https://100.64.1.2/tailscale").is_err());
        assert!(g.validate_url("https://legend-sg.edge.internal/secret").is_err());
        assert!(g.validate_url("https://localhost/secret").is_err());

        // Optional explicit allowlist mode still enforces strict authority matching when configured.
        let strict = CompatSsrfGuard::new(&["api.openai.com:443".to_string()], &[]);
        assert!(strict.validate_url("https://api.openai.com/v1/responses").is_ok());
        assert!(strict.validate_url("https://custom-relay.example.com/v1/messages").is_err());

        assert!(is_public_ipv4(Ipv4Addr::new(217, 116, 175, 208)));
        assert!(!is_public_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!is_public_ipv4(Ipv4Addr::new(100, 64, 1, 2)));
        assert!(!is_public_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
