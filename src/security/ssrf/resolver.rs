// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! DNS-pinning resolver (MIK-4019: anti-rebinding).
//!
//! Abstracts DNS lookups behind [`HostResolver`] so [`PinningResolver`] can
//! resolve a domain **once**, validate every returned IP, and hand reqwest
//! the already-checked addresses — closing the resolve/connect TOCTOU
//! window described in the `ssrf` module docs.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use super::is_private_or_reserved;
use crate::{Error, Result};

/// Trait for DNS name resolution used by [`PinningResolver`].
///
/// Abstracting this enables deterministic unit tests without touching the
/// real OS resolver — use [`SystemResolver`] in production or a mock in tests.
pub trait HostResolver: Send + Sync {
    /// Resolve `host` to a list of IP addresses.
    ///
    /// Implementations MUST NOT perform a second lookup after this call
    /// returns; the addresses returned here are what [`PinningResolver`]
    /// checks and what reqwest will connect to.
    fn lookup(&self, host: &str) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>>;
}

/// Production resolver: delegates to `tokio::net::lookup_host`.
///
/// Uses the OS/libc resolver. A port of `0` is appended so `lookup_host`
/// accepts a bare hostname.
#[derive(Debug, Clone, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn lookup(&self, host: &str) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        let host_owned = host.to_owned();
        Box::pin(async move {
            let with_port = format!("{host_owned}:0");
            let addrs = tokio::net::lookup_host(with_port).await.map_err(|e| {
                Error::Protocol(format!("DNS resolution failed for '{host_owned}': {e}"))
            })?;
            let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
            if ips.is_empty() {
                return Err(Error::Protocol(format!(
                    "DNS resolution returned no addresses for '{host_owned}'"
                )));
            }
            Ok(ips)
        })
    }
}

/// A reqwest-compatible DNS resolver that pins resolution to validated IPs.
///
/// On every new connection reqwest calls [`reqwest::dns::Resolve::resolve`].
/// This implementation:
/// 1. Resolves the name **once** via the inner [`HostResolver`].
/// 2. Validates **every** returned IP against the full deny list.
/// 3. Returns validated [`SocketAddr`]s to reqwest — no second lookup occurs.
///
/// This eliminates the DNS-rebinding TOCTOU window (MIK-4019, closes MIK-3621
/// gap; mirrors Microsoft `AntiSSRF` pattern).
///
/// # Trusted configured-backend exception
///
/// URLs from **operator-authored config** (servers.yaml) are trusted at
/// deployment time. When `trust_configured_backends = true` (default), the
/// proxy-time SSRF check in `gateway/router/authorization.rs` is skipped
/// for those backends (MIK-3529). **Tool-argument URLs** (capability endpoints,
/// GraphQL/JSON-RPC, UI import) are always pinned and never receive the
/// configured-backend exemption.
pub struct PinningResolver<R = SystemResolver> {
    inner: std::sync::Arc<R>,
}

impl<R: HostResolver> PinningResolver<R> {
    /// Wrap `inner` in a pinning resolver.
    pub fn new(inner: R) -> Self {
        Self {
            inner: std::sync::Arc::new(inner),
        }
    }
}

impl<R: HostResolver + 'static> reqwest::dns::Resolve for PinningResolver<R> {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        // Clone the Arc so the future is 'static (no borrow of self).
        let inner = std::sync::Arc::clone(&self.inner);
        Box::pin(async move {
            type BoxErr = Box<dyn std::error::Error + Send + Sync>;
            let ips = inner
                .lookup(&host)
                .await
                .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as BoxErr)?;

            for ip in &ips {
                if is_private_or_reserved(*ip) {
                    let msg =
                        format!("SSRF blocked: '{host}' resolves to private/reserved address {ip}");
                    return Err(Box::new(std::io::Error::other(msg)) as BoxErr);
                }
            }

            // Port 0 is replaced by reqwest with the scheme-default port.
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// Resolve a domain name and validate all returned IPs against SSRF deny lists.
///
/// Async counterpart to `check_host_not_ssrf` for domain names.  Call this
/// before any outbound request to a tool-supplied hostname to detect
/// DNS-rebinding attempts.
///
/// Returns the validated `Vec<IpAddr>` so the caller can connect to a specific
/// address.
///
/// # Errors
///
/// Returns `Error::Protocol` if resolution fails, no addresses are returned,
/// or any returned address falls in a blocked range.
pub async fn resolve_and_validate_host<R: HostResolver>(
    host: &str,
    resolver: &R,
) -> Result<Vec<IpAddr>> {
    let ips = resolver.lookup(host).await?;
    for ip in &ips {
        if is_private_or_reserved(*ip) {
            return Err(Error::Protocol(format!(
                "SSRF blocked: '{host}' resolves to private/reserved address {ip}"
            )));
        }
    }
    Ok(ips)
}
