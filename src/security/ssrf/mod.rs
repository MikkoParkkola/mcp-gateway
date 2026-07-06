//! SSRF protection: comprehensive RFC special-use IP range blocking, with
//! DNS-rebinding prevention via resolve-and-pin.
//!
//! When the gateway proxies requests on behalf of tools, we must prevent
//! Server-Side Request Forgery (SSRF) attacks where a malicious tool
//! target resolves to internal infrastructure.
//!
//! # DNS-Rebinding TOCTOU Gap (MIK-4019)
//!
//! Checking the URL host at call-time and then resolving it later (inside
//! `reqwest`) is a Time-Of-Check / Time-Of-Use (TOCTOU) race: an attacker
//! whose DNS record TTL is 0 can return a public IP during the check and a
//! private IP during the actual TCP connect.  This is the classic DNS-rebinding
//! SSRF vector (see also: Microsoft `AntiSSRF`, CVE-2021-21311 family).
//!
//! The fix is resolve-and-pin: resolve the domain name **once**, validate
//! **all** returned IPs against the deny list, then hand those concrete
//! `SocketAddr`s to `reqwest` via a custom `dns::Resolve` implementation so
//! that reqwest connects to the already-checked addresses.  A second DNS
//! lookup can never occur for that connection.
//!
//! Use [`PinningResolver`] with `ClientBuilder::dns_resolver` on every HTTP
//! client that follows tool-supplied or capability-supplied URLs.
//!
//! # Trusted configured-backend exception
//!
//! URLs coming from **operator-authored config** (servers.yaml / `gateway
//! config` writes) are already trusted: the operator declared those endpoints
//! as valid at deployment time.  When `trust_configured_backends = true`
//! (default), the proxy-time `validate_url_not_ssrf` call in
//! `gateway/router/authorization.rs` is skipped for those backends.  This
//! exemption is intentional and documented in MIK-3529.
//!
//! **Tool-argument URLs** — capability `endpoint` fields, GraphQL/JSON-RPC
//! endpoints injected at call time, UI import URLs, and any URL that flows
//! from untrusted input — are **always** pinned through [`PinningResolver`].
//! They never receive the configured-backend trust exemption.
//!
//! # Covered ranges
//!
//! All RFC special-use IPv4 ranges (RFC 5735/6890):
//! - `0.0.0.0/8` — "this" network
//! - `10.0.0.0/8` — private (RFC 1918)
//! - `100.64.0.0/10` — shared address space / CGNAT (RFC 6598)
//! - `127.0.0.0/8` — loopback (RFC 1122)
//! - `168.63.129.16/32` — Azure Wireserver
//! - `169.254.0.0/16` — link-local (RFC 3927)
//! - `172.16.0.0/12` — private (RFC 1918)
//! - `192.0.0.0/24` — IETF protocol assignments (RFC 5736)
//! - `192.0.2.0/24` — TEST-NET-1 (RFC 5737)
//! - `192.31.196.0/24` — AS112
//! - `192.52.193.0/24` — Automatic Multicast Tunneling
//! - `192.88.99.0/24` — 6to4 relay anycast (RFC 3068, deprecated)
//! - `192.168.0.0/16` — private (RFC 1918)
//! - `192.175.48.0/24` — AS112
//! - `198.18.0.0/15` — benchmarking (RFC 2544)
//! - `198.51.100.0/24` — TEST-NET-2 (RFC 5737)
//! - `203.0.113.0/24` — TEST-NET-3 (RFC 5737)
//! - `224.0.0.0/4` — multicast (RFC 3171)
//! - `240.0.0.0/4` — reserved (RFC 1112)
//! - `255.255.255.255/32` — broadcast
//!
//! All RFC special-use IPv6 ranges (RFC 4291/5156):
//! - `::1/128` — loopback
//! - `::/128` — unspecified
//! - `fc00::/7` — unique local (RFC 4193)
//! - `fe80::/10` — link-local (RFC 4291)
//! - `::ffff:0:0/96` — IPv4-mapped (RFC 4291)
//! - `2001:db8::/32` — documentation (RFC 3849)
//! - `3fff::/20` — documentation
//! - `64:ff9b::/96`, `64:ff9b:1::/48` — IPv4/IPv6 translation
//! - `100::/64`, `100:0:0:1::/64` — discard-only / dummy
//! - `2001::/23` — IETF protocol assignments
//! - `2620:4f:8000::/48` — AS112
//! - `5f00::/16` — `SRv6` SIDs
//! - `ff00::/8` — multicast (RFC 4291)
//!
//! Encoded-IPv4 vectors:
//! - `::x.x.x.x` — IPv4-compatible (deprecated, still parseable)
//! - `2002::/16` — 6to4, blocked as a translation range
//! - `2001:0000::/32` — Teredo, blocked by `2001::/23`
//!
//! # Module layout
//!
//! This module is split to stay under the repo's 800-LOC-per-file hygiene
//! cap. All items remain reachable at the flat `crate::security::ssrf::*`
//! path via the re-exports below — the split is a pure code move, not a
//! public-API change.
//!
//! - [`ranges`] — RFC special-use range checks (`is_private_ipv4`, `is_private_ipv6`)
//! - [`resolver`] — DNS-pinning resolver (MIK-4019): `HostResolver`, `SystemResolver`, `PinningResolver`
//! - [`redirect`] — redirect-chain SSRF re-validation policy

mod ranges;
mod redirect;
mod resolver;

#[cfg(test)]
mod tests;

use ranges::{is_private_ipv4, is_private_ipv6};

use crate::{Error, Result};
use std::net::IpAddr;

pub use resolver::{HostResolver, PinningResolver, SystemResolver, resolve_and_validate_host};

pub use redirect::validate_redirect_chain;
pub(crate) use redirect::{RedirectDecision, redirect_decision};
// Re-exported for path-compat (`crate::security::ssrf::MAX_REDIRECT_HOPS`) even
// though every current crate-internal use goes through `redirect_decision`.
#[allow(unused_imports)]
pub(crate) use redirect::MAX_REDIRECT_HOPS;

// ============================================================================
// Public API
// ============================================================================

/// Validate that a URL does not target a private/internal/reserved IP address.
///
/// IP-literal hosts are blocked immediately. Domain names pass through this
/// synchronous check — to close the DNS-rebinding TOCTOU window, wire
/// [`PinningResolver`] as the `dns_resolver` on the reqwest client (MIK-4019),
/// or call [`resolve_and_validate_host`] before the request.
///
/// # Errors
///
/// Returns `Error::Protocol` if the URL is malformed or targets a blocked range.
pub fn validate_url_not_ssrf(url_str: &str) -> Result<()> {
    let parsed = url::Url::parse(url_str).map_err(|e| {
        // A relative URL (no scheme://host) is the common symptom of an
        // unconfigured or path-only backend/capability base URL. Name the
        // offending value and say what is wrong, instead of the opaque
        // "Invalid URL: relative URL without a base" surfaced to tool callers.
        if e == url::ParseError::RelativeUrlWithoutBase {
            Error::Protocol(format!(
                "URL {url_str:?} is not absolute (missing scheme://host) — check the backend or capability base URL configuration"
            ))
        } else {
            Error::Protocol(format!("Invalid URL {url_str:?}: {e}"))
        }
    })?;

    let Some(host) = parsed.host_str() else {
        // e.g. "localhost:8080" parses with scheme="localhost" and no host —
        // the classic scheme-less host:port misconfiguration.
        return Err(Error::Protocol(format!(
            "URL {url_str:?} has no host — if this is a host:port, prefix it with a scheme (e.g. http://)"
        )));
    };

    check_host_not_ssrf(host)
}

/// Validate a bare host string (no scheme/path) for SSRF.
///
/// Strips IPv6 brackets before parsing so both `::1` and `[::1]` are handled.
///
/// # Errors
///
/// Returns `Error::Protocol` if the host is a blocked IP address.
pub fn check_host_not_ssrf(host: &str) -> Result<()> {
    // Direct parse (covers plain IPv4 and unbracketed IPv6)
    if let Ok(addr) = host.parse::<IpAddr>() {
        if is_private_or_reserved(addr) {
            return Err(Error::Protocol(format!(
                "SSRF blocked: host targets private/reserved address {addr}"
            )));
        }
        return Ok(());
    }

    // Strip brackets for IPv6 literals like `[::ffff:127.0.0.1]`
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(addr) = trimmed.parse::<IpAddr>()
        && is_private_or_reserved(addr)
    {
        return Err(Error::Protocol(format!(
            "SSRF blocked: host targets private/reserved address {addr}"
        )));
    }

    // Domain names: pass through — DNS resolution happens downstream.
    Ok(())
}

// ============================================================================
// Internal dispatch
// ============================================================================

fn is_private_or_reserved(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}
