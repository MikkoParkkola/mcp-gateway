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

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use crate::{Error, Result};

// ============================================================================
// IPv4 helpers
// ============================================================================

/// Check if an IPv4 address falls in any RFC special-use range that should
/// be blocked for outbound requests.
///
/// # Ranges checked
///
/// Covers all ranges listed in RFC 6890 as "not globally reachable":
/// loopback, private (RFC 1918), link-local, CGNAT, IETF protocol
/// assignments, TEST-NET-1/2/3, 6to4-relay, benchmarking, multicast,
/// reserved, and broadcast.
fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    is_this_network(o)          // 0.0.0.0/8
    || addr.is_loopback()       // 127.0.0.0/8
    || addr.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    || addr.is_link_local()     // 169.254.0.0/16
    || addr.is_broadcast()      // 255.255.255.255/32
    || addr.is_multicast()      // 224.0.0.0/4
    || is_shared_address(addr)  // 100.64.0.0/10
    || is_ietf_protocol(o)      // 192.0.0.0/24
    || is_documentation(o)      // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    || is_6to4_relay(o)         // 192.88.99.0/24
    || is_wireserver(o)         // 168.63.129.16/32
    || is_amt(o)                // 192.52.193.0/24
    || is_as112(o)              // 192.31.196.0/24, 192.175.48.0/24
    || is_benchmarking(o)       // 198.18.0.0/15
    || is_reserved(addr) // 240.0.0.0/4
}

/// `0.0.0.0/8` — "this" network.
fn is_this_network(o: [u8; 4]) -> bool {
    o[0] == 0
}

/// `100.64.0.0/10` — Carrier-Grade NAT / shared address space (RFC 6598).
fn is_shared_address(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    // /10 mask: first octet = 100, second octet bits 7-6 = 01 (i.e. 64-127)
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// `192.0.0.0/24` — IETF protocol assignments (RFC 5736).
fn is_ietf_protocol(o: [u8; 4]) -> bool {
    o[0] == 192 && o[1] == 0 && o[2] == 0
}

/// TEST-NET ranges (RFC 5737): `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
fn is_documentation(o: [u8; 4]) -> bool {
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

/// `192.88.99.0/24` — 6to4 relay anycast (RFC 3068, deprecated but still routed).
fn is_6to4_relay(o: [u8; 4]) -> bool {
    o[0] == 192 && o[1] == 88 && o[2] == 99
}

/// `168.63.129.16/32` — Azure Wireserver.
fn is_wireserver(o: [u8; 4]) -> bool {
    o == [168, 63, 129, 16]
}

/// `192.52.193.0/24` — Automatic Multicast Tunneling.
fn is_amt(o: [u8; 4]) -> bool {
    o[0] == 192 && o[1] == 52 && o[2] == 193
}

/// AS112 anycast service ranges.
fn is_as112(o: [u8; 4]) -> bool {
    (o[0] == 192 && o[1] == 31 && o[2] == 196) || (o[0] == 192 && o[1] == 175 && o[2] == 48)
}

/// `198.18.0.0/15` — benchmarking (RFC 2544).
fn is_benchmarking(o: [u8; 4]) -> bool {
    // /15: 198.18.x.x and 198.19.x.x
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// `240.0.0.0/4` — reserved for future use (RFC 1112).
fn is_reserved(addr: Ipv4Addr) -> bool {
    // Top nibble = 0xF0 means 240-255.  We exclude 255.255.255.255 (broadcast)
    // which is already caught by `is_broadcast()`, but overlapping is fine.
    addr.octets()[0] >= 240
}

// ============================================================================
// IPv6 helpers
// ============================================================================

/// Check if an IPv6 address falls in any RFC special-use range.
///
/// Also decodes 6to4, Teredo, IPv4-mapped, and IPv4-compatible encodings
/// so that private IPv4 addresses cannot be reached through IPv6 tunnels.
#[allow(clippy::cast_possible_truncation)] // u16 → u8 octet extraction is intentional
fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    // Loopback (::1/128)
    if addr.is_loopback() {
        return true;
    }
    // Unspecified (::/128)
    if addr.is_unspecified() {
        return true;
    }
    // Multicast (ff00::/8)
    if addr.is_multicast() {
        return true;
    }

    let seg = addr.segments();

    // Link-local (fe80::/10)
    if seg[0] & 0xFFC0 == 0xFE80 {
        return true;
    }

    // Unique local (fc00::/7): covers fc00:: and fd00::
    if seg[0] & 0xFE00 == 0xFC00 {
        return true;
    }

    // Documentation (2001:db8::/32, 3fff::/20) — not routable, used in examples/RFCs
    if (seg[0] == 0x2001 && seg[1] == 0x0DB8) || (seg[0] & 0xFFF0) == 0x3FF0 {
        return true;
    }

    // IPv4-mapped (::ffff:x.x.x.x / ::ffff:0:0/96) — the classic SSRF bypass vector
    if let Some(v4) = extract_ipv4_mapped(&addr) {
        return is_private_ipv4(v4);
    }

    // IPv4-compatible (deprecated ::x.x.x.x form, still parseable)
    if let Some(v4) = extract_ipv4_compatible(&addr) {
        return is_private_ipv4(v4);
    }

    // IPv4/IPv6 translation prefixes (64:ff9b::/96, 64:ff9b:1::/48)
    if seg[0] == 0x0064 && seg[1] == 0xFF9B && (seg[2..6] == [0, 0, 0, 0] || seg[2] == 0x0001) {
        return true;
    }

    // Discard-only and dummy prefixes (100::/64, 100:0:0:1::/64)
    if seg[0] == 0x0100 && (seg[1..4] == [0, 0, 0] || seg[1..4] == [0, 0, 1]) {
        return true;
    }

    // IETF Protocol Assignments (2001::/23), including Teredo, benchmarking,
    // AMT, AS112, deprecated ORCHID, ORCHIDv2, and DET prefixes.
    if seg[0] == 0x2001 && (seg[1] & 0xFE00) == 0x0000 {
        return true;
    }

    // 6to4 (2002::/16) — deprecated translation prefix.
    if seg[0] == 0x2002 {
        return true;
    }

    // AS112 (2620:4f:8000::/48)
    if seg[0] == 0x2620 && seg[1] == 0x004F && seg[2] == 0x8000 {
        return true;
    }

    // Segment Routing SIDs (5f00::/16)
    if seg[0] == 0x5F00 {
        return true;
    }

    false
}

/// Extract IPv4 from `::ffff:x.x.x.x` (segments `[0,0,0,0,0,0xFFFF, hi, lo]`).
#[allow(clippy::cast_possible_truncation)]
fn extract_ipv4_mapped(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = addr.segments();
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xFFFF {
        Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ))
    } else {
        None
    }
}

/// Extract IPv4 from the deprecated `::x.x.x.x` form (non-loopback, non-unspecified).
#[allow(clippy::cast_possible_truncation)]
fn extract_ipv4_compatible(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = addr.segments();
    if s[0] == 0
        && s[1] == 0
        && s[2] == 0
        && s[3] == 0
        && s[4] == 0
        && s[5] == 0
        && (s[6] != 0 || s[7] > 1)
    // exclude :: and ::1
    {
        Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ))
    } else {
        None
    }
}

// ============================================================================
// DNS-pinning resolver (MIK-4019: anti-rebinding)
// ============================================================================

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
/// Async counterpart to [`check_host_not_ssrf`] for domain names.  Call this
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

/// Validate every URL in a redirect chain against SSRF rules.
///
/// Redirect chains are an SSRF bypass vector: an initial request to a
/// public URL returns a 30x redirect to an internal address.  Every hop
/// in the chain must pass the SSRF check before the gateway follows it.
///
/// # Arguments
///
/// * `chain` — ordered slice of URL strings representing the redirect path,
///   starting with the initial request URL and ending with the final URL.
///
/// # Errors
///
/// Returns `Error::Protocol` with the offending hop number and URL if any
/// hop targets a blocked range.
pub fn validate_redirect_chain(chain: &[&str]) -> Result<()> {
    for (i, url) in chain.iter().enumerate() {
        validate_url_not_ssrf(url)
            .map_err(|e| Error::Protocol(format!("SSRF blocked at redirect hop {i}: {e}")))?;
    }
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4: loopback ────────────────────────────────────────────────────────

    #[test]
    fn ipv4_loopback_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::LOCALHOST));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    // ── IPv4: RFC 1918 private ────────────────────────────────────────────────

    #[test]
    fn ipv4_rfc1918_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // ── IPv4: link-local ──────────────────────────────────────────────────────

    #[test]
    fn ipv4_link_local_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 255, 255)));
    }

    // ── IPv4: CGNAT / shared ──────────────────────────────────────────────────

    #[test]
    fn ipv4_cgnat_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
    }

    #[test]
    fn ipv4_cgnat_boundary_public() {
        // 100.63.x.x is before the /10 range — should be public
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        // 100.128.x.x is after the /10 range — should be public
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
    }

    // ── IPv4: IETF protocol assignments ──────────────────────────────────────

    #[test]
    fn ipv4_ietf_protocol_assignments_blocked() {
        // 192.0.0.0/24
        assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 0, 255)));
    }

    // ── IPv4: TEST-NET (documentation) ───────────────────────────────────────

    #[test]
    fn ipv4_documentation_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 2, 1))); // TEST-NET-1
        assert!(is_private_ipv4(Ipv4Addr::new(198, 51, 100, 1))); // TEST-NET-2
        assert!(is_private_ipv4(Ipv4Addr::new(203, 0, 113, 1))); // TEST-NET-3
    }

    // ── IPv4: 6to4 relay anycast ─────────────────────────────────────────────

    #[test]
    fn ipv4_6to4_relay_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 88, 99, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 88, 99, 255)));
    }

    // ── IPv4: benchmarking ────────────────────────────────────────────────────

    #[test]
    fn ipv4_benchmarking_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_private_ipv4(Ipv4Addr::new(198, 19, 255, 255)));
    }

    #[test]
    fn ipv4_benchmarking_boundary_public() {
        assert!(!is_private_ipv4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(198, 20, 0, 0)));
    }

    // ── IPv4: multicast ───────────────────────────────────────────────────────

    #[test]
    fn ipv4_multicast_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(239, 255, 255, 255)));
    }

    // ── IPv4: reserved (240.0.0.0/4) ─────────────────────────────────────────

    #[test]
    fn ipv4_reserved_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(254, 255, 255, 255)));
    }

    // ── IPv4: broadcast + unspecified ─────────────────────────────────────────

    #[test]
    fn ipv4_broadcast_and_unspecified_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::BROADCAST));
        assert!(is_private_ipv4(Ipv4Addr::UNSPECIFIED));
        assert!(is_private_ipv4(Ipv4Addr::new(0, 1, 2, 3)));
        assert!(is_private_ipv4(Ipv4Addr::new(0, 255, 255, 255)));
    }

    #[test]
    fn ipv4_antissrf_cloud_and_infra_ranges_blocked() {
        assert!(is_private_ipv4(Ipv4Addr::new(168, 63, 129, 16)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 31, 196, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 52, 193, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 175, 48, 1)));
    }

    // ── IPv4: public addresses pass ───────────────────────────────────────────

    #[test]
    fn ipv4_public_passes() {
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    // ── IPv6: loopback / unspecified ──────────────────────────────────────────

    #[test]
    fn ipv6_loopback_blocked() {
        assert!(is_private_ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn ipv6_unspecified_blocked() {
        assert!(is_private_ipv6(Ipv6Addr::UNSPECIFIED));
    }

    // ── IPv6: multicast ───────────────────────────────────────────────────────

    #[test]
    fn ipv6_multicast_blocked() {
        let addr: Ipv6Addr = "ff02::1".parse().unwrap();
        assert!(is_private_ipv6(addr));
        let addr2: Ipv6Addr = "ff00::".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    // ── IPv6: link-local ──────────────────────────────────────────────────────

    #[test]
    fn ipv6_link_local_blocked() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    // ── IPv6: unique local ────────────────────────────────────────────────────

    #[test]
    fn ipv6_unique_local_blocked() {
        let addr1: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_private_ipv6(addr1));
        let addr2: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    // ── IPv6: documentation (2001:db8::/32) ──────────────────────────────────

    #[test]
    fn ipv6_documentation_blocked() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_private_ipv6(addr));
        let addr2: Ipv6Addr = "2001:db8:cafe::1".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    // ── IPv6: IPv4-mapped (::ffff:x.x.x.x) ───────────────────────────────────

    #[test]
    fn ipv6_ipv4_mapped_loopback_blocked() {
        let addr: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn ipv6_ipv4_mapped_private_blocked() {
        let addr1: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private_ipv6(addr1));
        let addr2: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    #[test]
    fn ipv6_ipv4_mapped_multicast_blocked() {
        let addr: Ipv6Addr = "::ffff:224.0.0.1".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn ipv6_ipv4_mapped_public_passes() {
        let addr: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ipv6(addr));
    }

    // ── IPv6: 6to4 ───────────────────────────────────────────────────────────

    #[test]
    fn ipv6_6to4_private_blocked() {
        // 2002:0a00:0001:: embeds 10.0.0.1
        let addr: Ipv6Addr = "2002:0a00:0001::".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn ipv6_6to4_public_is_blocked_as_translation_prefix() {
        let addr: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn ipv6_antissrf_recommended_ranges_blocked() {
        let samples = [
            "64:ff9b::8.8.8.8", // NAT64 well-known
            "64:ff9b:1::1",     // NAT64 local-use
            "100::1",           // discard-only
            "100:0:0:1::1",     // dummy
            "2001:2::1",        // benchmarking under IETF protocol assignments
            "2001:3::1",        // AMT under IETF protocol assignments
            "2001:4:112::1",    // AS112 under IETF protocol assignments
            "3fff::1",          // documentation
            "5f00::1",          // SRv6 SIDs
            "2620:4f:8000::1",  // AS112
        ];
        for sample in samples {
            let addr: Ipv6Addr = sample.parse().unwrap();
            assert!(is_private_ipv6(addr), "{sample} should be blocked");
        }
    }

    // ── IPv6: public passes ───────────────────────────────────────────────────

    #[test]
    fn ipv6_public_passes() {
        let addr: Ipv6Addr = "2607:f8b0:4004:800::200e".parse().unwrap();
        assert!(!is_private_ipv6(addr));
    }

    // ── validate_url_not_ssrf ────────────────────────────────────────────────

    #[test]
    fn url_blocks_loopback() {
        assert!(validate_url_not_ssrf("http://127.0.0.1/api").is_err());
        assert!(validate_url_not_ssrf("http://127.0.0.1:8080/foo").is_err());
    }

    #[test]
    fn url_blocks_private_ranges() {
        assert!(validate_url_not_ssrf("http://10.0.0.1/api").is_err());
        assert!(validate_url_not_ssrf("http://192.168.1.1/api").is_err());
        assert!(validate_url_not_ssrf("http://172.16.0.1/api").is_err());
    }

    #[test]
    fn url_blocks_multicast() {
        assert!(validate_url_not_ssrf("http://224.0.0.1/api").is_err());
    }

    #[test]
    fn url_blocks_reserved() {
        assert!(validate_url_not_ssrf("http://240.0.0.1/api").is_err());
    }

    #[test]
    fn url_blocks_benchmarking() {
        assert!(validate_url_not_ssrf("http://198.18.0.1/api").is_err());
        assert!(validate_url_not_ssrf("http://198.19.0.1/api").is_err());
    }

    #[test]
    fn url_blocks_6to4_relay() {
        assert!(validate_url_not_ssrf("http://192.88.99.1/api").is_err());
    }

    #[test]
    fn url_blocks_ietf_protocol() {
        assert!(validate_url_not_ssrf("http://192.0.0.1/api").is_err());
    }

    #[test]
    fn url_blocks_documentation() {
        assert!(validate_url_not_ssrf("http://192.0.2.1/api").is_err());
        assert!(validate_url_not_ssrf("http://198.51.100.1/api").is_err());
        assert!(validate_url_not_ssrf("http://203.0.113.1/api").is_err());
    }

    #[test]
    fn url_blocks_ipv4_mapped_ipv6() {
        assert!(validate_url_not_ssrf("http://[::ffff:127.0.0.1]/api").is_err());
        assert!(validate_url_not_ssrf("http://[::ffff:10.0.0.1]/api").is_err());
    }

    #[test]
    fn url_blocks_ipv6_loopback() {
        assert!(validate_url_not_ssrf("http://[::1]/api").is_err());
    }

    #[test]
    fn url_blocks_ipv6_documentation() {
        assert!(validate_url_not_ssrf("http://[2001:db8::1]/api").is_err());
    }

    #[test]
    fn url_blocks_ipv6_multicast() {
        assert!(validate_url_not_ssrf("http://[ff02::1]/api").is_err());
    }

    #[test]
    fn url_blocks_unspecified() {
        assert!(validate_url_not_ssrf("http://0.0.0.0/api").is_err());
        assert!(validate_url_not_ssrf("http://0.1.2.3/api").is_err());
    }

    #[test]
    fn url_blocks_antissrf_cloud_and_translation_ranges() {
        assert!(validate_url_not_ssrf("http://168.63.129.16/api").is_err());
        assert!(validate_url_not_ssrf("http://[64:ff9b::8.8.8.8]/api").is_err());
        assert!(validate_url_not_ssrf("http://[2002:0808:0808::]/api").is_err());
    }

    #[test]
    fn url_allows_public_ipv4() {
        assert!(validate_url_not_ssrf("http://8.8.8.8/api").is_ok());
        assert!(validate_url_not_ssrf("https://93.184.216.34/api").is_ok());
    }

    #[test]
    fn url_allows_public_ipv6() {
        assert!(validate_url_not_ssrf("http://[2607:f8b0:4004:800::200e]/api").is_ok());
    }

    #[test]
    fn url_allows_domain_names() {
        // Domain names pass through (DNS resolution happens downstream)
        assert!(validate_url_not_ssrf("https://api.example.com/v1").is_ok());
    }

    #[test]
    fn url_rejects_invalid_url() {
        assert!(validate_url_not_ssrf("not a url").is_err());
    }

    #[test]
    fn url_relative_gives_actionable_error() {
        // A bare relative URL (empty base + path, or a bare token) must fail with
        // an actionable message that names the value and says it is not absolute —
        // not the opaque "relative URL without a base". Regression for trvl#234.
        for relative in ["/rpc", "search_flights"] {
            let err = validate_url_not_ssrf(relative)
                .expect_err("relative URL must be rejected")
                .to_string();
            assert!(
                err.contains("not absolute"),
                "message should explain the URL is not absolute: {err}"
            );
            assert!(
                err.contains(relative),
                "message should name the offending URL {relative:?}: {err}"
            );
            assert!(
                !err.contains("relative URL without a base"),
                "must not surface the opaque parse error: {err}"
            );
        }
    }

    #[test]
    fn url_schemeless_host_port_gives_actionable_error() {
        // "localhost:8080/mcp" parses with scheme="localhost" and no host — the
        // scheme-less host:port misconfiguration. The error must name the value
        // and point at the missing scheme rather than a bare "no host".
        let err = validate_url_not_ssrf("localhost:8080/mcp")
            .expect_err("scheme-less host:port must be rejected")
            .to_string();
        assert!(
            err.contains("localhost:8080/mcp"),
            "should name the URL: {err}"
        );
        assert!(
            err.contains("scheme"),
            "should point at the missing scheme: {err}"
        );
    }

    #[test]
    fn url_rejects_missing_host() {
        // file:// URLs have no host
        assert!(validate_url_not_ssrf("file:///etc/passwd").is_err());
    }

    // ── validate_redirect_chain ───────────────────────────────────────────────

    #[test]
    fn redirect_chain_all_public_passes() {
        let chain = &[
            "https://api.example.com/redirect",
            "https://cdn.example.com/resource",
        ];
        assert!(validate_redirect_chain(chain).is_ok());
    }

    #[test]
    fn redirect_chain_blocks_internal_hop() {
        let chain = &[
            "https://api.example.com/redirect",
            "http://10.0.0.1/internal", // redirect to internal
        ];
        let err = validate_redirect_chain(chain).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("hop 1"),
            "error should name the hop index: {msg}"
        );
    }

    #[test]
    fn redirect_chain_blocks_first_hop() {
        let chain = &["http://127.0.0.1/api"];
        let err = validate_redirect_chain(chain).unwrap_err();
        assert!(err.to_string().contains("hop 0"));
    }

    #[test]
    fn redirect_chain_empty_passes() {
        assert!(validate_redirect_chain(&[]).is_ok());
    }

    // ── check_host_not_ssrf ───────────────────────────────────────────────────

    #[test]
    fn check_host_blocks_bare_ipv4() {
        assert!(check_host_not_ssrf("127.0.0.1").is_err());
        assert!(check_host_not_ssrf("10.0.0.1").is_err());
    }

    #[test]
    fn check_host_blocks_bracketed_ipv6() {
        assert!(check_host_not_ssrf("[::1]").is_err());
        assert!(check_host_not_ssrf("[fe80::1]").is_err());
    }

    #[test]
    fn check_host_allows_domain() {
        assert!(check_host_not_ssrf("example.com").is_ok());
    }

    #[test]
    fn check_host_allows_public_ipv4() {
        assert!(check_host_not_ssrf("8.8.8.8").is_ok());
    }

    // ── DNS pinning: resolve_and_validate_host / PinningResolver (MIK-4019) ──

    /// Minimal mock resolver for unit tests: returns a fixed IP list.
    struct MockResolver {
        ips: Vec<IpAddr>,
    }

    impl MockResolver {
        fn returning(ips: Vec<IpAddr>) -> Self {
            Self { ips }
        }
    }

    impl HostResolver for MockResolver {
        fn lookup(
            &self,
            _host: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
            let ips = self.ips.clone();
            Box::pin(async move { Ok(ips) })
        }
    }

    /// AC2: allowed public domain: mock returns a public IP, passes.
    #[tokio::test]
    async fn pinning_public_domain_passes() {
        let resolver = MockResolver::returning(vec!["8.8.8.8".parse().unwrap()]);
        let result = resolve_and_validate_host("public.test.invalid", &resolver).await;
        assert!(result.is_ok(), "public domain should pass: {result:?}");
        assert_eq!(result.unwrap(), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    /// AC2: private-rebinding: mock returns 127.0.0.1, blocked.
    #[tokio::test]
    async fn pinning_loopback_rebinding_blocked() {
        let resolver = MockResolver::returning(vec!["127.0.0.1".parse().unwrap()]);
        let err = resolve_and_validate_host("evil.test.invalid", &resolver)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("127.0.0.1"),
            "error must name the blocked IP: {msg}"
        );
        assert!(
            msg.contains("SSRF blocked"),
            "error must say SSRF blocked: {msg}"
        );
    }

    /// AC2: metadata-IP rebinding: mock returns 169.254.169.254, blocked.
    #[tokio::test]
    async fn pinning_metadata_rebinding_blocked() {
        let resolver = MockResolver::returning(vec!["169.254.169.254".parse().unwrap()]);
        let err = resolve_and_validate_host("metadata.test.invalid", &resolver)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("169.254.169.254"),
            "error must name the metadata IP: {msg}"
        );
    }

    /// AC2: private RFC-1918 rebinding: mock returns 10.0.0.1, blocked.
    #[tokio::test]
    async fn pinning_private_rfc1918_rebinding_blocked() {
        let resolver = MockResolver::returning(vec!["10.0.0.1".parse().unwrap()]);
        let err = resolve_and_validate_host("corp.test.invalid", &resolver)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("SSRF blocked"));
    }

    /// AC2: `PinningResolver` blocks private IP via `reqwest::dns::Resolve`.
    #[tokio::test]
    async fn pinning_resolver_blocks_private_via_reqwest_trait() {
        use reqwest::dns::{Name, Resolve};
        let resolver =
            PinningResolver::new(MockResolver::returning(vec!["127.0.0.1".parse().unwrap()]));
        let name: Name = "evil.test.invalid".parse().unwrap();
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "PinningResolver must reject private IP via reqwest Resolve trait"
        );
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => String::new(),
        };
        assert!(err_msg.contains("SSRF blocked"), "error: {err_msg}");
    }

    /// AC2: `PinningResolver` allows public IP via `reqwest::dns::Resolve`.
    #[tokio::test]
    async fn pinning_resolver_allows_public_via_reqwest_trait() {
        use reqwest::dns::{Name, Resolve};
        let resolver =
            PinningResolver::new(MockResolver::returning(vec!["8.8.8.8".parse().unwrap()]));
        let name: Name = "dns.google".parse().unwrap();
        let result = resolver.resolve(name).await;
        assert!(result.is_ok(), "PinningResolver must allow public IP");
    }

    /// AC2: redirect handling: `validate_redirect_chain` blocks loopback redirect hop.
    #[test]
    fn redirect_to_loopback_is_blocked() {
        let chain = &[
            "https://api.test.invalid/step1",
            "http://127.0.0.1/internal",
        ];
        let err = validate_redirect_chain(chain).unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    /// AC2: redirect handling: `validate_redirect_chain` blocks metadata IP redirect.
    #[test]
    fn redirect_to_metadata_ip_is_blocked() {
        let chain = &[
            "https://public.test.invalid/redirect",
            "http://169.254.169.254/latest/meta-data/",
        ];
        let err = validate_redirect_chain(chain).unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }
}
