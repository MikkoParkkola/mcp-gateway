//! SSRF protection: comprehensive RFC special-use IP range blocking.
//!
//! When the gateway proxies requests on behalf of tools, we must prevent
//! Server-Side Request Forgery (SSRF) attacks where a malicious tool
//! target resolves to internal infrastructure.
//!
//! # Covered ranges
//!
//! All RFC special-use IPv4 ranges (RFC 5735/6890):
//! - `0.0.0.0/8` — "this" network
//! - `10.0.0.0/8` — private (RFC 1918)
//! - `100.64.0.0/10` — shared address space / CGNAT (RFC 6598)
//! - `127.0.0.0/8` — loopback (RFC 1122)
//! - `169.254.0.0/16` — link-local (RFC 3927)
//! - `172.16.0.0/12` — private (RFC 1918)
//! - `192.0.0.0/24` — IETF protocol assignments (RFC 5736)
//! - `192.0.2.0/24` — TEST-NET-1 (RFC 5737)
//! - `192.88.99.0/24` — 6to4 relay anycast (RFC 3068, deprecated)
//! - `192.168.0.0/16` — private (RFC 1918)
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
//! - `ff00::/8` — multicast (RFC 4291)
//!
//! Encoded-IPv4 vectors:
//! - `::x.x.x.x` — IPv4-compatible (deprecated, still parseable)
//! - `2002::/16` — 6to4 with embedded IPv4
//! - `2001:0000::/32` — Teredo with obfuscated IPv4

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    addr.is_loopback()          // 127.0.0.0/8
    || addr.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    || addr.is_link_local()     // 169.254.0.0/16
    || addr.is_broadcast()      // 255.255.255.255/32
    || addr.is_unspecified()    // 0.0.0.0/8
    || addr.is_multicast()      // 224.0.0.0/4
    || is_shared_address(addr)  // 100.64.0.0/10
    || is_ietf_protocol(o)      // 192.0.0.0/24
    || is_documentation(o)      // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    || is_6to4_relay(o)         // 192.88.99.0/24
    || is_benchmarking(o)       // 198.18.0.0/15
    || is_reserved(addr) // 240.0.0.0/4
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

    // Documentation (2001:db8::/32) — not routable, used in examples/RFCs
    if seg[0] == 0x2001 && seg[1] == 0x0DB8 {
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

    // 6to4 (2002::/16) — embeds a public or private IPv4 in seg[1..2]
    if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return is_private_ipv4(embedded);
    }

    // Teredo (2001:0000::/32) — client IPv4 is XOR-obfuscated in seg[6..7]
    if seg[0] == 0x2001 && seg[1] == 0x0000 {
        let client = Ipv4Addr::new(
            (seg[6] >> 8) as u8 ^ 0xFF,
            seg[6] as u8 ^ 0xFF,
            (seg[7] >> 8) as u8 ^ 0xFF,
            seg[7] as u8 ^ 0xFF,
        );
        return is_private_ipv4(client);
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
// Public API
// ============================================================================

/// Validate that a URL does not target a private/internal/reserved IP address.
///
/// Parses the host from the URL and checks it against all RFC special-use
/// ranges for both IPv4 and IPv6.  Domain names pass through unchanged —
/// DNS resolution happens downstream and is outside the scope of this check.
///
/// # Errors
///
/// Returns `Error::Protocol` if the URL is malformed or targets a blocked range.
pub fn validate_url_not_ssrf(url_str: &str) -> Result<()> {
    let parsed =
        url::Url::parse(url_str).map_err(|e| Error::Protocol(format!("Invalid URL: {e}")))?;

    let Some(host) = parsed.host_str() else {
        return Err(Error::Protocol("URL has no host".to_string()));
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
    if let Ok(addr) = trimmed.parse::<IpAddr>() {
        if is_private_or_reserved(addr) {
            return Err(Error::Protocol(format!(
                "SSRF blocked: host targets private/reserved address {addr}"
            )));
        }
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
    fn ipv6_6to4_public_passes() {
        // 2002:0808:0808:: embeds 8.8.8.8
        let addr: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
        assert!(!is_private_ipv6(addr));
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
}
