//! SSRF protection: block IPv4-mapped IPv6 literals and private IP ranges.
//!
//! When the gateway proxies requests on behalf of tools, we must prevent
//! Server-Side Request Forgery (SSRF) attacks where a malicious tool
//! target resolves to internal infrastructure.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Error, Result};

/// Check whether an IP address is a private/loopback/link-local address
/// that should be blocked for outbound requests.
fn is_private_or_reserved(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private, loopback, or link-local.
fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_loopback()          // 127.0.0.0/8
    || addr.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    || addr.is_link_local()     // 169.254.0.0/16
    || addr.is_broadcast()      // 255.255.255.255
    || addr.is_unspecified()    // 0.0.0.0
    || is_shared_address(addr)  // 100.64.0.0/10 (CGN)
    || is_documentation(addr)   // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
}

/// Check 100.64.0.0/10 (Carrier-Grade NAT / shared address space).
fn is_shared_address(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Check documentation ranges (TEST-NET-1/2/3).
fn is_documentation(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    // 192.0.2.0/24
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
    // 198.51.100.0/24
    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
    // 203.0.113.0/24
    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

/// Check if an IPv6 address is private, loopback, link-local, or an
/// IPv4-mapped address pointing to a private range.
#[allow(clippy::cast_possible_truncation)] // Extracting u8 octets from u16 IPv6 segments is intentional
fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    // Loopback (::1)
    if addr.is_loopback() {
        return true;
    }
    // Unspecified (::)
    if addr.is_unspecified() {
        return true;
    }

    let segments = addr.segments();

    // Link-local (fe80::/10)
    if segments[0] & 0xFFC0 == 0xFE80 {
        return true;
    }

    // Unique Local Address (fc00::/7)
    if segments[0] & 0xFE00 == 0xFC00 {
        return true;
    }

    // IPv4-mapped IPv6 (`::ffff:x.x.x.x`) -- the key SSRF bypass vector
    if let Some(ipv4) = extract_ipv4_mapped(&addr) {
        return is_private_ipv4(ipv4);
    }

    // IPv4-compatible IPv6 (deprecated but still parseable: `::x.x.x.x`)
    if let Some(ipv4) = extract_ipv4_compatible(&addr) {
        return is_private_ipv4(ipv4);
    }

    // 6to4 (2002::/16) — can embed private IPv4
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        );
        return is_private_ipv4(embedded);
    }

    // Teredo (2001:0000::/32) — can embed private IPv4
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        // Teredo server and client IPv4 are obfuscated (XOR with 0xFFFF)
        let client_ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8 ^ 0xFF,
            segments[6] as u8 ^ 0xFF,
            (segments[7] >> 8) as u8 ^ 0xFF,
            segments[7] as u8 ^ 0xFF,
        );
        return is_private_ipv4(client_ipv4);
    }

    false
}

/// Extract IPv4 address from IPv4-mapped IPv6 (`::ffff:x.x.x.x`).
#[allow(clippy::cast_possible_truncation)] // Extracting u8 octets from u16 IPv6 segments is intentional
fn extract_ipv4_mapped(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = addr.segments();
    // ::ffff:x.x.x.x has segments [0,0,0,0,0,0xFFFF, hi, lo]
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xFFFF
    {
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else {
        None
    }
}

/// Extract IPv4 address from IPv4-compatible IPv6 (`::x.x.x.x`, deprecated).
#[allow(clippy::cast_possible_truncation)] // Extracting u8 octets from u16 IPv6 segments is intentional
fn extract_ipv4_compatible(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = addr.segments();
    // All zero prefix with non-zero last two segments (and not ::1 or ::)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && (segments[6] != 0 || segments[7] > 1) // exclude :: and ::1
    {
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else {
        None
    }
}

/// Validate that a URL does not target a private/internal IP address.
///
/// Parses the host from the URL and checks it against known private ranges,
/// including IPv4-mapped IPv6 addresses used to bypass naive SSRF filters.
///
/// # Errors
///
/// Returns `Error::Protocol` if the URL targets a private IP address.
pub fn validate_url_not_ssrf(url_str: &str) -> Result<()> {
    let parsed = url::Url::parse(url_str).map_err(|e| {
        Error::Protocol(format!("Invalid URL: {e}"))
    })?;

    let Some(host) = parsed.host_str() else {
        return Err(Error::Protocol("URL has no host".to_string()));
    };

    // Try to parse host as IP address directly
    if let Ok(addr) = host.parse::<IpAddr>() {
        if is_private_or_reserved(addr) {
            return Err(Error::Protocol(format!(
                "SSRF blocked: URL targets private/reserved IP address {addr}"
            )));
        }
    }

    // Handle bracket-enclosed IPv6 literals like [::ffff:127.0.0.1]
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(addr) = trimmed.parse::<IpAddr>() {
        if is_private_or_reserved(addr) {
            return Err(Error::Protocol(format!(
                "SSRF blocked: URL targets private/reserved IP address {addr}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_private_ipv4 ───────────────────────────────────────────────

    #[test]
    fn private_ipv4_loopback() {
        assert!(is_private_ipv4(Ipv4Addr::LOCALHOST));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn private_ipv4_rfc1918() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn private_ipv4_link_local() {
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 0, 1)));
    }

    #[test]
    fn private_ipv4_cgn() {
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
    }

    #[test]
    fn private_ipv4_documentation() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn private_ipv4_broadcast_and_unspecified() {
        assert!(is_private_ipv4(Ipv4Addr::BROADCAST));
        assert!(is_private_ipv4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn public_ipv4_passes() {
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    // ── is_private_ipv6 ───────────────────────────────────────────────

    #[test]
    fn private_ipv6_loopback() {
        assert!(is_private_ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn private_ipv6_unspecified() {
        assert!(is_private_ipv6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn private_ipv6_link_local() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn private_ipv6_unique_local() {
        let addr: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_private_ipv6(addr));
        let addr2: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    #[test]
    fn private_ipv6_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1 — the classic SSRF bypass
        let addr: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn private_ipv6_ipv4_mapped_private() {
        let addr: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private_ipv6(addr));
        let addr2: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private_ipv6(addr2));
    }

    #[test]
    fn private_ipv6_ipv4_mapped_public_passes() {
        let addr: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ipv6(addr));
    }

    #[test]
    fn private_ipv6_6to4_with_private() {
        // 2002:0a00:0001:: embeds 10.0.0.1
        let addr: Ipv6Addr = "2002:0a00:0001::".parse().unwrap();
        assert!(is_private_ipv6(addr));
    }

    #[test]
    fn private_ipv6_6to4_with_public() {
        // 2002:0808:0808:: embeds 8.8.8.8
        let addr: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
        assert!(!is_private_ipv6(addr));
    }

    #[test]
    fn public_ipv6_passes() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        // 2001:db8 is documentation, but not in our private check
        // (it's not routable, but it's not a security risk for SSRF)
        assert!(!is_private_ipv6(addr));
    }

    // ── validate_url_not_ssrf ─────────────────────────────────────────

    #[test]
    fn ssrf_blocks_loopback() {
        assert!(validate_url_not_ssrf("http://127.0.0.1/api").is_err());
        assert!(validate_url_not_ssrf("http://127.0.0.1:8080/foo").is_err());
    }

    #[test]
    fn ssrf_blocks_private_ranges() {
        assert!(validate_url_not_ssrf("http://10.0.0.1/api").is_err());
        assert!(validate_url_not_ssrf("http://192.168.1.1/api").is_err());
        assert!(validate_url_not_ssrf("http://172.16.0.1/api").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        assert!(validate_url_not_ssrf("http://[::ffff:127.0.0.1]/api").is_err());
        assert!(validate_url_not_ssrf("http://[::ffff:10.0.0.1]/api").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(validate_url_not_ssrf("http://[::1]/api").is_err());
    }

    #[test]
    fn ssrf_allows_public_ips() {
        assert!(validate_url_not_ssrf("http://8.8.8.8/api").is_ok());
        assert!(validate_url_not_ssrf("https://93.184.216.34/api").is_ok());
    }

    #[test]
    fn ssrf_allows_domain_names() {
        // Domain names pass through (DNS resolution happens later)
        assert!(validate_url_not_ssrf("https://api.example.com/v1").is_ok());
    }

    #[test]
    fn ssrf_rejects_invalid_url() {
        assert!(validate_url_not_ssrf("not a url").is_err());
    }

    #[test]
    fn ssrf_blocks_unspecified() {
        assert!(validate_url_not_ssrf("http://0.0.0.0/api").is_err());
    }

    #[test]
    fn ssrf_allows_public_ipv6() {
        assert!(validate_url_not_ssrf("http://[2607:f8b0:4004:800::200e]/api").is_ok());
    }
}
