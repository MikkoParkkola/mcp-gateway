//! RFC special-use IP range checks for [`super::validate_url_not_ssrf`] and
//! [`super::check_host_not_ssrf`].
//!
//! Covers all RFC special-use IPv4/IPv6 ranges (RFC 5735/6890, RFC 4291/5156)
//! plus the encoded-IPv4 vectors (IPv4-mapped, IPv4-compatible, 6to4, Teredo)
//! that would otherwise let a private IPv4 address be reached through an
//! IPv6 tunnel. See the module-level doc on `super` for the full range list.

use std::net::{Ipv4Addr, Ipv6Addr};

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
pub(super) fn is_private_ipv4(addr: Ipv4Addr) -> bool {
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
pub(super) fn is_private_ipv6(addr: Ipv6Addr) -> bool {
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
