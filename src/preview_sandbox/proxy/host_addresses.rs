// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The host's own addresses, read from /proc at each CONNECT with no new
//! dependency: the proxy refuses a registry name that resolves to one of them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// False only when the lookup failed with `NotFound`; true on success and every other error.
pub(super) fn ipv6_tree_present(lookup: io::Result<()>) -> bool {
    !matches!(lookup, Err(e) if e.kind() == io::ErrorKind::NotFound)
}

/// `Ok(text)` is `Ok(Some(text))`; `NotFound` is `Ok(None)`; other errors are returned unchanged.
pub(super) fn optional_text(read: io::Result<String>) -> io::Result<Option<String>> {
    match read {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The host's IPv4 networks from `/proc/net/fib_trie`: every leaf with a
/// LOCAL route, in every table, with that route's prefix length.
pub(super) fn fib_trie_local(text: &str) -> io::Result<Vec<(Ipv4Addr, u8)>> {
    let mut addresses = Vec::new();
    let mut current: Option<Ipv4Addr> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let line = line.trim();
        // A table header or an inner node: the next leaf starts afresh.
        if line.ends_with(':') || line.starts_with("+-- ") {
            current = None;
        } else if let Some(rest) = line.strip_prefix("|-- ") {
            current = Some(
                rest.parse()
                    .map_err(|_| io::Error::other(format!("bad fib_trie line: {line}")))?,
            );
        } else if let Some(info) = line.strip_prefix('/') {
            let bad = || io::Error::other(format!("bad fib_trie line: {line}"));
            let leaf = current.ok_or_else(bad)?;
            // `/<prefix length> <scope> <type>`: a LOCAL route over a prefix
            // makes the host answer on every address in it.
            let mut words = info.split_whitespace();
            let len = words
                .next()
                .and_then(|word| word.parse::<u8>().ok())
                .filter(|len| *len <= 32)
                .ok_or_else(bad)?;
            if words.next_back() == Some("LOCAL") && !addresses.contains(&(leaf, len)) {
                addresses.push((leaf, len));
            }
        } else {
            return Err(io::Error::other(format!("bad fib_trie line: {line}")));
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::other("no LOCAL entry in fib_trie"));
    }
    Ok(addresses)
}

/// The host's IPv6 addresses from `/proc/net/if_inet6`; a missing file means
/// no IPv6 only when the IPv6 sysctl tree is absent too.
pub(super) fn if_inet6(text: Option<&str>, ipv6_sysctl_present: bool) -> io::Result<Vec<Ipv6Addr>> {
    let Some(text) = text else {
        return missing_ipv6_file("if_inet6", ipv6_sysctl_present);
    };
    let mut addresses = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let value = line
            .split_whitespace()
            .next()
            .and_then(|field| hex_field(field, 32))
            .ok_or_else(|| io::Error::other(format!("bad if_inet6 line: {line}")))?;
        addresses.push(Ipv6Addr::from(value));
    }
    Ok(addresses)
}

/// A missing IPv6 file under `/proc/net` means no IPv6 only when the IPv6
/// sysctl tree is missing too (IPv6 disabled at boot); otherwise it refuses.
fn missing_ipv6_file<T>(name: &str, ipv6_sysctl_present: bool) -> io::Result<Vec<T>> {
    if ipv6_sysctl_present {
        Err(io::Error::other(format!(
            "/proc/net/{name} is missing while IPv6 is enabled"
        )))
    } else {
        Ok(Vec::new())
    }
}

/// A field of exactly `width` hex digits, as its value.
fn hex_field(field: &str, width: usize) -> Option<u128> {
    if field.len() != width || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(field, 16).ok()
}

/// `RTF_LOCAL` in an `ipv6_route` line's flags: the host answers on the
/// route's whole prefix.
const RTF_LOCAL: u128 = 0x8000_0000;

/// The host's IPv6 local routes from `/proc/net/ipv6_route`, an `AnyIP`
/// prefix included; a missing file follows the rule of [`if_inet6`].
pub(super) fn ipv6_route_local(
    text: Option<&str>,
    ipv6_sysctl_present: bool,
) -> io::Result<Vec<(Ipv6Addr, u8)>> {
    let Some(text) = text else {
        return missing_ipv6_file("ipv6_route", ipv6_sysctl_present);
    };
    let mut routes = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let bad = || io::Error::other(format!("bad ipv6_route line: {line}"));
        // destination, its prefix length, source, its length, next hop,
        // metric, reference count, use count, flags, device.
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [dest, len, _, _, _, _, _, _, flags, _] = fields[..] else {
            return Err(bad());
        };
        let dest = hex_field(dest, 32).ok_or_else(bad)?;
        let len = hex_field(len, 2)
            .and_then(|len| u8::try_from(len).ok())
            .filter(|len| *len <= 128)
            .ok_or_else(bad)?;
        let flags = hex_field(flags, 8).ok_or_else(bad)?;
        if flags & RTF_LOCAL != 0 {
            routes.push((Ipv6Addr::from(dest), len));
        }
    }
    Ok(routes)
}

/// Every network the host answers on: the IPv4 LOCAL routes, each IPv6
/// address, and the IPv6 local routes.
pub(super) fn networks(
    v4: Vec<(Ipv4Addr, u8)>,
    inet6: Vec<Ipv6Addr>,
    local6: Vec<(Ipv6Addr, u8)>,
) -> Vec<super::Owned> {
    v4.into_iter()
        .map(|(a, len)| (IpAddr::V4(a), len))
        .chain(inet6.into_iter().map(|a| (IpAddr::V6(a), 128)))
        .chain(local6.into_iter().map(|(a, len)| (IpAddr::V6(a), len)))
        .collect()
}

#[cfg(target_os = "linux")]
impl super::Interfaces for super::System {
    fn addresses(&self) -> io::Result<Vec<super::Owned>> {
        let v4 = fib_trie_local(&std::fs::read_to_string("/proc/net/fib_trie")?)?;
        let inet6 = optional_text(std::fs::read_to_string("/proc/net/if_inet6"))?;
        // Any error but a missing tree counts as present, so an unreadable
        // /proc refuses the read instead of reporting that IPv6 is off.
        let ipv6_sysctl_present =
            ipv6_tree_present(std::fs::symlink_metadata("/proc/sys/net/ipv6").map(|_| ()));
        let v6 = if_inet6(inet6.as_deref(), ipv6_sysctl_present)?;
        let routes = optional_text(std::fs::read_to_string("/proc/net/ipv6_route"))?;
        let local6 = ipv6_route_local(routes.as_deref(), ipv6_sysctl_present)?;
        Ok(networks(v4, v6, local6))
    }
}
