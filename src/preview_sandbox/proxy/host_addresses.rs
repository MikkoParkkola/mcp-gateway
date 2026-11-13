// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The host's own addresses, read from /proc at each CONNECT with no new
//! dependency: the proxy refuses a registry name that resolves to one of them.

use std::io;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// The host's IPv4 addresses from `/proc/net/fib_trie`: every leaf with a
/// LOCAL route, in every table.
pub(super) fn fib_trie_local(text: &str) -> io::Result<Vec<Ipv4Addr>> {
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
        } else if line.starts_with('/') {
            let leaf =
                current.ok_or_else(|| io::Error::other(format!("bad fib_trie line: {line}")))?;
            if line.split_whitespace().next_back() == Some("LOCAL") && !addresses.contains(&leaf) {
                addresses.push(leaf);
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
        return if ipv6_sysctl_present {
            Err(io::Error::other(
                "/proc/net/if_inet6 is missing while IPv6 is enabled",
            ))
        } else {
            Ok(Vec::new())
        };
    };
    let mut addresses = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let Some(field) = line.split_whitespace().next() else {
            return Err(io::Error::other(format!("bad if_inet6 line: {line}")));
        };
        if field.len() != 32 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::other(format!("bad if_inet6 line: {line}")));
        }
        let value = u128::from_str_radix(field, 16)
            .map_err(|_| io::Error::other(format!("bad if_inet6 line: {line}")))?;
        addresses.push(Ipv6Addr::from(value));
    }
    Ok(addresses)
}

#[cfg(target_os = "linux")]
impl super::Interfaces for super::System {
    fn addresses(&self) -> io::Result<Vec<IpAddr>> {
        let v4 = fib_trie_local(&std::fs::read_to_string("/proc/net/fib_trie")?)?;
        let inet6 = optional_text(std::fs::read_to_string("/proc/net/if_inet6"))?;
        // Any error but a missing tree counts as present, so an unreadable
        // /proc refuses the read instead of reporting that IPv6 is off.
        let ipv6_sysctl_present =
            ipv6_tree_present(std::fs::symlink_metadata("/proc/sys/net/ipv6").map(|_| ()));
        let v6 = if_inet6(inet6.as_deref(), ipv6_sysctl_present)?;
        Ok(v4
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6.into_iter().map(IpAddr::V6))
            .collect())
    }
}
