// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The host's own addresses from `/proc/net/fib_trie` and `/proc/net/if_inet6`.

use super::super::host_addresses::{
    fib_trie_local, if_inet6, ipv6_route_local, ipv6_tree_present, networks, optional_text,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(text: &str) -> Ipv4Addr {
    text.parse().expect("address")
}

fn v6(text: &str) -> Ipv6Addr {
    text.parse().expect("address")
}

/// Kills "BROADCAST and UNICAST are taken, and a /8 LOCAL route is dropped
/// or shrunk to its leaf address".
#[test]
fn t3_fib_trie_local_entries_are_read_from_a_sample() {
    let mut want = vec![
        (v4("10.0.7.1"), 32),
        (v4("10.0.62.1"), 32),
        (v4("203.0.113.30"), 32),
        (v4("127.0.0.0"), 8),
        (v4("127.0.0.1"), 32),
        (v4("172.17.0.1"), 32),
    ];
    want.sort();
    let got = fib_trie_local(include_str!("fib_trie_sample.txt")).map(|mut addrs| {
        addrs.sort();
        addrs
    });
    assert_eq!(got.ok(), Some(want));
}

/// Kills "a leaf is dropped unless every one of its routes is LOCAL".
#[test]
fn t3_a_leaf_with_several_routes_counts_if_any_is_local() {
    let text = "\
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /24 link UNICAST
        /32 host LOCAL
     |-- 10.1.2.4
        /32 link BROADCAST
";
    assert_eq!(fib_trie_local(text).ok(), Some(vec![(v4("10.1.2.3"), 32)]));
}

/// Kills "a LOCAL route over a prefix is kept as its leaf address alone": an
/// `AnyIP` route (`ip route add local 93.184.216.0/24 dev lo`) makes the host
/// answer on every address in it.
#[test]
fn t3_a_local_prefix_keeps_its_length() {
    let text = "\
Local:
  +-- 93.184.216.0/24 2 0 2
     |-- 93.184.216.0
        /24 host LOCAL
";
    assert_eq!(
        fib_trie_local(text).ok(),
        Some(vec![(v4("93.184.216.0"), 24)])
    );
}

/// Kills "a trie with no LOCAL entry is an empty success".
#[test]
fn t3_fib_trie_without_a_local_entry_is_an_error() {
    let text = "\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
";
    assert!(fib_trie_local(text).is_err());
}

/// Kills "a bad address, a stray line, an info line before a leaf, or a bad
/// prefix length is skipped".
#[test]
fn t3_an_unparsable_fib_trie_is_an_error() {
    // A valid LOCAL neighbour, so skipping the bad leaf would be a success.
    let bad_address = "\
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /32 host LOCAL
     |-- 10.1.2.x
        /32 host LOCAL
";
    // A valid LOCAL neighbour, so skipping the stray line would be a success.
    let stray = "\
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /32 host LOCAL
     garbage
";
    let info_before_leaf = "\
Local:
        /32 host LOCAL
";
    // A prefix length that is not a number from 0 to 32.
    let long_prefix = "\
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /33 host LOCAL
";
    let bad_prefix = "\
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /x host LOCAL
";
    for text in [
        bad_address,
        stray,
        info_before_leaf,
        long_prefix,
        bad_prefix,
    ] {
        assert!(fib_trie_local(text).is_err(), "{text:?}");
    }
}

/// Kills "`if_inet6` addresses are dropped or returned out of file order".
#[test]
fn t3_if_inet6_addresses_are_read_from_a_sample() {
    assert_eq!(
        if_inet6(Some(include_str!("if_inet6_sample.txt")), true).ok(),
        Some(vec![
            v6("::1"),
            v6("fe80::5c43:6cff:fed1:9b7e"),
            v6("fd00::1"),
            v6("2001:db8::42"),
        ])
    );
}

/// Kills "a first field that is not 32 hex digits is accepted".
#[test]
fn t3_an_unparsable_if_inet6_is_refused() {
    let lines = [
        "0000000000000000000000000000001\n",
        "0000000000000000000000000000000g\n",
        "000000000000000000000000000000001\n",
    ];
    for line in lines {
        assert!(if_inet6(Some(line), true).is_err(), "{line:?}");
    }
}

/// Kills "a missing `if_inet6` is an error when IPv6 was disabled at boot".
#[test]
fn t3_missing_if_inet6_without_ipv6_sysctl_is_empty_and_allowed() {
    assert_eq!(if_inet6(None, false).ok(), Some(vec![]));
}

/// Kills "a missing `if_inet6` is empty success while IPv6 is enabled".
#[test]
fn t3_missing_if_inet6_with_ipv6_sysctl_is_refused() {
    assert!(if_inet6(None, true).is_err());
}

/// Kills "an unreadable lookup reads as absent".
#[test]
fn t3_only_a_missing_ipv6_tree_reads_as_absent() {
    assert!(ipv6_tree_present(Ok(())));
    assert!(!ipv6_tree_present(Err(io::Error::from(
        io::ErrorKind::NotFound
    ))));
    assert!(ipv6_tree_present(Err(io::Error::from(
        io::ErrorKind::PermissionDenied
    ))));
    assert!(ipv6_tree_present(Err(io::Error::other("unreadable"))));
}

/// Kills "`NotFound` is an error, not `None`".
#[test]
fn t3_only_a_missing_if_inet6_file_reads_as_none() {
    assert!(matches!(optional_text(Ok("x".into())), Ok(Some(text)) if text == "x"));
    assert!(matches!(
        optional_text(Err(io::Error::from(io::ErrorKind::NotFound))),
        Ok(None)
    ));
    let denied = optional_text(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    assert_eq!(denied.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}

/// One `/proc/net/ipv6_route` line: destination, prefix length and flags; the
/// other seven fields as the kernel writes them.
fn route(dest: &str, len: &str, flags: &str) -> String {
    let zero = "0".repeat(32);
    format!("{dest} {len} {zero} 00 {zero} 00000000 00000001 00000000 {flags}       lo\n")
}

/// Kills "local routes are not read, a non-local route is taken, or an
/// `AnyIP` prefix is shrunk to one address".
#[test]
fn t3_ipv6_route_local_routes_are_read_from_a_sample() {
    assert_eq!(
        ipv6_route_local(Some(include_str!("ipv6_route_sample.txt")), true).ok(),
        Some(vec![
            (v6("::1"), 128),
            (v6("fe80::a8bb:ccff:fedd:1"), 128),
            (v6("2606:4700:10::"), 64),
        ])
    );
}

/// Kills "a malformed `ipv6_route` line is skipped": a short or long line,
/// a destination that is not 32 hex digits, a prefix length over 128, or
/// flags that are not 8 hex digits.
#[test]
fn t3_an_unparsable_ipv6_route_is_refused() {
    let good = route("00000000000000000000000000000001", "80", "80200001");
    let dest = "26064700001000000000000000000000";
    let bad = [
        good.replacen("       lo", "", 1),
        good.replacen("lo", "lo extra", 1),
        route("2606470000100000000000000000000", "40", "80200001"),
        route("2606470000100000000000000000000g", "40", "80200001"),
        route(dest, "81", "80200001"),
        route(dest, "4g", "80200001"),
        route(dest, "40", "8020000x"),
        route(dest, "40", "802000010"),
    ];
    for text in bad {
        // A valid local neighbour, so skipping the bad line would be a success.
        let text = format!("{good}{text}");
        assert!(ipv6_route_local(Some(&text), true).is_err(), "{text:?}");
    }
}

/// Kills "a missing `ipv6_route` is an error when IPv6 was disabled at boot".
#[test]
fn t3_missing_ipv6_route_without_ipv6_sysctl_is_empty_and_allowed() {
    assert_eq!(ipv6_route_local(None, false).ok(), Some(vec![]));
}

/// Kills "a missing `ipv6_route` is empty success while IPv6 is enabled".
#[test]
fn t3_missing_ipv6_route_with_ipv6_sysctl_is_refused() {
    assert!(ipv6_route_local(None, true).is_err());
}

/// Kills "a source is left out of the host's networks": the IPv4 LOCAL
/// routes, each IPv6 address (one address wide) and the IPv6 local routes
/// all count.
#[test]
fn t3_the_host_networks_join_all_three_sources() {
    let got = networks(
        vec![(v4("93.184.216.0"), 24)],
        vec![v6("fd00::1")],
        vec![(v6("2606:4700:10::"), 64)],
    );
    assert_eq!(
        got,
        vec![
            (IpAddr::V4(v4("93.184.216.0")), 24),
            (IpAddr::V6(v6("fd00::1")), 128),
            (IpAddr::V6(v6("2606:4700:10::")), 64),
        ]
    );
}
