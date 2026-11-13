// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The host's own addresses from `/proc/net/fib_trie` and `/proc/net/if_inet6`.

use super::super::host_addresses::{fib_trie_local, if_inet6, ipv6_tree_present, optional_text};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(text: &str) -> Ipv4Addr {
    text.parse().expect("address")
}

fn v6(text: &str) -> Ipv6Addr {
    text.parse().expect("address")
}

/// Kills "BROADCAST and UNICAST are taken, and a /8 LOCAL route is dropped".
#[test]
fn t3_fib_trie_local_entries_are_read_from_a_sample() {
    let mut want = vec![
        v4("10.0.7.1"),
        v4("10.0.62.1"),
        v4("203.0.113.30"),
        v4("127.0.0.0"),
        v4("127.0.0.1"),
        v4("172.17.0.1"),
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
    assert_eq!(fib_trie_local(text).ok(), Some(vec![v4("10.1.2.3")]));
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

/// Kills "a bad address, a stray line, or an info line before a leaf is skipped".
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
    for text in [bad_address, stray, info_before_leaf] {
        assert!(fib_trie_local(text).is_err(), "{text:?}");
    }
}

/// Kills "if_inet6 addresses are dropped or returned out of file order".
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

/// Kills "a missing if_inet6 is an error when IPv6 was disabled at boot".
#[test]
fn t3_missing_if_inet6_without_ipv6_sysctl_is_empty_and_allowed() {
    assert_eq!(if_inet6(None, false).ok(), Some(vec![]));
}

/// Kills "a missing if_inet6 is empty success while IPv6 is enabled".
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

/// Kills "NotFound is an error, not None".
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
