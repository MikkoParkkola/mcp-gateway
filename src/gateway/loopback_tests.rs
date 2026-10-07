// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The loopback classifier every cleartext-credential guard decides on
//! (MIK-8059): an IPv4-mapped IPv6 loopback address never leaves the machine,
//! so it is loopback; any other mapped address is not.

use super::{is_loopback_host, is_tls_or_loopback};

fn url(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

#[test]
fn a_mapped_ipv4_loopback_is_loopback() {
    assert!(is_loopback_host("[::ffff:127.0.0.1]"));
    assert!(is_loopback_host("::ffff:127.0.0.1"));
    assert!(is_loopback_host("[::ffff:127.0.0.2]"));
    assert!(is_tls_or_loopback(&url("http://[::ffff:127.0.0.1]:8080/")));
}

#[test]
fn a_mapped_address_off_the_machine_stays_refused() {
    for host in [
        "[::ffff:10.0.0.1]",
        "[::ffff:8.8.8.8]",
        "[::ffff:169.254.169.254]",
        "[::ffff:0.0.0.0]",
    ] {
        assert!(!is_loopback_host(host), "{host} is not loopback");
    }
    for text in [
        "http://[::ffff:10.0.0.1]:8080/",
        "http://[::ffff:8.8.8.8]/",
        "http://localhost./",
    ] {
        assert!(!is_tls_or_loopback(&url(text)), "{text} is refused");
    }
}
