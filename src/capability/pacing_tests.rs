// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pacing row RL7: the host key pacing counts by.

use super::pacing::{HostKey, host_key};

fn key(host: &str, port: u16) -> HostKey {
    HostKey {
        host: host.to_owned(),
        port,
    }
}

#[test]
fn rl7_host_case_is_folded() {
    assert_eq!(
        host_key("HTTPS://Example.ORG/x"),
        Some(key("example.org", 443))
    );
}

#[test]
fn rl7_an_explicit_default_port_is_the_same_key() {
    assert_eq!(
        host_key("https://example.org:443/x"),
        Some(key("example.org", 443))
    );
}

#[test]
fn rl7_another_port_is_another_key() {
    assert_eq!(
        host_key("https://example.org:8443/x"),
        Some(key("example.org", 8443))
    );
}

#[test]
fn rl7_plain_http_counts_port_80() {
    assert_eq!(
        host_key("http://example.org/x"),
        Some(key("example.org", 80))
    );
}

#[test]
fn rl7_a_url_without_a_host_has_no_key() {
    assert_eq!(host_key("data:text/plain,hi"), None);
}
