// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability destination naming loopback is refused by name before any
//! DNS lookup, and every literal spelling of a loopback or unspecified
//! address parses to an IP the synchronous check refuses (MIK-9038).

use super::{is_loopback_name, is_ssrf_refusal, refuse_loopback_name, validate_url_not_ssrf};

/// Every spelling of a loopback name, and names that only look like one.
#[test]
fn loopback_names_in_every_spelling() {
    for host in [
        "localhost",
        "LOCALHOST",
        "LocalHost",
        "localhost.",
        "foo.localhost",
        "foo.localhost.",
        "a.b.LOCALHOST",
    ] {
        assert!(is_loopback_name(host), "{host:?} is a loopback name");
    }
    for host in [
        "",
        ".",
        ".localhost",
        "localhostx",
        "xlocalhost",
        "localhost.example.com",
        "example.com",
        "127.0.0.1",
        "::1",
    ] {
        assert!(!is_loopback_name(host), "{host:?} is not a loopback name");
    }
}

/// A capability URL naming loopback is refused with the SSRF refusal; a
/// public name is not.
#[test]
fn a_loopback_name_url_is_refused_as_ssrf() {
    for url in [
        "http://localhost:8080/x",
        "http://LOCALHOST/x",
        "http://localhost.:8080/x",
        "https://foo.localhost/x",
        "http://foo.localhost.:9/x",
    ] {
        let refused = refuse_loopback_name(url).expect_err(url);
        assert!(is_ssrf_refusal(&refused), "{url}: {refused}");
    }
    refuse_loopback_name("https://api.example.com/x").expect("a public name passes");
    refuse_loopback_name("http://127.0.0.1/x").expect("a literal is the other check's");
}

/// Each literal spelling parses to an IP, not a name, so the synchronous
/// check refuses it and no spelling reaches DNS as a name.
#[test]
fn every_literal_spelling_parses_to_an_ip_the_check_refuses() {
    for (spelling, address) in [
        ("127.1", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("127.0.0.1.", "127.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("[::1]", "::1"),
        ("[::ffff:127.0.0.1]", "::ffff:127.0.0.1"),
    ] {
        let url = format!("http://{spelling}:8080/x");
        let parsed = url::Url::parse(&url).expect("parses");
        let ip: std::net::IpAddr = match parsed.host() {
            Some(url::Host::Ipv4(v4)) => v4.into(),
            Some(url::Host::Ipv6(v6)) => v6.into(),
            other => panic!("{spelling:?} parsed as {other:?}, not an IP"),
        };
        assert_eq!(
            ip,
            address.parse::<std::net::IpAddr>().unwrap(),
            "{spelling:?}"
        );
        let refused = validate_url_not_ssrf(&url).expect_err(&url);
        assert!(is_ssrf_refusal(&refused), "{spelling:?}: {refused}");
    }
}
