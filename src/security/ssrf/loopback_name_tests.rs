// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability destination naming loopback is refused by name before any
//! DNS lookup, and every literal spelling of a loopback or unspecified
//! address parses to an IP the synchronous check refuses.

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
        "localhost..",
        "LOCALHOST..",
        "foo.localhost..",
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

/// A capability URL naming loopback is refused with the SSRF refusal, in
/// every spelling the URL parser leaves a name: trailing dots, case, percent
/// encoding and full-width forms (both normalised to `localhost`), and a
/// loopback literal with extra trailing dots, which stays a name. A public
/// name is not refused.
#[test]
fn a_loopback_name_url_is_refused_as_ssrf() {
    for url in [
        "http://localhost:8080/x",
        "http://LOCALHOST/x",
        "http://localhost.:8080/x",
        "http://localhost..:8080/x",
        "https://foo.localhost/x",
        "http://foo.localhost.:9/x",
        "http://local%68ost:8080/x",
        "http://\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}:8080/x",
        "http://127.0.0.1..:8080/x",
    ] {
        let refused = refuse_loopback_name(url).expect_err(url);
        assert!(is_ssrf_refusal(&refused), "{url}: {refused}");
    }
    refuse_loopback_name("https://api.example.com/x").expect("a public name passes");
    // A literal is the synchronous check's, where the isolated runtime's
    // loopback-literal allowance applies.
    refuse_loopback_name("http://127.0.0.1/x").expect("a literal is left to the other check");
    refuse_loopback_name("http://[::1]/x").expect("a literal is left to the other check");
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
        ("0x7f.1", "127.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("[::1]", "::1"),
        ("[::ffff:127.0.0.1]", "::ffff:127.0.0.1"),
        ("[64:ff9b::7f00:1]", "64:ff9b::7f00:1"),
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
