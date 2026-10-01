// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::DestinationPolicy;
use crate::security::posture::SecurityPosture;

fn url(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

#[test]
fn public_refuses_private_literals_in_every_spelling() {
    for literal in [
        "http://127.0.0.1:9/mcp",
        "ws://10.0.0.5/",
        "https://169.254.169.254/latest",
        "http://[::1]:9/mcp",
        "http://[::ffff:127.0.0.1]:9/mcp",
        "http://[::ffff:169.254.169.254]/",
        "http://[2002:7f00:1::]:9/mcp",
        "http://[fe80::1]/",
        "http://192.168.1.1/",
        "http://172.16.5.5/",
        "http://0.0.0.0/",
        // Parser-normalised spellings of 127.0.0.1: the host is checked after parsing.
        "http://2130706433/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://0177.0.0.1/",
    ] {
        let error = DestinationPolicy::Public
            .check_literal(&url(literal))
            .expect_err(literal)
            .to_string();
        assert!(error.contains("SSRF blocked"), "{literal}: {error}");
    }
}

#[test]
fn public_passes_hostnames_and_public_literals() {
    for allowed in [
        "http://localhost:9/mcp",
        "https://mcp.example.com/",
        "http://8.8.8.8/",
    ] {
        DestinationPolicy::Public
            .check_literal(&url(allowed))
            .expect(allowed);
    }
}

#[test]
fn configured_checks_nothing() {
    DestinationPolicy::Configured
        .check_literal(&url("http://127.0.0.1:9/mcp"))
        .expect("standard keeps today's behaviour");
}

#[test]
fn posture_selects_the_policy() {
    assert_eq!(
        DestinationPolicy::for_posture(SecurityPosture::Hardened),
        DestinationPolicy::Public
    );
    assert_eq!(
        DestinationPolicy::for_posture(SecurityPosture::Standard),
        DestinationPolicy::Configured
    );
}

/// Row 13: what each policy denies. `Private` reaches exactly what `Public`
/// reaches plus loopback, RFC 1918 and unique-local; only an IPv4-mapped
/// address gets that allowance by its embedded IPv4.
#[test]
fn private_policy_denies() {
    use std::net::IpAddr;
    // (address, Public denies, Private denies)
    let table: &[(&str, bool, bool)] = &[
        ("8.8.8.8", false, false),
        ("127.0.0.1", true, false),
        ("10.0.0.1", true, false),
        ("172.16.0.1", true, false),
        ("172.31.255.255", true, false),
        ("172.32.0.1", false, false),
        ("192.168.1.1", true, false),
        ("169.254.169.254", true, true),
        ("169.254.0.1", true, true),
        ("100.64.0.1", true, true),
        ("0.0.0.0", true, true),
        ("::1", true, false),
        ("fd12:3456::1", true, false),
        ("fc00::1", true, false),
        ("fd00:ec2::254", true, true),
        ("fe80::1", true, true),
        ("::ffff:10.0.0.1", true, false),
        ("::ffff:169.254.169.254", true, true),
        ("::10.0.0.1", true, true),
        ("::8.8.8.8", false, false),
        ("64:ff9b::a00:1", true, true),
        ("2002:a00:1::", true, true),
        ("2001:0:a00:1::", true, true),
        ("2606:4700::1111", false, false),
        ("168.63.129.16", true, true),
    ];
    for (text, public, private) in table {
        let addr: IpAddr = text.parse().unwrap();
        assert!(
            !DestinationPolicy::Configured.denies(addr),
            "Configured denies {text}"
        );
        assert_eq!(
            DestinationPolicy::Public.denies(addr),
            *public,
            "Public, {text}"
        );
        assert_eq!(
            DestinationPolicy::Private.denies(addr),
            *private,
            "Private, {text}"
        );
    }
    let literal = |text: &str| DestinationPolicy::Private.check_literal(&url(text));
    assert!(literal("http://10.0.0.1/").is_ok());
    assert!(literal("http://[fd00:ec2::254]/").is_err());
    assert!(literal("http://169.254.169.254/").is_err());
}

/// Row 13: the pinning resolver of a listed backend refuses a name that
/// resolves to the metadata address, and admits one that resolves to loopback.
#[tokio::test]
async fn private_pin_refuses_metadata_names() {
    use std::net::IpAddr;
    use std::pin::Pin;

    use reqwest::dns::Resolve as _;

    use crate::security::ssrf::{HostResolver, PinningResolver};

    struct Fixed(IpAddr);
    impl HostResolver for Fixed {
        fn lookup(
            &self,
            _host: &str,
        ) -> Pin<Box<dyn Future<Output = crate::Result<Vec<IpAddr>>> + Send + '_>> {
            let ip = self.0;
            Box::pin(async move { Ok(vec![ip]) })
        }
    }
    let resolve = |ip: &str| {
        let resolver = PinningResolver::new(Fixed(ip.parse().unwrap()))
            .with_policy(DestinationPolicy::Private);
        resolver.resolve("backend.internal".parse().unwrap())
    };
    assert!(resolve("fd00:ec2::254").await.is_err(), "metadata by name");
    assert!(
        resolve("169.254.169.254").await.is_err(),
        "link-local by name"
    );
    assert!(resolve("127.0.0.1").await.is_ok(), "loopback by name");
}

/// Row 13: at proxy time a listed backend's loopback URL passes and its
/// link-local one does not; every other backend keeps the full validation.
#[test]
fn listed_private_backend_tool_call_passes_proxy_check() {
    let check = |policy: DestinationPolicy, text: &str| policy.check_configured_url(text);
    assert!(check(DestinationPolicy::Private, "http://127.0.0.1:9/mcp").is_ok());
    assert!(check(DestinationPolicy::Private, "http://10.1.2.3/mcp").is_ok());
    assert!(check(DestinationPolicy::Private, "http://169.254.169.254/").is_err());
    assert!(check(DestinationPolicy::Private, "http://[fd00:ec2::254]/").is_err());
    assert!(check(DestinationPolicy::Public, "http://127.0.0.1:9/mcp").is_err());
    assert!(check(DestinationPolicy::Configured, "http://127.0.0.1:9/mcp").is_err());
    // A URL without a host is refused under `Private` too, as the full
    // validation refuses it.
    for hostless in ["file:///tmp/example", "localhost:8080/mcp"] {
        assert!(
            check(DestinationPolicy::Private, hostless).is_err(),
            "{hostless}"
        );
        assert!(
            check(DestinationPolicy::Public, hostless).is_err(),
            "{hostless}"
        );
    }
}
