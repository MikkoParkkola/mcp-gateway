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
