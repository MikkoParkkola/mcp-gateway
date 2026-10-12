// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the identity-source facts a stream captures at attach, and the
//! redaction of the one that is a secret.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap, HeaderValue};

use super::*;
use crate::gateway::streaming::{Redacted, ViewSubject};

const ASSERTION: &str = "eyJhbGciOiJSUzI1NiJ9.payload.signature";

fn config(mode: CallerIdentityMode) -> CallerIdentityConfig {
    CallerIdentityConfig {
        mode,
        ..CallerIdentityConfig::default()
    }
}

fn cf_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_CF_ACCESS_JWT, HeaderValue::from_static(ASSERTION));
    headers
}

fn peer_extensions() -> (Extensions, SocketAddr) {
    let peer = SocketAddr::from(([10, 0, 0, 7], 4_433));
    let mut extensions = Extensions::new();
    extensions.insert(ConnectInfo(peer));
    (extensions, peer)
}

fn verified() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "user-1".to_string(),
        email: "owner@corp.example".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.example".to_string(),
    }
}

#[test]
fn cloudflare_mode_captures_the_assertion_and_no_peer() {
    let (extensions, _) = peer_extensions();
    let (assertion, peer) = identity_source_facts(
        &config(CallerIdentityMode::CloudflareAccess),
        (&cf_headers(), &extensions),
        None,
    );
    assert_eq!(assertion.as_ref().map(Redacted::expose), Some(ASSERTION));
    assert!(peer.is_none());
}

#[test]
fn trusted_proxy_mode_captures_the_peer_and_no_assertion() {
    let (extensions, expected) = peer_extensions();
    let (assertion, peer) = identity_source_facts(
        &config(CallerIdentityMode::TrustedProxy),
        (&cf_headers(), &extensions),
        None,
    );
    assert!(assertion.is_none());
    assert_eq!(peer, Some(expected));
}

#[test]
fn off_mode_captures_nothing() {
    let (extensions, _) = peer_extensions();
    let (assertion, peer) = identity_source_facts(
        &config(CallerIdentityMode::Off),
        (&cf_headers(), &extensions),
        None,
    );
    assert!(assertion.is_none() && peer.is_none());
}

#[test]
fn a_verified_identity_takes_precedence_over_both_sources() {
    let (extensions, _) = peer_extensions();
    for mode in [
        CallerIdentityMode::CloudflareAccess,
        CallerIdentityMode::TrustedProxy,
    ] {
        let (assertion, peer) = identity_source_facts(
            &config(mode),
            (&cf_headers(), &extensions),
            Some(&verified()),
        );
        assert!(assertion.is_none() && peer.is_none());
    }
}

#[test]
fn a_blank_issuer_does_not_take_precedence() {
    let mut blank = verified();
    blank.issuer.clear();
    let (assertion, _) = identity_source_facts(
        &config(CallerIdentityMode::CloudflareAccess),
        (&cf_headers(), &Extensions::new()),
        Some(&blank),
    );
    assert!(assertion.is_some());
}

#[test]
fn the_assertion_never_reaches_a_formatted_string() {
    let secret = Redacted::new(ASSERTION);
    assert!(!format!("{secret:?}").contains("signature"));
    assert!(!format!("{secret}").contains("signature"));
    let subject = ViewSubject {
        cf_assertion: Some(Redacted::new(ASSERTION)),
        ..ViewSubject::default()
    };
    let shown = format!("{subject:?} {:?}", Some(&subject.cf_assertion));
    assert!(!shown.contains("signature") && !shown.contains("payload"));
}
