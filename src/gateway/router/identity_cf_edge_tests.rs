// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `cloudflare_access` identity edges the signed-assertion cells do not
//! reach: a gateway identity header, an absent assertion, a missing verifier
//! and a verified identity with a blank issuer or subject.

use axum::http::{HeaderMap, HeaderValue};

use super::*;

fn map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn identity(issuer: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: "owner@corp.example".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: issuer.to_string(),
    }
}

#[tokio::test]
async fn a_gateway_identity_header_is_refused_in_access_mode() {
    let h = map(&[(HEADER_GATEWAY_IDENTITY, "someone")]);
    let result = cloudflare_access_identity(&h, None).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::WrongModeHeader));
}

#[tokio::test]
async fn no_access_headers_means_no_identity() {
    let result = cloudflare_access_identity(&HeaderMap::new(), None).await;
    assert_eq!(result, Ok(None));
}

#[tokio::test]
async fn an_assertion_without_a_verifier_is_refused() {
    let h = map(&[(HEADER_CF_ACCESS_JWT, "a.b.c")]);
    let result = cloudflare_access_identity(&h, None).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::AccessAssertion));
}

#[test]
fn a_blank_issuer_or_subject_yields_no_grant_subject() {
    assert!(grant_subject_from_verified_identity(&identity("", "sub")).is_none());
    assert!(grant_subject_from_verified_identity(&identity("https://iss", "")).is_none());
    let ok = grant_subject_from_verified_identity(&identity("https://iss", "sub")).unwrap();
    assert_eq!(
        (ok.authority.as_str(), ok.subject.as_str()),
        ("https://iss", "sub")
    );
}
