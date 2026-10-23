// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782: a body signed the way Hammerspoon's `hs.hash.hmacSHA256` signs it
//! (HMAC-SHA256 over the raw bytes, lowercase hex) verifies, bare or as
//! `sha256=<hex>`; the same JSON re-serialized differently does not. This is
//! the gateway side of `desktop_event_bus`; Hammerspoon's output format was
//! checked from its source (`libhash.m`, `%02x`), not by running it.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use hmac::{KeyInit, Mac as _};
use sha2::Sha256;

use super::tests::make_definition;
use super::validate_signature;

const SECRET: &str = "desktop-event-secret-7782";
const HEADER: &str = "X-Desktop-Signature";

/// What `hs.hash.hmacSHA256(SECRET, body)` returns: lowercase hex.
fn hammerspoon_signature(body: &[u8]) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn check(body: &[u8], header: &str) -> Result<(), String> {
    let mut definition = make_definition(false);
    definition.secret = Some(SECRET.to_owned());
    definition.signature_header = Some(HEADER.to_owned());
    let mut headers = HeaderMap::new();
    headers.insert(HEADER, HeaderValue::from_str(header).unwrap());
    validate_signature(
        &headers,
        body,
        &definition,
        &Arc::new(crate::config::LiveEnv::default()),
    )
}

#[test]
fn a_hammerspoon_signed_body_verifies_bare_and_prefixed() {
    let body =
        br#"{"app":"Slack","kind":"activated","title":"","bundle_id":"com.tinyspeck.slackmacgap"}"#;
    let signature = hammerspoon_signature(body);
    assert!(check(body, &signature).is_ok(), "bare hex");
    assert!(
        check(body, &format!("sha256={signature}")).is_ok(),
        "sha256= prefix"
    );
}

#[test]
fn the_same_event_reserialized_does_not_verify() {
    let signed = br#"{"app":"Slack","kind":"activated"}"#;
    let posted = br#"{"kind":"activated","app":"Slack"}"#;
    let signature = hammerspoon_signature(signed);
    assert!(
        check(posted, &format!("sha256={signature}")).is_err(),
        "the script must sign the exact bytes it posts"
    );
}

#[test]
fn uppercase_hex_is_not_what_hammerspoon_sends_and_does_not_verify() {
    let body = br#"{"app":"Slack","kind":"activated"}"#;
    let upper = hammerspoon_signature(body).to_uppercase();
    assert!(check(body, &upper).is_err());
}

// MIK-8660 T9a: signature checks across the constant-time compare (subtle `ct_eq`).

fn t9a_signature(secret: &str, body: &[u8]) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn t9a_check(body: &[u8], header: &str) -> Result<(), String> {
    let mut definition = make_definition(false);
    definition.secret = Some("t9a-webhook-secret-not-real".to_owned());
    definition.signature_header = Some("X-T9a-Signature".to_owned());
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-T9a-Signature",
        header.parse().expect("signature header value"),
    );
    validate_signature(
        &headers,
        body,
        &definition,
        &Arc::new(crate::config::LiveEnv::default()),
    )
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let body = br#"{"event":"t9a"}"#;
    let valid = t9a_signature("t9a-webhook-secret-not-real", body);
    let short = valid[..valid.len() - 1].to_owned();
    assert!(t9a_check(body, &short).is_err(), "short: {short}");
}

#[test]
fn a_signature_with_one_changed_digit_is_refused() {
    let body = br#"{"event":"t9a"}"#;
    let valid = t9a_signature("t9a-webhook-secret-not-real", body);
    let mut tampered = valid.clone();
    let first = tampered.as_bytes()[0];
    tampered.replace_range(0..1, if first == b'a' { "b" } else { "a" });
    assert_eq!(tampered.len(), valid.len(), "same length, one digit");
    assert!(t9a_check(body, &tampered).is_err(), "tampered: {tampered}");
}

#[test]
fn the_correct_lowercase_signature_is_accepted() {
    let body = br#"{"event":"t9a"}"#;
    let valid = t9a_signature("t9a-webhook-secret-not-real", body);
    assert!(t9a_check(body, &valid).is_ok(), "valid: {valid}");
}
