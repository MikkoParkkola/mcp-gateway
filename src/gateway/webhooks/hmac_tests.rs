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
