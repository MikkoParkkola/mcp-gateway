// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Signature state of one entry, on entries written by the real logger.

use std::sync::Arc;

use serde_json::Value;

use super::{SignatureState, signature_state};
use crate::security::audit_rotation_config::RotationConfig;
use crate::security::transparency_log::{TransparencyLogConfig, TransparencyLogger};

const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";

/// One invocation entry written by the real logger, signed when `signed`.
fn entry(signed: bool) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transparency.jsonl");
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: if signed { SECRET.into() } else { String::new() },
        rotation: RotationConfig::default(),
    }))
    .unwrap();
    logger
        .log_invocation("s", "c", "srv", "tool_a", "sha256:aa", "sha256:bb")
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(text.lines().last().unwrap()).unwrap()
}

fn secret() -> Option<&'static [u8]> {
    Some(SECRET.as_bytes())
}

#[test]
fn untouched_signed_entry_is_valid() {
    assert_eq!(
        signature_state(&entry(true), secret()),
        SignatureState::Valid
    );
}

#[test]
fn altered_field_with_stored_hash_and_sig_kept_is_invalid() {
    // The stored entry_hash and sig still agree with each other; only a
    // recomputed hash sees the edit.
    let mut signed = entry(true);
    signed["tool"] = "tool_b".into();
    assert_eq!(signature_state(&signed, secret()), SignatureState::Invalid);

    let mut unsigned = entry(false);
    assert!(unsigned.get("sig").is_none());
    unsigned["tool"] = "tool_b".into();
    assert_eq!(
        signature_state(&unsigned, secret()),
        SignatureState::Invalid
    );
    assert_eq!(signature_state(&unsigned, None), SignatureState::Invalid);
}

#[test]
fn signed_entry_without_the_secret_is_unverifiable_and_unsigned_stays_unsigned() {
    assert_eq!(
        signature_state(&entry(true), None),
        SignatureState::SignedUnverifiable
    );
    assert_eq!(
        signature_state(&entry(false), None),
        SignatureState::Unsigned
    );
    assert_eq!(
        signature_state(&entry(false), secret()),
        SignatureState::Unsigned
    );
}

#[test]
fn flipped_sig_byte_is_invalid() {
    let mut e = entry(true);
    let sig = e["sig"].as_str().unwrap().to_string();
    let last = sig.chars().last().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    e["sig"] = format!("{}{flipped}", &sig[..sig.len() - 1]).into();
    assert_eq!(signature_state(&e, secret()), SignatureState::Invalid);
}

#[test]
fn state_serialises_in_snake_case() {
    assert_eq!(
        serde_json::to_string(&SignatureState::SignedUnverifiable).unwrap(),
        "\"signed_unverifiable\""
    );
}
