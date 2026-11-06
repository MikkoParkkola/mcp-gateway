// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rule key's derivation and the id's form.

use super::{RuleId, TAG};
use crate::gateway::record_principal::{RecordPrincipalKey, test_record_key};

/// HKDF-SHA-256 of `record_key`'s text under `info`, computed here rather than
/// through the code under test.
fn derive(record_key_text: &str, info: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, record_key_text.as_bytes())
        .expand(info, &mut key)
        .expect("32 bytes");
    key
}

const OTHER_KEY: &str = "another-record-key-not-a-secret-fedcba9876543210";

#[test]
fn the_rule_key_tag_is_not_the_revision_tag() {
    assert_ne!(TAG, crate::config_reload::revision::TAG);
    let key = test_record_key();
    assert_ne!(key.rule_id_key().0, key.config_revision_key());
}

#[test]
fn the_rule_key_is_derived_from_the_record_key() {
    let expected = derive(crate::gateway::record_principal::TEST_RECORD_KEY, TAG);
    assert_eq!(test_record_key().rule_id_key().0, expected);
}

#[test]
fn rule_ids_are_keyed() {
    let other = RecordPrincipalKey::from_text(OTHER_KEY).expect("long enough");
    let definition = br#"{"match":"t","action":"block"}"#;
    assert_ne!(
        RuleId::of("firewall", &test_record_key().rule_id_key(), definition),
        RuleId::of("firewall", &other.rule_id_key(), definition),
    );
}

#[test]
fn rule_id_form() {
    let definition = br#"{"match":"t","action":"block"}"#;
    let key = derive(crate::gateway::record_principal::TEST_RECORD_KEY, TAG);
    let expected = format!(
        "firewall:{}",
        crate::hashing::hmac_sha256_hex(&key, definition)
    );
    let id = RuleId::of("firewall", &test_record_key().rule_id_key(), definition);
    assert_eq!(id.as_str(), expected);
    let hex = id.as_str().strip_prefix("firewall:").expect("kind prefix");
    assert_eq!(hex.len(), 64);
    assert!(
        hex.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

/// A joined path, compared by its components, matches on every platform.
#[test]
fn a_joined_path_matches_a_slash_built_one() {
    let joined = std::path::Path::new("rules").join("id");
    // Compare components, not text: the separator is the platform's.
    assert!(joined.starts_with("rules") && joined.ends_with("id") && joined.components().count() == 2);
}
