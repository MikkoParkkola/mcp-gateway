// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the config revision id. Golden values were computed by an
//! independent implementation of the stated encoding (Python hmac/hashlib),
//! and are shared with configuration history's tests.

use sha2::{Digest, Sha256};

use super::{AppliedInputs, ConsumedInput, ConsumedSource, config_revision};
use crate::gateway::record_principal::RecordPrincipalKey;

const KEY_TEXT: &str = "test-record-key-0123456789abcdef";

fn key() -> [u8; 32] {
    RecordPrincipalKey::from_text(KEY_TEXT)
        .expect("test key")
        .config_revision_key()
}

fn base() -> AppliedInputs {
    AppliedInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        ..AppliedInputs::default()
    }
}

#[test]
fn api2a_1_golden_values_match_the_shared_encoding() {
    assert_eq!(
        config_revision(&key(), &base()),
        "hmac-sha256:c73cac3642215c25411cad070cbafec3e95a16f255cda31e2c95c5e19cddf046"
    );
    let empty_grants = AppliedInputs {
        grants: Some(Vec::new()),
        ..base()
    };
    assert_eq!(
        config_revision(&key(), &empty_grants),
        "hmac-sha256:507a0fda762dbfa6f82bd4cea7deb4fc53e05c172ccb6d77552db8a0b02426c6",
        "no grants file and an empty grants file differ"
    );
    let full = AppliedInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        grants: Some(b"[]\n".to_vec()),
        env_files: vec![("/e/.env".to_owned(), Some(b"A=1\n".to_vec()))],
        capabilities: vec![("caps/a.yaml".to_owned(), b"name: a\n".to_vec())],
        consumed: vec![ConsumedInput {
            source: ConsumedSource::EnvVar,
            name: "A".to_owned(),
            value: b"1".to_vec(),
        }],
    };
    assert_eq!(
        config_revision(&key(), &full),
        "hmac-sha256:464fa7b60ee97d09a2893b86cc8ce5ff91c4d5a5cfb3e3c438fe7ba933ff9625"
    );
}

#[test]
fn api2a_1_any_input_byte_changes_the_id_and_order_of_unsorted_lists_does_not() {
    let a = config_revision(&key(), &base());
    let comment_only = AppliedInputs {
        gateway_yaml: b"server:\n  port: 1\n# note\n".to_vec(),
        ..base()
    };
    assert_ne!(a, config_revision(&key(), &comment_only));
    let caps = |order: [&str; 2]| AppliedInputs {
        capabilities: order
            .iter()
            .map(|p| ((*p).to_owned(), p.as_bytes().to_vec()))
            .collect(),
        ..base()
    };
    assert_eq!(
        config_revision(&key(), &caps(["a.yaml", "b.yaml"])),
        config_revision(&key(), &caps(["b.yaml", "a.yaml"])),
        "capabilities are sorted by path"
    );
}

#[test]
fn api2a_1_the_id_is_keyed_never_a_plain_hash() {
    let id = config_revision(&key(), &base());
    let other = RecordPrincipalKey::from_text("another-record-key-0123456789abcd")
        .expect("key")
        .config_revision_key();
    assert_ne!(
        id,
        config_revision(&other, &base()),
        "rotation gives a new id"
    );
    let plain = hex::encode(Sha256::digest(&base().gateway_yaml));
    assert!(!id.contains(&plain), "not a plain hash of the file");
    assert!(id.starts_with("hmac-sha256:"));
}

#[test]
fn api2a_1_a_missing_env_file_differs_from_an_empty_one() {
    let env = |bytes: Option<&[u8]>| AppliedInputs {
        env_files: vec![("/e/.env".to_owned(), bytes.map(<[u8]>::to_vec))],
        ..base()
    };
    assert_eq!(
        config_revision(&key(), &env(None)),
        "hmac-sha256:36fc97bc4ef2165a83a1503a6a93c2ae389c98a87ff66d82449baaf6e63a973f"
    );
    assert_ne!(
        config_revision(&key(), &env(None)),
        config_revision(&key(), &env(Some(b""))),
    );
}
