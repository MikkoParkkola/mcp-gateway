// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the config revision id. Golden values were computed by an
//! independent implementation of the stated encoding (Python hmac/hashlib),
//! and are shared with configuration history's tests.

use sha2::{Digest, Sha256};

use super::{AppliedInputs, ConsumedInput, ConsumedSource, RawInputs, config_revision};
use crate::gateway::record_principal::RecordPrincipalKey;

const KEY_TEXT: &str = "test-record-key-0123456789abcdef";

fn key() -> [u8; 32] {
    RecordPrincipalKey::from_text(KEY_TEXT)
        .expect("test key")
        .config_revision_key()
}

fn base() -> RawInputs {
    RawInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        ..RawInputs::default()
    }
}

fn id(raw: RawInputs) -> String {
    config_revision(&key(), &AppliedInputs::digest(&key(), raw))
}

fn consumed(name: &str, value: &[u8]) -> ConsumedInput<Vec<u8>> {
    ConsumedInput {
        source: ConsumedSource::EnvVar,
        name: name.to_owned(),
        value: value.to_vec(),
    }
}

#[test]
fn api2a_1_golden_values_match_the_shared_encoding() {
    assert_eq!(
        id(base()),
        "hmac-sha256:a493c115709164fd2eb0901f2a1e3c3a0975ad978d3b9de23f6ba701747846d0"
    );
    let empty_grants = RawInputs {
        grants: Some(Vec::new()),
        ..base()
    };
    assert_eq!(
        id(empty_grants),
        "hmac-sha256:9f509f437246225ee68b72db7702500f551a4eb4968f24fefba0a67bf2e9d609",
        "no grants file and an empty grants file differ"
    );
    let full = RawInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        grants: Some(b"[]\n".to_vec()),
        env_files: vec![("/e/.env".to_owned(), Some(b"A=1\n".to_vec()))],
        capabilities: vec![("caps/a.yaml".to_owned(), b"name: a\n".to_vec())],
        consumed: vec![consumed("A", b"1")],
    };
    assert_eq!(
        id(full),
        "hmac-sha256:639bbd92fb21b8f0ccb4cea01cea425a7fa48d540ece53b421460cb507fecbf4"
    );
    let missing_env = RawInputs {
        env_files: vec![("/e/.env".to_owned(), None)],
        ..base()
    };
    assert_eq!(
        id(missing_env),
        "hmac-sha256:a2d9868d9f5ac961210700c4bc361652db54962295734150c94e98b38755a4de"
    );
}

#[test]
fn api2a_1_any_input_byte_changes_the_id_and_order_of_unsorted_lists_does_not() {
    let comment_only = RawInputs {
        gateway_yaml: b"server:\n  port: 1\n# note\n".to_vec(),
        ..base()
    };
    assert_ne!(id(base()), id(comment_only));
    let caps = |order: [&str; 2]| RawInputs {
        capabilities: order
            .iter()
            .map(|p| ((*p).to_owned(), p.as_bytes().to_vec()))
            .collect(),
        ..base()
    };
    assert_eq!(
        id(caps(["a.yaml", "b.yaml"])),
        id(caps(["b.yaml", "a.yaml"])),
        "capabilities are sorted by path"
    );
}

#[test]
fn api2a_1_the_id_is_keyed_never_a_plain_hash() {
    let other = RecordPrincipalKey::from_text("another-record-key-0123456789abcd")
        .expect("key")
        .config_revision_key();
    let under_other = config_revision(&other, &AppliedInputs::digest(&other, base()));
    assert_ne!(id(base()), under_other, "rotation gives a new id");
    let plain = hex::encode(Sha256::digest(&base().gateway_yaml));
    assert!(!id(base()).contains(&plain), "not a plain hash of the file");
    assert!(id(base()).starts_with("hmac-sha256:"));
}

#[test]
fn api2a_1_a_missing_env_file_differs_from_an_empty_one() {
    let env = |bytes: Option<&[u8]>| RawInputs {
        env_files: vec![("/e/.env".to_owned(), bytes.map(<[u8]>::to_vec))],
        ..base()
    };
    assert_ne!(id(env(None)), id(env(Some(b""))));
}

#[test]
fn api2a_1_a_value_resolved_twice_counts_once() {
    let twice = |n: usize| RawInputs {
        consumed: vec![consumed("A", b"1"); n],
        ..base()
    };
    assert_eq!(id(twice(1)), id(twice(2)));
}

#[test]
fn the_held_digests_are_keyed_not_plain_sha256() {
    let digested = AppliedInputs::digest(&key(), base());
    let plain: [u8; 32] = Sha256::digest(&base().gateway_yaml).into();
    assert_ne!(digested.gateway_yaml, plain);
}

#[test]
fn debug_never_prints_input_bytes_for_any_input_type() {
    let raw = RawInputs {
        gateway_yaml: b"token: hunter2-yaml".to_vec(),
        grants: Some(b"hunter2-grants".to_vec()),
        env_files: vec![("/e/.env".to_owned(), Some(b"K=hunter2-env".to_vec()))],
        capabilities: vec![("c/a.yaml".to_owned(), b"hunter2-cap".to_vec())],
        consumed: vec![consumed("S", b"hunter2-secret")],
    };
    let applied = AppliedInputs::digest(&key(), raw.clone());
    let printed = format!(
        "{raw:?} {:?} {applied:?} {:?}",
        raw.consumed[0], applied.consumed[0]
    );
    assert!(!printed.contains("hunter2"), "{printed}");
    for byte_hex in [hex::encode(applied.gateway_yaml), hex::encode(b"hunter2")] {
        assert!(!printed.contains(&byte_hex), "{printed}");
    }
}
