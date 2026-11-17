// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability-part encoding. Expected bytes are built here from the stated
//! frame, never by the encoder under test.

use super::{
    AppliedInputs, CapabilityPart, PartDigest, RawInputs, capability_preimage, config_revision,
};
use crate::gateway::record_principal::RecordPrincipalKey;

const KEY_TEXT: &str = "test-record-key-0123456789abcdef";

/// The base's id (62d0b33d31) for E2's inputs: gateway bytes `server:\n  port: 1\n`, nothing
/// else, capabilities disabled, under the tests' key. Computed by running the base's own
/// encoder there (a throwaway test at that commit), never by the code under test.
const E2_BASE_ID: &str =
    "hmac-sha256:a493c115709164fd2eb0901f2a1e3c3a0975ad978d3b9de23f6ba701747846d0";

const PATH: &str = "caps/a.yaml";
const DIGEST: PartDigest = [0x11; 32];
/// `u64_be(u64::MAX)`.
const NOT_LOADED_MARK: [u8; 8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
/// `u64_be(u64::MAX - 1)`.
const PARTIAL_MARK: [u8; 8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];
const COUNT_ONE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

fn key() -> [u8; 32] {
    RecordPrincipalKey::from_text(KEY_TEXT)
        .expect("test key")
        .config_revision_key()
}

/// `part(b) = 0x01 || u64_be(len) || b`, as the frame states it.
fn framed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + bytes.len());
    out.push(0x01);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn one_file() -> Vec<(String, PartDigest)> {
    vec![(PATH.to_owned(), DIGEST)]
}

fn with_one_file(marker: Option<[u8; 8]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(marker) = marker {
        out.extend_from_slice(&marker);
    }
    out.extend_from_slice(&COUNT_ONE);
    out.extend(framed(PATH.as_bytes()));
    out.extend(framed(&DIGEST));
    out
}

/// `NotLoaded` is the max count and nothing else. Partial is the max-minus-one
/// marker, then the count and the one sorted entry. Loaded is today's count
/// and that entry. A sequence number is not an input: each literal is the
/// whole preimage.
#[test]
fn e1_the_three_encodings_are_the_literal_preimages() {
    let file = one_file();
    assert_eq!(
        capability_preimage(&CapabilityPart::NotLoaded),
        NOT_LOADED_MARK.as_slice(),
        "NotLoaded is u64::MAX and nothing else"
    );
    assert_eq!(
        capability_preimage(&CapabilityPart::Partial(file.clone())),
        with_one_file(Some(PARTIAL_MARK)),
        "Partial is the marker, then the count and the entry"
    );
    assert_eq!(
        capability_preimage(&CapabilityPart::Loaded(file)),
        with_one_file(None),
        "Loaded is today's count and entries"
    );
}

/// Capabilities disabled: the part is the empty loaded list, so the startup
/// id is the base id of these inputs.
#[test]
fn e2_capabilities_disabled_keeps_the_base_id() {
    let mut config = crate::config::Config::default();
    config.capabilities.enabled = false;
    let part = config.capability_part();
    assert!(
        matches!(&part, CapabilityPart::Loaded(entries) if entries.is_empty()),
        "disabled starts as the empty loaded list"
    );
    let inputs = RawInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        capabilities: part,
        ..RawInputs::default()
    };
    let id = config_revision(&key(), &AppliedInputs::digest(&key(), inputs));
    assert_eq!(id, E2_BASE_ID, "disabled id {id} is not the base id");
}
