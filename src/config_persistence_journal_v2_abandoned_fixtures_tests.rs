// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the abandoned-frame rows. The golden frames below are literal
//! wire bytes written from the contract by a generator that shares nothing
//! with the codec under test (sorted-key JSON, length and SHA-256 computed
//! outside Rust).

use super::super::fixtures::{JOURNAL_V2_ATTRIBUTION, JOURNAL_V2_HANDED_OVER};
use super::super::{FrozenRecord, JournalV2};
use crate::security::transparency_log::settle::Role;

pub(super) const ATTRIBUTION_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":{"decision":null,"handed_over":false,"intent_"####,
    r####"counter":null,"root":false},"record":{"attribution":{"actor":{"account":"key-admin","####,
    r####""authority":"https://issuer.example","credential_kind":"oidc_bearer","principal":"01"####,
    r####"23ab45cd67","subject":"operator-7"}},"caller_digest":"485a9281eea8d059ea8528045e677d"####,
    r####"06ae19ea25cea93d706395419c28878653","delivered":false,"parked":null,"payload_json":["####,
    r####"123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,107,101,121,95,99,114,101"####,
    r####",97,116,101,34,44,34,115,117,98,106,101,99,116,34,58,34,100,101,112,108,111,121,45,9"####,
    r####"8,111,116,34,125],"role":"config_key_create_intent"},"slot":"intent","token":"writer"####,
    r####"-1","v":1}"####,
);

pub(super) const ATTRIBUTION_LEN: usize = 682;

pub(super) const ATTRIBUTION_SHA: &str =
    "242d9e03081e2948a17557bd6bc17bb88b45ad1b197429c71ac4259b2af756e4";

pub(super) const ROOT_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":{"decision":null,"handed_over":false,"intent_"####,
    r####"counter":null,"root":true},"record":{"attribution":null,"caller_digest":"03593823b39"####,
    r####"11d4d24811355f1c9da7db9837441d59db3db0579072ea8435675","delivered":false,"parked":nu"####,
    r####"ll,"payload_json":[123,34,97,116,95,115,116,97,114,116,34,58,102,97,108,115,101,44,3"####,
    r####"4,107,105,110,100,34,58,34,115,101,116,116,108,101,46,114,101,99,111,118,101,114,121"####,
    r####",34,44,34,114,111,111,116,34,58,116,114,117,101,125],"role":"config_recovery_intent""####,
    r####"},"slot":"intent","token":"attempt-1","v":1}"####,
);

pub(super) const ROOT_LEN: usize = 548;

pub(super) const ROOT_SHA: &str =
    "0b33844aa5addca681aeffec23b40409e8ef3cb60d88bf2289052cd33a762ea7";

pub(super) const PARKED_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":{"decision":null,"handed_over":false,"intent_"####,
    r####"counter":null,"root":false},"record":{"attribution":null,"caller_digest":"40b5cafe04"####,
    r####"5b9c9e31a1c3fdcfbc89f934906ff06a6276b55c2a0e517be21655","delivered":false,"parked":""####,
    r####"invalid_payload","payload_json":[123,105,110,118,97,108,105,100],"role":"config_save"####,
    r####"_intent"},"slot":"intent","token":"writer-1","v":1}"####,
);

pub(super) const PARKED_LEN: usize = 387;

pub(super) const PARKED_SHA: &str =
    "825b9f1ccc6eb24906876523daae6c72e253f135d2d0c1cf98953cb2a0cfbd10";

pub(super) const HANDED_OVER_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":{"decision":null,"handed_over":true,"intent_c"####,
    r####"ounter":null,"root":false},"record":{"attribution":null,"caller_digest":"8db52a270d6"####,
    r####"06fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":false,"parked":nu"####,
    r####"ll,"payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,115,97"####,
    r####",118,101,34,125],"role":"config_save_intent"},"slot":"intent","token":"writer-1","v""####,
    r####":1}"####,
);

pub(super) const HANDED_OVER_LEN: usize = 423;

pub(super) const HANDED_OVER_SHA: &str =
    "fc20561f10d602d4d87ee188b0a3e33c75b23d87e780b6007c17a60e25723517";

pub(super) const RECORD_0_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":null,"record":{"attribution":null,"caller_dig"####,
    r####"est":"be6893e8947c600001c373b79c4e84348199a3b79c6f10bc5b9e9d8ce4e17b3a","delivered":"####,
    r####"true,"parked":null,"payload_json":[123,34,105,110,116,101,110,116,95,99,111,117,110,"####,
    r####"116,101,114,34,58,51,44,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,111,1"####,
    r####"17,116,99,111,109,101,34,44,34,114,101,115,117,108,116,34,58,34,119,114,105,116,116,"####,
    r####"101,110,34,125],"role":"config_write_outcome"},"slot":{"record":0},"token":"writer-1"####,
    r####"","v":1}"####,
);

pub(super) const RECORD_0_LEN: usize = 512;

pub(super) const RECORD_0_SHA: &str =
    "8643fe134f98c22407035cb274d0c683c26e2d68cac80d120d38d083387d1940";

pub(super) const RECORD_1_JSON: &str = concat!(
    r####"{"log_id":"opaque-log:fixture","owner":null,"record":{"attribution":null,"caller_dig"####,
    r####"est":"cf9828df4621dc35cd681bd09063edf252fdf0547c52be19364e2c846f7467ea","delivered":"####,
    r####"false,"parked":null,"payload_json":[123,34,105,110,116,101,110,116,95,99,111,117,110"####,
    r####",116,101,114,34,58,51,44,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46,100,"####,
    r####"101,102,101,114,114,101,100,34,125],"role":"config_write_deferred"},"slot":{"record""####,
    r####":1},"token":"writer-1","v":1}"####,
);

pub(super) const RECORD_1_LEN: usize = 449;

pub(super) const RECORD_1_SHA: &str =
    "1ebdf016c01b7c5990a3cb58e7fcef070d37d00bb656966d2d8109a2ae97958d";

/// One frame as the file stores it: declared length, tab, checksum, tab, JSON, newline.
pub(super) fn frame_bytes(json: &str, len: usize, sha: &str) -> Vec<u8> {
    format!("{len}\t{sha}\t{json}\n").into_bytes()
}

/// A frame for arbitrary JSON, with its real length and checksum: the control cases
/// that damage one field of a golden and must still carry a valid header.
pub(super) fn reframe(json: &str) -> Vec<u8> {
    let sha = crate::hashing::sha256_hex(json.as_bytes());
    frame_bytes(json, json.len(), &sha)
}

pub(super) fn attribution() -> Vec<u8> {
    frame_bytes(ATTRIBUTION_JSON, ATTRIBUTION_LEN, ATTRIBUTION_SHA)
}

pub(super) fn root() -> Vec<u8> {
    frame_bytes(ROOT_JSON, ROOT_LEN, ROOT_SHA)
}

pub(super) fn parked() -> Vec<u8> {
    frame_bytes(PARKED_JSON, PARKED_LEN, PARKED_SHA)
}

pub(super) fn handed_over() -> Vec<u8> {
    frame_bytes(HANDED_OVER_JSON, HANDED_OVER_LEN, HANDED_OVER_SHA)
}

pub(super) fn record_0() -> Vec<u8> {
    frame_bytes(RECORD_0_JSON, RECORD_0_LEN, RECORD_0_SHA)
}

pub(super) fn record_1() -> Vec<u8> {
    frame_bytes(RECORD_1_JSON, RECORD_1_LEN, RECORD_1_SHA)
}

/// The journal side of the handed-over token: the literal journal golden, whose writer is
/// handed over, plus the two further records the file's record frames carry.
pub(super) fn donor() -> JournalV2 {
    let mut state = JournalV2::decode(JOURNAL_V2_HANDED_OVER).expect("handed-over journal golden");
    let writer = state.writer.as_mut().expect("the golden has a writer");
    writer.records.push(further(
        Role::Outcome,
        r#"{"intent_counter":3,"kind":"settle.outcome","result":"written"}"#,
        true,
    ));
    writer.records.push(further(
        Role::Deferred,
        r#"{"intent_counter":3,"kind":"settle.deferred"}"#,
        false,
    ));
    state
}

fn further(role: Role, text: &str, delivered: bool) -> FrozenRecord {
    FrozenRecord {
        role,
        payload_json: text.as_bytes().to_vec(),
        attribution: None,
        caller_digest: crate::hashing::sha256_hex(text.as_bytes()),
        delivered,
        parked: None,
    }
}

/// The journal golden that carries an attributed actor.
pub(super) fn attributed_journal() -> JournalV2 {
    JournalV2::decode(JOURNAL_V2_ATTRIBUTION).expect("attribution journal golden")
}

/// Concatenate frames into a file.
pub(super) fn file(frames: &[&[u8]]) -> Vec<u8> {
    frames.concat()
}
