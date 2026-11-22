// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call's reach on its receipt and in the export: the issuance row of the
//! exchanged token the call names, found by its counter and taken only when
//! its stored hash, its recomputed hash, its event and its jti all agree.

use serde_json::{Value, json};

use super::super::decision_fixtures::{call, decision, write_chained};
use super::super::decision_receipt_tests::receipt_of_last;
use super::super::rows::Kind;
use super::super::seek::Reads;
use super::{add_evidence, receipt_reach};
use crate::security::decision_record::read::decision_evidence;

/// What the receipt says when the token's row is not in the log.
const NOT_FOUND: &str = "not found in the activity log";
/// What a call with no token on its decision has always said.
const LEGACY: &str = "not recorded by this gateway version";

/// An issuance row for `jti`; its identity and address are planted sentinels
/// the receipt must never show.
fn issued(jti: &str) -> Value {
    json!({
        "event": "token.issued", "token_jti": jti,
        "backends": ["alpha"], "tools": ["t"],
        "ttl_secs": 600, "expires_by": 1_800_000_630_u64,
        "timestamp": "2026-10-26T09:59:00+00:00",
        "identity": {"subject": "SENTINEL-subject", "issuer": "SENTINEL-issuer",
                     "email_hash": "SENTINEL-email-hash"},
        "client_ip": "SENTINEL-client-ip",
    })
}

/// A call whose decision names token `jti` and, when given, its issuance row.
fn call_with(jti: &str, row: Option<(u64, &str)>) -> Value {
    let mut d = decision(Some("r1"));
    d["token"] = json!({"jti": jti});
    if let Some((counter, hash)) = row {
        d["token"]["issuance_row"] = json!({"counter": counter, "entry_hash": hash});
    }
    call("alpha", "t", Some(d))
}

/// The hashes `rows` get as the first rows of a log: chaining is
/// deterministic, so the receipt's own chaining gives them the same ones.
fn hashes_of(rows: &[Value]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let mut rows = rows.to_vec();
    write_chained(&dir.path().join("scratch.jsonl"), &mut rows);
    rows.iter()
        .map(|r| r["entry_hash"].as_str().unwrap().to_owned())
        .collect()
}

fn reach_of(entries: &mut [Value]) -> Value {
    receipt_of_last(entries)["reach"].clone()
}

/// R7: the resolved reach holds exactly the token's id, backends, tools and
/// expiry bound, with the row's values; the receipt shows no sentinel.
#[test]
fn a_call_receipt_resolves_its_token_reach() {
    let row = issued("jti-a");
    let hash = hashes_of(std::slice::from_ref(&row)).remove(0);
    let mut entries = [row, call_with("jti-a", Some((1, &hash)))];
    assert_eq!(
        reach_of(&mut entries),
        json!({"jti": "jti-a", "backends": ["alpha"], "tools": ["t"],
               "expires_by": 1_800_000_630_u64})
    );
}

/// R8: the counter is right and the hash is another row's.
#[test]
fn a_row_with_another_hash_is_not_found() {
    let rows = [issued("jti-a"), issued("jti-b")];
    let h = hashes_of(&rows);
    let mut entries = [
        rows[0].clone(),
        rows[1].clone(),
        call_with("jti-a", Some((1, &h[1]))),
    ];
    assert_eq!(reach_of(&mut entries), NOT_FOUND);
}

/// R9: counter and hash are a real row's, but that row is a call, not an
/// issuance row.
#[test]
fn a_row_that_is_not_an_issuance_row_is_not_found() {
    let other = call("alpha", "t", None);
    let h = hashes_of(std::slice::from_ref(&other));
    let mut entries = [other, call_with("jti-a", Some((1, &h[0])))];
    assert_eq!(reach_of(&mut entries), NOT_FOUND);
}

/// R9 with only the kind wrong: the same token's revocation row carries its
/// jti and its own real hash, so the event check alone must refuse it.
#[test]
fn the_same_tokens_revocation_row_is_not_found() {
    let mut revoked = issued("jti-a");
    revoked["event"] = "token.revoked".into();
    let h = hashes_of(std::slice::from_ref(&revoked));
    let mut entries = [revoked, call_with("jti-a", Some((1, &h[0])))];
    assert_eq!(reach_of(&mut entries), NOT_FOUND);
}

/// R10: counter and hash are another token's real issuance row.
#[test]
fn another_tokens_row_is_not_found() {
    let rows = [issued("jti-a"), issued("jti-b")];
    let h = hashes_of(&rows);
    let mut entries = [
        rows[0].clone(),
        rows[1].clone(),
        call_with("jti-a", Some((2, &h[1]))),
    ];
    assert_eq!(reach_of(&mut entries), NOT_FOUND);
}

/// The control for R8-R10: the same three rows, the call naming its own row.
#[test]
fn the_tokens_own_row_among_others_is_found() {
    let rows = [issued("jti-a"), issued("jti-b")];
    let h = hashes_of(&rows);
    let mut entries = [
        rows[0].clone(),
        rows[1].clone(),
        call_with("jti-b", Some((2, &h[1]))),
    ];
    assert_eq!(reach_of(&mut entries)["jti"], "jti-b");
}

/// A row edited after it was written, its stored hash kept, is not taken.
#[test]
fn an_edited_row_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut rows = [issued("jti-a")];
    write_chained(&path, &mut rows);
    let hash = rows[0]["entry_hash"].as_str().unwrap().to_owned();
    let mut edited = rows[0].clone();
    edited["backends"] = json!(["alpha", "beta"]);
    std::fs::write(&path, edited.to_string() + "\n").unwrap();
    let d = decision_evidence(&call_with("jti-a", Some((1, &hash))));
    let reach = receipt_reach(&path, d.as_ref(), &mut Reads::default()).unwrap();
    assert_eq!(reach, NOT_FOUND);
}

/// R11: a row older than the kept log is not found, and finding that out
/// costs one seek, not a scan.
#[test]
fn a_row_rotated_out_is_not_found_with_one_seek() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let kept: String = (40..240)
        .map(|c| {
            json!({"counter": c, "request_hash": "sha256:aa", "pad": "p".repeat(200)}).to_string()
                + "\n"
        })
        .collect();
    std::fs::write(&path, kept).unwrap();
    let d = decision_evidence(&call_with("jti-a", Some((1, "sha256:gone"))));
    let mut reads = Reads::default();
    let reach = receipt_reach(&path, d.as_ref(), &mut reads).unwrap();
    assert_eq!(reach, NOT_FOUND);
    // One segment: its first line, then at most a bisection of the file.
    assert!(reads.0 <= 41, "{} reads", reads.0);
}

/// R14: a token minted with no issuance row reads not-found, never the legacy
/// value, and nothing is read to find that out.
#[test]
fn a_token_with_no_row_is_not_found_without_reading() {
    let dir = tempfile::tempdir().unwrap();
    let d = decision_evidence(&call_with("jti-a", None));
    let mut reads = Reads::default();
    let reach = receipt_reach(&dir.path().join("absent.jsonl"), d.as_ref(), &mut reads).unwrap();
    assert_eq!(reach, NOT_FOUND);
    assert_eq!(reads.0, 0);
    assert_eq!(reach_of(&mut [call_with("jti-a", None)]), NOT_FOUND);
}

/// A call whose token was lost before its decision was built (marked
/// unavailable) reads not-found, never the legacy value.
#[test]
fn a_call_marked_token_unavailable_is_not_found() {
    let mut d = decision(Some("r1"));
    d["token_unavailable"] = true.into();
    assert_eq!(reach_of(&mut [call("alpha", "t", Some(d))]), NOT_FOUND);
}

/// R13 and R15: a call with no token keeps the shipped legacy value, and the
/// two values are these fixed texts, naming no id, hash, counter or address.
#[test]
fn a_call_without_a_token_keeps_the_legacy_value() {
    assert_eq!(super::NOT_RECORDED, LEGACY);
    assert_eq!(super::NOT_FOUND, NOT_FOUND);
    let mut entries = [call("alpha", "t", Some(decision(Some("r1"))))];
    assert_eq!(reach_of(&mut entries), LEGACY);
}

/// R12: the export names the call's token and points at the receipt; it
/// never prints the legacy value for it and reads no other row to say so.
#[test]
fn the_export_points_a_token_call_at_its_receipt() {
    let mut body = serde_json::Map::new();
    add_evidence(
        &mut body,
        Kind::Call,
        &call_with("jti-a", Some((1, "sha256:aa"))),
    );
    assert_eq!(
        body["reach"],
        json!({"jti": "jti-a", "resolved_on": "this call's receipt"})
    );
    let mut unavailable = decision(Some("r1"));
    unavailable["token_unavailable"] = true.into();
    let mut body = serde_json::Map::new();
    add_evidence(
        &mut body,
        Kind::Call,
        &call("alpha", "t", Some(unavailable)),
    );
    assert_eq!(body["reach"], NOT_FOUND);
}
