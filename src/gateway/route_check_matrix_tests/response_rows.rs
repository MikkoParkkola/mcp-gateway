// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response matrix's HTTP seal rows (MIK-8689 phase A1): each drives a
//! real `/mcp` or `/mcp/alpha` call with both provenance signers installed
//! and reads the order of two stages off the delivered answer. The oracle is
//! the delivered JSON-RPC body, so a stage that runs after the seal and
//! changes a sealed member turns the receipt from Bound to a mismatch.

use serde_json::Value;

use crate::gateway::router::route_matrix_driver_tests::response::{
    BackendAnswer, HttpRoute, planted_credential, read_then_relay, signed_call,
    signed_recorded_call, signed_redacted_call, signed_replay, trust_set,
};
use crate::protocol::meta::Era;
use crate::trust::provenance_public::{VerifyRefusal, VerifyStatus, verify_public};

/// The delivered result of `body`.
fn delivered(body: &Value) -> &Value {
    body.get("result")
        .unwrap_or_else(|| panic!("the call answered with a result: {body}"))
}

/// The receipt on a delivered result.
fn receipt(result: &Value) -> &Value {
    result
        .pointer("/_meta/provenance")
        .unwrap_or_else(|| panic!("the delivered result carries a receipt: {result}"))
}

/// The receipt on `result` is sealed and Bound to exactly `result`.
fn assert_sealed_bound(row: &str, result: &Value) {
    let prov = receipt(result);
    assert!(
        prov.get("public_signature").is_some(),
        "{row}: the delivered receipt is sealed: {result}"
    );
    let verified = verify_public(prov, &trust_set(), Some(result))
        .unwrap_or_else(|refusal| panic!("{row}: the delivered receipt verifies: {refusal:?}"));
    assert_eq!(verified.status, VerifyStatus::Bound, "{row}: {result}");
}

/// R-SHAPE `shape_precedes_seal` (`Shape` < `Seal`; `Mcp`, `Direct` ×
/// `Fresh` × `Modern`). The backend answer carries no `resultType`, so only the shaper
/// writes it; a seal taken before the shaper binds a result without it and
/// fails against the delivered bytes.
#[tokio::test]
async fn r_shape_shape_precedes_seal() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let body = signed_call(route, Era::Modern, BackendAnswer::Ok).await;
        let result = delivered(&body);
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete"),
            "R-SHAPE {route:?}: the shaper wrote the result type: {result}"
        );
        assert_sealed_bound(&format!("R-SHAPE {route:?}"), result);
    }
}

/// R-CLAMP `scope_clamp_precedes_seal` (`ScopeClamp` < `Seal`; `Mcp`,
/// `Direct` × `Fresh` × both eras). The backend claims `cacheScope: "public"`; the clamp
/// delivers `private`. The receipt is Bound to the delivered bytes and
/// refuses the pre-clamp body, so the row tells the two orders apart.
#[tokio::test]
async fn r_clamp_scope_clamp_precedes_seal() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-CLAMP {route:?} {era:?}");
            let body = signed_call(route, era, BackendAnswer::PublicScope).await;
            let result = delivered(&body);
            assert_eq!(
                result.get("cacheScope").and_then(Value::as_str),
                Some("private"),
                "{row}: the clamp delivers private: {result}"
            );
            assert_sealed_bound(&row, result);
            let mut pre_clamp = result.clone();
            pre_clamp["cacheScope"] = Value::from("public");
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&pre_clamp)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the pre-clamp body"
            );
        }
    }
}

/// R-FWSEAL `firewall_precedes_seal` (`Firewall` < `Seal`; `Mcp`, `Direct`
/// × `Fresh` × both eras). The backend answers a credential; under a Warn
/// rule the egress firewall redacts it and still delivers the answer. The
/// receipt is Bound to the redacted bytes and refuses the unredacted body, so
/// a seal taken before the redaction fails here.
#[tokio::test]
async fn r_fwseal_firewall_precedes_seal() {
    let leak = planted_credential();
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-FWSEAL {route:?} {era:?}");
            let body = signed_redacted_call(route, era, leak).await;
            let result = delivered(&body);
            let text = result
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{row}: the answer carries its text: {result}"));
            assert!(
                !text.contains(leak) && text.contains("[REDACTED:credential]"),
                "{row}: the firewall redacted the delivered text: {text}"
            );
            assert_sealed_bound(&row, result);
            let mut unredacted = result.clone();
            unredacted["content"][0]["text"] = Value::from(leak);
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&unredacted)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the unredacted body"
            );
        }
    }
}

/// The delivery record's hash of `document`, as the record computes it
/// (`sorted-json-v1`).
fn record_hash(document: &Value) -> String {
    format!("sha256:{}", crate::hashing::canonical_json_sha256(document))
}

/// R-RECSIGN `sign_precedes_delivery_record` (`Sign` < `DeliveryRecord`;
/// `Mcp`, `Direct` × `Fresh` × `Modern`). A message-signed call delivers a
/// result carrying `_signature`, and its one delivery row hashes the
/// delivered document with that signature in it: a record taken before
/// signing would hash the unsigned document and differ.
#[tokio::test]
async fn r_recsign_sign_precedes_delivery_record() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-RECSIGN {route:?}");
        let recorded = signed_recorded_call(route).await;
        let result = delivered(&recorded.body);
        assert!(
            result.get("_signature").is_some(),
            "{row}: the answer is message-signed: {result}"
        );
        assert_eq!(
            recorded.rows.len(),
            1,
            "{row}: one delivery row: {:?}",
            recorded.rows
        );
        let record = &recorded.rows[0];
        assert_eq!(record["response_hash_encoding"], "sorted-json-v1", "{row}");
        let expected = record_hash(&recorded.body);
        assert_eq!(
            record["response_hash"].as_str(),
            Some(expected.as_str()),
            "{row}: the record hashes the delivered, signed document"
        );
        let mut unsigned = recorded.body.clone();
        if let Some(result) = unsigned.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("_signature");
        }
        assert_ne!(
            record_hash(&unsigned),
            expected,
            "{row}: the hash tells a signed document from an unsigned one"
        );
    }
}

/// Backend prose past the collusion detector's 48-character floor
/// (`security/firewall/collusion.rs:73`), so a receipted copy is caught when
/// another key sends it on.
const LONG_PROSE: &str =
    "The quarterly ledger reconciles every account against the vendor statements on file.";

/// R-COMMIT `delivery_record_precedes_relay_commit` (`DeliveryRecord` <
/// `RelayCommit`; `Mcp`, `Direct` × `Fresh` × `Modern`). With a fail-closed
/// log whose delivery record fails, the read's answer is replaced by the
/// audit refusal, and a relayed send of its text is not refused: no receipt
/// was committed for an answer the client never got. The control is the same
/// read with the record written: its text is receipted and the relay refused.
#[tokio::test]
async fn r_commit_delivery_record_precedes_relay_commit() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-COMMIT {route:?}");
        let control = read_then_relay(route, LONG_PROSE, false).await;
        assert!(
            control.read.to_string().contains(LONG_PROSE),
            "{row}: control: the read delivers the prose: {}",
            control.read
        );
        assert_eq!(
            control.relayed["error"]["code"], -32002,
            "{row}: control: delivered prose is receipted and its relay refused: {}",
            control.relayed
        );
        let failed = read_then_relay(route, LONG_PROSE, true).await;
        assert!(
            failed.read.get("error").is_some() && !failed.read.to_string().contains(LONG_PROSE),
            "{row}: the failed delivery record replaced the answer: {}",
            failed.read
        );
        assert!(
            failed.relayed.get("error").is_none(),
            "{row}: no receipt for the withheld answer, so the send runs: {}",
            failed.relayed
        );
    }
}

/// R-REPLAY-Mcp, `Mcp` × `IdempotentReplay` (`NotApplicable`:
/// `ReplayReservesTheStoredDelivery`). The route stores the finalized, sealed
/// delivery, and a keyed replay re-serves those bytes: the same result, its
/// receipt Bound and minted once (`cache: "miss"`, nothing minted in the
/// replay), and the backend ran once. A replay that served a pre-seal copy
/// would arrive unsealed and fail here.
#[tokio::test]
async fn r_replay_mcp_reserves_the_stored_delivery() {
    let (first, replay, calls) = signed_replay(HttpRoute::Mcp, BackendAnswer::Ok).await;
    assert_eq!(calls, 1, "R-REPLAY-Mcp: the replay sent nothing: {replay}");
    assert_eq!(
        delivered(&replay),
        delivered(&first),
        "R-REPLAY-Mcp: the replay re-serves the stored delivery"
    );
    assert_sealed_bound("R-REPLAY-Mcp replay", delivered(&replay));
    assert_eq!(
        receipt(delivered(&replay))
            .pointer("/receipt/cache")
            .and_then(Value::as_str),
        Some("miss"),
        "R-REPLAY-Mcp: the receipt was minted once, by the first call"
    );
}

/// R-REPLAYSEAL `direct_replay_seal_gap`, `Direct` × `IdempotentReplay`:
/// `ExpectedGap(MIK-8705)`. The first call is sealed (the control); the replay
/// serves its stored receipt unsealed: the route stores the answer
/// (`settle_direct_idempotency`) before `finish_tail` seals it. When MIK-8705
/// lands this fails: flip the cell to the /mcp shape and assert what
/// R-REPLAY-Mcp asserts (the stored, sealed delivery re-served).
#[tokio::test]
async fn r_replayseal_direct_replay_seal_gap() {
    let (first, replay, calls) = signed_replay(HttpRoute::Direct, BackendAnswer::Ok).await;
    assert_eq!(calls, 1, "R-REPLAYSEAL: the replay sent nothing: {replay}");
    assert_sealed_bound("R-REPLAYSEAL first", delivered(&first));
    let sealed = delivered(&replay)
        .pointer("/_meta/provenance/public_signature")
        .is_some();
    assert!(
        !sealed,
        "R-REPLAYSEAL: MIK-8705 gap closed? the direct replay is now sealed: flip the cell"
    );
}
