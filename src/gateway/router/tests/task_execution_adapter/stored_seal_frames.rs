// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored result redacted as it is served carries no provenance seal. The
//! seal was made over the unredacted result, and its readable payload holds
//! that result's digest: served next to the redacted body, it would let a
//! client test guesses of the hidden value offline, and it no longer covers
//! the bytes as delivered. The receipt stays (it holds no digest of the
//! result), as when `delivered_wire` drops a seal.
//!
//! Each row runs the real `/mcp` route with both provenance signers
//! installed, then marks the backend's answer text secret after the result
//! was stored, and reads one serve site back. A child of `notifications`, so
//! the notification row reads the same stream helpers.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{ReleasedOnDrop, expect_message, open_listen};

use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::trust::provenance_public::{
    ProvenancePublicSigner, TrustSet, VerifyStatus, verify_public,
};

/// The mock's answer text, marked secret after the result was stored.
const OUTPUT: &str = "mock-backend-answered";
const SEED: [u8; 32] = [9u8; 32];
const KID: &str = "prov-scrub-1";

/// The suite's state with both provenance signers installed, as in
/// `provenance_seal`.
async fn sealing_state(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, store) = super::super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.enable_provenance_stamping(
                BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
                    .with_audience("test-gateway")
                    .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
            );
            meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(SEED, KID));
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store)
}

fn mark(state: &Arc<AppState>, value: &str) {
    state.backends.mark_for_test(BACKEND, value);
}

/// A seal that verifies Bound against `result`, the bytes as served.
fn assert_sealed_bound(result: &Value, what: &str) {
    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, KID);
    let jwk = serde_json::to_string(&signer.public_jwk()).expect("jwk serializes");
    let trust = TrustSet::from_json(&jwk).expect("trust loads");
    let prov = result
        .pointer("/_meta/provenance")
        .unwrap_or_else(|| panic!("{what}: the result carries a receipt: {result}"));
    assert!(
        prov.get("public_signature").is_some(),
        "{what}: the result carries a seal: {result}"
    );
    let verified = verify_public(prov, &trust, Some(result))
        .unwrap_or_else(|error| panic!("{what}: the seal verifies: {error:?}"));
    std::assert_eq!(verified.status, VerifyStatus::Bound, "{what}");
}

/// Every seal in `served`, each with the value it seals, JSON text included.
fn seals_in(served: &Value) -> Vec<(Value, Value)> {
    let mut found = Vec::new();
    let mut pending = vec![served];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(object) => {
                if let Some(provenance) = next.pointer("/_meta/provenance")
                    && provenance.get("public_signature").is_some()
                {
                    found.push((provenance.clone(), next.clone()));
                }
                pending.extend(object.values());
            }
            Value::Array(items) => pending.extend(items),
            // A chain answer carries its steps' sealed results as JSON text.
            Value::String(text) if text.contains("public_signature") => {
                let inner = serde_json::from_str(text).expect("seal text parses");
                found.extend(seals_in(&inner));
            }
            _ => {}
        }
    }
    found
}

/// Redacted, its receipt kept, and no seal made over other bytes: a seal the
/// serve site minted afresh over the redacted bytes verifies Bound against
/// them; one kept from the stored result does not.
fn assert_redacted_unsealed(served: &Value, what: &str) {
    let text = served.to_string();
    assert!(
        !text.contains(OUTPUT),
        "{what}: the marked value was served: {served}"
    );
    assert!(
        text.contains("[redacted]"),
        "{what}: the value was not redacted: {served}"
    );
    assert!(
        text.contains("\"provenance\""),
        "{what}: the receipt stays: {served}"
    );
    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, KID);
    let jwk = serde_json::to_string(&signer.public_jwk()).expect("jwk serializes");
    let trust = TrustSet::from_json(&jwk).expect("trust loads");
    for (provenance, sealed) in seals_in(served) {
        let bound = verify_public(&provenance, &trust, Some(&sealed))
            .is_ok_and(|verified| verified.status == VerifyStatus::Bound);
        assert!(
            bound,
            "{what}: a result redacted at serve kept the seal made over its \
             unredacted bytes: {served}"
        );
    }
}

/// A completed task's stored result, sealed while plain.
async fn settled_sealed(state: &Arc<AppState>, key: &str) -> String {
    let id = task_id(&post(state, "key-a", task_invoke(1, key, json!({}))).await);
    let settled = poll_until_terminal(state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    let result = settled
        .pointer("/result/result")
        .expect("a completed tasks/get carries its result");
    assert_sealed_bound(result, "premise: the plain stored result");
    id
}

/// `tasks/get` (the egress scan of a stored task).
#[tokio::test]
async fn a_tasks_get_of_a_result_redacted_at_serve_carries_no_seal() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = sealing_state(&mock).await;
    let id = settled_sealed(&state, "seal-get").await;
    mark(&state, OUTPUT);
    assert_redacted_unsealed(&get_task(&state, "key-a", &id).await, "tasks/get");
}

/// A repeated keyed task serves its stored output.
#[tokio::test]
async fn a_repeated_keyed_task_redacted_at_serve_carries_no_seal() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = sealing_state(&mock).await;
    let _ = settled_sealed(&state, "seal-repeat").await;
    let plain = post(&state, "key-a", task_invoke(2, "seal-repeat", json!({}))).await;
    assert!(
        plain.to_string().contains("public_signature"),
        "premise: the repeat serves the sealed stored result: {plain}"
    );
    mark(&state, OUTPUT);
    let repeat = post(&state, "key-a", task_invoke(3, "seal-repeat", json!({}))).await;
    assert_redacted_unsealed(&repeat, "the repeated keyed task");
    std::assert_eq!(mock.calls(), 1, "premise: every repeat came from the store");
}

/// A task notification sends the stored output after the egress scan.
#[tokio::test]
async fn a_task_notification_redacted_at_serve_carries_no_seal() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = sealing_state(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "seal-notify", json!({}))).await;
    let id = task_id(&created);
    gate.0.wait_for_dispatch().await;
    let mut stream = open_listen(&state, "key-a", 7501, json!({ "taskIds": [&id] })).await;
    mark(&state, OUTPUT);
    gate.0.release_all();
    for _ in 0..4 {
        let frame = expect_message(&mut stream, "the task's completion frame").await;
        if frame.pointer("/params/status") == Some(&json!("completed")) {
            assert_redacted_unsealed(&frame, "the completion frame");
            return;
        }
    }
    panic!("no completion frame for task {id}");
}

/// Control: a scrub that removes nothing keeps the seal, and it still
/// verifies against the bytes served.
#[tokio::test]
async fn a_stored_result_with_nothing_to_redact_keeps_its_seal() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = sealing_state(&mock).await;
    let id = settled_sealed(&state, "seal-control").await;
    mark(&state, "a-value-the-result-does-not-hold");
    let served = get_task(&state, "key-a", &id).await;
    let result = served
        .pointer("/result/result")
        .expect("a completed tasks/get carries its result");
    assert_sealed_bound(result, "a result with nothing redacted");
}

/// A keyed synchronous call served again from the idempotency store.
#[tokio::test]
async fn a_keyed_sync_replay_redacted_at_serve_carries_no_seal() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = sealing_state(&mock).await;
    let call = |id| keyed(sync_invoke(id, json!({})), "seal-sync");
    let first = post(&state, "key-a", call(1)).await;
    assert!(
        first.to_string().contains("public_signature"),
        "premise: the first answer is sealed: {first}"
    );
    let plain = post(&state, "key-a", call(2)).await;
    assert!(
        plain.to_string().contains("public_signature"),
        "premise: the replay serves the sealed stored answer: {plain}"
    );
    mark(&state, OUTPUT);
    let replay = post(&state, "key-a", call(3)).await;
    assert_redacted_unsealed(&replay, "the keyed sync replay");
    std::assert_eq!(mock.calls(), 1, "premise: every replay came from the store");
}
