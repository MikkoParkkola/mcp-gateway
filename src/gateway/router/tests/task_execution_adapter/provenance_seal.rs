// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 C1d: a task the worker runs stores a sealed result.
//!
//! The worker's dispatch mints its receipt with no request scope around it,
//! so nothing seals it at creation. These rows run a task through the real
//! `/mcp` route with both provenance signers installed and read the delivered
//! `tasks/get` body back: its `result.result` must carry a public signature
//! that verifies Bound against those delivered bytes. The HTTP body from
//! `poll_until_terminal` is the oracle (MIK-8398 C1i): the claim is about the
//! bytes delivery serves, after every wire and serialization clamp, so any
//! post-seal mutation fails, not only this clamp. The in-memory wire check
//! adds nothing once delivery seals nothing (proven in
//! `provenance_delivery_tests`), so these rows keep only the delivered check.
use super::super::*;
use super::input_round::{
    STATE_1, answer, ask, create, done, state_only, update, wait_input_required,
};
use super::support::*;

use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::trust::provenance_public::{
    ProvenancePublicSigner, TrustSet, VerifyStatus, verify_public,
};

/// The suite's state with both provenance signers installed on the Meta-MCP
/// before it is shared (as in `relay_settlement`).
async fn dual_signed_state(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.enable_provenance_stamping(
                BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
                    .with_audience("test-gateway")
                    .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
            );
            meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(
                [7u8; 32],
                "prov-test-1",
            ));
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store)
}

fn trust_set() -> TrustSet {
    let signer = ProvenancePublicSigner::from_seed_for_test([7u8; 32], "prov-test-1");
    let jwk_text = serde_json::to_string(&signer.public_jwk()).expect("jwk serializes");
    TrustSet::from_json(&jwk_text).expect("trust loads")
}

/// The delivered completed result: `poll_until_terminal` returns the HTTP
/// `tasks/get` body the client parsed (a JSON-RPC response, as `status_of`
/// reads `/result/status`), so `/result/result` is the task result as
/// delivered, after every wire and serialization clamp.
fn delivered_result(settled: &Value) -> Value {
    settled
        .pointer("/result/result")
        .expect("a completed tasks/get carries its result")
        .clone()
}

fn assert_sealed_bound(delivered: &Value) {
    let prov = delivered
        .pointer("/_meta/provenance")
        .expect("the delivered result carries a receipt")
        .clone();
    assert!(
        prov.get("public_signature").is_some(),
        "the delivered receipt carries a public signature: {delivered}"
    );
    let verified = verify_public(&prov, &trust_set(), Some(delivered))
        .expect("the delivered receipt verifies");
    std::assert_eq!(verified.status, VerifyStatus::Bound);
}

/// R14: a tools/call submitted as a task and run by the worker stores a
/// sealed result. Mutant: the worker's dispatch mints with no scope, so the
/// stored receipt carries no public signature.
#[tokio::test]
async fn a_task_run_by_the_worker_stores_a_sealed_result() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = dual_signed_state(&mock).await;
    let created = post(
        &state,
        "key-a",
        task_invoke(1, "prov-worker-seal", json!({})),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(mock.calls(), 1, "one dispatch ran the task");
    assert_sealed_bound(&delivered_result(&settled));
}

/// R15: the same through an input round: the resume's dispatch and settle
/// share one scope, so the resumed result is sealed at creation. Mutant: the
/// resume mints with no scope, so the stored receipt carries no public
/// signature.
#[tokio::test]
async fn an_input_round_resume_stores_a_sealed_result() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = dual_signed_state(&mock).await;
    let created = post(&state, "key-a", create(1, "prov-resume-seal")).await;
    let id = task_id(&created);
    wait_input_required(&state, &id).await;
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "a complete answer set is accepted: {acked}"
    );
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(mock.calls(), 2, "one first dispatch and one resume");
    assert_sealed_bound(&delivered_result(&settled));
}

/// R16: a result stored after a state-only round is sealed. The worker
/// re-dispatches in place through `settle_or_ask`, and that re-dispatch mints
/// inside the worker scope, so the single worker seal point seals it. Mutant:
/// only the first dispatch and the resume are sealed, so the stored receipt
/// carries no public signature.
#[tokio::test]
async fn a_result_stored_after_a_state_only_round_is_sealed() {
    let mock = MockBackend::answering(Answer::Sequence(vec![state_only("s-only"), done()]));
    let (state, _store) = dual_signed_state(&mock).await;
    let created = post(&state, "key-a", create(1, "prov-state-only-seal")).await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(
        mock.calls(),
        2,
        "one first dispatch and one state-only resume"
    );
    assert_sealed_bound(&delivered_result(&settled));
}

/// R19 (MIK-8398 C1g, C1i): a worker task whose backend answer carries
/// `cacheScope: "public"` stores a result sealed over the delivered bytes.
/// The oracle is the HTTP `tasks/get` body, not the in-memory record, so a
/// seal over `public` fails Bound against the delivered `private`.
#[tokio::test]
async fn a_worker_task_with_a_public_scope_is_sealed_as_delivered() {
    let mock = MockBackend::answering(Answer::Result(json!({
        "content": [{ "type": "text", "text": "mock-backend-answered" }],
        "structuredContent": { "marker": "mock-backend-answered" },
        "cacheScope": "public",
    })));
    let (state, _store) = dual_signed_state(&mock).await;
    let created = post(
        &state,
        "key-a",
        task_invoke(1, "prov-worker-scope", json!({})),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(mock.calls(), 1, "one dispatch ran the task");
    let delivered = delivered_result(&settled);
    // A `tools/call` answer may not carry `cacheScope`: ingress removed it.
    std::assert_eq!(
        delivered.get("cacheScope"),
        None,
        "ingress removed the backend's scope: {delivered}"
    );
    assert_sealed_bound(&delivered);
}
