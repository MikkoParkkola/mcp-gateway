// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 C1d: a task the worker runs stores a sealed result.
//!
//! The worker's dispatch mints its receipt with no request scope around it,
//! so nothing seals it at creation. These rows run a task through the real
//! `/mcp` route with both provenance signers installed and read the stored
//! completed result back: its top-level receipt must carry a public signature
//! that verifies Bound against the stored result itself. The committed record
//! is the oracle (as in `egress_task`): the claim is about the stored bytes,
//! before delivery serves them.
use super::super::*;
use super::input_round::{
    STATE_1, answer, ask, create, done, state_only, update, wait_input_required,
};
use super::support::*;

use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::key_server::oidc::VerifiedIdentity;
use crate::trust::provenance_public::{
    ProvenancePublicSigner, TrustSet, VerifyStatus, verify_public,
};

/// The admission principal the route derives for `key-a` (as in
/// `provide_input_guards`).
fn alice() -> String {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

/// The suite's state with both provenance signers installed on the Meta-MCP
/// before it is shared (as in `relay_settlement`).
async fn dual_signed_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
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

/// The stored completed result of `id`, read back from the committed record.
fn stored_result(state: &Arc<AppState>, id: &str) -> Value {
    let committed = state
        .tasks
        .get(&alice(), id)
        .expect("the owner reads its task");
    assert_eq!(
        committed.task.status(),
        crate::protocol::tasks::TaskStatus::Completed,
        "the task completed"
    );
    committed
        .task
        .result()
        .expect("a completed task stores a result")
        .clone()
}

fn assert_sealed_bound(stored: &Value) {
    let prov = stored
        .pointer("/_meta/provenance")
        .expect("the stored result carries a receipt")
        .clone();
    assert!(
        prov.get("public_signature").is_some(),
        "the stored receipt carries a public signature: {stored}"
    );
    let verified =
        verify_public(&prov, &trust_set(), Some(stored)).expect("the stored receipt verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
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
    assert_eq!(status_of(&settled), "completed", "{settled}");
    assert_eq!(mock.calls(), 1, "one dispatch ran the task");
    assert_sealed_bound(&stored_result(&state, &id));
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
    assert_eq!(status_of(&settled), "completed", "{settled}");
    assert_eq!(mock.calls(), 2, "one first dispatch and one resume");
    assert_sealed_bound(&stored_result(&state, &id));
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
    assert_eq!(status_of(&settled), "completed", "{settled}");
    assert_eq!(
        mock.calls(),
        2,
        "one first dispatch and one state-only resume"
    );
    assert_sealed_bound(&stored_result(&state, &id));
}
