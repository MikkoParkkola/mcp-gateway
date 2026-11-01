// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Chain rows 14 and on: a first stop seals the chain identity, a resume is
//! never routed to the origin backend, and a step's notes follow it.

use super::*;
use crate::gateway::meta_mcp::chain_interim::{presented_resume, step_retry_for};

/// ROW 14. A first stop converts the step's own envelope into a chain resume.
///
/// The invariant: the envelope a stopping step arrives with was minted for that
/// step alone — `invoke.rs` sealed it over the step's own request, in the
/// backend-input domain, with no step index. Handing it back unchanged would
/// give the caller a token `plan_chain_resume` refuses on purpose, on digest
/// and on the absent `next_step`: a stop nobody can resume. The conversion is
/// what makes the round trip exist, and it re-seals rather than mints, or the
/// backend holding one exchange would be charged for two.
#[tokio::test]
async fn a_first_stop_seals_the_chain_identity_onto_the_steps_envelope() {
    let state = ContinuationState::new();
    let chain = three_step_chain();
    let hold_key = state
        .in_flight()
        .hold(
            "srv",
            &crate::protocol::continuation::QuotaKey::for_test("caller"),
            NOW + HOLD_SECONDS,
            NOW,
        )
        .await
        .expect("the in-flight table has room for one exchange");
    let step_scoped = Payload::mint(
        "srv".into(),
        Some(BACKEND_STATE.into()),
        CALLER.into(),
        "digest-of-the-single-step-request".into(),
        "replica-a".into(),
        hold_key.clone(),
        NOW,
    );
    assert_eq!(
        step_scoped.purpose,
        ContinuationPurpose::BackendInput,
        "the step's own envelope is not a chain resume to begin with"
    );

    let sealed = seal_chain_stop(&step_scoped, &chain, 1, Some(BACKEND_STATE.into()));

    assert_eq!(sealed.purpose, ContinuationPurpose::ChainResume);
    assert_eq!(
        sealed.original_request_digest,
        chain_digest(&chain),
        "the resume is not bound to the chain it may run"
    );
    assert_eq!(sealed.next_step, Some(1));
    assert_eq!(
        sealed.hold_key, hold_key,
        "a chain stop opened a second exchange for a backend already holding one"
    );
    assert_ne!(sealed.jti, step_scoped.jti, "the retired handle was reused");

    let token = state.keyring().mint(&sealed).expect("mint");
    let planned = plan_chain_resume(&state, &token, &chain, CALLER, NOW + 1)
        .await
        .expect("the envelope a first stop hands back must be redeemable");
    assert_eq!(planned.next_step, 1);
}

/// ROW 15. A chain resume is not routed to a backend by name.
///
/// The invariant: the envelope licenses the chain driver to run
/// `chain[next_step..]`, and the step it resumes is named by the sealed
/// `next_step` rather than by the tool the client called. Routing it by
/// `backend_id` — what every other purpose gets — would dispatch the pending
/// step's backend with the whole chain array as its arguments, and
/// `plan_chain_resume` would never see the handle at all.
///
/// Minted against the real clock, not [`NOW`]: `retry_origin_backend` reads the
/// wall clock itself, so an envelope pinned to the module's fixed timestamp
/// would be refused as expired and the row would pass for the wrong reason.
#[tokio::test]
async fn a_chain_resume_is_not_routed_to_the_origin_backend() {
    let state = ContinuationState::new();
    let chain = three_step_chain();
    let now = crate::protocol::continuation::now_unix_secs();
    let hold_key = state
        .in_flight()
        .hold(
            "srv",
            &crate::protocol::continuation::QuotaKey::for_test("caller"),
            now + HOLD_SECONDS,
            now,
        )
        .await
        .expect("the in-flight table has room for one exchange");
    let payload = Payload::mint(
        "srv".into(),
        Some(BACKEND_STATE.into()),
        CALLER.into(),
        chain_digest(&chain),
        "replica-a".into(),
        hold_key,
        now,
    )
    .with_purpose(ContinuationPurpose::ChainResume);
    let token = state.keyring().mint(&payload).expect("mint");

    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(token),
        ..crate::protocol::mrtr::RetryFields::default()
    };

    assert!(
        super::super::invoke::retry_origin_backend(&state, &retry).is_none(),
        "a chain resume was routed to a backend by name, so the chain driver never ran"
    );
}

/// A plan is bounded against the chain it was validated with, and nothing in
/// the type says the chain handed to `step_retry_for` is that same one. The
/// driver passes one array to both, so this is a refusal rather than a panic
/// only while that stays true — pin it, because an index is a crash and a crash
/// in the driver takes the whole call down.
#[tokio::test]
async fn a_step_outside_the_chain_is_refused_rather_than_indexed() {
    let state = ContinuationState::new();
    let chain = three_step_chain();

    let payload = chain_payload(&state, &chain, Some(2), 1).await;
    let token = state.keyring().mint(&payload).expect("mint");
    let plan: ChainResumePlan = plan_chain_resume(&state, &token, &chain, CALLER, NOW + 1)
        .await
        .expect("a resume inside the chain is allowed");
    assert_eq!(plan.next_step, 2);

    let error = step_retry_for(&state, &plan, &chain[..1], None, NOW + 1)
        .expect_err("a step past the end of the chain must not be indexed");
    assert!(
        error.to_string().contains("outside the chain"),
        "a step past the end was refused for some other reason: {error}"
    );
}

/// #2254. Answers without the `requestState` this gateway issued are not a
/// retry of anything it asked: presenting them must refuse, not run the chain
/// fresh and drop them.
#[tokio::test]
async fn answers_without_a_request_state_are_refused_not_dropped() {
    let state = ContinuationState::new();
    let retry = RetryFields {
        input_responses: Some(json!({"q": {"action": "accept"}})),
        ..RetryFields::default()
    };

    let refused = presented_resume(&state, &retry, &three_step_chain(), None, NOW).await;

    assert!(refused.is_err(), "stray answers let the chain run fresh");
}

/// A step's gateway notes follow its value into the
/// chain's `results`, at its place there. A resumed chain starts `results`
/// empty, so a step's place is its position in this run, not its index in
/// the chain.
#[tokio::test]
async fn a_steps_gateway_notes_follow_it_into_results() {
    use crate::gateway::gateway_writes::{Layer, note, recorded};
    for (start, place) in [(0_usize, "1"), (1, "0")] {
        let chain = vec![json!({"tool": "srv:a"}), json!({"tool": "srv:b"})];
        let stored = crate::gateway::meta_mcp::invoke::relay::collecting(async {
            let run = |idx: usize, _tool: String, _arguments: Value| async move {
                let value = json!({
                    "text": format!("step {idx}"),
                    "_cost_warnings": [format!("advice {idx}")],
                });
                // Only step 1's advice is the gateway's.
                if idx == 1 {
                    note(Layer::Value, &["_cost_warnings"], &value);
                }
                Ok(value)
            };
            let seal = |_: usize, _: &InputRequired| -> Result<String> { panic!("no step asks") };
            drive_chain(&chain, start, run, seal)
                .await
                .expect("the chain completes");
            serde_json::to_value(recorded()).expect("the record serializes")
        })
        .await;
        let dests: Vec<&Value> = stored
            .as_array()
            .expect("a list")
            .iter()
            .map(|entry| &entry["dest"])
            .collect();
        assert_eq!(
            dests,
            vec![&json!(["results", place, "result", "_cost_warnings"])],
            "start {start}: {stored}"
        );
    }
}
