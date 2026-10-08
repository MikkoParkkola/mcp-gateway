// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8168` on a paused chain: the step that stopped was sealed over a
//! request digest that binds its backend instance. The stop remembers that
//! digest against the exchange it holds (`InFlight::bind_step`, called by the
//! chain driver's seal), and the step handle a resume mints is sealed over it
//! rather than recomputed from the step's name, so a backend replaced under the
//! same name while the chain was paused cannot be answered the round.

use serde_json::json;

use super::{plan_chain_resume, seal_chain_stop, step_retry_for};
use crate::protocol::continuation::{ContinuationState, Payload};

const NOW: u64 = 1_780_000_000;
const STEP_DIGEST: &str = "step-digest-bound-to-the-asking-instance";

#[tokio::test]
async fn a_chain_resume_seals_the_step_over_its_bound_digest() {
    let state = ContinuationState::new();
    let chain = vec![json!({"tool": "srv:asks", "arguments": {"id": 7}})];
    let hold = state
        .in_flight()
        .hold("srv", NOW + 300, NOW)
        .await
        .expect("the in-flight table has room for one exchange");
    let asked = Payload::mint(
        "srv".into(),
        Some("backend-state".into()),
        "caller".into(),
        STEP_DIGEST.into(),
        state.replica().to_string(),
        hold,
        NOW,
    );
    state.in_flight().bind_step(&asked);
    let stopped = seal_chain_stop(&asked, &chain, 0, Some("backend-state".into()));
    let token = state
        .keyring()
        .mint(&stopped)
        .expect("the chain stop mints");

    let plan = plan_chain_resume(&state, &token, &chain, "caller", NOW + 1)
        .await
        .expect("the caller's own chain resumes");
    assert_eq!(plan.step_request_digest.as_deref(), Some(STEP_DIGEST));
    let retry = step_retry_for(&state, &plan, &chain, None, NOW + 1).expect("a step handle");
    let minted = state
        .keyring()
        .open(
            retry.request_state.as_deref().expect("a step envelope"),
            NOW + 1,
        )
        .expect("the step envelope opens");
    assert_eq!(
        minted.original_request_digest, STEP_DIGEST,
        "the step handle was recomputed from the name, not the stopped step's digest"
    );
}

#[tokio::test]
async fn a_step_digest_ends_with_its_exchange() {
    let state = ContinuationState::new();
    let hold = state
        .in_flight()
        .hold("srv", NOW + 300, NOW)
        .await
        .expect("room");
    let asked = Payload::mint(
        "srv".into(),
        None,
        "caller".into(),
        STEP_DIGEST.into(),
        state.replica().to_string(),
        hold.clone(),
        NOW,
    );
    state.in_flight().bind_step(&asked);
    assert_eq!(
        state.in_flight().step_digest(&hold, NOW).await.as_deref(),
        Some(STEP_DIGEST)
    );
    assert!(state.in_flight().complete(&hold, NOW).await);
    assert_eq!(state.in_flight().step_digest(&hold, NOW).await, None);
}
