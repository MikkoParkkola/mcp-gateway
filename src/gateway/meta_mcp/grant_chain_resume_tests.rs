// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A chain resume checks the step it resumes at before anything dispatches.
//! A step refused there has no invocation record of its own, so its grant
//! decision is written (traced to the step) and says so.

use std::sync::Arc;

use serde_json::{Value, json};

use super::chain_interim::chain_digest;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, invocations, wait_for_decisions};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::protocol::RequestId;
use crate::protocol::continuation::{ContinuationPurpose, Payload, QuotaKey, now_unix_secs};
use crate::protocol::mrtr::RetryFields;
use crate::security::audit::AuditFailurePolicy;

/// A two-step chain on the personal capability, and a resume handle pending
/// at its second step, minted by `meta`'s own keyring.
async fn chain_and_resume(meta: &super::MetaMcp) -> (Value, RetryFields) {
    let step = json!({ "tool": format!("{CAPS}:{PERSONAL}"), "arguments": {} });
    let chain = vec![step.clone(), step];
    let state = meta.continuation();
    let now = now_unix_secs();
    let hold_key = state
        .in_flight()
        .hold(CAPS, &QuotaKey::for_test("caller"), now + 300, now)
        .await
        .expect("the in-flight table has room for one exchange");
    let mut payload = Payload::mint(
        CAPS.into(),
        Some("backend-state".into()),
        "caller".into(),
        chain_digest(&chain),
        "replica-a".into(),
        hold_key,
        now,
    )
    .with_purpose(ContinuationPurpose::ChainResume);
    payload.next_step = Some(1);
    let retry = RetryFields {
        request_state: Some(state.keyring().mint(&payload).expect("mint")),
        ..RetryFields::default()
    };
    (json!({ "chain": chain }), retry)
}

/// A resume of the chain after the caller's grant was revoked: the answer.
async fn resume_after_revocation(dir: &Arc<tempfile::TempDir>) -> Value {
    let endpoint = Endpoint::start(false).await;
    let meta = gateway(&endpoint, vec![], Some(dir), AuditFailurePolicy::BestEffort);
    let (chain, retry) = chain_and_resume(&meta).await;
    let who = api_key("alice");
    let mut caller = context(&who);
    caller.retry = &retry;
    let response = meta
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_execute",
            chain,
            Some("d19"),
            caller,
        )
        .await;
    serde_json::to_value(&response).expect("a response serialises")
}

/// A pending step the caller can no longer see is refused as an absent name,
/// and the refusal is recorded: one decision, no invocation record, so it is
/// listed as the one row of a refused call.
#[tokio::test]
async fn a_resume_step_withheld_by_visibility_writes_one_unrecorded_decision() {
    let dir = Arc::new(tempfile::tempdir().unwrap());

    let answer = resume_after_revocation(&dir).await;

    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}: {answer}");
    assert_eq!(held[0]["outcome"], json!("denied"), "{held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&dir).is_empty(),
        "the step never dispatched: {answer}"
    );
}
