// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A chain resume checks the step it resumes at before anything dispatches.
//! A step refused there has no invocation record of its own, so its grant
//! decision is written (traced to the step) and says so.

use std::sync::Arc;

use serde_json::{Value, json};

use super::chain_interim::chain_digest;
use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, decisions, grant, grants, invocations, wait_for_decisions,
};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use super::visibility::after_grant_evaluation;
use crate::protocol::RequestId;
use crate::protocol::continuation::{ContinuationPurpose, Payload, QuotaKey, now_unix_secs};
use crate::protocol::mrtr::RetryFields;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

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
    let dir = crate::test_dir_keep::kept_tempdir();

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

/// Arm a revocation that lands right after the next grant evaluation, which
/// is the visibility judgement of the resume step: the step is judged visible
/// while its grant holds, and the policy check that follows finds it gone.
/// The flag says whether the revocation fired.
fn revoke_after_next_evaluation(meta: &super::MetaMcp) -> std::rc::Rc<std::cell::Cell<bool>> {
    let store = Arc::clone(&meta.identity_grants);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = std::rc::Rc::clone(&fired);
    after_grant_evaluation::set(move || {
        flag.set(true);
        *store.write() = grants(vec![]);
    });
    fired
}

/// A resume of the chain with `retry` pending, as alice.
async fn resume(meta: &super::MetaMcp, chain: Value, retry: &RetryFields) -> Value {
    let who = api_key("alice");
    let mut caller = context(&who);
    caller.retry = retry;
    let response = meta
        .handle_tools_call(
            RequestId::Number(2),
            "gateway_execute",
            chain,
            Some("d9"),
            caller,
        )
        .await;
    serde_json::to_value(&response).expect("a response serialises")
}

/// The decisions Activity lists as a Refusal: denied, no invocation record.
fn refusals(held: &[Value]) -> usize {
    let listed =
        |d: &&Value| d["outcome"] == json!("denied") && d["invocation_recorded"] == json!(false);
    held.iter().filter(listed).count()
}

/// A resume step whose grant is revoked after the step was judged visible is
/// refused by the audited policy check (chain_exec.rs:244-248), not withheld
/// by visibility (chain_exec.rs:233-243): its answer names the grant (denial
/// text at visibility.rs:585-588; the visibility branch answers "Unknown
/// tool"), and it writes one denied decision and no invocation record.
#[tokio::test]
async fn a_resume_step_refused_by_the_grant_check_is_one_unrecorded_decision() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let endpoint = Endpoint::start(false).await;
    let rows = vec![grant("g-alice", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let (chain, retry) = chain_and_resume(&meta).await;
    let fired = revoke_after_next_evaluation(&meta);

    let answer = resume(&meta, chain, &retry).await;

    assert!(
        fired.get(),
        "premise: the step was judged while its grant held: {answer}"
    );
    let text = answer.to_string();
    assert!(
        text.contains("Identity grant denied"),
        "policy check, not visibility: {answer}"
    );
    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}");
    assert_eq!(held[0]["outcome"], json!("denied"), "{held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&dir).is_empty(),
        "the step never dispatched: {answer}"
    );
    assert_eq!(refusals(&held), 1, "{held:#?}");
}

/// One slot holds a traced first step that succeeds and, after its grant is
/// revoked between the steps, a resume step on the same target that the
/// policy check refuses. The resume check runs under a trace id of its own
/// (chain_exec.rs:254-257), so `select_records` (grant_audit.rs:196-208)
/// keeps its note beside the first step's traced note: two decisions, and the
/// second is the one Refusal.
#[tokio::test]
async fn a_refused_resume_step_is_kept_beside_the_first_steps_traced_decision() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let endpoint = Endpoint::start(false).await;
    let rows = vec![grant("g-alice", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let (chain, retry) = chain_and_resume(&meta).await;
    let who = api_key("alice");
    let first = json!({ "chain": [{ "tool": format!("{CAPS}:{PERSONAL}"), "arguments": {} }] });

    let (answers, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        let call = super::grant_decision_audit_tests::call;
        let first = call(&meta, &who, "gateway_execute", first).await;
        let fired = revoke_after_next_evaluation(&meta);
        (first, resume(&meta, chain, &retry).await, fired)
    })
    .await;

    written.expect("the slot's records are written");
    let (first, second, fired) = answers;
    assert!(
        fired.get(),
        "premise: the resume step was judged while granted: {second}"
    );
    assert_eq!(
        invocations(&dir).len(),
        1,
        "only the first step dispatched: {first} {second}"
    );
    let held = decisions(&dir);
    assert_eq!(held.len(), 2, "{held:#?}");
    assert_eq!(held[0]["outcome"], json!("ok"), "{held:#?}");
    assert_eq!(held[1]["outcome"], json!("denied"), "{held:#?}");
    assert_eq!(held[1]["invocation_recorded"], json!(false), "{held:#?}");
    assert_eq!(refusals(&held), 1, "{held:#?}");
}
