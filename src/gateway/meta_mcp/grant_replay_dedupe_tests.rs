// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7692 (#2478): every read of a finished task re-checks the grants of
//! the calls that produced it (#2461). A poll that meets the same decision
//! again writes no new record within the window; a changed decision, such as
//! a revoked grant, is written at once.

use serde_json::json;

use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, decisions, grant, grants};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use super::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::identity_grants::GrantSubject;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::AuditFailurePolicy;
use crate::security::{ProofSource, ProvenAgentId};

/// Alice's own capability, granted to her.
const ALICE: (&str, &str) = ("api_key", "alice");

/// A completed task whose one recorded call was Alice's personal capability.
fn finished_task() -> CommittedTask {
    let mut task = Task::create("gateway_invoke");
    task.complete(json!({ "content": [] }));
    CommittedTask {
        task,
        revision: 1,
        targets: vec![Target {
            server: CAPS.to_owned(),
            tool: PERSONAL.to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
    }
}

/// One `tasks/get` read as Alice, in a slot as the HTTP handler opens one.
async fn poll(meta: &MetaMcp, stored: &CommittedTask) -> Option<JsonRpcResponse> {
    poll_as(meta, stored, &context(&api_key("alice"))).await
}

/// One `tasks/get` read as `caller`.
async fn poll_as(
    meta: &MetaMcp,
    stored: &CommittedTask,
    caller: &MetaMcpCallerContext<'_>,
) -> Option<JsonRpcResponse> {
    let (refusal, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(
            &RequestId::Number(1),
            stored,
            None,
            Some("poll-session"),
            caller,
        )
    })
    .await;
    written.expect("the slot's records are written");
    refusal
}

#[tokio::test]
async fn polling_a_finished_task_records_an_unchanged_decision_once() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![grant("g-poll", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let stored = finished_task();
    for _ in 0..5 {
        assert!(
            poll(&meta, &stored).await.is_none(),
            "the grant allows delivery"
        );
    }
    let allowed = decisions(&dir);
    assert_eq!(
        allowed.len(),
        1,
        "five identical decisions, one record: {allowed:#?}"
    );
    assert_eq!(allowed[0]["outcome"], json!("ok"), "{allowed:#?}");

    // The grant is revoked after the task finished: recorded at once.
    meta.set_identity_grants(grants(vec![]));
    assert!(
        poll(&meta, &stored).await.is_some(),
        "a revoked grant refuses delivery"
    );
    let after = decisions(&dir);
    assert_eq!(after.len(), 2, "the change is recorded at once: {after:#?}");
    assert_eq!(after[1]["outcome"], json!("denied"), "{after:#?}");

    for _ in 0..3 {
        assert!(poll(&meta, &stored).await.is_some());
    }
    assert_eq!(
        decisions(&dir).len(),
        2,
        "the unchanged denial is not written again"
    );

    // Another task is another key: its first read is written.
    assert!(poll(&meta, &finished_task()).await.is_some());
    assert_eq!(
        decisions(&dir).len(),
        3,
        "a second task's decision is its own record"
    );
}

/// The window bounds suppression: once it has passed since the last written
/// record, the same decision is written again, so polling stays visible.
#[test]
fn an_unchanged_decision_is_written_again_after_the_window() {
    use super::grant_audit::{REPEAT_WINDOW, RepeatLedger};
    let mut dedupe = RepeatLedger::default();
    let start = std::time::Instant::now();
    let key = "task|alice|caps|tool".to_owned();
    assert!(!dedupe.is_repeat(&key, "allow", start));
    dedupe.remember(key.clone(), "allow".to_owned(), start);
    assert!(
        dedupe.is_repeat(&key, "allow", start),
        "same decision inside the window"
    );
    assert!(
        !dedupe.is_repeat(&key, "deny", start),
        "a changed decision is never a repeat"
    );
    assert!(
        !dedupe.is_repeat(&key, "allow", start + REPEAT_WINDOW),
        "the window has passed"
    );
}

/// MIK-7826: a subject's label is display only, so a relabelled subject is
/// the same caller and its unchanged decision is not written again.
#[tokio::test]
async fn a_relabelled_subject_is_the_same_caller() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![grant("g-poll", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let stored = finished_task();
    let alice = api_key("alice");
    for label in [Some("alice"), Some("Alice Renamed"), None] {
        let mut caller = context(&alice);
        caller.grant_subject = Some(GrantSubject::new(
            "api_key",
            "alice",
            label.map(str::to_owned),
        ));
        assert!(poll_as(&meta, &stored, &caller).await.is_none());
    }
    let written = decisions(&dir);
    assert_eq!(written.len(), 1, "one caller, one record: {written:#?}");
}

/// MIK-7826: every identity field of the key still separates callers. Each
/// variant read between two reads as Alice is its own key, so the second
/// Alice read is still a repeat of the first.
#[tokio::test]
async fn each_caller_field_keeps_callers_apart() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![grant("g-poll", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let stored = finished_task();
    let alice = api_key("alice");
    let jwt = ProvenAgentId::for_test("agent-1", ProofSource::VerifiedJwtSubject);
    let mtls = ProvenAgentId::for_test("agent-1", ProofSource::MutualTls);
    let mut base = context(&alice);
    base.agent_id = Some(jwt);
    let subjects = [("api_key", "bob"), ("oidc", "alice")]
        .map(|(a, s)| Some(GrantSubject::new(a, s, Some("alice".to_owned()))));
    let mut variants = vec![];
    for subject in subjects {
        let mut c = context(&alice);
        c.agent_id = Some(jwt);
        c.grant_subject = subject;
        variants.push(c);
    }
    let mut proof = context(&alice);
    proof.agent_id = Some(mtls);
    variants.push(proof);
    let mut key = context(&alice);
    key.agent_id = Some(jwt);
    key.api_key_name = Some("bob");
    variants.push(key);
    let _ = poll_as(&meta, &stored, &base).await;
    for (i, variant) in variants.iter().enumerate() {
        let _ = poll_as(&meta, &stored, variant).await;
        let _ = poll_as(&meta, &stored, &base).await;
        let written = decisions(&dir);
        assert_eq!(
            written.len(),
            i + 2,
            "variant {i} merged with Alice: {written:#?}"
        );
    }
}
