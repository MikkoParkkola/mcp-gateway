// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7692 (#2478): every read of a finished task re-checks the grants of
//! the calls that produced it (#2461). A poll that meets the same decision
//! again writes no new record within the window; a changed decision, such as
//! a revoked grant, is written at once.

use serde_json::json;

use super::MetaMcp;
use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, decisions, grant, grants};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::AuditFailurePolicy;

/// Alice's own capability, granted to her.
const ALICE: (&str, &str) = ("api_key", "alice");

/// A completed task whose one recorded call was Alice's personal capability.
fn finished_task() -> CommittedTask {
    let mut task = Task::create("gateway_invoke");
    task.complete(json!({ "content": [] }));
    CommittedTask {
        task,
        revision: 1,
        backend: CAPS.to_owned(),
        targets: vec![Target {
            server: CAPS.to_owned(),
            tool: PERSONAL.to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
    }
}

/// One `tasks/get` read as Alice, in a slot as the HTTP handler opens one.
async fn poll(meta: &MetaMcp, stored: &CommittedTask) -> Option<JsonRpcResponse> {
    let who = api_key("alice");
    let caller = context(&who);
    let (refusal, written) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(
            &RequestId::Number(1),
            stored,
            None,
            Some("poll-session"),
            &caller,
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
}
