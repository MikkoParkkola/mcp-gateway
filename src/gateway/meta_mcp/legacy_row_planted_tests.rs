// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task row a published 4.0 pre-release stored (record version 6 at most,
//! no call bindings) is not stripped when served: it is refused instead, so a
//! member its backend planted is never delivered. Both stored-read paths,
//! HTTP (`router/handlers/tasks.rs`) and stdio (`server/stdio_tasks.rs`),
//! serve through `refuse_stored_delivery`, judged here. If that judge ever
//! serves such a row, this fails and the old rows need a read-time strip.

use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, grant};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::RequestId;
use crate::protocol::reserved_members::test_support::planted;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

#[tokio::test]
async fn a_pre_binding_row_with_a_planted_member_is_refused_when_served() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![grant("g-legacy", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.complete(&planted())
        .expect("a live task takes its outcome");
    let stored = CommittedTask {
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
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        // As every row a published pre-release wrote reads.
        bindings_recorded: false,
    };
    let caller = context(&api_key("alice"));
    let (refusal, _, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(&RequestId::Number(1), &stored, None, Some("s"), &caller)
    })
    .await;
    let refusal = refusal.expect("a pre-binding row's output is refused");
    let body = serde_json::to_string(&refusal).expect("serializes");
    assert!(refusal.error.is_some(), "{body}");
    assert!(!body.contains("FORGED-"), "{body}");
    assert!(refusal.result.is_none(), "{body}");
}
