// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a, harness H2: grant decision records on the task worker path (T12,
//! T13, T14, T24, T27's task variant). Every task is keyed and settles
//! through the real worker; the log is read at the first terminal poll.
use super::super::*;
use super::grant_decisions::{
    armed, only, personal_chain, personal_invoke, signing, surfaced, with_nonce,
};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, PERSONAL, decisions, invocations, stall_log, trace_of,
};
use crate::security::audit::AuditFailurePolicy;

/// Make an already-built call task-augmented and keyed.
pub(super) fn as_task(mut body: Value, key: &str) -> Value {
    body["params"]["task"] = json!({});
    keyed(body, key)
}

/// T12. An unsigned task's worker writes its execution decision, traced,
/// before the task settles. Since MIK-8315 the submit's decision comes first.
#[tokio::test]
async fn unsigned_task_writes_the_workers_record() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let created = post(&row.state, "key-a", as_task(personal_invoke(1), "d3a-t12")).await;
    let settled = poll_until_terminal(&row.state, "key-a", &task_id(&created)).await;
    let records = decisions(&row.dir);
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    let invocation = only(invocations(&row.dir), "invocation record");
    // The submit's decision (MIK-8315), the worker's, then the terminal
    // read's replay-check decision (#2450): reading a finished task re-runs
    // the grant check.
    std::assert_eq!(records.len(), 3, "{records:#?}");
    std::assert_eq!(trace_of(&records[1]), trace_of(&invocation), "{records:#?}");
}

/// T13. A signed task has two records: signing preparation's (untraced
/// shape, on the request) and then the worker's (traced).
#[tokio::test]
async fn signed_task_writes_preparation_and_execution_records() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let body = as_task(with_nonce(personal_invoke(1)), "d3a-t13");
    let created = post(&row.state, "key-a", body).await;
    let settled = poll_until_terminal(&row.state, "key-a", &task_id(&created)).await;
    let records = decisions(&row.dir);
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    let invocation = only(invocations(&row.dir), "invocation record");
    // Preparation, the worker's, then the terminal read's replay check (#2450).
    std::assert_eq!(records.len(), 3, "{records:#?}");
    assert_ne!(
        trace_of(&records[0]),
        trace_of(&invocation),
        "the preparation record comes first and is not the invocation's: {records:#?}"
    );
    std::assert_eq!(
        trace_of(&records[1]),
        trace_of(&invocation),
        "the execution record carries the worker's invocation trace: {records:#?}"
    );
}

/// T14. A worker cancelled while its capability call is held, after the
/// grant check has noted: the note is still written, the task is cancelled.
#[tokio::test]
async fn cancelled_worker_keeps_its_pending_record() {
    let row = armed(true, true, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let created = post(&row.state, "key-a", as_task(personal_invoke(1), "d3a-t14")).await;
    let id = task_id(&created);
    row.endpoint.wait_for_arrivals(1).await;

    let ack = post(
        &row.state,
        "key-a",
        task_method(2, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    assert!(ack.get("error").is_none(), "{ack}");
    std::assert_eq!(
        status_of(&poll_until_terminal(&row.state, "key-a", &id).await),
        "cancelled"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while decisions(&row.dir).len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    row.endpoint.release();
    // The submit's decision (MIK-8315), then the cancelled worker's pending
    // note, still written. Both are traced, each with its own trace: two
    // records under one trace would be one actor's, not submit and worker.
    let records = decisions(&row.dir);
    std::assert_eq!(records.len(), 2, "{records:#?}");
    assert_ne!(trace_of(&records[0]), trace_of(&records[1]), "{records:#?}");
    std::assert_eq!(records[1]["outcome"], json!("ok"), "{records:#?}");
}

/// T14b. The same cancellation on a stalled log: the dropped slot hands its
/// note to a bounded write, which the stall refuses at once instead of
/// pinning a thread.
#[tokio::test]
async fn cancelled_worker_on_stalled_log_writes_through_the_bound() {
    let row = armed(true, true, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let created = post(&row.state, "key-a", as_task(personal_invoke(1), "d3a-t14b")).await;
    let id = task_id(&created);
    row.endpoint.wait_for_arrivals(1).await;
    let release = stall_log(&row.log).await;

    let ack = post(
        &row.state,
        "key-a",
        task_method(2, "tasks/cancel", json!({ "taskId": id.clone() })),
    )
    .await;
    assert!(ack.get("error").is_none(), "{ack}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while row.log.refused_under_stall_for_test() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    release();
    row.endpoint.release();
    assert!(
        row.log.refused_under_stall_for_test() >= 1,
        "the cancelled slot's pending note went through the bounded path"
    );
}

/// A playbook of one personal-capability step whose failures continue.
pub(super) fn continuing_playbook() -> crate::playbook::PlaybookEngine {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "d3a-continue",
        "description": "one personal step; a failed step continues",
        "on_error": "continue",
        "steps": [
            { "name": "read", "tool": PERSONAL, "server": CAPS, "arguments": {} }
        ]
    }))
    .expect("the fixture playbook deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    engine
}

/// Builds one variant's request from its id.
type Body = fn(i64) -> Value;

/// T24. A failed decision write on the worker path settles the task as
/// -32005, not as chain orchestration's -32603 or a partial result: a
/// single `gateway_invoke`, a `gateway_execute` chain, and a playbook whose
/// step policy is `continue`.
#[tokio::test]
async fn worker_decision_write_failure_settles_as_audit_unavailable() {
    let variants: [(&str, Body); 3] = [
        ("gateway_invoke", personal_invoke),
        ("gateway_execute chain", personal_chain),
        ("playbook, continue", |id| {
            modern(
                id,
                "tools/call",
                json!({ "name": "gateway_run_playbook", "arguments": { "name": "d3a-continue" } }),
                true,
            )
        }),
    ];
    for (index, (variant, body)) in variants.into_iter().enumerate() {
        let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
        row.state
            .meta_mcp
            .set_playbook_engine(continuing_playbook());
        // The worker's append, not the submit's: since MIK-8315 the submit's
        // decision is the first append, and a failure there refuses the
        // submit itself (submit_authz_audit 4d).
        crate::gateway::meta_mcp::grant_audit::seams::fail_append_at_for_test(2);
        let key = format!("d3a-t24-{index}");
        let created = post(&row.state, "key-a", as_task(body(1), &key)).await;
        // Read from the committed store, not `tasks/get`: the read's own
        // grant re-check would write records and answer in the worker's place.
        let id = task_id(&created);
        let stored = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let stored = row
                    .state
                    .tasks
                    .get(&super::submit_authz::alice(), &id)
                    .expect("the committed task");
                if super::submit_authz::settled(stored.task.status()) {
                    break stored;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the task settles");
        let error = stored.task.error().expect("the worker's failure is stored");
        std::assert_eq!(error.code, -32005, "{variant}: {}", error.message);
    }
}

/// T27 (H2, task). The same surfaced direct-name call submitted as a task is
/// refused at submit as a name that matches no tool (MIK-8326; route-check-parity
/// P3), and recorded once. The run-time re-check is pinned by the chokepoint's
/// F5 and the worker's policy check.
#[tokio::test]
async fn surfaced_task_grant_denial_writes_one_record() {
    let row = armed(false, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let body = modern(
        1,
        "tools/call",
        json!({ "name": PERSONAL, "arguments": {} }),
        true,
    );
    let created = post(&row.state, "key-a", as_task(body, "d3a-t27")).await;
    std::assert_eq!(created["error"]["code"], json!(-32601), "{created}");
    std::assert_eq!(
        created["error"]["message"],
        json!("JSON-RPC error -32601: Unknown tool: calendar_read_day"),
        "{created}"
    );
    std::assert!(created.pointer("/result/taskId").is_none(), "{created}");
    std::assert_eq!(
        row.endpoint.arrivals(),
        0,
        "the refused task reaches nothing"
    );
    let records = decisions(&row.dir);
    std::assert_eq!(records.len(), 1, "the one grant decision: {records:#?}");
    std::assert!(
        records.iter().all(|r| r["outcome"] == json!("denied")),
        "{records:#?}"
    );
}
