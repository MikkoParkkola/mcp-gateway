// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8315 row 4: the audit of an allowed personal-capability task. The
//! submit's grant decisions are records of their own, and none carries the
//! trace of an invocation record (the worker's do). They are written before
//! the worker's first record. Terminal state is read from the committed
//! store, so no `tasks/get` adds a record of its own.
use super::super::*;
use super::grant_audit_order::Terminal;
use super::grant_decision_tasks::as_task;
use super::grant_decisions::{Armed, OWNER, armed, personal_invoke, surfaced};
use super::submit_authz::{committed, settled};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, DECISION_KIND, PERSONAL, decisions, grants, invocations, trace_of,
};
use crate::security::audit::AuditFailurePolicy;

const SECOND: &str = "calendar_read_week";

/// Observe commits and return the signal a terminal transition fires.
fn watch(row: &Armed) -> Arc<Terminal> {
    let terminal = Arc::new(Terminal(tokio::sync::Notify::new()));
    row.state.task_executor.observe_commits(
        Arc::clone(&terminal) as Arc<dyn crate::gateway::task_service::CommitObserver>
    );
    terminal
}

/// Wait until the only task is terminal, reading the committed store.
async fn settle(row: &Armed, terminal: &Terminal, id: &str) {
    tokio::time::timeout(Duration::from_secs(10), terminal.0.notified())
        .await
        .expect("the worker commits a transition");
    let owner = crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id();
    loop {
        let stored = row.state.tasks.get(&owner, id).expect("the committed task");
        if settled(stored.task.status()) {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// Submit `body`; returns (submit records, worker records). A worker record
/// carries the trace of one of the log's invocation records; a submit record
/// is any other decision. Every submit record must precede the worker's first.
async fn records_of_a_settled_task(row: &Armed, body: Value) -> (usize, usize) {
    let terminal = watch(row);
    let created = post(&row.state, "key-a", body).await;
    settle(row, &terminal, &task_id(&created)).await;
    let traces: Vec<String> = invocations(&row.dir)
        .iter()
        .filter_map(|r| trace_of(r).map(str::to_owned))
        .collect();
    let records = decisions(&row.dir);
    let is_worker = |r: &Value| trace_of(r).is_some_and(|t| traces.iter().any(|x| x == t));
    let first_worker = records.iter().position(is_worker);
    let last_submit = records.iter().rposition(|r| !is_worker(r));
    if let (Some(worker), Some(submit)) = (first_worker, last_submit) {
        assert!(submit < worker, "a submit record follows the worker's: {records:#?}");
    }
    let workers = records.iter().filter(|r| is_worker(r)).count();
    (records.len() - workers, workers)
}

/// 4a. An unsigned `gateway_invoke` task: the worker's record plus one submit record.
#[tokio::test]
async fn an_allowed_invoke_task_records_one_submit_decision() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let (submit, worker) =
        records_of_a_settled_task(&row, as_task(personal_invoke(1), "sa-4a")).await;
    std::assert_eq!((submit, worker), (1, 1), "{:#?}", decisions(&row.dir));
}

/// 4b. A surfaced name: the same, one submit record.
#[tokio::test]
async fn an_allowed_surfaced_task_records_one_submit_decision() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let call = modern(1, "tools/call", json!({ "name": PERSONAL, "arguments": {} }), true);
    let (submit, worker) = records_of_a_settled_task(&row, as_task(call, "sa-4b")).await;
    std::assert_eq!((submit, worker), (1, 1), "{:#?}", decisions(&row.dir));
}

/// A second personal capability beside the first, granted to `key-a`.
fn add_second_target(row: &Armed) {
    let first = row.state.meta_mcp.get_capabilities().expect("capabilities");
    let yaml = format!(
        "name: {SECOND}\ndescription: Read one calendar week\nmetadata:\n  exposure: personal\n  \
         read_only: true\n  identity_owner:\n    authority: {}\n    subject: {}\nproviders:\n  \
         primary:\n    service: rest\n    config:\n      base_url: http://localhost:{}\n      \
         path: /read\n      method: GET\n",
        OWNER.0, OWNER.1, row.endpoint.port
    );
    first
        .register_capability(crate::capability::parse_capability(&yaml).expect("parses"))
        .expect("the second target registers");
    let mut rows = vec![crate::gateway::meta_mcp::grant_audit_fixture::grant("g1", OWNER, OWNER)];
    let mut second: serde_json::Value = serde_json::to_value(&rows[0]).expect("serialises");
    second["grant_id"] = json!("g2");
    second["capability"] = json!(SECOND);
    rows.push(serde_json::from_value(second).expect("the second grant deserialises"));
    row.state.meta_mcp.set_identity_grants(grants(rows));
}

/// 4c. A keyed plan naming X twice and Y once: two submit records (one per
/// distinct target after `select_records`), not three.
#[tokio::test]
async fn an_allowed_plan_task_records_one_submit_decision_per_target() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    add_second_target(&row);
    let step = |tool: &str| json!({ "tool": format!("{CAPS}:{tool}"), "arguments": {} });
    let chain = json!([step(PERSONAL), step(PERSONAL), step(SECOND)]);
    let call = modern(
        1,
        "tools/call",
        json!({ "name": "gateway_execute", "arguments": { "chain": chain } }),
        true,
    );
    let (submit, worker) = records_of_a_settled_task(&row, as_task(call, "sa-4c")).await;
    std::assert_eq!((submit, worker), (2, 3), "{:#?}", decisions(&row.dir));
}

/// 4d. `FailClosed` with a failing append: the submit answers `AuditUnavailable`
/// (-32005) and creates no task.
#[tokio::test]
async fn a_failing_submit_append_under_fail_closed_creates_no_task() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
    row.log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let rows = committed(&row);
    let answer = post(&row.state, "key-a", as_task(personal_invoke(1), "sa-4d")).await;
    assert!(
        answer.pointer("/result/taskId").is_none(),
        "a task handle was returned although the submit's decision could not be recorded: {answer}"
    );
    std::assert_eq!(answer.pointer("/error/code"), Some(&json!(-32005)), "{answer}");
    std::assert_eq!(committed(&row), rows, "a task row was committed");
    std::assert_eq!(row.endpoint.arrivals(), 0, "the backend ran without its cause on record");
}

/// 4e. The inverse of O5 for a personal capability: the submit's grant
/// decision IS appended before the worker spawns (the design's new order;
/// MIK-8204 flushes the submit's slot before the hand-off).
#[tokio::test]
async fn an_allowed_task_appends_its_submit_decision_before_the_spawn() {
    use crate::gateway::meta_mcp::grant_audit::seams::{appends_for_test, worker_spawns_for_test};
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let (start, appends) = (worker_spawns_for_test().len(), appends_for_test());
    let created = post(&row.state, "key-a", as_task(personal_invoke(1), "sa-4e")).await;
    task_id(&created);
    let edge = worker_spawns_for_test()
        .get(start)
        .copied()
        .unwrap_or_else(|| panic!("the worker spawned: {created}"));
    std::assert_eq!(
        edge.appends,
        appends + 1,
        "exactly the submit's decision is appended before the spawn"
    );
}

/// 4f. A stalled audit sink fails the submit within its bound instead of
/// hanging it: the submit's own append is the write that stalls, and under
/// `FailClosed` the submit answers `AuditUnavailable` (-32005) and creates no
/// task. The outer bound only guards the suite.
#[tokio::test]
async fn a_stalled_sink_fails_the_submit_within_its_bound() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
    // The log's append bound, shortened as the other stall rows do; the
    // submit's grant record is the next write, and it is held.
    let gate = row.log.stall_next_write_for_test(Duration::from_millis(200));
    let rows = committed(&row);
    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        post(&row.state, "key-a", as_task(personal_invoke(1), "sa-4f")),
    )
    .await
    .expect("the submit hung on a stalled audit sink");
    gate.release();
    assert!(answer.pointer("/result/taskId").is_none(), "{answer}");
    std::assert_eq!(answer.pointer("/error/code"), Some(&json!(-32005)), "{answer}");
    std::assert_eq!(committed(&row), rows, "a task row was committed");
    std::assert_eq!(row.endpoint.arrivals(), 0, "the backend ran without its cause on record");
}
