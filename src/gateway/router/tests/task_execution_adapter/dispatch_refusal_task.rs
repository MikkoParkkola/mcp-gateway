// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway refusal inside a task worker's dispatch is tied to its task: the
//! settlement writes the task's own record, joined to the worker's dispatch
//! record by its trace. A backend's own error with the same code is not, and
//! no task read's delivery record gains the refusal.

use super::super::*;
use super::support::*;
use crate::config::ResponseContractConfig;
use pretty_assertions::assert_eq;

/// A contract that fails closed: an answer from a tool with no declared
/// contract is refused inside the dispatch, with `-32603`.
fn fail_closed() -> ResponseContractConfig {
    ResponseContractConfig {
        enabled: true,
        action_mode: true,
        fail_closed: true,
        ..Default::default()
    }
}

/// A contract that refuses only an answer carrying the mock's final text: an
/// interim round with no text passes, the answer after it is refused.
fn refusing_final_answer() -> ResponseContractConfig {
    let mut contract = ResponseContractConfig {
        enabled: true,
        action_mode: true,
        ..Default::default()
    };
    contract.tools.insert(
        TOOL.to_owned(),
        crate::config::ToolContractConfig {
            forbidden_patterns: vec!["mock-backend-answered".to_owned()],
            action_mode: Some(true),
            ..Default::default()
        },
    );
    contract
}

async fn contract_state(
    log: Arc<crate::security::TransparencyLogger>,
    contract: Option<ResponseContractConfig>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            if let Some(contract) = contract {
                meta.set_response_contract(contract);
            }
            meta.enable_transparency_log(log);
            meta
        },
    )
    .await
}

/// One task-augmented call (`request`) answered with `answer`, run to its
/// terminal state: the task id, its terminal read, every record in the log,
/// and how many times the backend was called. Under `policy` a failed
/// `task_settlement` append is armed first.
async fn settled_task_with(
    (answer, contract): (Answer, Option<ResponseContractConfig>),
    request: Value,
    policy: Option<crate::security::audit::AuditFailurePolicy>,
) -> (String, Value, Vec<Value>, usize) {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let (_dir, log) = temp_log(policy);
    let (state, _store) = contract_state(Arc::clone(&log), contract).await;
    let mock = MockBackend::answering(answer);
    register(&state, BACKEND, &mock);
    if policy.is_some() {
        log.fail_next_append_of_kind_for_test("task_settlement");
    }
    let created = post(&state, "key-a", request).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(mock.calls() > 0, "premise: the worker reached the backend");
    let _ = delivery_rows(&log).await;
    let entries = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    (task, settled, entries, mock.calls())
}

async fn settled_task(
    answer: Answer,
    contract: Option<ResponseContractConfig>,
) -> (String, Value, Vec<Value>) {
    let request = task_invoke(2, "dispatch-refusal", json!({}));
    let (task, settled, entries, _) =
        Box::pin(settled_task_with((answer, contract), request, None)).await;
    (task, settled, entries)
}

fn clean_answer() -> Answer {
    Answer::Result(json!({"content": [{"type": "text", "text": "ok"}], "isError": false}))
}

/// The task's `task_settlement` records.
fn settlements<'a>(entries: &'a [Value], task: &str) -> Vec<&'a Value> {
    entries
        .iter()
        .filter(|entry| entry["route"] == "task_settlement" && entry["task_id"] == task)
        .collect()
}

/// The task's one settlement record, and that it joins the worker's dispatch
/// record by trace. That record's outcome is read from the code alone
/// (`error`), so only the settlement record says the gateway refused.
fn refused_record<'a>(entries: &'a [Value], task: &str) -> &'a Value {
    let records = settlements(entries, task);
    let [record] = records.as_slice() else {
        panic!("task {task}: one task_settlement record: {entries:#?}");
    };
    assert_eq!(record["response_effect"], "refused", "{record}");
    assert_eq!(record["outcome"], "denied", "{record}");
    assert_eq!(record["error_code"], -32603, "{record}");
    let trace = &record["trace_id"];
    assert!(
        entries.iter().any(|entry| entry["route"] == "meta"
            && &entry["trace_id"] == trace
            && entry["error_code"] == -32603),
        "the record joins the worker's dispatch record by trace: {entries:#?}"
    );
    record
}

/// A refusal the gateway's response contract decides inside the worker's
/// dispatch writes the task's settlement record, carrying the code the task
/// settles with and joined to the worker's dispatch record by trace.
#[tokio::test]
async fn a_dispatch_refusal_is_tied_to_its_task() {
    let (task, settled, entries) =
        Box::pin(settled_task(clean_answer(), Some(fail_closed()))).await;
    assert_eq!(status_of(&settled), "failed", "premise: refused: {settled}");
    refused_record(&entries, &task);
}

/// A refusal of the dispatch after a state-only round, the worker's own
/// continuation, is tied to the task as the first dispatch's is.
#[tokio::test]
async fn a_continuation_refusal_is_tied_to_its_task() {
    use super::input_round::{STATE_1, create, done, state_only};
    let answer = Answer::Sequence(vec![state_only(STATE_1), done()]);
    let (task, settled, entries, calls) = Box::pin(settled_task_with(
        (answer, Some(refusing_final_answer())),
        create(2, "dispatch-refusal-continued"),
        None,
    ))
    .await;
    assert_eq!(calls, 2, "premise: the continuation was dispatched");
    assert_eq!(status_of(&settled), "failed", "premise: refused: {settled}");
    refused_record(&entries, &task);
}

/// Paired control: a backend's own error with the same code is the
/// backend's, not a gateway refusal, and writes no settlement record.
#[tokio::test]
async fn a_backend_error_with_the_same_code_is_not_tied_as_a_refusal() {
    let (task, _settled, entries) = Box::pin(settled_task(Answer::FailureCode(-32603), None)).await;
    assert!(
        settlements(&entries, &task).is_empty(),
        "task {task}: no task_settlement record: {entries:#?}"
    );
}

/// A dispatch the gateway did not refuse writes no settlement record.
#[tokio::test]
async fn a_delivered_dispatch_writes_no_settlement_record() {
    let (task, settled, entries) = Box::pin(settled_task(clean_answer(), None)).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    assert!(
        settlements(&entries, &task).is_empty(),
        "task {task}: no task_settlement record: {entries:#?}"
    );
}

/// Under fail-closed audit, a dispatch refusal whose settlement record
/// cannot be written settles the task on `-32005`.
#[tokio::test]
async fn a_failed_refusal_record_under_fail_closed_withholds() {
    use crate::security::audit::AuditFailurePolicy;
    let (task, settled, entries, _) = Box::pin(settled_task_with(
        (clean_answer(), Some(fail_closed())),
        task_invoke(2, "dispatch-refusal-withheld", json!({})),
        Some(AuditFailurePolicy::FailClosed),
    ))
    .await;
    assert!(
        settlements(&entries, &task).is_empty(),
        "premise: the settlement append failed: {entries:#?}"
    );
    assert!(settled.to_string().contains("-32005"), "{settled}");
}

/// Task reads stay unvouched: after a refused dispatch, no delivery record
/// (the creating call's or any `tasks/get`) carries the refusal.
#[tokio::test]
async fn a_task_read_after_a_dispatch_refusal_records_no_refusal() {
    let (_task, settled, entries) =
        Box::pin(settled_task(clean_answer(), Some(fail_closed()))).await;
    assert_eq!(status_of(&settled), "failed", "premise: refused: {settled}");
    let refused: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            entry["event"] == "response_delivery_attempt" && entry["response_effect"] == "refused"
        })
        .collect();
    assert!(refused.is_empty(), "{refused:#?}");
}
