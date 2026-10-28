// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway refusal inside a task worker's dispatch is tied to its task: the
//! settlement writes the task's own record, joined to the worker's dispatch
//! record by its trace. A backend's own error with the same code is not, and
//! no task read's delivery record gains the refusal.

use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

/// A gateway whose response contract fails closed: an answer from a tool with
/// no declared contract is refused inside the dispatch, with `-32603`.
async fn contract_state(
    log: Arc<crate::security::TransparencyLogger>,
    contract: bool,
) -> (Arc<AppState>, tempfile::TempDir) {
    super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            if contract {
                meta.set_response_contract(crate::config::ResponseContractConfig {
                    enabled: true,
                    action_mode: true,
                    fail_closed: true,
                    ..Default::default()
                });
            }
            meta.enable_transparency_log(log);
            meta
        },
    )
    .await
}

/// One task-augmented call answered with `answer`, run to its terminal
/// state: the task id, its terminal read, and every record in the log.
async fn settled_task(answer: Answer, contract: bool) -> (String, Value, Vec<Value>) {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let (_dir, log) = temp_log(None);
    let (state, _store) = contract_state(Arc::clone(&log), contract).await;
    let mock = MockBackend::answering(answer);
    register(&state, BACKEND, &mock);
    let created = post(
        &state,
        "key-a",
        task_invoke(2, "dispatch-refusal", json!({})),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(mock.calls() > 0, "premise: the worker reached the backend");
    let _ = delivery_rows(&log).await;
    let entries = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    (task, settled, entries)
}

/// The task's `task_settlement` records.
fn settlements<'a>(entries: &'a [Value], task: &str) -> Vec<&'a Value> {
    entries
        .iter()
        .filter(|entry| entry["route"] == "task_settlement" && entry["task_id"] == task)
        .collect()
}

/// A refusal the gateway's response contract decides inside the worker's
/// dispatch writes the task's settlement record, carrying the code the task
/// settles with and joined to the worker's dispatch record by trace. That
/// record's outcome is read from the code alone (`error`), so only this one
/// says the gateway refused.
#[tokio::test]
async fn a_dispatch_refusal_is_tied_to_its_task() {
    let (task, settled, entries) = Box::pin(settled_task(
        Answer::Result(json!({"content": [{"type": "text", "text": "ok"}], "isError": false})),
        true,
    ))
    .await;
    assert_eq!(status_of(&settled), "failed", "premise: refused: {settled}");
    let records = settlements(&entries, &task);
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
}

/// Paired control: a backend's own error with the same code is the
/// backend's, not a gateway refusal, and writes no settlement record.
#[tokio::test]
async fn a_backend_error_with_the_same_code_is_not_tied_as_a_refusal() {
    let (task, _settled, entries) =
        Box::pin(settled_task(Answer::FailureCode(-32603), false)).await;
    assert!(
        settlements(&entries, &task).is_empty(),
        "task {task}: no task_settlement record: {entries:#?}"
    );
}

/// Task reads stay unvouched: after a refused dispatch, no delivery record
/// (the creating call's or any `tasks/get`) carries the refusal.
#[tokio::test]
async fn a_task_read_after_a_dispatch_refusal_records_no_refusal() {
    let (_task, settled, entries) = Box::pin(settled_task(
        Answer::Result(json!({"content": [{"type": "text", "text": "ok"}], "isError": false})),
        true,
    ))
    .await;
    assert_eq!(status_of(&settled), "failed", "premise: refused: {settled}");
    let refused: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            entry["event"] == "response_delivery_attempt" && entry["response_effect"] == "refused"
        })
        .collect();
    assert!(refused.is_empty(), "{refused:#?}");
}
