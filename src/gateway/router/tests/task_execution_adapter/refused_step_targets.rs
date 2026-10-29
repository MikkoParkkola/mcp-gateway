// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the gateway refuses before its backend is not a call the task
//! made: a refused plan step adds no target, and a refused single call
//! settles as the gateway's own answer, which no reader takes for backend
//! output. The backend's own count is the premise that nothing was sent.
use super::super::*;
use super::stored_result_policy::{install_playbook, playbook_call, withhold};
use super::support::*;

/// A playbook task's settled row as served, and its recorded targets.
async fn settled_targets(
    state: &Arc<AppState>,
    key: &str,
) -> (Value, Vec<crate::gateway::task_service::Target>) {
    let created = post(state, "key-a", playbook_call(2, key)).await;
    let id = task_id(&created);
    let settled = settled_row(state, &id).await;
    let done = serde_json::to_value(settled.task.wire()).unwrap_or(Value::Null);
    (
        done,
        state.task_executor.service.store.targets_for_test(&id),
    )
}

/// The task's row once settled, read from the store: a stored read through
/// `tasks/get` judges the caller's current view, so a row whose tool is
/// withheld is refused there, settled or not.
async fn settled_row(
    state: &Arc<AppState>,
    id: &str,
) -> crate::gateway::task_service::CommittedTask {
    use crate::protocol::tasks::TaskStatus;
    let owner = admission_principal();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(row) = state.tasks.get(&owner, id)
                && matches!(
                    row.task.status(),
                    TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                )
            {
                return row;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the task never settled"))
}

/// A step tool withheld between the task's intake and its run: the intake
/// admitted the playbook, and the worker's step is answered by the gateway.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_withheld_plan_step_records_no_target() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    install_playbook(&state, TOOL);
    let withheld = Arc::clone(&state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        withhold(&withheld, TOOL);
    });
    let (done, targets) = settled_targets(&state, "refused-withheld").await;
    std::assert_eq!(mock.calls(), 0, "premise: nothing sent: {done}");
    assert!(
        targets.is_empty(),
        "a refused step is not a target: {targets:?} ({done})"
    );
}

/// Control: the same playbook with nothing withheld records its one step.
#[tokio::test]
async fn a_sent_plan_step_records_its_target() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    install_playbook(&state, TOOL);
    let (done, targets) = settled_targets(&state, "refused-control").await;
    std::assert_eq!(mock.calls(), 1, "{done}");
    std::assert_eq!(
        crate::gateway::task_service::Target::pairs(&targets),
        vec![(BACKEND, TOOL)],
        "{done}"
    );
}

/// A single call whose tool is withheld between intake and run settles on
/// the gateway's own answer: the row records the gateway as its author, so
/// no reader takes the stored answer for the backend's.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refused_single_call_settles_as_the_gateways_answer() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = state_with(&mock).await;
    let withheld = Arc::clone(&state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        withhold(&withheld, TOOL);
    });
    let created = post(&state, "key-a", task_invoke(1, "refused-single", json!({}))).await;
    let id = task_id(&created);
    let row = settled_row(&state, &id).await;
    std::assert_eq!(mock.calls(), 0, "premise: nothing sent");
    std::assert_eq!(
        row.error_author,
        Some(crate::gateway::task_service::ErrorAuthor::Gateway),
        "the gateway answered this round"
    );
    assert!(
        row.backend_result().is_none() && row.backend_error().is_none(),
        "the gateway's answer is not backend output"
    );
    // On disk: a row this release creates is version 9 and stays so; the
    // author needs version 6 or later, so no rollback boundary moves.
    let file = store.path().join("tasks").join(format!("{id}.json"));
    let value: Value = serde_json::from_slice(&std::fs::read(&file).expect("the row's file"))
        .expect("the row is JSON");
    std::assert_eq!(value["version"], json!(9), "{value}");
    std::assert_eq!(value["errorAuthor"], json!("gateway"), "{value}");
}

/// Control: the same call, nothing withheld, keeps the backend's result.
#[tokio::test]
async fn a_sent_single_call_keeps_the_backends_result() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "sent-single", json!({}))).await;
    let row = settled_row(&state, &task_id(&created)).await;
    std::assert_eq!(mock.calls(), 1);
    std::assert_eq!(row.error_author, None);
    assert!(row.backend_result().is_some(), "the backend's answer");
}
