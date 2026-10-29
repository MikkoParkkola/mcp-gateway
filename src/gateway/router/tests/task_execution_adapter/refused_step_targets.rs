// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A plan step the gateway refuses before its backend is not a call the task
//! made: the worker's dispatch log records no target and no replay call for
//! it. The backend's own count is the premise that nothing was sent.
use super::super::*;
use super::stored_result_policy::{install_playbook, playbook_call, withhold};
use super::support::*;

/// The settled row's recorded targets, read once the task is terminal.
async fn settled_targets(
    state: &Arc<AppState>,
    key: &str,
) -> (Value, Vec<crate::gateway::task_service::Target>) {
    let created = post(state, "key-a", playbook_call(2, key)).await;
    let id = task_id(&created);
    let done = poll_until_terminal(state, "key-a", &id).await;
    (
        done,
        state.task_executor.service.store.targets_for_test(&id),
    )
}

/// A withheld step tool: the playbook step is answered by the gateway.
#[tokio::test]
async fn a_withheld_plan_step_records_no_target() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    install_playbook(&state, TOOL);
    withhold(&state, TOOL);
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
