// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A plan step the gateway refuses before its backend is not a call the task
//! made: the worker's dispatch log records no target and no replay call for
//! it. The backend's own count is the premise that nothing was sent.
use super::super::*;
use super::stored_result_policy::{install_playbook, playbook_call, withhold};
use super::support::*;

/// The settled row's recorded targets. Read from the store, not through
/// `tasks/get`: a stored read judges the caller's current view, so a row
/// whose step tool is withheld is refused there, settled or not.
async fn settled_targets(
    state: &Arc<AppState>,
    key: &str,
) -> (Value, Vec<crate::gateway::task_service::Target>) {
    use crate::protocol::tasks::TaskStatus;
    let created = post(state, "key-a", playbook_call(2, key)).await;
    let id = task_id(&created);
    let owner = admission_principal();
    let settled = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(row) = state.tasks.get(&owner, &id)
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
    .unwrap_or_else(|_| panic!("the task never settled"));
    let done = serde_json::to_value(settled.task.wire()).unwrap_or(Value::Null);
    (
        done,
        state.task_executor.service.store.targets_for_test(&id),
    )
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
