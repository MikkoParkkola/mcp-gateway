// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's `allowed_tools`, on the timing path a stored task opens: the
//! call is admitted when the task is queued and runs later. A reload that
//! drops the tool from the selection between the two must refuse at the
//! worker's dispatch, with no backend call.
use std::time::Duration;

use super::super::*;
use super::support::*;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::transport::Transport;

/// Register a mock under `name`, as [`register`] does, offering only `tools`.
fn register_selected(state: &Arc<AppState>, name: &str, mock: &Arc<MockBackend>, tools: &[&str]) {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            enabled: true,
            allowed_tools: Some(tools.iter().map(ToString::to_string).collect()),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::clone(mock) as Arc<dyn Transport>;
    backend.set_transport_for_test(transport);
    assert!(state.backends.register(backend), "{name} registers");
}

/// The task is queued while [`TOOL`] is selected; the reload that narrows the
/// selection lands between the intake and the worker's dispatch. The worker
/// refuses, and the backend is never called.
#[tokio::test]
async fn a_task_queued_before_a_deselect_is_refused_at_its_dispatch() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let (reloaded, narrowed_mock) = (Arc::clone(&state), Arc::clone(&mock));
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        assert!(reloaded.backends.remove(BACKEND), "premise: registered");
        register_selected(&reloaded, BACKEND, &narrowed_mock, &["some_other_tool"]);
    });
    let created = post(&state, "key-a", task_invoke(1, "sel-deselect", json!({}))).await;
    let task = task_id(&created);
    // The committed record is the oracle: once the tool is out of the
    // selection, `tasks/get` judges the stored target as absent and never
    // shows the record.
    let owner = admission_principal();
    let committed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(committed) = state.tasks.get(&owner, &task) {
                use crate::protocol::tasks::TaskStatus;
                if matches!(
                    committed.task.status(),
                    TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                ) {
                    return committed;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the task never settled"));
    // The worker's dispatch answers a name outside the selection as it
    // answers any withheld name: as a lacked one (src/backend/input_keys.rs
    // "A withheld name answers as a lacked one", and meta_mcp/invoke/gate.rs
    // absent_answer), an isError result with the catalogue's miss text. The
    // task stores that answer; the backend's count is the oracle for "not
    // called".
    std::assert_eq!(mock.calls(), 0, "the backend was called");
    std::assert_eq!(
        committed.task.status(),
        crate::protocol::tasks::TaskStatus::Completed
    );
    std::assert_eq!(
        committed.task.result().cloned().unwrap_or(Value::Null),
        json!({
            "content": [{"type": "text", "text": crate::backend::text_absent(TOOL)}],
            "isError": true,
        }),
        "the stored answer is the withheld name's absent answer"
    );
    let read = get_task(&state, "key-a", &task).await;
    std::assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "the stored read answers the deselected tool as absent: {read}"
    );
}

/// Control: the same reload that keeps [`TOOL`] selected lets the task run.
#[tokio::test]
async fn a_task_queued_before_a_reload_that_keeps_it_runs() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let (reloaded, kept_mock) = (Arc::clone(&state), Arc::clone(&mock));
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        assert!(reloaded.backends.remove(BACKEND), "premise: registered");
        register_selected(&reloaded, BACKEND, &kept_mock, &[TOOL]);
    });
    let created = post(&state, "key-a", task_invoke(1, "sel-keep", json!({}))).await;
    let settled = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(mock.calls(), 1, "{settled}");
}
