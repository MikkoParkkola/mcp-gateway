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
    let settled = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    std::assert!(
        !settled.to_string().contains("mock-backend-answered"),
        "the deselected tool answered: {settled}"
    );
    std::assert_eq!(mock.calls(), 0, "the backend was called: {settled}");
    std::assert_eq!(status_of(&settled), "failed", "{settled}");
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
