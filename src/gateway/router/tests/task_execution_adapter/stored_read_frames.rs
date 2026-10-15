// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 T3 (batch A): a task notification frame delivers stored
//! output only while the caller's current view still offers the target. Once
//! the listing withholds the tool, the frame carries the task id and status
//! only. A child of `notifications`, so it reads the same stream helpers.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{ReleasedOnDrop, expect_message, open_listen};

const OUTPUT: &str = "mock-backend-answered";

/// The listing relists the tool with a structurally invalid schema (P1b).
fn withhold_by_schema(state: &Arc<AppState>) {
    let invalid: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    state
        .backends
        .get(BACKEND)
        .expect("the mock is registered")
        .store_shared_tools_for_test(vec![invalid]);
}

/// A held task, a listener on it, then `before_release` and the release.
/// Returns the first frame that reports the task completed.
async fn completed_frame(key: &str, before_release: fn(&Arc<AppState>)) -> Value {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, key, json!({ "q": 1 }))).await;
    let id = task_id(&created);
    gate.0.wait_for_dispatch().await;
    let mut stream = open_listen(&state, "key-a", 7401, json!({ "taskIds": [&id] })).await;
    before_release(&state);
    gate.0.release_all();
    for _ in 0..4 {
        let frame = expect_message(&mut stream, "the task's completion frame").await;
        if frame.pointer("/params/status") == Some(&json!("completed")) {
            return frame;
        }
    }
    panic!("no completion frame for task {id}");
}

/// T3 control: while visible, the completion frame carries the output.
#[tokio::test]
async fn t3_control_a_visible_targets_completion_frame_carries_the_output() {
    let frame = completed_frame("s1-t3c", |_| {}).await;
    assert!(
        frame.to_string().contains(OUTPUT),
        "control: the frame carries the stored output: {frame}"
    );
}

/// T3: once the listing withholds the tool, the frame carries status only.
#[tokio::test]
async fn t3_a_withheld_targets_completion_frame_carries_status_only() {
    let frame = completed_frame("s1-t3", withhold_by_schema).await;
    assert!(
        !frame.to_string().contains(OUTPUT),
        "T3: the frame delivered the stored output of a withheld tool: {frame}"
    );
    assert!(
        frame.pointer("/params/taskId").is_some(),
        "T3: the frame still names the task: {frame}"
    );
}
