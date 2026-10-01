// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 4: the `tasks/get` envelope's `result` slot.

use crate::gateway::task_route::task_envelope;
use crate::protocol::tasks::Task;
use serde_json::json;

#[test]
fn tasks_get_envelope_carries_a_retained_public_scope_as_private() {
    let mut task = Task::create("probe");
    task.complete(json!({"content": [], "cacheScope": "public"}));
    assert_eq!(task.result().expect("completed")["cacheScope"], "public");

    let envelope = task_envelope(&task, "complete");

    assert_eq!(envelope["status"], "completed", "{envelope}");
    assert_eq!(envelope["result"]["cacheScope"], "private", "{envelope}");
}
