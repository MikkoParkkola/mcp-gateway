// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 4: a retained task result never leaves as `public`.

use super::*;
use serde_json::json;

/// A completed snapshot as an earlier release stored it: raw bytes, with the
/// retained result still claiming `public`.
const OLD_RECORD: &str = r#"{
  "version": 1,
  "tool": "old-tool",
  "task": {
    "taskId": "task-6f0f7bd8-6f0a-4f0e-8f2b-3c1f1e2d4a5b",
    "createdAt": "2026-09-01T00:00:00Z",
    "lastUpdatedAt": "2026-09-01T00:00:01Z",
    "ttlMs": null,
    "status": "completed",
    "result": {"content": [], "cacheScope": "public"}
  },
  "issuedInputKeys": []
}"#;

#[test]
fn the_fixture_really_holds_a_public_scope() {
    assert!(OLD_RECORD.contains("\"public\""));
}

#[test]
fn a_record_written_before_the_change_is_served_private() {
    let snapshot: TaskSnapshot = serde_json::from_str(OLD_RECORD).expect("old record parses");
    let task = Task::from_snapshot(snapshot).expect("old record restores");
    assert_eq!(task.result().expect("kept")["cacheScope"], "public");
    let wire = serde_json::to_value(task.wire()).expect("wire serializes");
    assert_eq!(wire["result"]["cacheScope"], "private", "{wire}");
}

#[test]
fn a_completed_task_is_stored_and_served_private() {
    let mut task = Task::create("probe");
    task.complete(json!({"content": [], "cacheScope": "public"}));
    let wire = serde_json::to_value(task.wire()).expect("wire serializes");
    assert_eq!(wire["result"]["cacheScope"], "private", "{wire}");
    let stored = serde_json::to_value(task.snapshot()).expect("snapshot serializes");
    assert_eq!(
        stored["task"]["result"]["cacheScope"], "private",
        "{stored}"
    );
}
