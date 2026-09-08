// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! Bounded TASK.1 model assertions. No durable/store/transport acceptance claims.

use super::*;
use chrono::TimeZone;
use serde_json::json;

fn at(tick: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(1_800_000_000_000 + tick).unwrap()
}

fn task() -> Task {
    Task::create_at(
        "private-tool-name",
        at(0),
        TaskOptions {
            ttl_ms: Some(24_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

fn wire(task: &Task) -> Value {
    serde_json::to_value(task.wire()).unwrap()
}
fn snapshot(task: &Task) -> Value {
    serde_json::to_value(task.snapshot()).unwrap()
}
fn error() -> JsonRpcError {
    JsonRpcError {
        code: -32042,
        message: "upstream refused".into(),
        data: Some(json!({ "detail": [1, 2] })),
    }
}
fn requests(keys: &[&str]) -> InputRequired {
    InputRequired {
        requests: keys
            .iter()
            .map(|key| ((*key).into(), json!({ "method": "roots/list" })))
            .collect(),
        request_state: Some("private-backend-state".into()),
    }
}
fn apply(task: &mut Task, event: TaskTransition, tick: i64) -> TaskChange {
    let before = wire(task);
    let change = task.transition(event, at(tick)).expect("legal transition");
    if change.changed {
        let after = wire(task);
        let previous_time = DateTime::parse_from_rfc3339(before["lastUpdatedAt"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
        let updated_time = DateTime::parse_from_rfc3339(after["lastUpdatedAt"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(updated_time, previous_time.max(at(tick)));
        for field in ["createdAt", "ttlMs", "pollIntervalMs", "taskId"] {
            assert_eq!(
                after[field], before[field],
                "accepted transition changed {field}"
            );
        }
    }
    change
}
fn assert_only_payload(task: &Task, expected: &str, field: Option<&str>) {
    let value = wire(task);
    assert_eq!(value["status"], expected);
    let mut allowed = vec![
        "createdAt",
        "lastUpdatedAt",
        "pollIntervalMs",
        "status",
        "taskId",
        "ttlMs",
    ];
    allowed.extend(field);
    if value.get("statusMessage").is_some() {
        allowed.push("statusMessage");
    }
    allowed.sort_unstable();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        allowed
    );
    let public = value.to_string();
    for private in [
        "private-tool-name",
        "private-backend-state",
        "issuedInputKeys",
    ] {
        assert!(
            !public.contains(private),
            "private model data leaked: {public}"
        );
    }
    if expected != "input_required" {
        for old_key in ["r1-a", "r1-b", "r2-a"] {
            assert!(
                !public.contains(old_key),
                "input key history leaked: {public}"
            );
        }
    }
    for candidate in ["result", "error", "inputRequests"] {
        assert_eq!(
            value.get(candidate).is_some(),
            field == Some(candidate),
            "wrong payload in {value}"
        );
    }
}

#[test]
fn model_01_flat_metadata_nullability_and_private_data_boundary() {
    let task = task();
    let value = wire(&task);
    let object = value.as_object().unwrap();
    let expected = [
        "createdAt",
        "lastUpdatedAt",
        "pollIntervalMs",
        "status",
        "taskId",
        "ttlMs",
    ];
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(value["status"], "working");
    assert_eq!(value["ttlMs"], 24_000);
    assert_eq!(value["pollIntervalMs"], 1_000);
    for field in ["createdAt", "lastUpdatedAt"] {
        assert_eq!(
            DateTime::parse_from_rfc3339(value[field].as_str().unwrap())
                .unwrap()
                .with_timezone(&Utc),
            at(0)
        );
    }
    let id = value["taskId"].as_str().unwrap();
    assert_eq!(id, task.id());
    let uuid = uuid::Uuid::parse_str(id.strip_prefix("task-").unwrap()).unwrap();
    assert_eq!(uuid.get_version_num(), 4);
    assert_eq!(task.tool(), "private-tool-name");
    assert!(!value.to_string().contains("private-tool-name"));
    let unlimited = Task::create_at(
        "other",
        at(0),
        TaskOptions {
            ttl_ms: None,
            poll_interval_ms: None,
        },
    );
    assert_ne!(task.id(), unlimited.id());
    let value = wire(&unlimited);
    assert!(value.as_object().unwrap().contains_key("ttlMs"));
    assert!(value["ttlMs"].is_null());
    assert!(value.get("pollIntervalMs").is_none());
}

#[test]
fn model_02_all_five_status_payloads_and_error_data_are_preserved() {
    let mut task = task();
    assert_only_payload(&task, "working", None);
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r1-a"])),
            1
        )
        .changed
    );
    assert_eq!(task.status(), TaskStatus::InputRequired);
    assert_only_payload(&task, "input_required", Some("inputRequests"));
    assert!(!wire(&task).to_string().contains("private-backend-state"));
    let mut failed = task.clone();
    assert!(apply(&mut failed, TaskTransition::Fail(error()), 2).changed);
    assert_only_payload(&failed, "failed", Some("error"));
    assert_eq!(
        wire(&failed)["error"],
        json!({ "code": -32042, "message": "upstream refused", "data": { "detail": [1, 2] } })
    );
    let mut cancelled = task.clone();
    assert!(apply(&mut cancelled, TaskTransition::Cancel, 2).changed);
    assert_only_payload(&cancelled, "cancelled", None);
    let result =
        json!({ "content": [{ "type": "text", "text": "tool refused" }], "isError": true });
    assert!(apply(&mut task, TaskTransition::Complete(result.clone()), 2).changed);
    assert_only_payload(&task, "completed", Some("result"));
    assert_eq!(wire(&task)["result"], result);
    assert!(task.error().is_none());
}

#[test]
fn model_03_every_terminal_state_resists_every_late_event_and_timestamp_change() {
    for input_first in [false, true] {
        for terminal in [
            TaskTransition::Complete(json!({ "answer": 42 })),
            TaskTransition::Fail(error()),
            TaskTransition::Cancel,
        ] {
            let mut task = task();
            if input_first {
                assert!(
                    apply(
                        &mut task,
                        TaskTransition::RequireInput(requests(&["r1-a"])),
                        1
                    )
                    .changed
                );
            }
            assert!(apply(&mut task, terminal, 2).changed);
            let before = wire(&task);
            let durable = snapshot(&task);
            for event in [
                TaskTransition::Complete(json!({ "answer": "late" })),
                TaskTransition::Fail(error()),
                TaskTransition::Cancel,
                TaskTransition::RequireInput(requests(&["r2-a"])),
                TaskTransition::ProvideInput(json!({ "r1-a": { "roots": [] } })),
                TaskTransition::StatusMessage(Some("late".into())),
            ] {
                let change = apply(&mut task, event, 99);
                assert!(!change.changed);
                assert!(change.accepted_inputs.is_empty());
                assert_eq!(wire(&task), before);
                assert_eq!(snapshot(&task), durable);
            }
        }
    }
}

#[test]
fn model_04_partial_unknown_duplicate_and_final_input_have_distinct_effects() {
    let mut task = task();
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r1-a", "r1-b"])),
            1
        )
        .changed
    );
    let first = json!({ "roots": [{ "uri": "file:///a", "name": "first" }] });
    let change = apply(
        &mut task,
        TaskTransition::ProvideInput(json!({ "unknown": { "roots": [] }, "r1-a": first })),
        2,
    );
    assert!(change.changed);
    assert_eq!(
        change.accepted_inputs,
        serde_json::from_value::<Map<String, Value>>(json!({ "r1-a": first })).unwrap()
    );
    assert_eq!(task.status(), TaskStatus::InputRequired);
    assert_eq!(
        wire(&task)["inputRequests"],
        json!({ "r1-b": { "method": "roots/list" } })
    );
    let before = snapshot(&task);
    let repeated = apply(
        &mut task,
        TaskTransition::ProvideInput(
            json!({ "r1-a": { "roots": ["wrong-late-answer"] }, "unknown": {} }),
        ),
        3,
    );
    assert!(!repeated.changed);
    assert!(repeated.accepted_inputs.is_empty());
    assert_eq!(snapshot(&task), before);
    let final_answer = apply(
        &mut task,
        TaskTransition::ProvideInput(json!({ "r1-b": { "roots": [] } })),
        4,
    );
    assert!(final_answer.changed);
    assert_eq!(final_answer.accepted_inputs.len(), 1);
    assert_only_payload(&task, "working", None);
    let before = snapshot(&task);
    assert!(
        !apply(
            &mut task,
            TaskTransition::ProvideInput(json!({ "r1-b": { "roots": [] } })),
            5
        )
        .changed
    );
    assert_eq!(snapshot(&task), before);
}

#[test]
fn model_04_invalid_input_types_reject_atomically_even_with_a_valid_peer() {
    let mut task = task();
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r1-a", "r1-b"])),
            1
        )
        .changed
    );
    for invalid in [
        Value::Null,
        json!([]),
        json!("bad"),
        json!({ "r1-a": { "roots": [] }, "r1-b": 7 }),
    ] {
        let before = snapshot(&task);
        assert_eq!(
            task.transition(TaskTransition::ProvideInput(invalid), at(2))
                .unwrap_err(),
            TaskModelError::InvalidInput
        );
        assert_eq!(snapshot(&task), before);
    }
    let accepted = apply(
        &mut task,
        TaskTransition::ProvideInput(json!({ "r1-a": { "roots": [] }, "r1-b": { "roots": [] } })),
        3,
    );
    assert_eq!(accepted.accepted_inputs.len(), 2);
    assert_eq!(task.status(), TaskStatus::Working);
}

#[test]
fn model_05_round_keys_are_unique_and_an_outstanding_round_cannot_be_replaced() {
    let mut task = task();
    for keys in [vec![], vec!["same", "same"]] {
        let before = snapshot(&task);
        assert!(
            task.transition(TaskTransition::RequireInput(requests(&keys)), at(1))
                .is_err()
        );
        assert_eq!(snapshot(&task), before);
    }
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r1-a"])),
            2
        )
        .changed
    );
    let before = snapshot(&task);
    assert_eq!(
        task.transition(TaskTransition::RequireInput(requests(&["r2-a"])), at(3))
            .unwrap_err(),
        TaskModelError::InvalidTransition
    );
    assert_eq!(snapshot(&task), before);
    assert!(
        apply(
            &mut task,
            TaskTransition::ProvideInput(json!({ "r1-a": { "roots": [] } })),
            4
        )
        .changed
    );
    let before = snapshot(&task);
    assert_eq!(
        task.transition(TaskTransition::RequireInput(requests(&["r1-a"])), at(5))
            .unwrap_err(),
        TaskModelError::InvalidInput
    );
    assert_eq!(snapshot(&task), before);
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r2-a"])),
            6
        )
        .changed
    );
    assert_eq!(
        wire(&task)["inputRequests"],
        json!({ "r2-a": { "method": "roots/list" } })
    );
}

#[test]
fn model_06_timestamps_follow_mutations_and_record_options_stay_immutable() {
    let mut task = task();
    let original = wire(&task);
    assert!(
        apply(
            &mut task,
            TaskTransition::StatusMessage(Some("waiting".into())),
            10
        )
        .changed
    );
    assert_eq!(wire(&task)["statusMessage"], "waiting");
    assert_eq!(
        DateTime::parse_from_rfc3339(wire(&task)["lastUpdatedAt"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc),
        at(10)
    );
    let before = snapshot(&task);
    assert!(
        !apply(
            &mut task,
            TaskTransition::StatusMessage(Some("waiting".into())),
            20
        )
        .changed
    );
    assert_eq!(snapshot(&task), before);
    assert!(apply(&mut task, TaskTransition::StatusMessage(None), 5).changed);
    assert!(wire(&task).get("statusMessage").is_none());
    assert_eq!(
        wire(&task)["lastUpdatedAt"],
        before["task"]["lastUpdatedAt"]
    );
    assert!(
        apply(
            &mut task,
            TaskTransition::Complete(json!({ "ok": true })),
            30
        )
        .changed
    );
    for field in ["createdAt", "ttlMs", "pollIntervalMs", "taskId"] {
        assert_eq!(wire(&task)[field], original[field]);
    }
}

#[test]
fn model_07_private_snapshot_round_trip_preserves_consumed_key_history() {
    let mut task = task();
    assert!(
        apply(
            &mut task,
            TaskTransition::RequireInput(requests(&["r1-a", "r1-b"])),
            1
        )
        .changed
    );
    assert!(
        apply(
            &mut task,
            TaskTransition::ProvideInput(json!({ "r1-a": { "roots": [] } })),
            2
        )
        .changed
    );
    let encoded = serde_json::to_vec(&task.snapshot()).unwrap();
    let mut restored = Task::from_snapshot(serde_json::from_slice(&encoded).unwrap()).unwrap();
    assert_eq!(restored.tool(), "private-tool-name");
    assert_eq!(wire(&restored), wire(&task));
    assert!(
        apply(
            &mut restored,
            TaskTransition::ProvideInput(json!({ "r1-b": { "roots": [] } })),
            3
        )
        .changed
    );
    assert!(
        restored
            .transition(TaskTransition::RequireInput(requests(&["r1-a"])), at(4))
            .is_err()
    );
    assert!(
        apply(
            &mut restored,
            TaskTransition::RequireInput(requests(&["r2-a"])),
            5
        )
        .changed
    );
    let public = wire(&restored).to_string();
    for private in [
        "private-tool-name",
        "private-backend-state",
        "r1-a",
        "r1-b",
        "issuedInputKeys",
    ] {
        assert!(
            !public.contains(private),
            "private model value leaked: {public}"
        );
    }
}

#[test]
fn model_07_invalid_snapshots_cannot_reopen_or_invent_task_state() {
    let task = task();
    let valid = snapshot(&task);
    assert_eq!(
        wire(&Task::from_snapshot(serde_json::from_value(valid.clone()).unwrap()).unwrap()),
        wire(&task)
    );
    let mut variants = vec![];
    let mut bad = valid.clone();
    bad["version"] = json!(99);
    variants.push(bad);
    let mut bad = valid.clone();
    bad["task"]["lastUpdatedAt"] = json!("1900-01-01T00:00:00Z");
    variants.push(bad);
    let mut bad = valid.clone();
    bad["task"].as_object_mut().unwrap().remove("ttlMs");
    variants.push(bad);
    let mut bad = valid.clone();
    bad["task"]["ttlMs"] = json!(-1);
    variants.push(bad);
    let mut bad = valid.clone();
    bad["task"]["status"] = json!("completed");
    variants.push(bad);
    let mut bad = valid;
    bad["task"]["taskId"] = json!("../../other-task");
    variants.push(bad);
    for bad in variants {
        let restored = serde_json::from_value::<TaskSnapshot>(bad)
            .ok()
            .and_then(|snapshot| Task::from_snapshot(snapshot).ok());
        assert!(restored.is_none(), "corrupt snapshot became a valid model");
    }
}

#[test]
fn model_02_non_object_completion_is_rejected_without_settling() {
    let mut task = task();
    let before = snapshot(&task);
    assert_eq!(
        task.transition(TaskTransition::Complete(json!("not-a-tool-result")), at(1))
            .unwrap_err(),
        TaskModelError::InvalidInput
    );
    assert_eq!(snapshot(&task), before);
    assert_eq!(task.status(), TaskStatus::Working);
    assert!(
        apply(
            &mut task,
            TaskTransition::Complete(json!({ "content": [] })),
            2
        )
        .changed
    );
}
