// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! Snapshot preservation and corrupt-state refusals for MODEL-05/07.

use super::*;
use serde_json::json;

fn restore(value: Value) -> Result<Task, TaskModelError> {
    let snapshot = serde_json::from_value(value).map_err(|_| TaskModelError::InvalidSnapshot)?;
    Task::from_snapshot(snapshot)
}

fn round_trip(data: Option<Value>) {
    let mut task = Task::create("snapshot-probe");
    task.fail(JsonRpcError {
        code: -32042,
        message: "backend failure".into(),
        data,
    });
    let before = serde_json::to_value(task.wire()).unwrap();
    let bytes = serde_json::to_vec(&task.snapshot()).unwrap();
    let restored = Task::from_snapshot(serde_json::from_slice(&bytes).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(restored.wire()).unwrap(),
        before,
        "private snapshot must preserve the exact public JSON-RPC error, including explicit null data"
    );
}

#[test]
fn explicit_null_error_data_survives_snapshot() {
    round_trip(Some(Value::Null));
}
#[test]
fn absent_error_data_survives_snapshot() {
    round_trip(None);
}
#[test]
fn nested_error_data_survives_snapshot() {
    round_trip(Some(json!({"nested": [null, 7]})));
}

#[test]
fn malformed_request_key_or_value_is_refused_atomically() {
    for (key, value) in [("", json!({"method":"roots/list"})), ("key", json!(7))] {
        let mut task = Task::create("input-probe");
        let before = serde_json::to_value(task.snapshot()).unwrap();
        let input = InputRequired {
            requests: vec![(key.into(), value)],
            request_state: None,
        };
        assert_eq!(
            task.transition(TaskTransition::RequireInput(input), Utc::now())
                .unwrap_err(),
            TaskModelError::InvalidInput
        );
        assert_eq!(serde_json::to_value(task.snapshot()).unwrap(), before);
    }
}

#[test]
fn every_snapshot_status_restores_only_its_own_complete_payload() {
    for event in [
        None,
        Some(TaskTransition::Complete(json!({"content":[]}))),
        Some(TaskTransition::Fail(JsonRpcError {
            code: -32603,
            message: "failed".into(),
            data: None,
        })),
        Some(TaskTransition::Cancel),
        Some(TaskTransition::RequireInput(InputRequired {
            requests: vec![("key".into(), json!({"method":"roots/list"}))],
            request_state: None,
        })),
    ] {
        let mut task = Task::create("snapshot-state-probe");
        if let Some(event) = event {
            task.transition(event, Utc::now()).unwrap();
        }
        let valid = serde_json::to_value(task.snapshot()).unwrap();
        let restored = restore(valid.clone()).unwrap();
        assert_eq!(serde_json::to_value(restored.snapshot()).unwrap(), valid);
        let status = task.status();
        for (field, value) in [
            ("result", json!({"content":[]})),
            ("error", json!({"code":-32603,"message":"failed"})),
            ("inputRequests", json!({"key":{"method":"roots/list"}})),
        ] {
            let expected = matches!(
                (status, field),
                (TaskStatus::Completed, "result")
                    | (TaskStatus::Failed, "error")
                    | (TaskStatus::InputRequired, "inputRequests")
            );
            let mut bad = valid.clone();
            if expected {
                bad["task"].as_object_mut().unwrap().remove(field);
            } else {
                bad["task"][field] = value;
            }
            assert!(
                restore(bad).is_err(),
                "{status:?} accepted an inconsistent {field}"
            );
        }
        if status == TaskStatus::InputRequired {
            for (field, value) in [
                ("inputRequests", json!({})),
                ("inputRequests", json!({"key":7})),
            ] {
                let mut bad = valid.clone();
                bad["task"][field] = value;
                assert!(restore(bad).is_err());
            }
            let mut bad = valid.clone();
            bad["issuedInputKeys"] = json!([]);
            assert!(restore(bad).is_err());
        }
    }
}

#[test]
fn noncanonical_or_non_v4_snapshot_ids_are_refused() {
    let valid = serde_json::to_value(Task::create("id-probe").snapshot()).unwrap();
    for id in [
        format!("task-{}", uuid::Uuid::new_v4().simple()),
        "task-00000000-0000-3000-8000-000000000000".to_owned(),
    ] {
        let mut bad = valid.clone();
        bad["task"]["taskId"] = json!(id);
        assert!(restore(bad).is_err());
    }
}
