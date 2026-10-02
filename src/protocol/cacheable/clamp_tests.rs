// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 11: the delivery clamp and its serializer.

use super::{clamp_delivered_scope, message_event_data};
use crate::protocol::{JsonRpcResponse, RequestId};
use serde_json::{Value, json};

fn delivered(result: Value) -> Value {
    let response = JsonRpcResponse::success(RequestId::Number(1), result);
    serde_json::to_value(&response).expect("a response serializes")
}

#[test]
fn absent_scope_stays_absent() {
    let wire = delivered(json!({"content": []}));
    assert!(wire["result"].get("cacheScope").is_none(), "{wire}");
}

#[test]
fn private_scope_is_unchanged() {
    let wire = delivered(json!({"cacheScope": "private", "ttlMs": 5}));
    assert_eq!(wire["result"], json!({"cacheScope": "private", "ttlMs": 5}));
}

#[test]
fn every_non_private_scope_is_delivered_as_private() {
    for scope in [json!("public"), Value::Null, json!(7), json!("shared")] {
        let wire = delivered(json!({"cacheScope": scope.clone()}));
        assert_eq!(wire["result"]["cacheScope"], "private", "input {scope}");
    }
}

#[test]
fn nested_scopes_and_json_strings_are_preserved() {
    let text = r#"{"cacheScope":"public"}"#;
    let wire = delivered(json!({
        "cacheScope": "public",
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"cacheScope": "public"}
    }));
    assert_eq!(wire["result"]["cacheScope"], "private", "{wire}");
    assert_eq!(wire["result"]["content"][0]["text"], text, "{wire}");
    assert_eq!(
        wire["result"]["structuredContent"]["cacheScope"], "public",
        "{wire}"
    );
}

#[test]
fn a_batch_is_clamped_per_response() {
    let batch = vec![
        JsonRpcResponse::success(RequestId::Number(1), json!({"cacheScope": "public"})),
        JsonRpcResponse::success(RequestId::Number(2), json!({"cacheScope": "private"})),
    ];
    let wire = serde_json::to_value(&batch).expect("a batch serializes");
    assert_eq!(wire[0]["result"]["cacheScope"], "private", "{wire}");
    assert_eq!(wire[1]["result"]["cacheScope"], "private", "{wire}");
}

#[test]
fn a_response_serialized_as_text_is_clamped() {
    // The SSE and stdio writers serialize the response to text.
    let response = JsonRpcResponse::success(RequestId::Number(3), json!({"cacheScope": "public"}));
    let text = serde_json::to_string(&response).expect("a response serializes");
    let wire: Value = serde_json::from_str(&text).expect("text parses back");
    assert_eq!(wire["result"]["cacheScope"], "private", "{text}");
}

#[test]
fn clamp_rewrites_only_the_top_level_key_of_an_object() {
    let mut result = json!({"cacheScope": "public", "inner": {"cacheScope": "public"}});
    clamp_delivered_scope(&mut result);
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(result["inner"]["cacheScope"], "public");
    let mut not_an_object = json!(["public"]);
    clamp_delivered_scope(&mut not_an_object);
    assert_eq!(not_an_object, json!(["public"]));
}

#[test]
fn a_message_response_payload_is_clamped_and_a_notification_is_not() {
    let response = json!({"jsonrpc": "2.0", "id": 1, "result": {"cacheScope": "public"}});
    let data: Value = serde_json::from_str(&message_event_data(&response)).expect("json");
    assert_eq!(data["result"]["cacheScope"], "private", "{data}");

    let notification = json!({"jsonrpc": "2.0", "method": "notifications/x", "params": {
        "cacheScope": "public"}});
    assert_eq!(message_event_data(&notification), notification.to_string());
}

#[test]
fn a_message_batch_clamps_each_response_and_spares_notifications() {
    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "result": {"cacheScope": "public"}},
        {"jsonrpc": "2.0", "method": "notifications/x", "params": {"cacheScope": "public"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"cacheScope": "private"}}
    ]);
    let data: Value = serde_json::from_str(&message_event_data(&batch)).expect("json");
    assert_eq!(data[0]["result"]["cacheScope"], "private", "{data}");
    assert_eq!(data[1]["params"]["cacheScope"], "public", "{data}");
    assert_eq!(data[2]["result"]["cacheScope"], "private", "{data}");
}

#[test]
fn a_raw_task_envelope_clamps_its_retained_result_only() {
    let mut envelope = json!({
        "taskId": "t1", "status": "completed",
        "result": {"cacheScope": "public", "inner": {"cacheScope": "public"}}
    });
    clamp_delivered_scope(&mut envelope);
    assert_eq!(envelope["result"]["cacheScope"], "private");
    assert_eq!(envelope["result"]["inner"]["cacheScope"], "public");

    let mut not_a_task = json!({"result": {"cacheScope": "public"}});
    clamp_delivered_scope(&mut not_a_task);
    assert_eq!(not_a_task["result"]["cacheScope"], "public");
}

/// MIK-7702: error data claims no scope either. It is not a cacheable result,
/// but a malformed backend's `cacheScope` there is delivered as `private`.
#[test]
fn error_data_is_delivered_private() {
    let mut response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "failed");
    response.error.as_mut().expect("an error").data =
        Some(json!({"cacheScope": "public", "inner": {"cacheScope": "public"}}));
    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert_eq!(wire["error"]["data"]["cacheScope"], "private", "{wire}");
    assert_eq!(
        wire["error"]["data"]["inner"]["cacheScope"], "public",
        "{wire}"
    );

    // The SSE path clamps a raw payload, not a serialized response.
    let mut raw = wire;
    raw["error"]["data"]["cacheScope"] = json!("public");
    let data: Value = serde_json::from_str(&message_event_data(&raw)).expect("JSON");
    assert_eq!(data["error"]["data"]["cacheScope"], "private", "{data}");
}

/// MIK-7702: a task envelope whose `taskId` is not a string still has its
/// retained result followed, while tool data that merely nests the same keys
/// is untouched.
#[test]
fn a_task_envelope_with_a_non_string_task_id_clamps_its_retained_result() {
    for task_id in [json!(7), Value::Null, json!({"id": "t1"})] {
        let mut envelope = json!({
            "taskId": task_id.clone(), "status": "completed",
            "result": {"cacheScope": "public"}
        });
        clamp_delivered_scope(&mut envelope);
        assert_eq!(
            envelope["result"]["cacheScope"], "private",
            "taskId {task_id}"
        );
    }

    let mut no_status = json!({"taskId": 7, "result": {"cacheScope": "public"}});
    clamp_delivered_scope(&mut no_status);
    assert_eq!(
        no_status["result"]["cacheScope"], "public",
        "a non-string taskId without a status is not an envelope"
    );

    let mut tool = json!({"structuredContent": {
        "taskId": 7, "status": "completed", "result": {"cacheScope": "public"}
    }});
    clamp_delivered_scope(&mut tool);
    assert_eq!(
        tool["structuredContent"]["result"]["cacheScope"], "public",
        "nested tool data is untouched"
    );
}

/// MIK-7702: the retained slot is followed once. A retained result that itself
/// looks like an envelope is tool data and keeps its nested scope.
#[test]
fn the_retained_slot_is_followed_once_not_recursively() {
    let mut envelope = json!({
        "taskId": 7, "status": "completed",
        "result": {
            "cacheScope": "public",
            "taskId": "t2", "status": "completed",
            "result": {"cacheScope": "public"}
        }
    });
    clamp_delivered_scope(&mut envelope);
    assert_eq!(envelope["result"]["cacheScope"], "private");
    assert_eq!(envelope["result"]["result"]["cacheScope"], "public");
}
