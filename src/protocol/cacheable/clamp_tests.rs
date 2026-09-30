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
