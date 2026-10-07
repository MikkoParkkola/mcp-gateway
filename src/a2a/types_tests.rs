// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A2A 1.0 wire shapes, pinned against the specification tag v1.0.1.

use serde_json::json;

use super::*;

#[test]
fn a_user_message_serializes_in_the_1_0_shape() {
    let message = Message::user_text("hi");
    let wire = serde_json::to_value(&message).unwrap();
    assert_eq!(wire["role"], "ROLE_USER");
    assert_eq!(
        wire["parts"],
        json!([{"text": "hi"}]),
        "one content field, no kind"
    );
    assert!(wire.get("kind").is_none(), "kind is 0.3 vocabulary");
    assert!(
        wire["messageId"].as_str().is_some_and(|id| !id.is_empty()),
        "messageId is required: {wire}"
    );
    assert!(wire.get("contextId").is_none() && wire.get("taskId").is_none());
}

#[test]
fn every_user_message_gets_its_own_id() {
    assert_ne!(Message::user_text("a").id, Message::user_text("a").id);
}

#[test]
fn every_task_state_decodes_and_an_unknown_one_is_unspecified() {
    for (wire, state) in [
        ("TASK_STATE_SUBMITTED", TaskState::Submitted),
        ("TASK_STATE_WORKING", TaskState::Working),
        ("TASK_STATE_COMPLETED", TaskState::Completed),
        ("TASK_STATE_FAILED", TaskState::Failed),
        ("TASK_STATE_CANCELED", TaskState::Canceled),
        ("TASK_STATE_INPUT_REQUIRED", TaskState::InputRequired),
        ("TASK_STATE_REJECTED", TaskState::Rejected),
        ("TASK_STATE_AUTH_REQUIRED", TaskState::AuthRequired),
        ("TASK_STATE_FROM_THE_FUTURE", TaskState::Unspecified),
        ("completed", TaskState::Unspecified),
    ] {
        let decoded: TaskState = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(decoded, state, "{wire}");
    }
}

#[test]
fn only_a_jsonrpc_1_x_interface_is_spoken() {
    let interface = |binding: &str, version: &str| AgentInterface {
        url: "https://agent.invalid/a2a".into(),
        protocol_binding: binding.into(),
        protocol_version: version.into(),
        tenant: None,
    };
    assert!(interface("JSONRPC", "1.0").is_jsonrpc_v1());
    assert!(interface("JSONRPC", "1.2").is_jsonrpc_v1());
    assert!(!interface("JSONRPC", "0.3").is_jsonrpc_v1());
    assert!(!interface("GRPC", "1.0").is_jsonrpc_v1());
    assert!(!interface("HTTP+JSON", "1.0").is_jsonrpc_v1());
}

#[test]
fn a_reply_is_a_task_or_a_message() {
    let task: SendMessageResponse = serde_json::from_value(json!({"task": {
        "id": "t", "status": {"state": "TASK_STATE_WORKING"}}}))
    .unwrap();
    assert!(task.task.is_some() && task.message.is_none());
    let message: SendMessageResponse = serde_json::from_value(json!({"message": {
        "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "x"}]}}))
    .unwrap();
    assert!(message.message.is_some() && message.task.is_none());
}
