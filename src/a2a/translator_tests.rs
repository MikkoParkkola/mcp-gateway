// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Card -> tool and reply -> MCP result, pinned row by row.

use serde_json::{Value, json};

use super::*;

fn reply(value: Value) -> SendMessageResponse {
    serde_json::from_value(value).unwrap()
}

fn completed(parts: &Value) -> SendMessageResponse {
    reply(
        json!({"task": {"id": "t1", "status": {"state": "TASK_STATE_COMPLETED"},
        "artifacts": [{"artifactId": "a", "parts": parts}]}}),
    )
}

#[test]
fn a_card_is_one_tool_whose_text_carries_the_skills() {
    let card: AgentCard = serde_json::from_value(json!({"name": "Travel", "skills": [
        {"id": "s1", "name": "Flights", "description": "Finds flights", "tags": ["air"],
         "examples": ["HEL to AMS"]},
        {"id": "s2", "name": "Hotels"}
    ]}))
    .unwrap();
    let tool = card_to_tool(&card);
    assert_eq!(tool.name, TOOL_NAME);
    let text = tool.description.unwrap();
    for needle in ["Flights: Finds flights", "[air]", "HEL to AMS", "Hotels"] {
        assert!(text.contains(needle), "{needle} in {text}");
    }
    assert_eq!(tool.input_schema["required"], json!(["message"]));
    assert!(tool.input_schema["properties"].get("context_id").is_none());
}

#[test]
fn every_part_kind_is_kept() {
    let result = reply_to_result(&completed(&json!([
        {"text": "hello"},
        {"data": {"k": 1}},
        {"raw": "AAEC", "mediaType": "image/png"},
        {"url": "https://files.invalid/x.pdf", "filename": "x.pdf", "mediaType": "application/pdf"}
    ])));
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"], json!({"k": 1}));
    let content = result["content"].as_array().unwrap();
    assert_eq!(content[0], json!({"type": "text", "text": "hello"}));
    assert_eq!(content[1], json!({"type": "text", "text": "{\"k\":1}"}));
    assert_eq!(content[2]["resource"]["blob"], "AAEC");
    assert_eq!(content[2]["resource"]["mimeType"], "image/png");
    assert_eq!(content[3]["type"], "resource_link");
    assert_eq!(content[3]["name"], "x.pdf");
}

#[test]
fn structured_content_is_only_a_sole_object() {
    let array = reply_to_result(&completed(&json!([{"data": [1, 2]}])));
    assert!(array.get("structuredContent").is_none());
    let two = reply_to_result(&completed(&json!([{"data": {"a": 1}}, {"data": {"b": 2}}])));
    assert!(
        two.get("structuredContent").is_none(),
        "two data parts: no single object"
    );
}

#[test]
fn a_message_reply_is_an_answer_and_an_empty_one_says_so() {
    let result = reply_to_result(&reply(json!({"message": {
        "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "direct"}]}})));
    assert_eq!(result["content"][0]["text"], "direct");
    let empty = reply_to_result(&completed(&json!([])));
    assert_eq!(empty["isError"], false);
    assert_eq!(
        empty["content"][0]["text"],
        "The agent returned no content."
    );
}

#[test]
fn every_other_state_is_a_tool_error_with_the_agents_words() {
    for state in [
        "TASK_STATE_FAILED",
        "TASK_STATE_REJECTED",
        "TASK_STATE_CANCELED",
        "TASK_STATE_INPUT_REQUIRED",
        "TASK_STATE_AUTH_REQUIRED",
        "TASK_STATE_WORKING",
        "TASK_STATE_SUBMITTED",
        "TASK_STATE_SOMETHING_NEW",
    ] {
        let result = reply_to_result(&reply(json!({"task": {"id": "t", "status": {
            "state": state,
            "message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "why"}]}}}})));
        assert_eq!(result["isError"], true, "{state}");
        let text = result["content"][0]["text"].as_str().unwrap();
        if !matches!(
            state,
            "TASK_STATE_WORKING" | "TASK_STATE_SUBMITTED" | "TASK_STATE_SOMETHING_NEW"
        ) {
            assert!(text.contains("why"), "{state}: {text}");
        }
    }
}

#[test]
fn a_null_data_part_is_an_answer_not_empty_content() {
    let result = reply_to_result(&completed(&json!([{"data": null}])));
    assert_eq!(result["content"], json!([{"type": "text", "text": "null"}]));
    assert!(result.get("structuredContent").is_none());
}
