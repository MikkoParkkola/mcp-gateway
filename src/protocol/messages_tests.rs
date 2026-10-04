// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
/// A frame carrying `method` is a request or notification. Deserializing it
/// as a response is what let an inbound `sampling/createMessage` be handed
/// back to a waiting caller as its (empty) answer.
#[test]
fn response_deser_rejects_frame_carrying_method() {
    let frame = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let outcome = serde_json::from_str::<JsonRpcResponse>(frame);
    assert!(
        outcome.is_err(),
        "expected rejection, got {:?}",
        outcome.ok()
    );
}

/// The stricter impl must not shift how the untagged `JsonRpcMessage` enum
/// classifies either frame shape.
#[test]
fn message_enum_still_classifies_both_frame_shapes() {
    let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}"#;
    assert!(matches!(
        serde_json::from_str::<JsonRpcMessage>(req).unwrap(),
        JsonRpcMessage::Request(_)
    ));

    let res = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[]}}"#;
    assert!(matches!(
        serde_json::from_str::<JsonRpcMessage>(res).unwrap(),
        JsonRpcMessage::Response(_)
    ));

    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    assert!(matches!(
        serde_json::from_str::<JsonRpcMessage>(note).unwrap(),
        JsonRpcMessage::Notification(_)
    ));
}

use super::*;
use serde_json::json;

// ── ResourcesReadParams ───────────────────────────────────────────

#[test]
fn resources_read_params_serializes() {
    let params = ResourcesReadParams {
        uri: "file:///README.md".to_string(),
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["uri"], "file:///README.md");
}

#[test]
fn resources_read_params_deserializes() {
    let json = json!({"uri": "https://example.com/data"});
    let params: ResourcesReadParams = serde_json::from_value(json).unwrap();
    assert_eq!(params.uri, "https://example.com/data");
}

// ── ResourcesReadResult ───────────────────────────────────────────

#[test]
fn resources_read_result_with_text_content() {
    let result = ResourcesReadResult {
        contents: vec![super::super::ResourceContents::Text {
            uri: "file:///test.txt".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: "Hello world".to_string(),
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["contents"][0]["text"], "Hello world");
    assert_eq!(json["contents"][0]["uri"], "file:///test.txt");
}

#[test]
fn resources_read_result_empty_contents() {
    let result = ResourcesReadResult { contents: vec![] };
    let json = serde_json::to_value(&result).unwrap();
    assert!(json["contents"].as_array().unwrap().is_empty());
}

// ── ResourcesTemplatesListParams ──────────────────────────────────

#[test]
fn resources_templates_list_params_default_has_no_cursor() {
    let params = ResourcesTemplatesListParams::default();
    assert!(params.cursor.is_none());
    let json = serde_json::to_value(&params).unwrap();
    assert!(json.get("cursor").is_none());
}

#[test]
fn resources_templates_list_params_with_cursor() {
    let params = ResourcesTemplatesListParams {
        cursor: Some("abc123".to_string()),
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["cursor"], "abc123");
}

// ── ResourcesTemplatesListResult ──────────────────────────────────

#[test]
fn resources_templates_list_result_uses_camel_case() {
    let result = ResourcesTemplatesListResult {
        resource_templates: vec![super::super::ResourceTemplate {
            uri_template: "file:///{path}".to_string(),
            name: "file".to_string(),
            title: None,
            description: None,
            mime_type: None,
        }],
        next_cursor: Some("next".to_string()),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert!(json.get("resourceTemplates").is_some());
    assert_eq!(json["nextCursor"], "next");
}

// ── ResourcesSubscribeParams ──────────────────────────────────────

#[test]
fn resources_subscribe_params_roundtrip() {
    let original = ResourcesSubscribeParams {
        uri: "file:///watched.txt".to_string(),
    };
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: ResourcesSubscribeParams = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.uri, original.uri);
}

// ── ResourcesUnsubscribeParams ────────────────────────────────────

#[test]
fn resources_unsubscribe_params_roundtrip() {
    let original = ResourcesUnsubscribeParams {
        uri: "file:///watched.txt".to_string(),
    };
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: ResourcesUnsubscribeParams = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.uri, original.uri);
}

// ── PromptsGetParams ──────────────────────────────────────────────

#[test]
fn prompts_get_params_with_arguments() {
    let params = PromptsGetParams {
        name: "review_code".to_string(),
        arguments: Some(HashMap::from([
            ("language".to_string(), "rust".to_string()),
            ("style".to_string(), "concise".to_string()),
        ])),
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["name"], "review_code");
    assert_eq!(json["arguments"]["language"], "rust");
}

#[test]
fn prompts_get_params_without_arguments() {
    let params = PromptsGetParams {
        name: "greeting".to_string(),
        arguments: None,
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["name"], "greeting");
    assert!(json.get("arguments").is_none());
}

#[test]
fn prompts_get_params_deserializes_from_json() {
    let json = json!({
        "name": "summarize",
        "arguments": {"length": "short"}
    });
    let params: PromptsGetParams = serde_json::from_value(json).unwrap();
    assert_eq!(params.name, "summarize");
    assert_eq!(
        params.arguments.as_ref().unwrap().get("length").unwrap(),
        "short"
    );
}

// ── PromptsGetResult ──────────────────────────────────────────────

#[test]
fn prompts_get_result_with_messages() {
    let result = PromptsGetResult {
        description: Some("A helpful prompt".to_string()),
        messages: vec![super::super::PromptMessage {
            role: "user".to_string(),
            content: super::super::Content::Text {
                text: "Summarize this document.".to_string(),
                annotations: None,
            },
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["description"], "A helpful prompt");
    assert_eq!(json["messages"][0]["role"], "user");
}

#[test]
fn prompts_get_result_no_description() {
    let result = PromptsGetResult {
        description: None,
        messages: vec![],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert!(json.get("description").is_none());
    assert!(json["messages"].as_array().unwrap().is_empty());
}

// ── LoggingSetLevelParams ─────────────────────────────────────────

#[test]
fn logging_set_level_params_serializes() {
    let params = LoggingSetLevelParams {
        level: super::super::LoggingLevel::Error,
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["level"], "error");
}

#[test]
fn logging_set_level_params_deserializes() {
    let json = json!({"level": "debug"});
    let params: LoggingSetLevelParams = serde_json::from_value(json).unwrap();
    assert_eq!(params.level, super::super::LoggingLevel::Debug);
}

// ── RootsListResult ───────────────────────────────────────────────

#[test]
fn roots_list_result_serializes() {
    let result = RootsListResult {
        roots: vec![super::super::Root {
            uri: "file:///home/user".to_string(),
            name: Some("Home".to_string()),
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["roots"][0]["uri"], "file:///home/user");
    assert_eq!(json["roots"][0]["name"], "Home");
}

// ── ElicitationCreateParams ───────────────────────────────────────

#[test]
fn elicitation_create_params_with_schema() {
    let params = ElicitationCreateParams {
        mode: None,
        message: "Enter your name".to_string(),
        requested_schema: Some(
            json!({"type": "object", "properties": {"name": {"type": "string"}}}),
        ),
        url: None,
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["message"], "Enter your name");
    assert!(json.get("requestedSchema").is_some());
}

#[test]
fn elicitation_create_params_without_schema() {
    let params = ElicitationCreateParams {
        mode: None,
        message: "Confirm action".to_string(),
        requested_schema: None,
        url: None,
    };
    let json = serde_json::to_value(&params).unwrap();
    assert!(json.get("requestedSchema").is_none());
}

// ── ElicitationCreateResult ───────────────────────────────────────

#[test]
fn elicitation_create_result_accept() {
    let result = ElicitationCreateResult {
        action: "accept".to_string(),
        content: Some(json!({"name": "Alice"})),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["action"], "accept");
    assert_eq!(json["content"]["name"], "Alice");
}

#[test]
fn elicitation_create_result_decline() {
    let result = ElicitationCreateResult {
        action: "decline".to_string(),
        content: None,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["action"], "decline");
    assert!(json.get("content").is_none());
}

// ── SamplingCreateMessageParams ───────────────────────────────────

#[test]
fn sampling_create_message_params_camel_case() {
    let params = SamplingCreateMessageParams {
        messages: vec![],
        tools: None,
        tool_choice: None,
        model_preferences: None,
        system_prompt: Some("You are helpful.".to_string()),
        max_tokens: 1024,
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["maxTokens"], 1024);
    assert_eq!(json["systemPrompt"], "You are helpful.");
    assert!(json.get("tools").is_none());
    assert!(json.get("toolChoice").is_none());
    assert!(json.get("modelPreferences").is_none());
}

// ── SamplingCreateMessageResult ───────────────────────────────────

#[test]
fn sampling_create_message_result_serializes() {
    let result = SamplingCreateMessageResult {
        role: "assistant".to_string(),
        content: super::super::Content::Text {
            text: "Hello!".to_string(),
            annotations: None,
        },
        model: "claude-opus-4-6".to_string(),
        stop_reason: Some("end_turn".to_string()),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["role"], "assistant");
    assert_eq!(json["model"], "claude-opus-4-6");
    assert_eq!(json["stopReason"], "end_turn");
}

// ── JsonRpcResponse helpers ───────────────────────────────────────

#[test]
fn json_rpc_response_success() {
    let resp = JsonRpcResponse::success(RequestId::Number(1), json!({"tools": []}));
    assert!(resp.error.is_none());
    assert!(resp.result.is_some());
    assert_eq!(resp.id.unwrap(), RequestId::Number(1));
}

#[test]
fn json_rpc_response_error() {
    let resp = JsonRpcResponse::error(
        Some(RequestId::String("req-1".to_string())),
        -32601,
        "Method not found",
    );
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32601);
    assert_eq!(err.message, "Method not found");
}

#[test]
fn json_rpc_response_without_request_id_serializes_explicit_null_id() {
    let resp = JsonRpcResponse::error(None, -32700, "Parse error");
    let json = serde_json::to_value(&resp).unwrap();

    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32700);
}

#[test]
fn json_rpc_response_internal_error_uses_standard_contract() {
    let resp = JsonRpcResponse::internal_error(None);
    let json = serde_json::to_value(&resp).unwrap();

    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["error"]["code"], -32603);
    assert_eq!(json["error"]["message"], "Internal error");
}

#[test]
fn json_rpc_response_success_serialized_wraps_payload() {
    let resp = JsonRpcResponse::success_serialized(RequestId::Number(1), json!({"tools": []}));
    assert!(resp.error.is_none());
    assert_eq!(resp.id, Some(RequestId::Number(1)));
    assert_eq!(resp.result, Some(json!({"tools": []})));
}

#[test]
fn json_rpc_response_success_serialized_falls_back_to_internal_error() {
    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    let resp = JsonRpcResponse::success_serialized(RequestId::Number(7), FailingSerialize);
    assert!(resp.result.is_none());
    assert_eq!(resp.id, Some(RequestId::Number(7)));
    let err = resp.error.expect("internal error payload");
    assert_eq!(err.code, -32603);
    assert_eq!(err.message, "Internal error");
}

#[test]
fn request_id_display() {
    assert_eq!(RequestId::Number(42).to_string(), "42");
    assert_eq!(RequestId::String("abc".to_string()).to_string(), "abc");
}
