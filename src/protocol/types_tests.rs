// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use serde_json::json;

// ── Tool descriptor: role + projection (MIK-3531) ─────────────────

fn bare_tool() -> Tool {
    Tool {
        name: "t".to_string(),
        title: None,
        description: None,
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

#[test]
fn untagged_tool_omits_role_and_projection_on_the_wire() {
    // Backward compatibility: an untagged tool must serialize exactly as
    // before — no `role` / `projection` keys (skip_serializing_if).
    let v = serde_json::to_value(bare_tool()).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("role"), "untagged tool must omit role");
    assert!(
        !obj.contains_key("projection"),
        "untagged tool must omit projection"
    );
}

#[test]
fn untagged_tool_deserializes_from_pre_existing_json() {
    // Old payloads with no role/projection keys must still parse, defaulting
    // both to None.
    let t: Tool = serde_json::from_value(json!({
        "name": "legacy", "inputSchema": {"type": "object"}
    }))
    .unwrap();
    assert!(t.role.is_none());
    assert!(t.projection.is_none());
}

#[test]
fn tagged_tool_round_trips_role_and_projection() {
    use crate::projection::{ActorSpec, ProjectionSpec, Role};
    let mut t = bare_tool();
    t.role = Some(Role::Selector);
    t.projection = Some(ProjectionSpec {
        actor: Some(ActorSpec {
            email: Some("assignee.email".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });
    let v = serde_json::to_value(&t).unwrap();
    assert_eq!(v["role"], json!("selector"));
    assert_eq!(v["projection"]["actor"]["email"], json!("assignee.email"));
    let back: Tool = serde_json::from_value(v).unwrap();
    assert_eq!(back.role, Some(Role::Selector));
    assert_eq!(
        back.projection.unwrap().actor.unwrap().email.as_deref(),
        Some("assignee.email")
    );
}

// ── ResourceTemplate ──────────────────────────────────────────────

#[test]
fn resource_template_serializes_with_camel_case_fields() {
    let template = ResourceTemplate {
        uri_template: "file:///{path}".to_string(),
        name: "file".to_string(),
        title: Some("File Template".to_string()),
        description: None,
        mime_type: Some("text/plain".to_string()),
    };
    let json = serde_json::to_value(&template).unwrap();
    assert_eq!(json["uriTemplate"], "file:///{path}");
    assert_eq!(json["mimeType"], "text/plain");
    assert!(json.get("description").is_none());
}

#[test]
fn resource_template_deserializes_from_camel_case() {
    let json = json!({
        "uriTemplate": "http://example.com/{id}",
        "name": "example",
        "title": "Example",
        "mimeType": "application/json"
    });
    let template: ResourceTemplate = serde_json::from_value(json).unwrap();
    assert_eq!(template.uri_template, "http://example.com/{id}");
    assert_eq!(template.mime_type.as_deref(), Some("application/json"));
    assert!(template.description.is_none());
}

#[test]
fn resource_template_roundtrip() {
    let original = ResourceTemplate {
        uri_template: "gs://bucket/{key}".to_string(),
        name: "gcs".to_string(),
        title: None,
        description: Some("GCS object".to_string()),
        mime_type: None,
    };
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: ResourceTemplate = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.uri_template, original.uri_template);
    assert_eq!(deserialized.name, original.name);
    assert_eq!(deserialized.description, original.description);
}

// ── PromptMessage ─────────────────────────────────────────────────

#[test]
fn prompt_message_with_text_content() {
    let msg = PromptMessage {
        role: "user".to_string(),
        content: Content::Text {
            text: "Hello".to_string(),
            annotations: None,
        },
    };
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["role"], "user");
    assert_eq!(json["content"]["type"], "text");
    assert_eq!(json["content"]["text"], "Hello");
}

#[test]
fn prompt_message_deserializes_assistant_role() {
    let json = json!({
        "role": "assistant",
        "content": {
            "type": "text",
            "text": "I can help with that."
        }
    });
    let msg: PromptMessage = serde_json::from_value(json).unwrap();
    assert_eq!(msg.role, "assistant");
    if let Content::Text { text, .. } = &msg.content {
        assert_eq!(text, "I can help with that.");
    } else {
        panic!("Expected text content");
    }
}

// ── LoggingLevel ──────────────────────────────────────────────────

#[test]
fn logging_level_serializes_lowercase() {
    assert_eq!(
        serde_json::to_value(LoggingLevel::Debug).unwrap(),
        json!("debug")
    );
    assert_eq!(
        serde_json::to_value(LoggingLevel::Emergency).unwrap(),
        json!("emergency")
    );
    assert_eq!(
        serde_json::to_value(LoggingLevel::Warning).unwrap(),
        json!("warning")
    );
}

#[test]
fn logging_level_deserializes_lowercase() {
    let level: LoggingLevel = serde_json::from_value(json!("info")).unwrap();
    assert_eq!(level, LoggingLevel::Info);

    let level: LoggingLevel = serde_json::from_value(json!("critical")).unwrap();
    assert_eq!(level, LoggingLevel::Critical);
}

#[test]
fn logging_level_ordering() {
    assert!(LoggingLevel::Debug < LoggingLevel::Info);
    assert!(LoggingLevel::Info < LoggingLevel::Notice);
    assert!(LoggingLevel::Notice < LoggingLevel::Warning);
    assert!(LoggingLevel::Warning < LoggingLevel::Error);
    assert!(LoggingLevel::Error < LoggingLevel::Critical);
    assert!(LoggingLevel::Critical < LoggingLevel::Alert);
    assert!(LoggingLevel::Alert < LoggingLevel::Emergency);
}

#[test]
fn logging_level_default_is_warning() {
    assert_eq!(LoggingLevel::default(), LoggingLevel::Warning);
}

#[test]
fn logging_level_roundtrip_all_variants() {
    let levels = [
        LoggingLevel::Debug,
        LoggingLevel::Info,
        LoggingLevel::Notice,
        LoggingLevel::Warning,
        LoggingLevel::Error,
        LoggingLevel::Critical,
        LoggingLevel::Alert,
        LoggingLevel::Emergency,
    ];
    for level in &levels {
        let serialized = serde_json::to_string(level).unwrap();
        let deserialized: LoggingLevel = serde_json::from_str(&serialized).unwrap();
        assert_eq!(*level, deserialized);
    }
}

// ── Root ──────────────────────────────────────────────────────────

#[test]
fn root_serializes_with_optional_name() {
    let root = Root {
        uri: "file:///home/user/project".to_string(),
        name: Some("My Project".to_string()),
    };
    let json = serde_json::to_value(&root).unwrap();
    assert_eq!(json["uri"], "file:///home/user/project");
    assert_eq!(json["name"], "My Project");
}

#[test]
fn root_skips_none_name() {
    let root = Root {
        uri: "file:///tmp".to_string(),
        name: None,
    };
    let json = serde_json::to_value(&root).unwrap();
    assert!(json.get("name").is_none());
}

// ── ToolChoice ────────────────────────────────────────────────────

#[test]
fn tool_choice_serializes_as_tagged_enum() {
    let auto = serde_json::to_value(ToolChoice::Auto).unwrap();
    assert_eq!(auto["mode"], "auto");

    let required = serde_json::to_value(ToolChoice::Required).unwrap();
    assert_eq!(required["mode"], "required");

    let none = serde_json::to_value(ToolChoice::None).unwrap();
    assert_eq!(none["mode"], "none");
}

#[test]
fn tool_choice_deserializes_from_tagged_json() {
    let tc: ToolChoice = serde_json::from_value(json!({"mode": "auto"})).unwrap();
    assert_eq!(tc, ToolChoice::Auto);

    let tc: ToolChoice = serde_json::from_value(json!({"mode": "required"})).unwrap();
    assert_eq!(tc, ToolChoice::Required);
}

// ── ModelPreferences ──────────────────────────────────────────────

#[test]
fn model_preferences_camel_case_serialization() {
    let prefs = ModelPreferences {
        hints: vec![ModelHint {
            name: "claude-3-opus".to_string(),
        }],
        cost_priority: Some(0.3),
        speed_priority: Some(0.5),
        intelligence_priority: Some(0.8),
    };
    let json = serde_json::to_value(&prefs).unwrap();
    assert_eq!(json["costPriority"], 0.3);
    assert_eq!(json["speedPriority"], 0.5);
    assert_eq!(json["intelligencePriority"], 0.8);
    assert_eq!(json["hints"][0]["name"], "claude-3-opus");
}

#[test]
fn model_preferences_omits_empty_hints() {
    let prefs = ModelPreferences {
        hints: vec![],
        cost_priority: None,
        speed_priority: None,
        intelligence_priority: None,
    };
    let json = serde_json::to_value(&prefs).unwrap();
    assert!(json.get("hints").is_none());
}
