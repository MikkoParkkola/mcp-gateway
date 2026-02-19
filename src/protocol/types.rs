//! MCP Protocol type definitions

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name (1-128 chars, [a-zA-Z0-9_.-])
    pub name: String,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Tool description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input JSON Schema
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// Output JSON Schema
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Tool annotations (hints about behavior)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Tool annotations (hints about tool behavior)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolAnnotations {
    /// Human-readable title for the tool
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// If true, tool does not modify external state
    #[serde(rename = "readOnlyHint", skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    /// If true, tool may perform destructive actions
    #[serde(rename = "destructiveHint", skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    /// If true, tool may have side effects beyond its return value
    #[serde(rename = "idempotentHint", skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    /// If true, tool interacts with external entities
    #[serde(rename = "openWorldHint", skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

/// Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Resource URI
    pub uri: String,
    /// Resource name
    pub name: String,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Resource description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Prompt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    /// Prompt name
    pub name: String,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Prompt description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt arguments
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// Prompt argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name
    pub name: String,
    /// Argument description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether argument is required
    #[serde(default)]
    pub required: bool,
}

/// Content item in tool call response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Content {
    /// Text content
    #[serde(rename = "text")]
    Text {
        /// Text value
        text: String,
        /// Annotations
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    /// Image content
    #[serde(rename = "image")]
    Image {
        /// Base64-encoded data
        data: String,
        /// MIME type
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Annotations
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    /// Audio content (new in 2025-11-25)
    #[serde(rename = "audio")]
    Audio {
        /// Base64-encoded audio data
        data: String,
        /// MIME type (e.g., "audio/wav", "audio/mp3")
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Annotations
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    /// Resource link
    #[serde(rename = "resource_link")]
    ResourceLink {
        /// Resource URI
        uri: String,
        /// Resource name
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Resource description
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// MIME type
        #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Annotations
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
    /// Embedded resource
    #[serde(rename = "resource")]
    Resource {
        /// Resource contents
        resource: ResourceContents,
        /// Annotations
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
    },
}

/// Resource contents (text or blob)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceContents {
    /// Text resource
    Text {
        /// Resource URI
        uri: String,
        /// MIME type
        #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Text content
        text: String,
    },
    /// Binary resource
    Blob {
        /// Resource URI
        uri: String,
        /// MIME type
        #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Base64-encoded blob data
        blob: String,
    },
}

/// Content annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotations {
    /// Intended audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Priority (0.0-1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
}

/// Client/Server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    /// Name
    pub name: String,
    /// Version
    pub version: String,
    /// Title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Server capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Completions capability (argument autocompletion)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completions: Option<CompletionsCapability>,
    /// Experimental capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<HashMap<String, Value>>,
    /// Logging capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<HashMap<String, Value>>,
    /// Prompts capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    /// Resources capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Tasks capability (task-augmented requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<ServerTasksCapability>,
    /// Tools capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

/// Completions capability (argument autocompletion)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompletionsCapability {}

/// Server tasks capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerTasksCapability {
    /// Whether server supports tasks/cancel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel: Option<HashMap<String, Value>>,
    /// Whether server supports tasks/list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<HashMap<String, Value>>,
    /// Which request types can be augmented with tasks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests: Option<TaskRequestsCapability>,
}

/// Task requests capability (which request types support tasks)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskRequestsCapability {
    /// Task support for tool-related requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<TaskToolsCapability>,
}

/// Task tools capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskToolsCapability {
    /// Whether server supports task-augmented tools/call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<HashMap<String, Value>>,
}

/// Prompts capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptsCapability {
    /// List changed notification support
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

/// Resources capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesCapability {
    /// Subscribe support
    #[serde(default)]
    pub subscribe: bool,
    /// List changed notification support
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

/// Tools capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsCapability {
    /// List changed notification support
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

/// Client capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Elicitation capability (server can request input from user)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<ElicitationCapability>,
    /// Experimental capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<HashMap<String, Value>>,
    /// Roots capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapability>,
    /// Sampling capability (LLM sampling)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingCapability>,
    /// Tasks capability (task-augmented requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<ClientTasksCapability>,
}

/// Elicitation capability (server requesting user input)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElicitationCapability {
    /// Form-based elicitation support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<HashMap<String, Value>>,
    /// URL-based elicitation support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<HashMap<String, Value>>,
}

/// Sampling capability (LLM sampling)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamplingCapability {
    /// Context inclusion support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, Value>>,
    /// Tool use support in sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<HashMap<String, Value>>,
}

/// Client tasks capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientTasksCapability {
    /// Whether client supports tasks/cancel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel: Option<HashMap<String, Value>>,
    /// Whether client supports tasks/list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<HashMap<String, Value>>,
    /// Which request types can be augmented with tasks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests: Option<ClientTaskRequestsCapability>,
}

/// Client task requests capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientTaskRequestsCapability {
    /// Task support for elicitation requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<TaskElicitationCapability>,
    /// Task support for sampling requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<TaskSamplingCapability>,
}

/// Task elicitation capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskElicitationCapability {
    /// Whether client supports task-augmented elicitation/create
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create: Option<HashMap<String, Value>>,
}

/// Task sampling capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskSamplingCapability {
    /// Whether client supports task-augmented sampling/createMessage
    #[serde(rename = "createMessage", skip_serializing_if = "Option::is_none")]
    pub create_message: Option<HashMap<String, Value>>,
}

/// Roots capability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootsCapability {
    /// List changed notification support
    #[serde(rename = "listChanged", default)]
    pub list_changed: bool,
}

// ============================================================================
// Resource Templates, Prompt Messages, Logging
// ============================================================================

/// Resource template (parameterized resource with URI template per RFC 6570)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// URI template (RFC 6570)
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Template name
    pub name: String,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Template description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type of resources produced by this template
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Prompt message in a prompt response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Role: "user" or "assistant"
    pub role: String,
    /// Content (text, image, audio, or embedded resource)
    pub content: Content,
}

/// Logging level (RFC 5424 severity)
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    /// Debug-level messages
    Debug,
    /// Informational messages
    Info,
    /// Normal but significant conditions
    Notice,
    /// Warning conditions
    #[default]
    Warning,
    /// Error conditions
    Error,
    /// Critical conditions
    Critical,
    /// Action must be taken immediately
    Alert,
    /// System is unusable
    Emergency,
}

// ============================================================================
// Roots, Sampling, Elicitation types
// ============================================================================

/// Root definition (filesystem boundary exposed by the client)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Root {
    /// Root URI (typically file://)
    pub uri: String,
    /// Human-readable name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Model preferences for sampling requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelPreferences {
    /// Hints for model selection
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<ModelHint>,
    /// Priority for cost optimization (0.0-1.0)
    #[serde(rename = "costPriority", skip_serializing_if = "Option::is_none")]
    pub cost_priority: Option<f64>,
    /// Priority for speed optimization (0.0-1.0)
    #[serde(rename = "speedPriority", skip_serializing_if = "Option::is_none")]
    pub speed_priority: Option<f64>,
    /// Priority for intelligence/quality (0.0-1.0)
    #[serde(
        rename = "intelligencePriority",
        skip_serializing_if = "Option::is_none"
    )]
    pub intelligence_priority: Option<f64>,
}

/// Hint for model selection in sampling
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelHint {
    /// Model name hint (e.g., "claude-3-opus", "gpt-4")
    pub name: String,
}

/// Message in a sampling request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingMessage {
    /// Role: "user" or "assistant"
    pub role: String,
    /// Message content
    pub content: Content,
}

/// Tool choice specification for sampling with tools
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode")]
pub enum ToolChoice {
    /// Model decides whether to use tools
    #[serde(rename = "auto")]
    Auto,
    /// Model must use at least one tool
    #[serde(rename = "required")]
    Required,
    /// Model must not use tools
    #[serde(rename = "none")]
    None,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
