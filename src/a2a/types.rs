//! A2A protocol types.
//!
//! Implements the `Agent2Agent` (A2A) wire-format types per the A2A specification.
//! These are intentionally self-contained: no MCP dependencies so the boundary
//! between protocols stays explicit.
//!
//! # References
//!
//! - <https://a2a-protocol.org/latest/specification/>
//! - <https://github.com/a2aproject/a2a-spec>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Agent Card ────────────────────────────────────────────────────────────────

/// Published descriptor for an A2A agent, fetched from
/// `GET /.well-known/agent.json`.
///
/// The gateway caches this after the first fetch and re-uses it
/// to synthesize MCP `Tool` definitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCard {
    /// Display name of the agent.
    pub name: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Base URL of the A2A agent (used for constructing endpoint URLs).
    pub url: String,
    /// Agent capabilities declared by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<AgentCapabilities>,
    /// Authentication schemes accepted by this agent.
    #[serde(
        default,
        rename = "securitySchemes",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub security_schemes: HashMap<String, SecurityScheme>,
    /// Skills exposed by this agent.
    #[serde(default)]
    pub skills: Vec<Skill>,
}

/// Agent capability flags declared in the Agent Card.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentCapabilities {
    /// Agent supports SSE streaming (`message/stream`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    /// Agent supports push notifications via webhooks.
    #[serde(
        default,
        rename = "pushNotifications",
        skip_serializing_if = "Option::is_none"
    )]
    pub push_notifications: Option<bool>,
    /// Agent supports the extended Agent Card endpoint.
    #[serde(
        default,
        rename = "stateTransitionHistory",
        skip_serializing_if = "Option::is_none"
    )]
    pub state_transition_history: Option<bool>,
}

/// A single skill exposed by an A2A agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Skill {
    /// Stable identifier for the skill.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Description of what the skill does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Semantic tags for discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// MIME types the skill accepts as input.
    #[serde(default, rename = "inputModes", skip_serializing_if = "Vec::is_empty")]
    pub input_modes: Vec<String>,
    /// MIME types the skill can produce as output.
    #[serde(default, rename = "outputModes", skip_serializing_if = "Vec::is_empty")]
    pub output_modes: Vec<String>,
    /// Examples for this skill (shown as tool annotations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
}

/// Security scheme declared by an agent (maps to gateway auth mechanisms).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SecurityScheme {
    /// API key authentication.
    ApiKey {
        /// Header or query name.
        name: String,
        /// Location: `"header"` or `"query"`.
        #[serde(rename = "in")]
        location: String,
    },
    /// HTTP authentication (bearer, basic, etc.).
    Http {
        /// Scheme name (e.g., `"bearer"`).
        scheme: String,
    },
    /// OAuth 2.0.
    OAuth2 {
        /// OAuth flows.
        flows: Value,
    },
    /// OIDC authentication.
    OpenIdConnect {
        /// OIDC discovery URL.
        #[serde(rename = "openIdConnectUrl")]
        open_id_connect_url: String,
    },
}

// ── Task & lifecycle ──────────────────────────────────────────────────────────

/// A2A task lifecycle states.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    /// Task received and queued.
    Submitted,
    /// Task is actively being worked on.
    Working,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
    /// Task was canceled.
    Canceled,
    /// Agent needs further input before proceeding.
    InputRequired,
}

impl TaskState {
    /// Returns `true` for terminal states where no further transitions occur.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

/// Full A2A task, returned by `message/send` and `tasks/get`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct A2aTask {
    /// Stable task identifier.
    pub id: String,
    /// Context identifier for multi-turn conversations.
    #[serde(default, rename = "contextId", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Current lifecycle status.
    pub status: TaskStatus,
    /// Result artifacts produced by the task (may be empty while in progress).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    /// Passthrough metadata attached by the originating agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Status block within a task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStatus {
    /// Lifecycle state.
    pub state: TaskState,
    /// Human-readable status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    /// ISO-8601 timestamp of the last state transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ── Message & parts ───────────────────────────────────────────────────────────

/// A2A message (request or response).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct A2aMessage {
    /// Conversation role: `"user"` or `"agent"`.
    pub role: MessageRole,
    /// Message content parts.
    pub parts: Vec<Part>,
    /// Shared context identifier for multi-turn flows.
    #[serde(default, rename = "contextId", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Message-level metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Role of the message sender.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    /// Message from the calling agent/user.
    User,
    /// Message from the responding agent.
    Agent,
}

/// A single content part within an A2A message or artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Part {
    /// Plain-text or markdown content.
    Text {
        /// Text body.
        text: String,
        /// Optional MIME type (default `"text/plain"`).
        #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
    /// File reference (URI + optional inline bytes).
    File {
        /// File descriptor.
        file: FileContent,
    },
    /// Arbitrary structured data.
    Data {
        /// JSON payload.
        data: Value,
        /// Optional MIME type hint.
        #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
}

/// File content within a [`Part::File`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileContent {
    /// File name (may include path segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// MIME type of the file.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Accessible URI (preferred over inline bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Base64-encoded inline content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
}

/// Named collection of output parts produced by a task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Artifact {
    /// Artifact identifier.
    #[serde(
        default,
        rename = "artifactId",
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_id: Option<String>,
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Description of the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Content parts that make up this artifact.
    pub parts: Vec<Part>,
    /// Whether this artifact replaces a previous one with the same `name`.
    #[serde(default, rename = "lastChunk", skip_serializing_if = "Option::is_none")]
    pub last_chunk: Option<bool>,
    /// Artifact-level metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// ── JSON-RPC wrappers ─────────────────────────────────────────────────────────

/// JSON-RPC 2.0 request wrapper for A2A methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Caller-assigned request identifier.
    pub id: Value,
    /// A2A method name (e.g., `"message/send"`, `"tasks/get"`).
    pub method: String,
    /// Method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl A2aRequest {
    /// Construct a well-formed request with the given method and params.
    #[must_use]
    pub fn new(id: impl Into<Value>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC 2.0 response wrapper for A2A methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Echoed request identifier.
    pub id: Value,
    /// Success payload (`result` xor `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload (`result` xor `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<A2aError>,
}

/// JSON-RPC error object returned by an A2A agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct A2aError {
    /// Numeric error code.
    pub code: i32,
    /// Short description.
    pub message: String,
    /// Optional structured detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Parameters for the `message/send` RPC method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageParams {
    /// The message to send.
    pub message: A2aMessage,
    /// Optional execution configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<MessageConfiguration>,
    /// Request-level metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Configuration hints for a `message/send` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageConfiguration {
    /// MIME types the caller can accept as output.
    #[serde(
        default,
        rename = "acceptedOutputModes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub accepted_output_modes: Vec<String>,
    /// Whether the agent should block until a terminal state is reached.
    ///
    /// Phase 1 always uses `true`; non-blocking polling is a Phase 1b concern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking: Option<bool>,
    /// Timeout hint in seconds.
    #[serde(
        default,
        rename = "timeoutSeconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout_seconds: Option<u64>,
}

/// Parameters for `tasks/get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTaskParams {
    /// Task identifier to retrieve.
    pub id: String,
    /// Optional history length to include.
    #[serde(
        default,
        rename = "historyLength",
        skip_serializing_if = "Option::is_none"
    )]
    pub history_length: Option<u32>,
}

/// Parameters for `tasks/cancel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskParams {
    /// Task identifier to cancel.
    pub id: String,
    /// Optional cancellation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ── TaskState ────────────────────────────────────────────────────────────

    #[test]
    fn task_state_terminal_states_are_correct() {
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Canceled.is_terminal());
    }

    #[test]
    fn task_state_non_terminal_states_are_correct() {
        assert!(!TaskState::Submitted.is_terminal());
        assert!(!TaskState::Working.is_terminal());
        assert!(!TaskState::InputRequired.is_terminal());
    }

    #[test]
    fn task_state_roundtrip_serde() {
        let states = [
            (TaskState::Submitted, "\"submitted\""),
            (TaskState::Working, "\"working\""),
            (TaskState::Completed, "\"completed\""),
            (TaskState::Failed, "\"failed\""),
            (TaskState::Canceled, "\"canceled\""),
            (TaskState::InputRequired, "\"input-required\""),
        ];
        for (state, expected_json) in states {
            let serialized = serde_json::to_string(&state).unwrap();
            assert_eq!(serialized, expected_json);
            let deserialized: TaskState = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, state);
        }
    }

    // ── Part ────────────────────────────────────────────────────────────────

    #[test]
    fn part_text_roundtrip_serde() {
        let part = Part::Text {
            text: "hello world".to_string(),
            mime_type: None,
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["kind"], "text");
        assert_eq!(json["text"], "hello world");

        let back: Part = serde_json::from_value(json).unwrap();
        assert_eq!(back, part);
    }

    #[test]
    fn part_file_roundtrip_serde() {
        let part = Part::File {
            file: FileContent {
                name: Some("report.pdf".to_string()),
                mime_type: Some("application/pdf".to_string()),
                uri: Some("https://example.com/report.pdf".to_string()),
                bytes: None,
            },
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["kind"], "file");
        assert_eq!(json["file"]["name"], "report.pdf");

        let back: Part = serde_json::from_value(json).unwrap();
        assert_eq!(back, part);
    }

    #[test]
    fn part_data_roundtrip_serde() {
        let part = Part::Data {
            data: json!({"score": 42}),
            mime_type: Some("application/json".to_string()),
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["kind"], "data");
        assert_eq!(json["data"]["score"], 42);

        let back: Part = serde_json::from_value(json).unwrap();
        assert_eq!(back, part);
    }

    // ── AgentCard ────────────────────────────────────────────────────────────

    #[test]
    fn agent_card_deserializes_minimal_json() {
        let raw = json!({
            "name": "Travel Agent",
            "url": "https://travel.example.com",
            "skills": []
        });
        let card: AgentCard = serde_json::from_value(raw).unwrap();
        assert_eq!(card.name, "Travel Agent");
        assert!(card.skills.is_empty());
        assert!(card.security_schemes.is_empty());
    }

    #[test]
    fn agent_card_deserializes_with_skills() {
        let raw = json!({
            "name": "SearchBot",
            "url": "https://search.example.com",
            "skills": [{
                "id": "web_search",
                "name": "Web Search",
                "description": "Search the web",
                "tags": ["search", "web"],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"]
            }]
        });
        let card: AgentCard = serde_json::from_value(raw).unwrap();
        assert_eq!(card.skills.len(), 1);
        let skill = &card.skills[0];
        assert_eq!(skill.id, "web_search");
        assert_eq!(skill.tags, ["search", "web"]);
        assert_eq!(skill.output_modes.len(), 2);
    }

    // ── A2aRequest / A2aResponse ─────────────────────────────────────────────

    #[test]
    fn a2a_request_new_sets_jsonrpc_version() {
        let req = A2aRequest::new(1u64, "message/send", None);
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "message/send");
    }

    #[test]
    fn a2a_response_error_deserializes() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        });
        let resp: A2aResponse = serde_json::from_value(raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
    }

    // ── Artifact ─────────────────────────────────────────────────────────────

    #[test]
    fn artifact_with_multiple_parts_roundtrips() {
        let artifact = Artifact {
            artifact_id: Some("a1".to_string()),
            name: Some("output".to_string()),
            description: None,
            parts: vec![
                Part::Text {
                    text: "Summary".to_string(),
                    mime_type: None,
                },
                Part::Data {
                    data: json!({"key": "value"}),
                    mime_type: None,
                },
            ],
            last_chunk: Some(true),
            metadata: None,
        };
        let json = serde_json::to_value(&artifact).unwrap();
        let back: Artifact = serde_json::from_value(json).unwrap();
        assert_eq!(back, artifact);
        assert_eq!(back.parts.len(), 2);
    }

    // ── MessageRole ──────────────────────────────────────────────────────────

    #[test]
    fn message_role_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&MessageRole::User).unwrap(),
            "\"user\""
        );
        assert_eq!(
            serde_json::to_string(&MessageRole::Agent).unwrap(),
            "\"agent\""
        );
    }
}
