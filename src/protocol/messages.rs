//! MCP JSON-RPC message types

use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::collections::HashMap;

use super::{
    ClientCapabilities, Content, Info, LoggingLevel, Prompt, PromptMessage, Resource,
    ResourceContents, ResourceTemplate, ServerCapabilities, Tool,
};

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID
    pub id: RequestId,
    /// Method name
    pub method: String,
    /// Parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC notification (no id)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Method name
    pub method: String,
    /// Parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
    /// Result (on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response
    #[must_use]
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: Option<RequestId>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Create an error response with data
    pub fn error_with_data(
        id: Option<RequestId>,
        code: i32,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Optional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Request ID (string or number)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// String ID
    String(String),
    /// Numeric ID
    Number(i64),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

/// Generic JSON-RPC message (request, notification, or response)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    /// Request
    Request(JsonRpcRequest),
    /// Notification
    Notification(JsonRpcNotification),
    /// Response
    Response(JsonRpcResponse),
}

impl JsonRpcMessage {
    /// Check if this is a request
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Check if this is a notification
    #[must_use]
    pub fn is_notification(&self) -> bool {
        matches!(self, Self::Notification(_))
    }

    /// Check if this is a response
    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Get the method name (for requests and notifications)
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Request(r) => Some(&r.method),
            Self::Notification(n) => Some(&n.method),
            Self::Response(_) => None,
        }
    }
}

// ============================================================================
// Initialize
// ============================================================================

/// Initialize request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Protocol version
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities
    pub capabilities: ClientCapabilities,
    /// Client info
    #[serde(rename = "clientInfo")]
    pub client_info: Info,
}

/// Initialize result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Protocol version
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
    /// Server info
    #[serde(rename = "serverInfo")]
    pub server_info: Info,
    /// Optional instructions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

// ============================================================================
// Tools
// ============================================================================

/// Tools list request params
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsListParams {
    /// Pagination cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Tools list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    /// List of tools
    pub tools: Vec<Tool>,
    /// Next cursor for pagination
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Tools call request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCallParams {
    /// Tool name
    pub name: String,
    /// Tool arguments
    #[serde(default)]
    pub arguments: Value,
}

/// Tools call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCallResult {
    /// Content items
    pub content: Vec<Content>,
    /// Whether result is an error
    #[serde(rename = "isError", default)]
    pub is_error: bool,
}

// ============================================================================
// Resources
// ============================================================================

/// Resources list request params
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesListParams {
    /// Pagination cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Resources list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListResult {
    /// List of resources
    pub resources: Vec<Resource>,
    /// Next cursor for pagination
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// Prompts
// ============================================================================

/// Prompts list request params
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptsListParams {
    /// Pagination cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Prompts list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsListResult {
    /// List of prompts
    pub prompts: Vec<Prompt>,
    /// Next cursor for pagination
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// Resources (read, templates, subscribe)
// ============================================================================

/// Resources read request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadParams {
    /// URI of the resource to read
    pub uri: String,
}

/// Resources read result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadResult {
    /// Resource contents
    pub contents: Vec<ResourceContents>,
}

/// Resources templates list request params
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesTemplatesListParams {
    /// Pagination cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Resources templates list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesTemplatesListResult {
    /// List of resource templates
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<ResourceTemplate>,
    /// Next cursor for pagination
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Resources subscribe request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesSubscribeParams {
    /// URI of the resource to subscribe to
    pub uri: String,
}

/// Resources unsubscribe request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesUnsubscribeParams {
    /// URI of the resource to unsubscribe from
    pub uri: String,
}

// ============================================================================
// Prompts (get)
// ============================================================================

/// Prompts get request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsGetParams {
    /// Prompt name
    pub name: String,
    /// Prompt arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<HashMap<String, String>>,
}

/// Prompts get result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsGetResult {
    /// Prompt description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt messages
    pub messages: Vec<PromptMessage>,
}

// ============================================================================
// Logging
// ============================================================================

/// Logging set level request params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSetLevelParams {
    /// Desired logging level
    pub level: LoggingLevel,
}

// ============================================================================
// Roots
// ============================================================================

/// Roots list result (response to roots/list)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsListResult {
    /// List of roots
    pub roots: Vec<super::Root>,
}

// ============================================================================
// Elicitation
// ============================================================================

/// Elicitation create request params (server->client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationCreateParams {
    /// Human-readable message describing what input is needed
    pub message: String,
    /// JSON Schema for the requested input (form mode)
    #[serde(rename = "requestedSchema", skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
}

/// Elicitation create result (client->server response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationCreateResult {
    /// Action taken: "accept", "decline", or "cancel"
    pub action: String,
    /// User-provided content (present when action is "accept")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

// ============================================================================
// Sampling
// ============================================================================

/// Sampling create message request params (server->client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCreateMessageParams {
    /// Messages for the sampling request
    pub messages: Vec<super::SamplingMessage>,
    /// Tools available for the model to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// Tool choice mode
    #[serde(rename = "toolChoice", skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<super::ToolChoice>,
    /// Model selection preferences
    #[serde(rename = "modelPreferences", skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<super::ModelPreferences>,
    /// System prompt for the sampling request
    #[serde(rename = "systemPrompt", skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Maximum tokens to generate
    #[serde(rename = "maxTokens")]
    pub max_tokens: u64,
}

/// Sampling create message result (client->server response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCreateMessageResult {
    /// Role of the generated message ("assistant")
    pub role: String,
    /// Generated content
    pub content: Content,
    /// Model that generated the response
    pub model: String,
    /// Reason for stopping generation
    #[serde(rename = "stopReason", skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
            message: "Enter your name".to_string(),
            requested_schema: Some(
                json!({"type": "object", "properties": {"name": {"type": "string"}}}),
            ),
        };
        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["message"], "Enter your name");
        assert!(json.get("requestedSchema").is_some());
    }

    #[test]
    fn elicitation_create_params_without_schema() {
        let params = ElicitationCreateParams {
            message: "Confirm action".to_string(),
            requested_schema: None,
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
    fn request_id_display() {
        assert_eq!(RequestId::Number(42).to_string(), "42");
        assert_eq!(RequestId::String("abc".to_string()).to_string(), "abc");
    }
}
