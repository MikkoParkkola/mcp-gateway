// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MCP JSON-RPC message types

use crate::error::rpc_codes::INTERNAL_ERROR;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

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

/// The server-owned flags a response carries beside its wire members. Never
/// on the wire in either direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WireMeta {
    /// Server-owned response security refusal. Never accepted from wire data
    /// or serialized; it excludes both client strikes and success resets.
    pub(crate) delivery_refusal: bool,
    /// Server-owned: the egress scan screened this frame (or a discovery
    /// handler did, on its canonical value before serialisation,
    /// `MIK-7407.RESPONSE.3`), so no later exit scans it again. Never on the
    /// wire, so no caller can set it.
    pub(crate) egress_scanned: bool,
    /// Server-owned: who wrote an error in this frame. `Backend` only from
    /// `backend_request`, `BackendFailure` only from `Error::origin` through
    /// `of_error`; never on the wire, so no caller can set it.
    pub(crate) origin: Origin,
    /// Server-owned: a failure this answer carries folded into a tool
    /// result (an `isError` the gateway made of a dispatch failure), stamped
    /// from the delivery's facts where the frame is finalised. The error
    /// count reads it when the frame has no error of its own; never on the
    /// wire.
    pub(crate) folded: Option<crate::gateway::health_metrics::RpcError>,
}

/// Who an error frame blames, for the error count: the gateway's own fault or
/// refusal, a backend failure the gateway reports, or a backend's own answer
/// the gateway forwarded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The gateway's own error or policy refusal.
    #[default]
    Gateway,
    /// A backend-side failure the gateway built (timeout, unavailable, circuit
    /// open, transport); the gateway itself is healthy.
    BackendFailure,
    /// A frame a backend's transport returned.
    Backend,
}

/// JSON-RPC response
///
/// `Deserialize` is implemented by hand rather than derived: a frame carrying
/// `method` is a request or a notification, and accepting one here is what let
/// an inbound `sampling/createMessage` reach a waiting caller as its answer.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID (`null` when the response cannot be correlated to a request)
    pub id: Option<RequestId>,
    /// Result (on success). Serialized through the `cacheScope` clamp: no
    /// delivered result claims a scope other than `private` (MIK-7211.PARENT.6).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::protocol::cacheable::serialize_delivered_result"
    )]
    pub result: Option<Value>,
    /// Error (on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Internal marker: this response answered a destructive call without
    /// running it (confirmation unobtainable, declined, or still pending).
    /// Never on the wire in either direction; read only by the dispatcher, to
    /// keep a refusal out of client failure accounting.
    #[serde(skip)]
    pub confirmation_refusal: bool,
    /// Server-owned off-wire flags; never accepted from wire data or
    /// serialized, so no caller can set them.
    #[serde(skip)]
    pub(crate) wire_meta: WireMeta,
    /// Server-owned chain eligibility; never on the wire, `NotEligible` by default.
    #[serde(skip)]
    pub(crate) chain_source: super::ChainSource,
    /// The upstream chain outcome for a chained backend; never on the wire.
    #[serde(skip)]
    pub(crate) chain_upstream: Option<std::sync::Arc<super::UpstreamChain>>,
    /// Server-owned: the trace of the invocation this response answers, so
    /// its delivery record joins that invocation's record. Never
    /// on the wire, so no caller and no backend can set it.
    #[serde(skip)]
    pub(crate) invocation_trace: Option<std::sync::Arc<str>>,
    /// Server-owned: the top-level gateway-only members ingress removed from
    /// the backend's result, kept only so a signature chain is
    /// verified over the content the backend signed. Never on the wire and
    /// never put back into the result.
    #[serde(skip)]
    pub(crate) ingress_withheld: Option<Box<super::reserved_members::Withheld>>,
}

#[path = "messages_classify.rs"]
mod classify;
#[path = "messages_response_de.rs"]
mod response_de;

impl JsonRpcResponse {
    /// The one place every server-owned marker gets its default.
    fn envelope(id: Option<RequestId>, result: Option<Value>, error: Option<JsonRpcError>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result,
            error,
            confirmation_refusal: false,
            wire_meta: WireMeta::default(),
            chain_source: super::ChainSource::NotEligible,
            chain_upstream: None,
            invocation_trace: None,
            ingress_withheld: None,
        }
    }

    /// Create a success response
    #[must_use]
    pub fn success(id: RequestId, result: Value) -> Self {
        Self::envelope(Some(id), Some(result), None)
    }

    /// Create a success response from any serializable payload.
    ///
    /// Falls back to a standard internal error response if the payload cannot be
    /// converted into a JSON value.
    #[must_use]
    pub fn success_serialized<T>(id: RequestId, result: T) -> Self
    where
        T: Serialize,
    {
        match serde_json::to_value(result) {
            Ok(value) => Self::success(id, value),
            Err(err) => {
                warn!(response_id = %id, error = %err, "failed to serialize JSON-RPC success result");
                Self::internal_error(Some(id))
            }
        }
    }

    /// Create an error response
    pub fn error(id: Option<RequestId>, code: i32, message: impl Into<String>) -> Self {
        Self::failure(id, code, message.into(), None)
    }

    /// Create a standard internal error response.
    #[must_use]
    pub fn internal_error(id: Option<RequestId>) -> Self {
        Self::error(id, INTERNAL_ERROR, "Internal error")
    }

    /// Serialize this response into a JSON value, falling back to a standard
    /// internal error payload if serialization unexpectedly fails.
    #[must_use]
    pub fn to_value_lossy(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|err| {
            warn!(error = %err, "failed to serialize JSON-RPC response");
            serde_json::to_value(Self::internal_error(None))
                .expect("internal JSON-RPC fallback must serialize")
        })
    }

    /// Create an error response with data
    pub fn error_with_data(
        id: Option<RequestId>,
        code: i32,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self::failure(id, code, message.into(), Some(data))
    }

    fn failure(id: Option<RequestId>, code: i32, message: String, data: Option<Value>) -> Self {
        let error = JsonRpcError {
            code,
            message,
            data,
        };
        Self::envelope(id, None, Some(error))
    }
}

impl JsonRpcResponse {
    /// The one constructor of an error frame from a [`crate::Error`]: code from
    /// `to_rpc_code`, text from `Display`, origin from `Error::origin`.
    pub(crate) fn of_error(id: Option<RequestId>, error: &crate::Error) -> Self {
        Self::of_error_text(id, error, error.to_string())
    }

    /// [`Self::of_error`] with the wire text a site already chose (a redacted
    /// or inner message), so the frame keeps the bytes it always had.
    pub(crate) fn of_error_text(
        id: Option<RequestId>,
        error: &crate::Error,
        text: impl Into<String>,
    ) -> Self {
        let mut response = Self::error(id, error.to_rpc_code(), text);
        response.wire_meta.origin = error.origin();
        response
    }

    /// Only gateway-owned finalization failures acquire this private marker.
    pub(crate) fn delivery_refusal_error(id: Option<RequestId>, code: i32, message: &str) -> Self {
        let mut response = Self::error(id, code, message);
        response.wire_meta.delivery_refusal = true;
        // The gateway's own refusal carries no backend text to screen.
        response.wire_meta.egress_scanned = true;
        response
    }

    /// An error the gateway wrote from its own text (a signing refusal before
    /// dispatch): nothing a backend sent, so the egress scan skips it.
    pub(crate) fn gateway_error(
        id: Option<RequestId>,
        code: i32,
        message: impl Into<String>,
    ) -> Self {
        let mut response = Self::error(id, code, message);
        response.wire_meta.egress_scanned = true;
        response
    }

    /// This response answers the invocation traced `trace`.
    #[must_use]
    pub(crate) fn with_invocation_trace(mut self, trace: std::sync::Arc<str>) -> Self {
        self.invocation_trace = Some(trace);
        self
    }

    /// Policy refusals neither consume a failure strike nor reset prior strikes.
    pub(crate) fn excludes_client_accounting(&self) -> bool {
        self.confirmation_refusal || self.wire_meta.delivery_refusal
    }
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Optional error data; its own `cacheScope` is clamped (MIK-7702)
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::protocol::cacheable::serialize_delivered_error_data"
    )]
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
    /// Content items (text representation for backward compatibility)
    pub content: Vec<Content>,
    /// Structured JSON content matching the tool's `outputSchema`.
    ///
    /// Per the MCP spec (2025-06-18), when a tool declares an `outputSchema`,
    /// the response **must** include `structuredContent` with a JSON object
    /// that conforms to that schema. Clients that enforce this requirement
    /// (e.g. the Python SDK `mcp>=1.24.0`, Kiro) will reject responses that
    /// omit this field when `outputSchema` is present.
    #[serde(rename = "structuredContent", skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
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
    /// How the client should render this: `form` or `url`.
    ///
    /// Carried rather than assumed. A `url`-mode question rendered as a form
    /// asks the user to type what they were meant to go and do, and the mode is
    /// the only field that says which one it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Human-readable message describing what input is needed
    pub message: String,
    /// JSON Schema for the requested input (form mode)
    #[serde(rename = "requestedSchema", skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
    /// Where the client should send the user (url mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
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
// Tool result payload
// ============================================================================

/// The tool's value inside an MCP tool result: its `structuredContent` when
/// present (even `null`), else its one `content` block's text parsed as JSON.
///
/// This is the strict reader, the one rule the output-schema gate, response
/// projection, response transforms, the trust extractor and the audit replay
/// share (MIK-8663). Several content blocks, non-JSON text, or neither field
/// yield `None`: the caller then judges the envelope itself, never a guess
/// from part of a multi-part answer.
///
/// Two decoders keep other contracts on purpose (MIK-8734): the watch
/// source's total reader (`router/watch_poll.rs` `application_value`) and
/// the capability executor's MCP process path. They are not unfinished
/// consolidation; change them only through that ticket.
pub(crate) fn tool_result_payload(result: &Value) -> Option<Value> {
    if let Some(structured) = result.get("structuredContent") {
        return Some(structured.clone());
    }
    let content = result.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let text = content[0].get("text")?.as_str()?;
    serde_json::from_str::<Value>(text).ok()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "messages_payload_tests.rs"]
mod payload_tests;
#[cfg(test)]
#[path = "messages_tests.rs"]
mod tests;
