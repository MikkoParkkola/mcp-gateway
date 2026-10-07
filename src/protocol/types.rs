// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MCP Protocol type definitions

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Tool role for discovery filtering (projection layer, MIK-3531/3532).
    /// `None` (the default) is treated as [`crate::projection::Role::Action`],
    /// preserving backward compatibility for untagged tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<crate::projection::Role>,
    /// Canonical projection spec for this tool's responses, if declared.
    /// `None` means the response is not projected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<crate::projection::ProjectionSpec>,
}

/// Tool annotations (hints about tool behavior)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
    /// Extensions this gateway implements and honours today (`io.modelcontextprotocol/extensions`).
    /// Populated from implemented-and-enabled handlers only, never from a static list of known
    /// identifiers — see docs/design/2026-08-31-cluster-b-capability-and-trace-metadata.md §3.1a.
    ///
    /// Omitted when empty, like every sibling field. An earlier revision serialized it
    /// unconditionally so that `{}` could mean "speaks the mechanism, supports nothing" as
    /// distinct from silence. That distinction is not available to us: MIK-7217 AC discover-3
    /// requires the initialize result to be byte-identical for a client that asks for an
    /// already-supported protocol version, so a new always-present key is a breaking change to
    /// the handshake no matter how empty it is. Discovery has to be additive, and a key that
    /// appears for every client is not additive. A gateway with no extensions is therefore
    /// indistinguishable from one that predates the field, which is the correct trade.
    ///
    /// `default` covers deserialize: this type is public API and JSON written before the field
    /// existed must still parse. It is the sole non-`Option` field, so without this a missing
    /// key is a hard error where every sibling field tolerates absence.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, Value>,
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
    /// SEP-1821: Server supports filtered `tools/list` with a `query` parameter.
    ///
    /// Only present when the `spec-preview` feature is enabled.
    #[cfg(feature = "spec-preview")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtering: Option<bool>,
    /// SEP-1862: Server supports `tools/resolve` to fetch a full `Tool` schema by name.
    ///
    /// Only present when the `spec-preview` feature is enabled.
    #[cfg(feature = "spec-preview")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve: Option<bool>,
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
#[path = "types_tests.rs"]
mod tests;
