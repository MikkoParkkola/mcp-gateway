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
