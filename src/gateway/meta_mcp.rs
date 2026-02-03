//! Meta-MCP implementation - 4 meta-tools for dynamic discovery
//!
//! This module provides the gateway's meta-tools for discovering and invoking
//! tools across all backends, including:
//! - MCP backends (stdio, http)
//! - Capability backends (direct REST API integration)

use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::debug;

use crate::backend::BackendRegistry;
use crate::capability::CapabilityBackend;
use crate::protocol::{
    Content, Info, InitializeResult, JsonRpcResponse, RequestId,
    ServerCapabilities, Tool, ToolsCallResult, ToolsCapability, ToolsListResult,
    negotiate_version,
};
use crate::{Error, Result};

/// Meta-MCP handler
pub struct MetaMcp {
    /// Backend registry (MCP backends)
    backends: Arc<BackendRegistry>,
    /// Capability backend (direct REST APIs)
    capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
}

impl MetaMcp {
    /// Create a new Meta-MCP handler
    pub fn new(backends: Arc<BackendRegistry>) -> Self {
        Self {
            backends,
            capabilities: RwLock::new(None),
        }
    }

    /// Set the capability backend
    pub fn set_capabilities(&self, capabilities: Arc<CapabilityBackend>) {
        *self.capabilities.write() = Some(capabilities);
    }

    /// Get capability backend if available
    fn get_capabilities(&self) -> Option<Arc<CapabilityBackend>> {
        self.capabilities.read().clone()
    }

    /// Handle initialize request with version negotiation
    pub fn handle_initialize(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse {
        // Extract client's requested protocol version
        let client_version = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(|v| v.as_str())
            .unwrap_or("2024-11-05");

        // Negotiate to highest mutually supported version
        let negotiated_version = negotiate_version(client_version);
        debug!(client = client_version, negotiated = negotiated_version, "Protocol version negotiation");

        let result = InitializeResult {
            protocol_version: negotiated_version.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                ..Default::default()
            },
            server_info: Info {
                name: "mcp-gateway".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("MCP Gateway".to_string()),
                description: Some(
                    "Universal MCP Gateway with Meta-MCP for dynamic tool discovery".to_string(),
                ),
            },
            instructions: Some(
                "Use gateway_list_servers to discover backends, \
                 gateway_list_tools to get tools from a backend, \
                 gateway_search_tools to search, and \
                 gateway_invoke to call tools."
                    .to_string(),
            ),
        };

        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/list request
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        let tools = vec![
            Tool {
                name: "gateway_list_servers".to_string(),
                title: Some("List Servers".to_string()),
                description: Some("List all available MCP backend servers".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
                output_schema: None,
            },
            Tool {
                name: "gateway_list_tools".to_string(),
                title: Some("List Tools".to_string()),
                description: Some("List all tools from a specific backend server".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Name of the backend server"
                        }
                    },
                    "required": ["server"]
                }),
                output_schema: None,
            },
            Tool {
                name: "gateway_search_tools".to_string(),
                title: Some("Search Tools".to_string()),
                description: Some("Search for tools across all backends by keyword".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search keyword"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results (default 10)",
                            "default": 10
                        }
                    },
                    "required": ["query"]
                }),
                output_schema: None,
            },
            Tool {
                name: "gateway_invoke".to_string(),
                title: Some("Invoke Tool".to_string()),
                description: Some("Invoke a tool on a specific backend".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Backend server name"
                        },
                        "tool": {
                            "type": "string",
                            "description": "Tool name to invoke"
                        },
                        "arguments": {
                            "type": "object",
                            "description": "Tool arguments",
                            "default": {}
                        }
                    },
                    "required": ["server", "tool"]
                }),
                output_schema: None,
            },
        ];

        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };

        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/call request
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
    ) -> JsonRpcResponse {
        let result = match tool_name {
            "gateway_list_servers" => self.list_servers().await,
            "gateway_list_tools" => self.list_tools(&arguments).await,
            "gateway_search_tools" => self.search_tools(&arguments).await,
            "gateway_invoke" => self.invoke_tool(&arguments).await,
            _ => Err(Error::json_rpc(
                -32601,
                format!("Unknown tool: {tool_name}"),
            )),
        };

        match result {
            Ok(content) => {
                let result = ToolsCallResult {
                    content: vec![Content::Text {
                        text: serde_json::to_string_pretty(&content).unwrap_or_default(),
                        annotations: None,
                    }],
                    is_error: false,
                };
                JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// List all servers
    async fn list_servers(&self) -> Result<Value> {
        let mut servers: Vec<Value> = self
            .backends
            .all()
            .iter()
            .map(|b| {
                let status = b.status();
                json!({
                    "name": status.name,
                    "running": status.running,
                    "transport": status.transport,
                    "tools_count": status.tools_cached,
                    "circuit_state": status.circuit_state
                })
            })
            .collect();

        // Add capability backend if available
        if let Some(cap) = self.get_capabilities() {
            let status = cap.status();
            servers.push(json!({
                "name": status.name,
                "running": true,
                "transport": "capability",
                "tools_count": status.capabilities_count,
                "circuit_state": "Closed"
            }));
        }

        Ok(json!({ "servers": servers }))
    }

    /// List tools from a specific server
    async fn list_tools(&self, args: &Value) -> Result<Value> {
        let server = args
            .get("server")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::json_rpc(-32602, "Missing 'server' parameter"))?;

        // Check if it's the capability backend
        if let Some(cap) = self.get_capabilities() {
            if server == cap.name {
                let tools = cap.get_tools();
                return Ok(json!({
                    "server": server,
                    "tools": tools
                }));
            }
        }

        // Otherwise, look in MCP backends
        let backend = self
            .backends
            .get(server)
            .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        let tools = backend.get_tools().await?;

        Ok(json!({
            "server": server,
            "tools": tools
        }))
    }

    /// Search tools across all backends
    async fn search_tools(&self, args: &Value) -> Result<Value> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::json_rpc(-32602, "Missing 'query' parameter"))?
            .to_lowercase();

        let limit = args
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(10) as usize;

        let mut matches = Vec::new();

        // Search capability backend first (faster, no network)
        if let Some(cap) = self.get_capabilities() {
            for tool in cap.get_tools() {
                let name_match = tool.name.to_lowercase().contains(&query);
                let desc_match = tool
                    .description
                    .as_ref()
                    .is_some_and(|d| d.to_lowercase().contains(&query));

                if name_match || desc_match {
                    matches.push(json!({
                        "server": cap.name,
                        "tool": tool.name,
                        "description": tool.description.as_deref().unwrap_or("").chars().take(200).collect::<String>()
                    }));

                    if matches.len() >= limit {
                        break;
                    }
                }
            }
        }

        // Then search MCP backends
        for backend in self.backends.all() {
            if matches.len() >= limit {
                break;
            }

            if let Ok(tools) = backend.get_tools().await {
                for tool in tools {
                    let name_match = tool.name.to_lowercase().contains(&query);
                    let desc_match = tool
                        .description
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&query));

                    if name_match || desc_match {
                        matches.push(json!({
                            "server": backend.name,
                            "tool": tool.name,
                            "description": tool.description.as_deref().unwrap_or("").chars().take(200).collect::<String>()
                        }));

                        if matches.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        Ok(json!({
            "query": query,
            "matches": matches,
            "total": matches.len()
        }))
    }

    /// Invoke a tool on a backend
    async fn invoke_tool(&self, args: &Value) -> Result<Value> {
        let server = args
            .get("server")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::json_rpc(-32602, "Missing 'server' parameter"))?;

        let tool = args
            .get("tool")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::json_rpc(-32602, "Missing 'tool' parameter"))?;

        let mut arguments = args.get("arguments").cloned().unwrap_or(json!({}));

        // Accept OpenAI-style tool arguments passed as a JSON string.
        // This prevents backends (e.g. rmcp-based servers) from crashing on invalid types.
        if let Value::String(raw) = &arguments {
            let parsed: Value = serde_json::from_str(raw).map_err(|e| {
                Error::json_rpc(-32602, format!("Invalid 'arguments' JSON string: {e}"))
            })?;
            arguments = parsed;
        }

        if !arguments.is_object() {
            return Err(Error::json_rpc(
                -32602,
                "Invalid 'arguments': expected object or JSON object string",
            ));
        }

        debug!(server = server, tool = tool, "Invoking tool");

        // Check if it's a capability
        if let Some(cap) = self.get_capabilities() {
            if server == cap.name && cap.has_capability(tool) {
                let result = cap.call_tool(tool, arguments).await?;
                return Ok(serde_json::to_value(result)?);
            }
        }

        // Otherwise, invoke on MCP backend
        let backend = self
            .backends
            .get(server)
            .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        let response = backend
            .request(
                "tools/call",
                Some(json!({
                    "name": tool,
                    "arguments": arguments
                })),
            )
            .await?;

        // Return the response result directly
        if let Some(error) = response.error {
            Err(Error::JsonRpc {
                code: error.code,
                message: error.message,
                data: error.data,
            })
        } else {
            Ok(response.result.unwrap_or(json!(null)))
        }
    }
}
