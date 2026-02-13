//! Meta-MCP implementation - 4 meta-tools for dynamic discovery
//!
//! This module provides the gateway's meta-tools for discovering and invoking
//! tools across all backends, including:
//! - MCP backends (stdio, http)
//! - Capability backends (direct REST API integration)
//!
//! Pure business logic functions are in [`super::meta_mcp_helpers`]. Async methods
//! here are thin wrappers that gather data and delegate to those pure functions.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::debug;

use crate::backend::BackendRegistry;
use crate::cache::ResponseCache;
use crate::capability::CapabilityBackend;
use crate::protocol::{
    JsonRpcResponse, RequestId, ToolsListResult, negotiate_version,
};
use crate::ranking::{SearchRanker, json_to_search_result};
use crate::stats::UsageStats;
use crate::{Error, Result};

use super::meta_mcp_helpers::{
    build_initialize_result, build_match_json, build_meta_tools, build_search_response,
    build_stats_response, extract_client_version, extract_price_per_million,
    extract_required_str, extract_search_limit, parse_tool_arguments, ranked_results_to_json,
    tool_matches_query, wrap_tool_success,
};

// ============================================================================
// MetaMcp struct and async methods (thin wrappers)
// ============================================================================

/// Meta-MCP handler
pub struct MetaMcp {
    /// Backend registry (MCP backends)
    backends: Arc<BackendRegistry>,
    /// Capability backend (direct REST APIs)
    capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
    /// Response cache for `gateway_invoke`
    cache: Option<Arc<ResponseCache>>,
    /// Default cache TTL
    default_cache_ttl: Duration,
    /// Usage statistics
    stats: Option<Arc<UsageStats>>,
    /// Search ranker for usage-based ranking
    ranker: Option<Arc<SearchRanker>>,
}

impl MetaMcp {
    /// Create a new Meta-MCP handler
    #[allow(dead_code)]
    pub fn new(backends: Arc<BackendRegistry>) -> Self {
        Self {
            backends,
            capabilities: RwLock::new(None),
            cache: None,
            default_cache_ttl: Duration::from_secs(60),
            stats: None,
            ranker: None,
        }
    }

    /// Create a new Meta-MCP handler with cache, stats, and ranking support
    pub fn with_features(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            backends,
            capabilities: RwLock::new(None),
            cache,
            default_cache_ttl: default_ttl,
            stats,
            ranker,
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
    pub fn handle_initialize(id: RequestId, params: Option<&Value>) -> JsonRpcResponse {
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        debug!(
            client = client_version,
            negotiated = negotiated_version,
            "Protocol version negotiation"
        );

        let result = build_initialize_result(negotiated_version);
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/list request
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        let tools = build_meta_tools(self.stats.is_some());
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
            "gateway_list_servers" => self.list_servers(),
            "gateway_list_tools" => self.list_tools(&arguments).await,
            "gateway_search_tools" => self.search_tools(&arguments).await,
            "gateway_invoke" => self.invoke_tool(&arguments).await,
            "gateway_get_stats" => self.get_stats(&arguments).await,
            _ => Err(Error::json_rpc(
                -32601,
                format!("Unknown tool: {tool_name}"),
            )),
        };

        match result {
            Ok(content) => wrap_tool_success(id, &content),
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// List all servers
    #[allow(clippy::unnecessary_wraps)]
    fn list_servers(&self) -> Result<Value> {
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
        let server = extract_required_str(args, "server")?;

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
        let query = extract_required_str(args, "query")?.to_lowercase();
        let limit = extract_search_limit(args);

        let mut matches = Vec::new();
        let mut total_found = 0u64;

        // Search capability backend first (faster, no network)
        if let Some(cap) = self.get_capabilities() {
            for tool in cap.get_tools() {
                if tool_matches_query(&tool, &query) {
                    total_found += 1;
                    matches.push(build_match_json(&cap.name, &tool));
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
                    if tool_matches_query(&tool, &query) {
                        total_found += 1;
                        matches.push(build_match_json(&backend.name, &tool));
                        if matches.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        // Record search stats
        if let Some(ref stats) = self.stats {
            stats.record_search(total_found);
        }

        // Apply ranking if enabled
        if let Some(ref ranker) = self.ranker {
            let search_results: Vec<_> = matches
                .iter()
                .filter_map(json_to_search_result)
                .collect();
            let ranked = ranker.rank(search_results, &query);
            matches = ranked_results_to_json(ranked);
        }

        Ok(build_search_response(&query, &matches))
    }

    /// Invoke a tool on a backend
    #[allow(clippy::too_many_lines)]
    async fn invoke_tool(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        let arguments = parse_tool_arguments(args)?;

        // Check cache first (if enabled)
        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            if let Some(cached) = cache.get(&cache_key) {
                debug!(server = server, tool = tool, "Cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_cache_hit();
                }
                return Ok(cached);
            }
        }

        // Record invocation and usage for ranking
        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        debug!(server = server, tool = tool, "Invoking tool");

        // Check if it's a capability
        let result = if let Some(cap) = self.get_capabilities() {
            if server == cap.name && cap.has_capability(tool) {
                let result = cap.call_tool(tool, arguments.clone()).await?;
                serde_json::to_value(result)?
            } else {
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

                if let Some(error) = response.error {
                    return Err(Error::JsonRpc {
                        code: error.code,
                        message: error.message,
                        data: error.data,
                    });
                }
                response.result.unwrap_or(json!(null))
            }
        } else {
            // No capabilities, must be MCP backend
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

            if let Some(error) = response.error {
                return Err(Error::JsonRpc {
                    code: error.code,
                    message: error.message,
                    data: error.data,
                });
            }
            response.result.unwrap_or(json!(null))
        };

        // Cache the successful result (if cache enabled)
        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            cache.set(&cache_key, result.clone(), self.default_cache_ttl);
            debug!(server = server, tool = tool, ttl = ?self.default_cache_ttl, "Cached result");
        }

        Ok(result)
    }

    /// Get gateway statistics
    async fn get_stats(&self, args: &Value) -> Result<Value> {
        let price_per_million = extract_price_per_million(args);

        let stats = self.stats.as_ref().ok_or_else(|| {
            Error::json_rpc(-32603, "Statistics not enabled for this gateway")
        })?;

        // Count total tools across all backends
        let mut total_tools = 0;
        for backend in self.backends.all() {
            if let Ok(tools) = backend.get_tools().await {
                total_tools += tools.len();
            }
        }
        if let Some(cap) = self.get_capabilities() {
            total_tools += cap.get_tools().len();
        }

        let snapshot = stats.snapshot(total_tools);
        Ok(build_stats_response(&snapshot, price_per_million))
    }
}
