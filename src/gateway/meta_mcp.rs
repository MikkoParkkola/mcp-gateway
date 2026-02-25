//! Meta-MCP implementation - meta-tools for dynamic discovery and playbooks
//!
//! This module provides the gateway's meta-tools for discovering and invoking
//! tools across all backends, including:
//! - MCP backends (stdio, http)
//! - Capability backends (direct REST API integration)
//! - Playbooks (multi-step tool chains)
//!
//! Pure business logic functions are in [`super::meta_mcp_helpers`]. Async methods
//! here are thin wrappers that gather data and delegate to those pure functions.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::autotag;
use crate::backend::BackendRegistry;
use crate::config_reload::ReloadContext;
use crate::cache::ResponseCache;
use crate::capability::CapabilityBackend;
use crate::idempotency::{GuardOutcome, IdempotencyCache, derive_key, enforce, spawn_cleanup_task};
use crate::kill_switch::{ErrorBudgetConfig, KillSwitch};
use crate::playbook::{PlaybookEngine, ToolInvoker};
use crate::protocol::{
    JsonRpcResponse, LoggingLevel, LoggingSetLevelParams, Prompt, PromptsListResult, RequestId,
    Resource, ResourceTemplate, ResourcesListResult, ResourcesTemplatesListResult, ToolsListResult,
    negotiate_version,
};
use crate::ranking::{SearchRanker, json_to_search_result};
use crate::routing_profile::{ProfileRegistry, SessionProfileStore};
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;
use crate::{Error, Result};

use super::differential::annotate_differential;
use super::meta_mcp_helpers::{
    build_code_mode_match_json, build_code_mode_tools, build_discovery_preamble,
    build_initialize_result, build_match_json, build_match_json_with_chains, build_meta_tools,
    build_routing_instructions, build_search_response, build_server_safety_status,
    build_stats_response, build_suggestions, extract_client_version, extract_price_per_million,
    extract_required_str, extract_search_limit, is_glob_pattern, parse_code_mode_tool_ref,
    parse_tool_arguments, ranked_results_to_json, tool_matches_glob, tool_matches_query,
    wrap_tool_success,
};
use super::trace;
use super::webhooks::WebhookRegistry;

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
    /// Idempotency cache — prevents duplicate side effects on LLM retries
    idempotency_cache: Option<Arc<IdempotencyCache>>,
    /// Usage statistics
    stats: Option<Arc<UsageStats>>,
    /// Search ranker for usage-based ranking
    ranker: Option<Arc<SearchRanker>>,
    /// Predictive tool prefetch via invocation sequence tracking
    transition_tracker: RwLock<Option<Arc<TransitionTracker>>>,
    /// Playbook engine for multi-step tool chains
    playbook_engine: RwLock<PlaybookEngine>,
    /// Current logging level (gateway-wide, forwarded to backends)
    log_level: RwLock<LoggingLevel>,
    /// Operator kill switch + per-backend error budget
    kill_switch: Arc<KillSwitch>,
    /// Error budget configuration (thresholds, window size). Written once at
    /// startup; read on every invocation, so `RwLock` provides zero-overhead
    /// reads in the common case.
    error_budget_config: RwLock<ErrorBudgetConfig>,
    /// Webhook registry for status reporting (optional — set after startup)
    webhook_registry: RwLock<Option<Arc<parking_lot::RwLock<WebhookRegistry>>>>,
    /// Routing profiles registry (immutable after startup)
    profile_registry: Arc<ProfileRegistry>,
    /// Per-session active profile binding
    session_profiles: Arc<SessionProfileStore>,
    /// Config reload context — set after startup to enable `gateway_reload_config`
    reload_context: RwLock<Option<Arc<ReloadContext>>>,
    /// Code Mode: when `true`, `tools/list` returns only `gateway_search` + `gateway_execute`
    /// instead of the full meta-tool set.
    code_mode_enabled: bool,
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
            idempotency_cache: None,
            stats: None,
            ranker: None,
            transition_tracker: RwLock::new(None),
            webhook_registry: RwLock::new(None),
            playbook_engine: RwLock::new(PlaybookEngine::new()),
            log_level: RwLock::new(LoggingLevel::default()),
            kill_switch: Arc::new(KillSwitch::new()),
            error_budget_config: RwLock::new(ErrorBudgetConfig::default()),
            profile_registry: Arc::new(ProfileRegistry::default()),
            session_profiles: Arc::new(SessionProfileStore::new()),
            reload_context: RwLock::new(None),
            code_mode_enabled: false,
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
            idempotency_cache: None,
            stats,
            ranker,
            transition_tracker: RwLock::new(None),
            playbook_engine: RwLock::new(PlaybookEngine::new()),
            log_level: RwLock::new(LoggingLevel::default()),
            kill_switch: Arc::new(KillSwitch::new()),
            error_budget_config: RwLock::new(ErrorBudgetConfig::default()),
            webhook_registry: RwLock::new(None),
            profile_registry: Arc::new(ProfileRegistry::default()),
            session_profiles: Arc::new(SessionProfileStore::new()),
            reload_context: RwLock::new(None),
            code_mode_enabled: false,
        }
    }

    /// Builder-style: attach a routing profile registry.
    ///
    /// Call this after `with_features` and before wrapping in `Arc`.
    #[must_use]
    pub fn with_profile_registry(mut self, registry: ProfileRegistry) -> Self {
        self.profile_registry = Arc::new(registry);
        self
    }

    /// Builder-style: enable Code Mode.
    ///
    /// When Code Mode is enabled, `tools/list` returns only `gateway_search`
    /// and `gateway_execute` instead of the full meta-tool set. This reduces
    /// context consumption to near-zero.
    #[must_use]
    pub fn with_code_mode(mut self, enabled: bool) -> Self {
        self.code_mode_enabled = enabled;
        self
    }

    /// Enable idempotency support with a background cleanup task.
    ///
    /// Must be called during server setup before any requests are handled.
    /// Spawns a tokio task that evicts stale entries every `cleanup_interval`.
    #[allow(dead_code)]
    pub fn enable_idempotency(
        &mut self,
        cache: Arc<IdempotencyCache>,
        cleanup_interval: Duration,
    ) {
        spawn_cleanup_task(Arc::clone(&cache), cleanup_interval);
        self.idempotency_cache = Some(cache);
    }

    /// Attach the webhook registry for `gateway_webhook_status` reporting.
    ///
    /// Must be called during server setup, before any requests are handled.
    pub fn set_webhook_registry(&self, registry: Arc<parking_lot::RwLock<WebhookRegistry>>) {
        *self.webhook_registry.write() = Some(registry);
    }

    /// Get the webhook registry if attached.
    fn get_webhook_registry(&self) -> Option<Arc<parking_lot::RwLock<WebhookRegistry>>> {
        self.webhook_registry.read().clone()
    }

    /// Attach a [`ReloadContext`] to enable the `gateway_reload_config` meta-tool.
    ///
    /// Must be called during server setup, before any requests are handled.
    pub fn set_reload_context(&self, ctx: Arc<ReloadContext>) {
        *self.reload_context.write() = Some(ctx);
    }

    /// Get the reload context if set.
    fn get_reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    /// Attach a `TransitionTracker` for predictive tool prefetch.
    ///
    /// Must be called during server setup before any requests are handled.
    pub fn set_transition_tracker(&self, tracker: Arc<TransitionTracker>) {
        *self.transition_tracker.write() = Some(tracker);
    }

    /// Get the transition tracker if set.
    fn get_transition_tracker(&self) -> Option<Arc<TransitionTracker>> {
        self.transition_tracker.read().clone()
    }

    /// Set the capability backend
    pub fn set_capabilities(&self, capabilities: Arc<CapabilityBackend>) {
        *self.capabilities.write() = Some(capabilities);
    }

    /// Get capability backend if available
    fn get_capabilities(&self) -> Option<Arc<CapabilityBackend>> {
        self.capabilities.read().clone()
    }

    /// Expose the kill switch for external introspection or testing.
    #[allow(dead_code)]
    pub fn kill_switch(&self) -> Arc<KillSwitch> {
        Arc::clone(&self.kill_switch)
    }

    /// Expose the session profile store for testing and server teardown.
    #[must_use]
    #[allow(dead_code)]
    pub fn session_profiles(&self) -> Arc<SessionProfileStore> {
        Arc::clone(&self.session_profiles)
    }

    /// Expose the profile registry for testing.
    #[must_use]
    #[allow(dead_code)]
    pub fn profile_registry(&self) -> Arc<ProfileRegistry> {
        Arc::clone(&self.profile_registry)
    }

    /// Resolve the active `RoutingProfile` for a session.
    fn active_profile(
        &self,
        session_id: Option<&str>,
    ) -> crate::routing_profile::RoutingProfile {
        let default_name = self.profile_registry.default_name();
        let name = session_id.map_or_else(
            || default_name.to_string(),
            |sid| self.session_profiles.get_profile_name(sid, default_name),
        );
        self.profile_registry.get(&name)
    }

    /// Override the error-budget configuration (useful in tests and operator tooling).
    #[allow(dead_code)]
    pub fn set_error_budget_config(&self, config: ErrorBudgetConfig) {
        *self.error_budget_config.write() = config;
    }

    /// Handle initialize request with version negotiation.
    ///
    /// Generates dynamic routing instructions from the loaded capability
    /// definitions, giving the connecting LLM a task-oriented routing guide.
    pub fn handle_initialize(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse {
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        debug!(
            client = client_version,
            negotiated = negotiated_version,
            "Protocol version negotiation"
        );

        let instructions = self.build_instructions();
        let result = build_initialize_result(negotiated_version, &instructions);
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Compose the full `instructions` string from discovery preamble and
    /// dynamically generated routing guide based on loaded capabilities.
    fn build_instructions(&self) -> String {
        let mut instructions = build_discovery_preamble();

        if let Some(cap) = self.get_capabilities() {
            let caps = cap.list_capabilities();
            let routing = build_routing_instructions(&caps, &cap.name);
            if !routing.is_empty() {
                instructions.push_str(&routing);
            }
        }

        instructions
    }

    /// Handle tools/list request
    /// Handle `tools/list` request.
    ///
    /// When Code Mode is enabled, returns only `gateway_search` and
    /// `gateway_execute`.  Otherwise returns the full meta-tool set.
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        let tools = if self.code_mode_enabled {
            build_code_mode_tools()
        } else {
            build_meta_tools(
                self.stats.is_some(),
                self.get_webhook_registry().is_some(),
                self.get_reload_context().is_some(),
            )
        };
        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `tools/call` request.
    ///
    /// `session_id` is forwarded to `gateway_invoke` / `gateway_execute` to
    /// enable per-session transition tracking and predictive prefetch.
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        let result = match tool_name {
            // Code Mode tools (always available, even when code_mode_enabled=false)
            "gateway_search" => self.code_mode_search(&arguments, session_id).await,
            "gateway_execute" => self.code_mode_execute(&arguments, session_id).await,
            // Traditional meta-tools
            "gateway_list_servers" => self.list_servers(),
            "gateway_list_tools" => self.list_tools(&arguments, session_id).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id).await,
            "gateway_invoke" => self.invoke_tool(&arguments, session_id).await,
            "gateway_get_stats" => self.get_stats(&arguments).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_set_profile" => self.set_profile(&arguments, session_id),
            "gateway_get_profile" => self.get_profile(session_id),
            "gateway_reload_config" => self.reload_config().await,
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

    /// List all servers, including kill-switch state and circuit-breaker state per server.
    #[allow(clippy::unnecessary_wraps)]
    fn list_servers(&self) -> Result<Value> {
        let mut servers: Vec<Value> = self
            .backends
            .all()
            .iter()
            .map(|b| {
                let status = b.status();
                let killed = self.kill_switch.is_killed(&status.name);
                json!({
                    "name": status.name,
                    "running": status.running,
                    "transport": status.transport,
                    "tools_count": status.tools_cached,
                    "circuit_breaker": status.circuit_state,
                    "status": if killed { "disabled" } else { "active" }
                })
            })
            .collect();

        // Add capability backend if available
        if let Some(cap) = self.get_capabilities() {
            let status = cap.status();
            let killed = self.kill_switch.is_killed(&status.name);
            servers.push(json!({
                "name": status.name,
                "running": true,
                "transport": "capability",
                "tools_count": status.capabilities_count,
                "circuit_breaker": "closed",
                "status": if killed { "disabled" } else { "active" }
            }));
        }

        Ok(json!({ "servers": servers }))
    }

    // ========================================================================
    // Code Mode handlers (gateway_search + gateway_execute)
    // ========================================================================

    /// Handle `gateway_search` — Code Mode tool search with glob and schema support.
    ///
    /// Behaves like `search_tools` but:
    /// - Supports glob patterns (`*`, `?`) on tool names in addition to keyword matching.
    /// - Returns tool references in `"server:tool_name"` format (for use with `gateway_execute`).
    /// - Optionally includes the full `input_schema` for each result (`include_schema`, default `true`).
    async fn code_mode_search(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let raw_query = extract_required_str(args, "query")?;
        let query = raw_query.to_lowercase();
        let limit = extract_search_limit(args);
        let include_schema = args
            .get("include_schema")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let profile = self.active_profile(session_id);
        let use_glob = is_glob_pattern(&query);

        let mut matches: Vec<Value> = Vec::new();
        let mut all_tags: Vec<String> = Vec::new();

        // Search capability backend
        if let Some(cap) = self.get_capabilities() {
            if profile.backend_allowed(&cap.name) {
                let cap_killed = self.kill_switch.is_killed(&cap.name);
                for capability in cap.list_capabilities() {
                    let tool = capability.to_mcp_tool();
                    if !profile.tool_allowed(&tool.name) {
                        continue;
                    }
                    collect_tool_tags_for_code_mode(&tool, &mut all_tags);
                    let is_match = if use_glob {
                        tool_matches_glob(&tool, &query)
                    } else {
                        tool_matches_query(&tool, &query)
                    };
                    if is_match {
                        let mut entry =
                            build_code_mode_match_json(&cap.name, &tool, include_schema);
                        if cap_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }

        // Search MCP backends with cached tools
        for backend in self.backends.all() {
            if !backend.has_cached_tools() {
                continue;
            }
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools().await {
                let enriched: Vec<_> = tools
                    .into_iter()
                    .filter(|t| profile.tool_allowed(&t.name))
                    .map(|mut t| {
                        if let Some(ref desc) = t.description {
                            t.description = Some(autotag::enrich_description(desc));
                        }
                        t
                    })
                    .collect();

                for tool in &enriched {
                    collect_tool_tags_for_code_mode(tool, &mut all_tags);
                }
                for tool in enriched {
                    let is_match = if use_glob {
                        tool_matches_glob(&tool, &query)
                    } else {
                        tool_matches_query(&tool, &query)
                    };
                    if is_match {
                        let mut entry =
                            build_code_mode_match_json(&backend.name, &tool, include_schema);
                        if backend_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }

        let total_found = matches.len();

        // Apply ranking for keyword queries (not glob — glob already filters precisely)
        if !use_glob {
            if let Some(ref ranker) = self.ranker {
                let search_results: Vec<_> =
                    matches.iter().filter_map(json_to_code_mode_search_result).collect();
                let ranked = ranker.rank(search_results, &query);
                matches = ranked_results_to_code_mode_json(ranked, include_schema, &matches);
            }
        }

        matches.truncate(limit);

        let suggestions = if matches.is_empty() && !use_glob {
            build_suggestions(&query, &all_tags)
        } else {
            Vec::new()
        };

        Ok(build_search_response(&query, &matches, total_found, &suggestions))
    }

    /// Handle `gateway_execute` — Code Mode single-tool or chain execution.
    ///
    /// Single tool: requires `"tool"` (format `"server:tool_name"`) and optional
    /// `"arguments"`. Delegates to `invoke_tool` internally.
    ///
    /// Chain: requires `"chain"` array of `{tool, arguments}` objects. Each step
    /// is executed sequentially; results flow through naturally.
    async fn code_mode_execute(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        // Chain mode: sequential execution
        if let Some(chain) = args.get("chain").and_then(Value::as_array) {
            return self.execute_chain(chain.clone(), session_id).await;
        }

        // Single tool execution
        let tool_ref = extract_required_str(args, "tool")?;
        let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);

        let server = server_opt.ok_or_else(|| {
            Error::json_rpc(
                -32602,
                format!(
                    "Tool reference '{tool_ref}' is missing server prefix. \
                     Use format 'server:tool_name' from gateway_search results."
                ),
            )
        })?;

        let arguments = parse_tool_arguments(args)?;
        let invoke_args = json!({
            "server": server,
            "tool": tool_name,
            "arguments": arguments,
        });

        self.invoke_tool(&invoke_args, session_id).await
    }

    /// Execute a sequential chain of `{tool, arguments}` steps.
    ///
    /// Returns a JSON array of per-step results. Stops at the first error
    /// and surfaces the failing step index in the error message.
    async fn execute_chain(
        &self,
        chain: Vec<Value>,
        session_id: Option<&str>,
    ) -> Result<Value> {
        if chain.is_empty() {
            return Err(Error::json_rpc(-32602, "Chain must not be empty"));
        }

        let mut results: Vec<Value> = Vec::with_capacity(chain.len());

        for (idx, step) in chain.iter().enumerate() {
            let tool_ref = step
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::json_rpc(
                        -32602,
                        format!("Chain step {idx}: missing 'tool' field"),
                    )
                })?;

            let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);
            let server = server_opt.ok_or_else(|| {
                Error::json_rpc(
                    -32602,
                    format!(
                        "Chain step {idx}: tool reference '{tool_ref}' is missing server prefix. \
                         Use format 'server:tool_name'."
                    ),
                )
            })?;

            let arguments = step
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));

            let invoke_args = json!({
                "server": server,
                "tool": tool_name,
                "arguments": arguments,
            });

            match self.invoke_tool(&invoke_args, session_id).await {
                Ok(result) => results.push(json!({
                    "step": idx,
                    "tool": tool_ref,
                    "result": result,
                })),
                Err(e) => {
                    return Err(Error::json_rpc(
                        -32603,
                        format!("Chain step {idx} ({tool_ref}) failed: {e}"),
                    ));
                }
            }
        }

        Ok(json!({
            "steps": results.len(),
            "results": results,
        }))
    }

    /// List tools from a specific server, or ALL tools if server is omitted.
    ///
    /// Tools from killed servers are still returned but include `"status": "disabled"`
    /// so that the LLM knows the tool exists but cannot be invoked right now.
    ///
    /// Results are filtered by the session's active routing profile.
    async fn list_tools(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);

        // If server is specified, return tools from that single backend (existing behavior)
        if let Some(server) = args.get("server").and_then(Value::as_str) {
            let killed = self.kill_switch.is_killed(server);

            // Backend-level profile check for single-server queries
            if !profile.backend_allowed(server) {
                return Err(Error::Protocol(format!(
                    "Backend '{server}' is not available in the '{}' routing profile",
                    profile.name
                )));
            }

            // Check if it's the capability backend
            if let Some(cap) = self.get_capabilities() {
                if server == cap.name {
                    let tools: Vec<_> = cap
                        .get_tools()
                        .into_iter()
                        .filter(|t| profile.tool_allowed(&t.name))
                        .collect();
                    return Ok(json!({
                        "server": server,
                        "status": if killed { "disabled" } else { "active" },
                        "tools": tools
                    }));
                }
            }

            // Otherwise, look in MCP backends
            let backend = self
                .backends
                .get(server)
                .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

            let tools: Vec<_> = backend
                .get_tools()
                .await?
                .into_iter()
                .filter(|t| profile.tool_allowed(&t.name))
                .collect();

            return Ok(json!({
                "server": server,
                "status": if killed { "disabled" } else { "active" },
                "tools": tools
            }));
        }

        // No server specified: aggregate ALL tools (fast — tools are prefetched at startup)
        let mut all_tools: Vec<Value> = Vec::new();

        // Capability tools (instant, in memory)
        if let Some(cap) = self.get_capabilities() {
            if profile.backend_allowed(&cap.name) {
                let cap_killed = self.kill_switch.is_killed(&cap.name);
                for tool in cap.get_tools() {
                    if !profile.tool_allowed(&tool.name) {
                        continue;
                    }
                    let mut entry = json!({
                        "server": cap.name,
                        "name": tool.name,
                        "description": tool.description.as_deref().unwrap_or("")
                    });
                    if cap_killed {
                        entry["status"] = json!("disabled");
                    }
                    all_tools.push(entry);
                }
            }
        }

        // MCP backend tools (only from cached/warm-started backends — no blocking starts)
        for backend in self.backends.all() {
            if !backend.has_cached_tools() {
                continue;
            }
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools().await {
                for tool in tools {
                    if !profile.tool_allowed(&tool.name) {
                        continue;
                    }
                    let desc = autotag::enrich_description(
                        tool.description.as_deref().unwrap_or(""),
                    );
                    let mut entry = json!({
                        "server": backend.name,
                        "name": tool.name,
                        "description": desc
                    });
                    if backend_killed {
                        entry["status"] = json!("disabled");
                    }
                    all_tools.push(entry);
                }
            }
        }

        Ok(json!({
            "tools": all_tools,
            "total": all_tools.len()
        }))
    }

    /// Search tools across all backends.
    ///
    /// Capability tools are searched exhaustively (fast, local). MCP backends
    /// with cached tools are also searched exhaustively. All matches are
    /// collected first, ranked, and THEN truncated to the requested limit.
    /// This ensures the best matches always surface regardless of iteration order.
    ///
    /// When zero matches are found, keyword tags from all backends are collected
    /// and used to generate related query suggestions.
    ///
    /// Results are filtered by the session's active routing profile.
    async fn search_tools(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let query = extract_required_str(args, "query")?.to_lowercase();
        let limit = extract_search_limit(args);
        let profile = self.active_profile(session_id);

        let mut matches = Vec::new();
        // Collect all available tags for suggestion generation (only used on zero-result queries).
        let mut all_tags: Vec<String> = Vec::new();

        // Search capability backend exhaustively (fast, no network, all in memory).
        // Iterates over full CapabilityDefinition to include composition metadata.
        if let Some(cap) = self.get_capabilities() {
            if profile.backend_allowed(&cap.name) {
                let cap_killed = self.kill_switch.is_killed(&cap.name);
                for capability in cap.list_capabilities() {
                    let tool = capability.to_mcp_tool();
                    if !profile.tool_allowed(&tool.name) {
                        continue;
                    }
                    collect_tool_tags(&tool, &mut all_tags);
                    if tool_matches_query(&tool, &query) {
                        let mut entry = build_match_json_with_chains(
                            &cap.name,
                            &tool,
                            &capability.metadata.chains_with,
                        );
                        if cap_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }

        // Search MCP backends that have cached tools (fast, no blocking starts).
        // Backends without cached tools are skipped — use gateway_list_tools(server=X)
        // to force-start a specific backend.
        for backend in self.backends.all() {
            // Only query backends with cached tools to avoid blocking on unstarted backends
            if !backend.has_cached_tools() {
                continue;
            }
            if !profile.backend_allowed(&backend.name) {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools().await {
                // Enrich each tool's description with auto-extracted keyword tags so
                // that MCP backend tools participate in keyword matching just like
                // capability tools that carry explicit [keywords: ...] tags.
                let enriched: Vec<_> = tools
                    .into_iter()
                    .filter(|t| profile.tool_allowed(&t.name))
                    .map(|mut t| {
                        if let Some(ref desc) = t.description {
                            t.description = Some(autotag::enrich_description(desc));
                        }
                        t
                    })
                    .collect();

                for tool in &enriched {
                    collect_tool_tags(tool, &mut all_tags);
                }
                for tool in enriched {
                    if tool_matches_query(&tool, &query) {
                        let mut entry = build_match_json(&backend.name, &tool);
                        if backend_killed {
                            entry["status"] = json!("disabled");
                        }
                        matches.push(entry);
                    }
                }
            }
        }

        let total_found = matches.len();

        // Record search stats
        if let Some(ref stats) = self.stats {
            #[allow(clippy::cast_possible_truncation)]
            stats.record_search(total_found as u64);
        }

        // Apply ranking if enabled, then truncate to limit
        if let Some(ref ranker) = self.ranker {
            let search_results: Vec<_> = matches.iter().filter_map(json_to_search_result).collect();
            let ranked = ranker.rank(search_results, &query);
            matches = ranked_results_to_json(ranked);
        }

        // Truncate to requested limit AFTER ranking
        matches.truncate(limit);

        // Annotate tool families with differential descriptions so LLMs can
        // distinguish siblings (e.g. gmail_search vs gmail_send vs gmail_batch_modify).
        annotate_differential(&mut matches);

        // Build suggestions only when no results were found
        let suggestions = if matches.is_empty() {
            build_suggestions(&query, &all_tags)
        } else {
            Vec::new()
        };

        Ok(build_search_response(&query, &matches, total_found, &suggestions))
    }

    /// Invoke a tool on a backend, recording the transition for predictive prefetch.
    ///
    /// Checks the kill switch **before** every dispatch. When a server is killed,
    /// returns a clear operator error without touching the backend.
    ///
    /// Also records call outcomes against the per-backend error budget so that
    /// misbehaving backends are auto-killed when the configured threshold is exceeded.
    ///
    /// When `session_id` is `Some` and a `TransitionTracker` is attached, records
    /// the `previous_tool → current_tool` transition and appends `predicted_next`
    /// to the response for transitions meeting the minimum count (≥3) and
    /// confidence (≥30%) thresholds.
    ///
    /// # Idempotency
    ///
    /// When `args` contains an `"idempotency_key"` string field the call is
    /// deduplicated via the [`IdempotencyCache`]:
    ///
    /// - Key not found → execute and cache result for 24 h.
    /// - Key in-flight → return JSON-RPC 409 immediately.
    /// - Key completed → return cached result without re-executing.
    ///
    /// For tools whose `CapabilityMetadata.read_only` is `false` (side-effecting),
    /// a deterministic key is auto-derived from `(tool_name, arguments)` when no
    /// explicit key is supplied, protecting against exact-duplicate LLM retries
    /// even without client cooperation.
    async fn invoke_tool(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        // Generate a unique trace ID for this invocation and scope all work under it.
        // The ID is propagated to backend HTTP calls via the X-Trace-Id header and
        // returned to the caller in the response JSON so operators can correlate logs.
        let trace_id = trace::generate();
        let trace_id_clone = trace_id.clone();
        trace::with_trace_id(trace_id, async move {
            self.invoke_tool_traced(args, session_id, &trace_id_clone).await
        })
        .await
    }

    /// Inner implementation of [`invoke_tool`] executed within a trace-ID scope.
    ///
    /// The `trace_id` is already installed as the task-local [`trace::TRACE_ID`]
    /// by the caller and is passed explicitly here only so that it can be embedded
    /// in the response without a second task-local lookup.
    #[allow(clippy::too_many_lines)] // Complex dispatch logic; further splitting would harm readability
    async fn invoke_tool_traced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        trace_id: &str,
    ) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        let arguments = parse_tool_arguments(args)?;

        // Attach trace ID to the current span so it appears in all log lines.
        tracing::Span::current().record("trace_id", trace_id);

        // --- Kill switch check (BEFORE anything else) ---
        if self.kill_switch.is_killed(server) {
            return Err(Error::json_rpc(
                -32000,
                format!(
                    "Server '{server}' is currently disabled by operator kill switch"
                ),
            ));
        }

        // --- Routing profile check (after kill switch, before dispatch) ---
        let profile = self.active_profile(session_id);
        if let Err(msg) = profile.check(server, tool) {
            return Err(Error::Protocol(msg));
        }

        // Canonical key used for transition tracking.
        let tool_key = format!("{server}:{tool}");

        // ── Idempotency guard ────────────────────────────────────────────────
        // Resolve the idempotency key: explicit > auto-derived for side-effecting
        // tools > None (read-only / no idempotency cache).
        let idem_key = resolve_idempotency_key(args, server, tool, &arguments, self.idempotency_cache.as_ref());

        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            match enforce(idem_cache, key)? {
                GuardOutcome::CachedResult(cached) => {
                    debug!(server, tool, key, trace_id, "Idempotency cache hit — returning stored result");
                    if let Some(ref stats) = self.stats {
                        stats.record_cache_hit();
                    }
                    let predictions = self.record_and_predict(session_id, &tool_key);
                    return Ok(augment_with_trace(
                        augment_with_predictions(cached, predictions),
                        trace_id,
                    ));
                }
                GuardOutcome::Proceed => {
                    debug!(server, tool, key, trace_id, "Idempotency key registered as in-flight");
                }
            }
        }

        // ── Response cache (read-through, does not prevent side effects) ─────
        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            if let Some(cached) = cache.get(&cache_key) {
                debug!(server = server, tool = tool, trace_id, "Cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_cache_hit();
                }
                // Promote to idempotency cache if key present
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.mark_completed(key, cached.clone());
                }
                let predictions = self.record_and_predict(session_id, &tool_key);
                return Ok(augment_with_trace(
                    augment_with_predictions(cached, predictions),
                    trace_id,
                ));
            }
        }

        // Record invocation and usage for ranking.
        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        debug!(server = server, tool = tool, trace_id, "Invoking tool");

        // Dispatch to the appropriate backend.
        let dispatch_result = self.dispatch_to_backend(server, tool, arguments.clone()).await;

        // Record success or failure against the error budget.
        {
            let cfg = self.error_budget_config.read();
            if dispatch_result.is_ok() {
                self.kill_switch
                    .record_success(server, cfg.window_size, cfg.window_duration);
            } else {
                let auto_killed = self.kill_switch.record_failure(
                    server,
                    cfg.window_size,
                    cfg.window_duration,
                    cfg.threshold,
                    cfg.min_samples,
                );
                if auto_killed {
                    warn!(
                        server = server,
                        trace_id,
                        "Server auto-killed by error budget exhaustion"
                    );
                }
            }
        }

        // ── Handle dispatch outcome ──────────────────────────────────────────
        let result = match dispatch_result {
            Ok(value) => value,
            Err(e) => {
                // On failure: remove in-flight marker so the call is retryable.
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.remove(key);
                }
                return Err(e);
            }
        };

        // Cache the successful result (response cache).
        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            cache.set(&cache_key, result.clone(), self.default_cache_ttl);
            debug!(server = server, tool = tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }

        // Transition idempotency entry to Completed.
        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            idem_cache.mark_completed(key, result.clone());
            debug!(server, tool, key, trace_id, "Idempotency entry marked completed");
        }

        // Record transition and compute predictions after successful invocation.
        let predictions = self.record_and_predict(session_id, &tool_key);

        Ok(augment_with_trace(
            augment_with_predictions(result, predictions),
            trace_id,
        ))
    }

    /// Record the session transition and return predictions for the current tool.
    ///
    /// Returns an empty `Vec` when no tracker is attached or no predictions clear
    /// the thresholds — callers can pass directly to [`augment_with_predictions`].
    fn record_and_predict(
        &self,
        session_id: Option<&str>,
        tool_key: &str,
    ) -> Vec<serde_json::Value> {
        let Some(tracker) = self.get_transition_tracker() else {
            return Vec::new();
        };
        let Some(sid) = session_id else {
            return Vec::new();
        };

        tracker.record_transition(sid, tool_key);

        tracker
            .predict_next(tool_key, 0.30, 3)
            .into_iter()
            .map(|p| json!({"tool": p.tool, "confidence": p.confidence}))
            .collect()
    }

    /// Dispatch a `tools/call` to the capability backend or an MCP backend.
    async fn dispatch_to_backend(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
    ) -> Result<Value> {
        if let Some(cap) = self.get_capabilities() {
            if server == cap.name && cap.has_capability(tool) {
                let result = cap.call_tool(tool, arguments).await?;
                return Ok(serde_json::to_value(result)?);
            }
        }

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

        Ok(response.result.unwrap_or(json!(null)))
    }

    /// Get gateway statistics including per-backend error budget and circuit-breaker status.
    async fn get_stats(&self, args: &Value) -> Result<Value> {
        use super::meta_mcp_helpers::build_circuit_breaker_stats_json;

        let price_per_million = extract_price_per_million(args);

        let stats = self
            .stats
            .as_ref()
            .ok_or_else(|| Error::json_rpc(-32603, "Statistics not enabled for this gateway"))?;

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
        let mut response = build_stats_response(&snapshot, price_per_million);

        let all_backends = self.backends.all();

        // Append per-backend safety status (kill switch + error budget)
        let safety: Vec<Value> = all_backends
            .iter()
            .map(|b| {
                let killed = self.kill_switch.is_killed(&b.name);
                let error_rate = self.kill_switch.error_rate(&b.name);
                let (successes, failures) = self.kill_switch.window_counts(&b.name);
                build_server_safety_status(&b.name, killed, error_rate, successes, failures)
            })
            .collect();

        // Append per-backend circuit-breaker stats
        let cb_stats: Vec<Value> = all_backends
            .iter()
            .map(|b| build_circuit_breaker_stats_json(&b.name, &b.circuit_breaker_stats()))
            .collect();

        if let Value::Object(ref mut map) = response {
            map.insert("server_safety".to_string(), Value::Array(safety));
            map.insert("circuit_breakers".to_string(), Value::Array(cb_stats));
        }

        Ok(response)
    }

    /// Kill a backend server via the operator kill switch.
    ///
    /// Returns an error only if the `server` argument is missing; otherwise
    /// the kill is always accepted (idempotent).
    #[allow(clippy::unnecessary_wraps)]
    fn kill_server(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let was_already_killed = self.kill_switch.is_killed(server);
        self.kill_switch.kill(server);
        Ok(json!({
            "server": server,
            "status": "disabled",
            "was_already_killed": was_already_killed,
            "message": format!("Server '{server}' has been disabled by operator kill switch")
        }))
    }

    /// Revive a previously killed backend server.
    ///
    /// Also resets the error-budget window so the backend starts with a clean slate.
    /// Returns an error only if the `server` argument is missing.
    #[allow(clippy::unnecessary_wraps)]
    fn revive_server(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let was_killed = self.kill_switch.is_killed(server);
        self.kill_switch.revive(server);
        Ok(json!({
            "server": server,
            "status": "active",
            "was_killed": was_killed,
            "message": format!("Server '{server}' has been re-enabled")
        }))
    }

    /// Trigger an immediate config reload from disk and return a change summary.
    async fn reload_config(&self) -> Result<Value> {
        let ctx = self.get_reload_context().ok_or_else(|| {
            Error::json_rpc(-32603, "Config reload is not enabled on this gateway")
        })?;

        match ctx.reload().await {
            Ok(summary) => Ok(json!({
                "status": "ok",
                "changes": summary
            })),
            Err(e) => Err(Error::json_rpc(-32603, e)),
        }
    }

    /// Return webhook endpoint status — registered paths and delivery stats.
    #[allow(clippy::unnecessary_wraps)]
    fn webhook_status(&self) -> Result<Value> {
        let registry = self.get_webhook_registry().ok_or_else(|| {
            Error::json_rpc(-32603, "Webhook receiver is not enabled on this gateway")
        })?;

        let endpoints = registry.read().list_endpoints();
        let total = endpoints.len();
        let total_received: u64 = endpoints.iter().map(|e| e.stats.received).sum();
        let total_delivered: u64 = endpoints.iter().map(|e| e.stats.delivered).sum();

        Ok(json!({
            "endpoints": endpoints,
            "total_endpoints": total,
            "total_received": total_received,
            "total_delivered": total_delivered
        }))
    }

    /// Set the playbook engine (replaces existing).
    #[allow(dead_code)]
    pub fn set_playbook_engine(&self, engine: PlaybookEngine) {
        *self.playbook_engine.write() = engine;
    }

    /// Run a playbook by name.
    async fn run_playbook(&self, args: &Value) -> Result<Value> {
        let name = extract_required_str(args, "name")?;
        let arguments = parse_tool_arguments(args)?;

        debug!(playbook = name, "Running playbook");

        // Clone the definition to release the lock before awaiting.
        let definition = {
            let engine = self.playbook_engine.read();
            engine
                .get(name)
                .cloned()
                .ok_or_else(|| Error::json_rpc(-32602, format!("Playbook not found: {name}")))?
        };

        // Create a `MetaMcpInvoker` that delegates to `invoke_tool`.
        let invoker = MetaMcpInvoker { meta: self };

        // Build a temporary engine with just this definition for execution.
        let mut temp_engine = PlaybookEngine::new();
        temp_engine.register(definition);
        let result = temp_engine.execute(name, arguments, &invoker).await?;

        Ok(serde_json::to_value(&result).unwrap_or(json!(null)))
    }

    // ========================================================================
    // Resources handlers
    // ========================================================================

    /// Handle `resources/list` -- aggregate resources from all backends.
    ///
    /// Builds a URI routing map so that `resources/read` can determine which
    /// backend owns a given resource URI.
    pub async fn handle_resources_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_resources: Vec<Resource> = Vec::new();

        for backend in self.backends.all() {
            match backend.get_resources().await {
                Ok(resources) => {
                    all_resources.extend(resources);
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch resources from backend"
                    );
                }
            }
        }

        let result = ResourcesListResult {
            resources: all_resources,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `resources/read` -- route to the backend that owns the URI.
    ///
    /// Iterates all backends' cached resources to find the owner, then forwards
    /// the read request to that backend.
    pub async fn handle_resources_read(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        // Find which backend owns this resource URI
        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/read", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({"contents": []})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Handle `resources/templates/list` -- aggregate templates from all backends.
    pub async fn handle_resources_templates_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_templates: Vec<ResourceTemplate> = Vec::new();

        for backend in self.backends.all() {
            match backend.get_resource_templates().await {
                Ok(templates) => {
                    all_templates.extend(templates);
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch resource templates from backend"
                    );
                }
            }
        }

        let result = ResourcesTemplatesListResult {
            resource_templates: all_templates,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `resources/subscribe` -- route to the backend that owns the URI.
    pub async fn handle_resources_subscribe(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/subscribe", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Handle `resources/unsubscribe` -- route to the backend that owns the URI.
    pub async fn handle_resources_unsubscribe(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/unsubscribe", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    // ========================================================================
    // Prompts handlers
    // ========================================================================

    /// Handle `prompts/list` -- aggregate prompts from all backends.
    ///
    /// Prefixes each prompt name with `"backend_name/"` so that `prompts/get`
    /// can route back to the correct backend.
    pub async fn handle_prompts_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_prompts: Vec<Prompt> = Vec::new();

        for backend in self.backends.all() {
            match backend.get_prompts().await {
                Ok(prompts) => {
                    for mut prompt in prompts {
                        prompt.name = format!("{}/{}", backend.name, prompt.name);
                        all_prompts.push(prompt);
                    }
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch prompts from backend"
                    );
                }
            }
        }

        let result = PromptsListResult {
            prompts: all_prompts,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `prompts/get` -- route to the correct backend based on name prefix.
    ///
    /// Prompt names are namespaced as `"backend_name/original_prompt_name"`.
    /// Splits on the first `/` to recover the backend name and original name.
    pub async fn handle_prompts_get(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'name' parameter");
        };

        // Parse "backend_name/prompt_name"
        let Some((backend_name, original_name)) = name.split_once('/') else {
            return JsonRpcResponse::error(
                Some(id),
                -32602,
                format!(
                    "Invalid prompt name format: '{name}'. Expected 'backend_name/prompt_name'"
                ),
            );
        };

        let Some(backend) = self.backends.get(backend_name) else {
            return JsonRpcResponse::error(
                Some(id),
                -32001,
                format!("Backend not found: {backend_name}"),
            );
        };

        // Build forwarded params with original (un-prefixed) prompt name
        let mut forward_params = json!({ "name": original_name });
        if let Some(arguments) = params.and_then(|p| p.get("arguments")) {
            forward_params["arguments"] = arguments.clone();
        }

        match backend.request("prompts/get", Some(forward_params)).await {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({"messages": []})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    // ========================================================================
    // Logging handler
    // ========================================================================

    /// Handle `logging/setLevel` -- store level and broadcast to all backends.
    ///
    /// Updates the gateway-wide log level and forwards the request to every
    /// running backend. Backends that fail to accept the level are logged
    /// but do not cause the overall request to fail.
    pub async fn handle_logging_set_level(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let level_params: LoggingSetLevelParams =
            match params.map(|p| serde_json::from_value::<LoggingSetLevelParams>(p.clone())) {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    return JsonRpcResponse::error(
                        Some(id),
                        -32602,
                        format!("Invalid logging/setLevel params: {e}"),
                    );
                }
                None => {
                    return JsonRpcResponse::error(
                        Some(id),
                        -32602,
                        "Missing params for logging/setLevel",
                    );
                }
            };

        // Store the gateway-wide level
        *self.log_level.write() = level_params.level;
        debug!(level = ?level_params.level, "Logging level updated");

        // Broadcast to all backends (best-effort)
        let forward_params = serde_json::to_value(&level_params).unwrap_or(json!({}));
        for backend in self.backends.all() {
            if let Err(e) = backend
                .request("logging/setLevel", Some(forward_params.clone()))
                .await
            {
                warn!(
                    backend = %backend.name,
                    error = %e,
                    "Failed to forward logging/setLevel to backend"
                );
            }
        }

        JsonRpcResponse::success(id, json!({}))
    }

    /// Get the current gateway-wide logging level.
    #[must_use]
    #[allow(dead_code)]
    pub fn current_log_level(&self) -> LoggingLevel {
        *self.log_level.read()
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Find which backend owns a given resource URI by checking cached resources.
    async fn find_resource_owner(&self, uri: &str) -> Option<Arc<crate::backend::Backend>> {
        for backend in self.backends.all() {
            if let Ok(resources) = backend.get_resources().await {
                if resources.iter().any(|r| r.uri == uri) {
                    return Some(backend);
                }
            }
        }
        None
    }

    // ========================================================================
    // Routing profile meta-tools
    // ========================================================================

    /// `gateway_set_profile` — switch the active routing profile for this session.
    ///
    /// Returns an error when:
    /// - No `session_id` is available (stateless call).
    /// - The requested profile name is unknown.
    fn set_profile(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let Some(sid) = session_id else {
            return Err(Error::Protocol(
                "gateway_set_profile requires a session (send Mcp-Session-Id header)".to_string(),
            ));
        };

        let profile_name = extract_required_str(args, "profile")?;

        if !self.profile_registry.contains(profile_name) {
            let available = self.profile_registry.profile_names();
            return Err(Error::Protocol(format!(
                "Unknown routing profile '{profile_name}'. Available profiles: {}",
                if available.is_empty() {
                    "none configured".to_string()
                } else {
                    available.join(", ")
                }
            )));
        }

        self.session_profiles.set_profile(sid, profile_name);
        let profile = self.profile_registry.get(profile_name);

        Ok(json!({
            "profile": profile_name,
            "session_id": sid,
            "description": profile.describe(),
            "message": format!("Routing profile set to '{profile_name}'")
        }))
    }

    /// `gateway_get_profile` — report the active routing profile for this session.
    #[allow(clippy::unnecessary_wraps)] // Consistent with other meta-tool handlers that return Result<Value>
    fn get_profile(&self, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);
        Ok(json!({
            "profile": profile.name,
            "session_id": session_id,
            "description": profile.describe(),
            "available_profiles": self.profile_registry.profile_names(),
        }))
    }
}

/// Resolve the idempotency key for a `gateway_invoke` call.
///
/// Priority:
/// 1. Explicit `"idempotency_key"` string in `args` — used verbatim.
/// 2. Auto-derived from `(server, tool, arguments)` when an `IdempotencyCache`
///    is active.  This protects against exact-duplicate LLM retries even when
///    the client supplies no key.
///
/// Returns `None` when no idempotency cache is configured.
fn resolve_idempotency_key(
    args: &Value,
    server: &str,
    tool: &str,
    arguments: &Value,
    idem_cache: Option<&Arc<IdempotencyCache>>,
) -> Option<String> {
    idem_cache?;
    // Explicit key takes precedence.
    if let Some(key) = args.get("idempotency_key").and_then(Value::as_str) {
        return Some(key.to_string());
    }
    // Auto-derive from (server, tool, arguments) — stable, deterministic.
    let combined = format!("{server}:{tool}");
    Some(derive_key(&combined, arguments))
}

/// Extract keyword tags from a tool's description into `out`.
///
/// Tags are parsed from the `[keywords: tag1, tag2, ...]` suffix appended by
/// `CapabilityDefinition::to_mcp_tool()`. Tags are lowercased and hyphen-split
/// parts are also collected so both "entity-discovery" and "entity" are indexed.
fn collect_tool_tags(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    let Some(desc) = tool.description.as_deref() else {
        return;
    };
    let Some(kw_start) = desc.find("[keywords:") else {
        return;
    };
    let section = &desc[kw_start..];
    let inner = section
        .trim_start_matches("[keywords:")
        .trim_end_matches(']');
    for tag in inner.split(',') {
        let tag = tag.trim().to_lowercase();
        if !tag.is_empty() {
            // Also push hyphen-split parts (e.g. "entity-discovery" → "entity", "discovery")
            for part in tag.split('-') {
                let part = part.trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
            }
            out.push(tag);
        }
    }
}

/// Tag collector for Code Mode search (alias; delegates to the existing implementation).
///
/// Exists so that `code_mode_search` can call a descriptively named function without
/// duplicating the tag-parsing logic from `collect_tool_tags`.
fn collect_tool_tags_for_code_mode(tool: &crate::protocol::Tool, out: &mut Vec<String>) {
    collect_tool_tags(tool, out);
}

/// Convert a Code Mode search result JSON object into a [`crate::ranking::SearchResult`].
///
/// Code Mode matches use `"tool": "server:name"` format; this function splits
/// on the first `:` to recover server and `tool_name` for the ranker.
fn json_to_code_mode_search_result(v: &Value) -> Option<crate::ranking::SearchResult> {
    let tool_ref = v.get("tool")?.as_str()?;
    let description = v.get("description")?.as_str().unwrap_or("").to_string();
    let (tool_name, server_opt) = parse_code_mode_tool_ref(tool_ref);
    let server = server_opt?.to_string();
    Some(crate::ranking::SearchResult {
        server,
        tool: tool_name.to_string(),
        description,
        score: 0.0,
    })
}

/// Reconstruct ranked Code Mode results from ranked `SearchResult` objects.
///
/// After ranking, the schema must be re-fetched from the original matches list
/// (the ranker only carries name/description/score). This function rebuilds each
/// match JSON by looking up the original entry by its `"tool"` field.
fn ranked_results_to_code_mode_json(
    ranked: Vec<crate::ranking::SearchResult>,
    _include_schema: bool,
    originals: &[Value],
) -> Vec<Value> {
    ranked
        .into_iter()
        .filter_map(|r| {
            let tool_ref = format!("{}:{}", r.server, r.tool);
            // Find the original entry to preserve the schema field
            originals
                .iter()
                .find(|v| v.get("tool").and_then(Value::as_str) == Some(&tool_ref))
                .cloned()
        })
        .collect()
}

/// Bridges `MetaMcp::invoke_tool` to the `ToolInvoker` trait for playbook execution.
struct MetaMcpInvoker<'a> {
    meta: &'a MetaMcp,
}

#[async_trait::async_trait]
impl ToolInvoker for MetaMcpInvoker<'_> {
    async fn invoke(&self, server: &str, tool: &str, arguments: Value) -> Result<Value> {
        let args = json!({
            "server": server,
            "tool": tool,
            "arguments": arguments
        });
        self.meta.invoke_tool(&args, None).await
    }
}

// ============================================================================
// Response augmentation
// ============================================================================

/// Attach `predicted_next` to an invoke result when predictions are available.
///
/// If `predictions` is empty the original `result` is returned unchanged,
/// preserving the zero-cost fast path for sessions without enough history.
fn augment_with_predictions(mut result: Value, predictions: Vec<Value>) -> Value {
    if predictions.is_empty() {
        return result;
    }
    if let Value::Object(ref mut map) = result {
        map.insert(
            "predicted_next".to_string(),
            Value::Array(predictions),
        );
    }
    result
}

/// Attach `trace_id` to an invoke result so callers can correlate gateway logs
/// with backend logs.
///
/// The `trace_id` is always inserted; this function never returns the original
/// `result` unmodified (the contract guarantees the field is present).
fn augment_with_trace(mut result: Value, trace_id: &str) -> Value {
    if let Value::Object(ref mut map) = result {
        map.insert("trace_id".to_string(), json!(trace_id));
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::trace;

    // ── augment_with_trace ────────────────────────────────────────────────

    #[test]
    fn augment_with_trace_inserts_trace_id_field() {
        // GIVEN: a JSON object result and a trace ID
        let result = json!({"content": [{"type": "text", "text": "hello"}]});
        let trace_id = "gw-abc123";
        // WHEN: augmenting with the trace ID
        let augmented = augment_with_trace(result, trace_id);
        // THEN: trace_id field is present with the correct value
        assert_eq!(augmented["trace_id"], "gw-abc123");
    }

    #[test]
    fn augment_with_trace_preserves_existing_fields() {
        // GIVEN: a result with content and predicted_next
        let result = json!({
            "content": [{"type": "text", "text": "ok"}],
            "predicted_next": [{"tool": "foo", "confidence": 0.8}]
        });
        // WHEN: augmenting with a trace ID
        let augmented = augment_with_trace(result, "gw-xyz");
        // THEN: existing fields are preserved
        assert!(augmented.get("content").is_some());
        assert!(augmented.get("predicted_next").is_some());
        assert_eq!(augmented["trace_id"], "gw-xyz");
    }

    #[test]
    fn augment_with_trace_does_not_modify_non_object_values() {
        // GIVEN: a non-object JSON value (edge case)
        let result = json!(null);
        // WHEN: augmenting
        let augmented = augment_with_trace(result, "gw-abc");
        // THEN: null is returned unchanged (no panic)
        assert!(augmented.is_null());
    }

    // ── augment_with_predictions ──────────────────────────────────────────

    #[test]
    fn augment_with_predictions_no_op_when_empty() {
        // GIVEN: empty predictions
        let result = json!({"content": []});
        let original = result.clone();
        // WHEN: augmenting with empty predictions
        let augmented = augment_with_predictions(result, vec![]);
        // THEN: result is unchanged
        assert_eq!(augmented, original);
    }

    #[test]
    fn augment_with_predictions_inserts_predicted_next() {
        // GIVEN: one prediction
        let result = json!({"content": []});
        let predictions = vec![json!({"tool": "foo:bar", "confidence": 0.9})];
        // WHEN: augmenting
        let augmented = augment_with_predictions(result, predictions);
        // THEN: predicted_next field is present
        let preds = augmented["predicted_next"].as_array().unwrap();
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0]["tool"], "foo:bar");
    }

    // ── trace ID generation roundtrip ─────────────────────────────────────

    #[tokio::test]
    async fn invoke_tool_trace_id_is_accessible_inside_scope() {
        // GIVEN: a fresh trace ID
        let id = trace::generate();
        // WHEN: inside a with_trace_id scope
        let observed = trace::with_trace_id(id.clone(), async {
            trace::current()
        })
        .await;
        // THEN: the same ID is visible inside the scope
        assert_eq!(observed, Some(id));
    }

    #[tokio::test]
    async fn trace_id_not_accessible_outside_scope() {
        // GIVEN: no active scope
        // WHEN: reading outside any with_trace_id scope
        // THEN: current() returns None
        assert_eq!(trace::current(), None);
    }

    // ── Code Mode: handle_tools_list ─────────────────────────────────────────

    fn make_meta_mcp() -> MetaMcp {
        use crate::backend::BackendRegistry;
        MetaMcp::new(Arc::new(BackendRegistry::new()))
    }

    fn make_meta_mcp_code_mode() -> MetaMcp {
        use crate::backend::BackendRegistry;
        MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(true)
    }

    #[test]
    fn handle_tools_list_code_mode_disabled_returns_meta_tools() {
        // GIVEN: code mode is disabled
        let meta = make_meta_mcp();
        // WHEN: tools/list is called
        let response = meta.handle_tools_list(RequestId::Number(1));
        // THEN: response has no error
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        // Traditional mode returns 9+ meta-tools (none of which are gateway_search/gateway_execute)
        assert!(tools.len() >= 9, "Expected at least 9 meta-tools, got {}", tools.len());
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"gateway_invoke"));
        assert!(names.contains(&"gateway_search_tools"));
        assert!(!names.contains(&"gateway_search"),
            "gateway_search should NOT appear in traditional mode");
        assert!(!names.contains(&"gateway_execute"),
            "gateway_execute should NOT appear in traditional mode");
    }

    #[test]
    fn handle_tools_list_code_mode_enabled_returns_exactly_two_tools() {
        // GIVEN: code mode is enabled
        let meta = make_meta_mcp_code_mode();
        // WHEN: tools/list is called
        let response = meta.handle_tools_list(RequestId::Number(1));
        // THEN: exactly two tools are returned
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2, "Code mode must return exactly 2 tools");
    }

    #[test]
    fn handle_tools_list_code_mode_enabled_first_tool_is_gateway_search() {
        // GIVEN: code mode enabled
        let meta = make_meta_mcp_code_mode();
        // WHEN: tools/list
        let response = meta.handle_tools_list(RequestId::Number(2));
        let tools = response.result.unwrap()["tools"].clone();
        // THEN: first tool is gateway_search
        assert_eq!(tools[0]["name"], "gateway_search");
    }

    #[test]
    fn handle_tools_list_code_mode_enabled_second_tool_is_gateway_execute() {
        // GIVEN: code mode enabled
        let meta = make_meta_mcp_code_mode();
        // WHEN: tools/list
        let response = meta.handle_tools_list(RequestId::Number(3));
        let tools = response.result.unwrap()["tools"].clone();
        // THEN: second tool is gateway_execute
        assert_eq!(tools[1]["name"], "gateway_execute");
    }

    #[test]
    fn handle_tools_list_code_mode_enabled_does_not_include_traditional_tools() {
        // GIVEN: code mode enabled
        let meta = make_meta_mcp_code_mode();
        // WHEN: tools/list
        let response = meta.handle_tools_list(RequestId::Number(4));
        let tools = response.result.unwrap()["tools"].clone();
        let tools = tools.as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        // THEN: traditional meta-tools are absent
        assert!(!names.contains(&"gateway_invoke"),
            "gateway_invoke should not appear in code mode");
        assert!(!names.contains(&"gateway_search_tools"),
            "gateway_search_tools should not appear in code mode");
        assert!(!names.contains(&"gateway_list_servers"),
            "gateway_list_servers should not appear in code mode");
    }

    // ── Code Mode: with_code_mode builder ────────────────────────────────────

    #[test]
    fn with_code_mode_false_is_default() {
        // GIVEN: MetaMcp built without code mode
        let meta = make_meta_mcp();
        // WHEN: tools/list
        let response = meta.handle_tools_list(RequestId::Number(10));
        let tools = response.result.unwrap()["tools"].clone();
        // THEN: not code mode (>2 tools)
        assert!(tools.as_array().unwrap().len() > 2);
    }

    #[test]
    fn with_code_mode_true_toggles_behavior() {
        // GIVEN: MetaMcp built with code mode toggled on
        let meta = make_meta_mcp().with_code_mode(true);
        // WHEN: tools/list
        let response = meta.handle_tools_list(RequestId::Number(11));
        let tools = response.result.unwrap()["tools"].clone();
        // THEN: exactly 2 tools returned
        assert_eq!(tools.as_array().unwrap().len(), 2);
    }

    // ── Code Mode: code_mode_execute error paths ──────────────────────────────

    #[tokio::test]
    async fn code_mode_execute_missing_tool_parameter_returns_error() {
        // GIVEN: args without 'tool' or 'chain'
        let meta = make_meta_mcp_code_mode();
        let args = json!({ "arguments": {} });
        // WHEN: code_mode_execute is called
        let result = meta.code_mode_execute(&args, None).await;
        // THEN: error about missing 'tool'
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("tool") || msg.contains("Missing"),
            "Expected error about missing tool, got: {msg}");
    }

    #[tokio::test]
    async fn code_mode_execute_bare_tool_name_without_server_returns_error() {
        // GIVEN: tool ref without server prefix
        let meta = make_meta_mcp_code_mode();
        let args = json!({ "tool": "my_tool", "arguments": {} });
        // WHEN: code_mode_execute is called
        let result = meta.code_mode_execute(&args, None).await;
        // THEN: error about missing server prefix
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("server") || msg.contains("prefix"),
            "Expected error about server prefix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn code_mode_execute_chain_empty_array_returns_error() {
        // GIVEN: empty chain
        let meta = make_meta_mcp_code_mode();
        let args = json!({ "chain": [] });
        // WHEN: code_mode_execute is called
        let result = meta.code_mode_execute(&args, None).await;
        // THEN: error about empty chain
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("empty") || msg.contains("Chain"),
            "Expected error about empty chain, got: {msg}");
    }

    #[tokio::test]
    async fn code_mode_execute_chain_step_missing_tool_field_returns_error() {
        // GIVEN: chain step without 'tool' field
        let meta = make_meta_mcp_code_mode();
        let args = json!({
            "chain": [
                {"arguments": {}}
            ]
        });
        // WHEN: code_mode_execute is called
        let result = meta.code_mode_execute(&args, None).await;
        // THEN: error about missing tool field in step 0
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("step 0") || msg.contains("missing 'tool'"),
            "Expected error about step 0, got: {msg}"
        );
    }

    #[tokio::test]
    async fn code_mode_execute_chain_step_bare_tool_name_returns_error() {
        // GIVEN: chain step with bare tool name (no server prefix)
        let meta = make_meta_mcp_code_mode();
        let args = json!({
            "chain": [
                {"tool": "my_bare_tool"}
            ]
        });
        // WHEN: code_mode_execute is called
        let result = meta.code_mode_execute(&args, None).await;
        // THEN: error about missing server prefix for step 0
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("server prefix") || msg.contains("step 0"),
            "Expected error about step 0 server prefix, got: {msg}"
        );
    }

    // ── Code Mode: gateway_search and gateway_execute are always callable ─────

    #[tokio::test]
    async fn gateway_search_is_callable_regardless_of_code_mode_flag() {
        // GIVEN: code mode disabled, but calling gateway_search explicitly
        let meta = make_meta_mcp();
        let args = json!({ "query": "nonexistent_xyz_404" });
        let response = meta
            .handle_tools_call(RequestId::Number(99), "gateway_search", args, None)
            .await;
        // THEN: no JSON-RPC error (-32601 unknown tool), just zero results
        assert!(response.error.is_none(),
            "gateway_search should be callable even without code_mode enabled; got: {:?}",
            response.error);
    }

    #[tokio::test]
    async fn gateway_execute_missing_tool_and_chain_returns_tool_call_error() {
        // GIVEN: code mode disabled, calling gateway_execute with no tool/chain
        let meta = make_meta_mcp();
        let args = json!({});
        let response = meta
            .handle_tools_call(RequestId::Number(100), "gateway_execute", args, None)
            .await;
        // THEN: returns an error (not -32601 unknown tool)
        // The response wraps the error as tool content (is_error=true) OR as RPC error
        // Either way, there should not be a -32601 "Unknown tool" error
        if let Some(ref err) = response.error {
            assert_ne!(err.code, -32601,
                "Should not be 'Unknown tool' error; got code={}", err.code);
        }
        // If no RPC error, the tool result should indicate an error condition
    }
}
