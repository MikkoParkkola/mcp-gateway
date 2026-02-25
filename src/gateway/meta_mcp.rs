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
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;
use crate::{Error, Result};

use super::differential::annotate_differential;
use super::meta_mcp_helpers::{
    build_discovery_preamble, build_initialize_result, build_match_json,
    build_match_json_with_chains, build_meta_tools, build_routing_instructions,
    build_search_response, build_server_safety_status, build_stats_response, build_suggestions,
    extract_client_version, extract_price_per_million, extract_required_str, extract_search_limit,
    parse_tool_arguments, ranked_results_to_json, tool_matches_query, wrap_tool_success,
};
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
    /// Config reload context — set after startup to enable `gateway_reload_config`
    reload_context: RwLock<Option<Arc<ReloadContext>>>,
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
            reload_context: RwLock::new(None),
            playbook_engine: RwLock::new(PlaybookEngine::new()),
            log_level: RwLock::new(LoggingLevel::default()),
            kill_switch: Arc::new(KillSwitch::new()),
            error_budget_config: RwLock::new(ErrorBudgetConfig::default()),
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
            reload_context: RwLock::new(None),
        }
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
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        let tools = build_meta_tools(
            self.stats.is_some(),
            self.get_webhook_registry().is_some(),
            self.get_reload_context().is_some(),
        );
        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/call request.
    ///
    /// `session_id` is forwarded to `gateway_invoke` to enable per-session
    /// transition tracking and predictive prefetch.
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        let result = match tool_name {
            "gateway_list_servers" => self.list_servers(),
            "gateway_list_tools" => self.list_tools(&arguments).await,
            "gateway_search_tools" => self.search_tools(&arguments).await,
            "gateway_invoke" => self.invoke_tool(&arguments, session_id).await,
            "gateway_get_stats" => self.get_stats(&arguments).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
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

    /// List all servers, including kill-switch state per server.
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
                    "circuit_state": status.circuit_state,
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
                "circuit_state": "Closed",
                "status": if killed { "disabled" } else { "active" }
            }));
        }

        Ok(json!({ "servers": servers }))
    }

    /// List tools from a specific server, or ALL tools if server is omitted.
    ///
    /// Tools from killed servers are still returned but include `"status": "disabled"`
    /// so that the LLM knows the tool exists but cannot be invoked right now.
    async fn list_tools(&self, args: &Value) -> Result<Value> {
        // If server is specified, return tools from that single backend (existing behavior)
        if let Some(server) = args.get("server").and_then(Value::as_str) {
            let killed = self.kill_switch.is_killed(server);

            // Check if it's the capability backend
            if let Some(cap) = self.get_capabilities() {
                if server == cap.name {
                    let tools = cap.get_tools();
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

            let tools = backend.get_tools().await?;

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
            let cap_killed = self.kill_switch.is_killed(&cap.name);
            for tool in cap.get_tools() {
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

        // MCP backend tools (only from cached/warm-started backends — no blocking starts)
        for backend in self.backends.all() {
            if !backend.has_cached_tools() {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools().await {
                for tool in tools {
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
    async fn search_tools(&self, args: &Value) -> Result<Value> {
        let query = extract_required_str(args, "query")?.to_lowercase();
        let limit = extract_search_limit(args);

        let mut matches = Vec::new();
        // Collect all available tags for suggestion generation (only used on zero-result queries).
        let mut all_tags: Vec<String> = Vec::new();

        // Search capability backend exhaustively (fast, no network, all in memory).
        // Iterates over full CapabilityDefinition to include composition metadata.
        if let Some(cap) = self.get_capabilities() {
            let cap_killed = self.kill_switch.is_killed(&cap.name);
            for capability in cap.list_capabilities() {
                let tool = capability.to_mcp_tool();
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

        // Search MCP backends that have cached tools (fast, no blocking starts).
        // Backends without cached tools are skipped — use gateway_list_tools(server=X)
        // to force-start a specific backend.
        for backend in self.backends.all() {
            // Only query backends with cached tools to avoid blocking on unstarted backends
            if !backend.has_cached_tools() {
                continue;
            }
            let backend_killed = self.kill_switch.is_killed(&backend.name);
            if let Ok(tools) = backend.get_tools().await {
                // Enrich each tool's description with auto-extracted keyword tags so
                // that MCP backend tools participate in keyword matching just like
                // capability tools that carry explicit [keywords: ...] tags.
                let enriched: Vec<_> = tools
                    .into_iter()
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
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        let arguments = parse_tool_arguments(args)?;

        // --- Kill switch check (BEFORE anything else) ---
        if self.kill_switch.is_killed(server) {
            return Err(Error::json_rpc(
                -32000,
                format!(
                    "Server '{server}' is currently disabled by operator kill switch"
                ),
            ));
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
                    debug!(server, tool, key, "Idempotency cache hit — returning stored result");
                    if let Some(ref stats) = self.stats {
                        stats.record_cache_hit();
                    }
                    let predictions = self.record_and_predict(session_id, &tool_key);
                    return Ok(augment_with_predictions(cached, predictions));
                }
                GuardOutcome::Proceed => {
                    debug!(server, tool, key, "Idempotency key registered as in-flight");
                }
            }
        }

        // ── Response cache (read-through, does not prevent side effects) ─────
        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            if let Some(cached) = cache.get(&cache_key) {
                debug!(server = server, tool = tool, "Cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_cache_hit();
                }
                // Promote to idempotency cache if key present
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.mark_completed(key, cached.clone());
                }
                let predictions = self.record_and_predict(session_id, &tool_key);
                return Ok(augment_with_predictions(cached, predictions));
            }
        }

        // Record invocation and usage for ranking.
        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        debug!(server = server, tool = tool, "Invoking tool");

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
                );
                if auto_killed {
                    warn!(
                        server = server,
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
            debug!(server = server, tool = tool, ttl = ?self.default_cache_ttl, "Cached result");
        }

        // Transition idempotency entry to Completed.
        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            idem_cache.mark_completed(key, result.clone());
            debug!(server, tool, key, "Idempotency entry marked completed");
        }

        // Record transition and compute predictions after successful invocation.
        let predictions = self.record_and_predict(session_id, &tool_key);

        Ok(augment_with_predictions(result, predictions))
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

    /// Get gateway statistics including per-backend error budget status.
    async fn get_stats(&self, args: &Value) -> Result<Value> {
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

        // Append per-backend safety status (kill switch + error budget)
        let safety: Vec<Value> = self
            .backends
            .all()
            .iter()
            .map(|b| {
                let killed = self.kill_switch.is_killed(&b.name);
                let error_rate = self.kill_switch.error_rate(&b.name);
                let (successes, failures) = self.kill_switch.window_counts(&b.name);
                build_server_safety_status(&b.name, killed, error_rate, successes, failures)
            })
            .collect();

        if let Value::Object(ref mut map) = response {
            map.insert("server_safety".to_string(), Value::Array(safety));
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
