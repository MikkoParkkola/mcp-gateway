//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::cache::ResponseCache;
use crate::cache_key::{CacheKeyDeriver, extract_cached_tokens, inject_cache_key};
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::idempotency::{GuardOutcome, enforce};
use crate::playbook::PlaybookEngine;
use crate::security::validate_tool_name;
use crate::{Error, Result};

use super::super::meta_mcp_helpers::{
    build_circuit_breaker_stats_json, build_server_safety_status, build_stats_response,
    extract_price_per_million, extract_required_str, parse_tool_arguments,
};
use super::super::trace;
use super::MetaMcp;
use super::support::{
    MetaMcpInvoker, augment_with_predictions, augment_with_trace, resolve_idempotency_key,
};

/// Monotonically increasing request counter for load-balanced cache key slot selection.
///
/// Global across all backends; overflow wraps (u64 → effectively infinite for our purposes).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

impl MetaMcp {
    /// `gateway_invoke` — invoke a tool on a backend with full tracing, caching,
    /// idempotency, error-budget tracking, and predictive prefetch.
    pub(super) async fn invoke_tool(
        &self,
        args: &Value,
        session_id: Option<&str>,
        api_key_name: Option<&str>,
    ) -> Result<Value> {
        let trace_id = trace::generate();
        let trace_id_clone = trace_id.clone();
        trace::with_trace_id(trace_id, async move {
            self.invoke_tool_traced(args, session_id, api_key_name, &trace_id_clone)
                .await
        })
        .await
    }

    /// Inner implementation executed within a trace-ID scope.
    #[allow(clippy::too_many_lines)] // Complex dispatch logic; splitting further harms readability
    async fn invoke_tool_traced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        api_key_name: Option<&str>,
        trace_id: &str,
    ) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        let arguments = parse_tool_arguments(args)?;

        // Validate tool name syntax before any work — prevents session corruption
        // from malformed names injected by compromised backend servers.
        if let Err(reason) = validate_tool_name(tool) {
            return Err(Error::Protocol(format!(
                "Invalid tool name '{tool}': {reason}"
            )));
        }

        tracing::Span::current().record("trace_id", trace_id);

        if self.kill_switch.is_killed(server) {
            return Err(Error::json_rpc(
                -32000,
                format!("Server '{server}' is currently disabled by operator kill switch"),
            ));
        }

        {
            let cap_cfg = self.capability_budget_config.read();
            if self
                .kill_switch
                .is_capability_disabled_with_cooldown(server, tool, cap_cfg.cooldown)
            {
                return Err(Error::json_rpc(
                    -32000,
                    format!(
                        "Capability '{tool}' on server '{server}' is temporarily disabled due to \
                         a high error rate. It will auto-recover after the cooldown period. \
                         Use gateway_list_disabled_capabilities to see all disabled capabilities."
                    ),
                ));
            }
        }

        let profile = self.active_profile(session_id);
        if let Err(msg) = profile.check(server, tool) {
            return Err(Error::Protocol(msg));
        }

        let tool_key = format!("{server}:{tool}");

        let idem_key = resolve_idempotency_key(
            args,
            server,
            tool,
            &arguments,
            self.idempotency_cache.as_ref(),
        );

        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            match enforce(idem_cache, key)? {
                GuardOutcome::CachedResult(cached) => {
                    debug!(server, tool, key, trace_id, "Idempotency cache hit");
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
                    debug!(
                        server,
                        tool, key, trace_id, "Idempotency key registered as in-flight"
                    );
                }
            }
        }

        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            if let Some(cached) = cache.get(&cache_key) {
                debug!(server, tool, trace_id, "Cache hit");
                if let Some(ref stats) = self.stats {
                    stats.record_cache_hit();
                }
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

        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        debug!(server, tool, trace_id, "Invoking tool");

        // === PRE-INVOKE: Cost governance budget check ===
        //
        // Returns the warnings to inject post-dispatch and blocks when the
        // budget is exceeded (returns JSON-RPC -32003 error).
        #[cfg(feature = "cost-governance")]
        let cost_warnings: Vec<String> = if let Some(ref enforcer) = self.budget_enforcer {
            let result = enforcer.check(tool, api_key_name);
            if !result.allowed {
                return Err(Error::json_rpc(
                    -32003,
                    result
                        .block_reason
                        .unwrap_or_else(|| "Budget exceeded".to_string()),
                ));
            }
            result.warnings
        } else {
            Vec::new()
        };

        // Derive a prompt_cache_key for OpenAI-compatible backends.
        // Priority: explicit _meta.prompt_cache_key from caller > session hash.
        let prompt_cache_key: Option<String> = args
            .get("_meta")
            .and_then(|m| m.get("prompt_cache_key"))
            .and_then(Value::as_str)
            .map(CacheKeyDeriver::from_header)
            .or_else(|| {
                session_id.map(|sid| {
                    let deriver = CacheKeyDeriver::with_slots(3);
                    let base = CacheKeyDeriver::from_context(sid);
                    let req_idx = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
                    let slot = deriver.slot_for_request(req_idx);
                    deriver.key_for_slot(&base, slot)
                })
            });

        let dispatch_result = self
            .dispatch_to_backend(server, tool, arguments.clone(), prompt_cache_key.as_deref())
            .await;

        // Record prompt-cached tokens from the backend response (if any)
        if let Ok(ref response) = dispatch_result {
            let cached_tokens = extract_cached_tokens(response);
            if cached_tokens > 0
                && let Some(ref stats) = self.stats
            {
                stats.record_cached_tokens(server, session_id, cached_tokens);
                debug!(
                    server,
                    tool, cached_tokens, trace_id, "Prompt cache hit recorded"
                );
            }
        }

        self.record_error_budget(server, tool, dispatch_result.is_ok());

        // Record cost for successful calls (token count estimated at 0 for non-LLM tools).
        if dispatch_result.is_ok()
            && let Some(sid) = session_id
        {
            self.cost_tracker.record(
                sid,
                api_key_name,
                server,
                tool,
                0, // token_count: 0 for backend tool calls (no model inference)
                crate::cost_accounting::DEFAULT_PRICE_PER_MILLION,
            );
        }

        // === POST-INVOKE: BudgetEnforcer cost recording ===
        //
        // Record actual spend for per-tool and global daily accumulators.
        // Only on success — the call actually incurred the cost.
        #[cfg(feature = "cost-governance")]
        if dispatch_result.is_ok()
            && let Some(ref enforcer) = self.budget_enforcer
        {
            let cost = enforcer.registry.cost_for(tool);
            enforcer.record_spend(tool, api_key_name, cost);
        }

        let mut result = match dispatch_result {
            Ok(value) => value,
            Err(e) => {
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.remove(key);
                }
                return Err(e);
            }
        };

        // === POST-INVOKE: Inject cost warnings and suggestions ===
        //
        // `_cost_warnings` — active at ≥80% budget consumption (Notify tier).
        // `_cost_suggestion` — present when a cheaper alternative exists.
        #[cfg(feature = "cost-governance")]
        {
            if !cost_warnings.is_empty()
                && let Some(obj) = result.as_object_mut()
            {
                obj.insert(
                    "_cost_warnings".to_string(),
                    serde_json::json!(cost_warnings),
                );
            }

            if let Some(ref enforcer) = self.budget_enforcer {
                let cost = enforcer.registry.cost_for(tool);
                if cost > 0.0 {
                    let all_costs = enforcer.registry.snapshot();
                    let alternatives = enforcer.config.alternatives.as_ref();
                    if let Some(suggestion) =
                        suggestions::suggest_cheaper(tool, cost, &all_costs, alternatives)
                        && let Some(obj) = result.as_object_mut()
                    {
                        obj.insert(
                            "_cost_suggestion".to_string(),
                            serde_json::json!({
                                "message": suggestion.reason,
                                "alternative": suggestion.alternative,
                                "savings_per_call": suggestion.savings_per_call,
                                "alternative_cost": suggestion.alternative_cost,
                            }),
                        );
                    }
                }
            }
        }

        if let Some(ref cache) = self.cache {
            let cache_key = ResponseCache::build_key(server, tool, &arguments);
            cache.set(&cache_key, result.clone(), self.default_cache_ttl);
            debug!(server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }

        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            idem_cache.mark_completed(key, result.clone());
            debug!(
                server,
                tool, key, trace_id, "Idempotency entry marked completed"
            );
        }

        let predictions = self.record_and_predict(session_id, &tool_key);
        Ok(augment_with_trace(
            augment_with_predictions(result, predictions),
            trace_id,
        ))
    }

    /// Record success/failure against both backend and per-capability error budgets.
    fn record_error_budget(&self, server: &str, tool: &str, success: bool) {
        let cfg = self.error_budget_config.read();
        let cap_cfg = self.capability_budget_config.read();
        if success {
            self.kill_switch
                .record_success(server, cfg.window_size, cfg.window_duration);
            self.kill_switch
                .record_capability_success(server, tool, &cap_cfg);
        } else {
            let auto_killed = self.kill_switch.record_failure(
                server,
                cfg.window_size,
                cfg.window_duration,
                cfg.threshold,
                cfg.min_samples,
            );
            let cap_disabled = self
                .kill_switch
                .record_capability_failure(server, tool, &cap_cfg);
            if auto_killed {
                warn!(server, "Server auto-killed by error budget exhaustion");
            }
            if cap_disabled {
                warn!(
                    server,
                    tool, "Capability auto-disabled by per-capability error budget"
                );
            }
        }
    }

    /// Record the session transition and return predictions for the current tool.
    ///
    /// Side-effects:
    /// - Records `session_id → tool_key` in the `TransitionTracker`.
    /// - If a `ToolRegistry` is attached, triggers schema prefetching for the
    ///   top-N predicted successors (see [`crate::tool_registry::ToolRegistry::prefetch_after`]).
    pub(super) fn record_and_predict(
        &self,
        session_id: Option<&str>,
        tool_key: &str,
    ) -> Vec<Value> {
        let Some(tracker) = self.get_transition_tracker() else {
            return Vec::new();
        };
        let Some(sid) = session_id else {
            return Vec::new();
        };

        tracker.record_transition(sid, tool_key);

        // Warm registry schemas for predicted-next tools (no-op when no registry).
        if let Some(registry) = self.get_tool_registry() {
            registry.prefetch_after(tool_key, &tracker, 0.20, 2);
        }

        tracker
            .predict_next(tool_key, 0.30, 3)
            .into_iter()
            .map(|p| json!({"tool": p.tool, "confidence": p.confidence}))
            .collect()
    }

    /// Dispatch a `tools/call` to the capability backend or an MCP backend.
    ///
    /// Applies secret injection before forwarding. When `prompt_cache_key` is
    /// `Some`, it is injected into the request `_meta` field so that
    /// OpenAI-compatible backends can use it for prompt caching.
    async fn dispatch_to_backend(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
        prompt_cache_key: Option<&str>,
    ) -> Result<Value> {
        let injection = self.secret_injector.inject(server, tool, arguments)?;
        let arguments = injection.arguments;

        if let Some(cap) = self.get_capabilities()
            && server == cap.name
            && cap.has_capability(tool)
        {
            let result = cap.call_tool(tool, arguments).await?;
            return Ok(serde_json::to_value(result)?);
        }

        let backend = self
            .backends
            .get(server)
            .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        // Build request params, injecting cache key into _meta when present.
        let base_params = json!({ "name": tool, "arguments": arguments });
        let params = match prompt_cache_key {
            Some(key) => inject_cache_key(Some(base_params), key),
            None => base_params,
        };

        let response = backend.request("tools/call", Some(params)).await?;

        if let Some(error) = response.error {
            return Err(Error::JsonRpc {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }

        Ok(response.result.unwrap_or(json!(null)))
    }

    // ========================================================================
    // Operator control meta-tools
    // ========================================================================

    /// `gateway_cost_report` — per-session and per-API-key spend report.
    #[allow(clippy::unnecessary_wraps, clippy::unused_async)]
    pub(super) async fn get_cost_report(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let include_all_sessions = args
            .get("include_all_sessions")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let include_all_keys = args
            .get("include_all_keys")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Resolve target session (explicit arg or current session)
        let target_session_id = args
            .get("session_id")
            .and_then(Value::as_str)
            .or(session_id);

        let session_report = if include_all_sessions {
            serde_json::to_value(self.cost_tracker.all_sessions()).unwrap_or(json!([]))
        } else if let Some(sid) = target_session_id {
            self.cost_tracker
                .session_snapshot(sid)
                .map(|s| serde_json::to_value(s).unwrap_or(json!(null)))
                .unwrap_or(json!(null))
        } else {
            json!(null)
        };

        let key_report = if include_all_keys {
            serde_json::to_value(self.cost_tracker.all_keys()).unwrap_or(json!([]))
        } else {
            json!(null)
        };

        let aggregate = serde_json::to_value(self.cost_tracker.aggregate()).unwrap_or(json!(null));

        Ok(json!({
            "session": session_report,
            "keys": key_report,
            "aggregate": aggregate,
        }))
    }

    /// `gateway_get_stats` — gateway statistics with per-backend error budget
    /// and circuit-breaker status.
    #[allow(clippy::unused_async)]
    pub(super) async fn get_stats(&self, args: &Value) -> Result<Value> {
        let price_per_million = extract_price_per_million(args);

        let stats = self
            .stats
            .as_ref()
            .ok_or_else(|| Error::json_rpc(-32603, "Statistics not enabled for this gateway"))?;

        let mut total_tools: usize = self
            .backends
            .all()
            .iter()
            .map(|b| b.cached_tools_count())
            .sum();
        if let Some(cap) = self.get_capabilities() {
            total_tools += cap.get_tools().len();
        }

        let snapshot = stats.snapshot(total_tools);
        let mut response = build_stats_response(&snapshot, price_per_million);

        let all_backends = self.backends.all();

        let safety: Vec<Value> = all_backends
            .iter()
            .map(|b| {
                let killed = self.kill_switch.is_killed(&b.name);
                let error_rate = self.kill_switch.error_rate(&b.name);
                let (successes, failures) = self.kill_switch.window_counts(&b.name);
                build_server_safety_status(&b.name, killed, error_rate, successes, failures)
            })
            .collect();

        let cb_stats: Vec<Value> = all_backends
            .iter()
            .map(|b| build_circuit_breaker_stats_json(&b.name, &b.circuit_breaker_stats()))
            .collect();

        if let Value::Object(ref mut map) = response {
            map.insert("server_safety".to_string(), Value::Array(safety));
            map.insert("circuit_breakers".to_string(), Value::Array(cb_stats));
        }

        // Inject cost governance section when enabled
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = self.budget_enforcer {
            let snap = enforcer.snapshot();
            let cost_section = json!({
                "global_daily_spend_usd": snap.global_daily_usd,
                "global_daily_limit_usd": snap.global_daily_limit,
                "tool_daily_spend": snap.tool_daily,
                "tool_daily_limits": snap.tool_limits,
                "key_daily_spend": snap.key_daily,
            });
            if let Value::Object(ref mut map) = response {
                map.insert("cost_governance".to_string(), cost_section);
            }
            if let Some(ref registry) = self.cost_registry {
                let tool_costs = json!(registry.snapshot());
                if let Value::Object(ref mut map) = response {
                    map.insert("tool_costs".to_string(), tool_costs);
                }
            }
        }

        Ok(response)
    }

    /// `gateway_kill_server` — disable a backend via the operator kill switch.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn kill_server(&self, args: &Value) -> Result<Value> {
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

    /// `gateway_revive_server` — re-enable a previously killed backend.
    ///
    /// Also resets the error-budget window so the backend starts with a clean slate.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn revive_server(&self, args: &Value) -> Result<Value> {
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

    /// `gateway_list_disabled_capabilities` — list capabilities suspended by
    /// the per-capability error budget.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn list_disabled_capabilities(&self) -> Result<Value> {
        let cap_cfg = self.capability_budget_config.read();
        let disabled = self.kill_switch.disabled_capabilities(cap_cfg.cooldown);
        let entries: Vec<Value> = disabled
            .iter()
            .filter_map(|key| {
                let (backend, capability) = key.split_once(':')?;
                let error_rate = self.kill_switch.capability_error_rate(backend, capability);
                Some(json!({
                    "backend": backend,
                    "capability": capability,
                    "error_rate": error_rate,
                    "cooldown_seconds": cap_cfg.cooldown.as_secs(),
                }))
            })
            .collect();
        Ok(json!({
            "disabled_count": entries.len(),
            "disabled_capabilities": entries,
            "note": if entries.is_empty() {
                "No capabilities are currently disabled."
            } else {
                "Capabilities auto-recover after the cooldown period elapses."
            }
        }))
    }

    /// `gateway_reload_config` — trigger an immediate config reload from disk.
    pub(super) async fn reload_config(&self) -> Result<Value> {
        let ctx = self.get_reload_context().ok_or_else(|| {
            Error::json_rpc(-32603, "Config reload is not enabled on this gateway")
        })?;

        match ctx.reload().await {
            Ok(summary) => Ok(json!({ "status": "ok", "changes": summary })),
            Err(e) => Err(Error::json_rpc(-32603, e)),
        }
    }

    /// `gateway_webhook_status` — webhook endpoint status and delivery stats.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn webhook_status(&self) -> Result<Value> {
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

    /// `gateway_run_playbook` — run a named playbook.
    pub(super) async fn run_playbook(&self, args: &Value) -> Result<Value> {
        let name = extract_required_str(args, "name")?;
        let arguments = parse_tool_arguments(args)?;

        debug!(playbook = name, "Running playbook");

        let definition = {
            let engine = self.playbook_engine.read();
            engine
                .get(name)
                .cloned()
                .ok_or_else(|| Error::json_rpc(-32602, format!("Playbook not found: {name}")))?
        };

        let invoker = MetaMcpInvoker { meta: self };

        let mut temp_engine = PlaybookEngine::new();
        temp_engine.register(definition);
        let result = temp_engine.execute(name, arguments, &invoker).await?;

        Ok(serde_json::to_value(&result).unwrap_or(json!(null)))
    }
}
