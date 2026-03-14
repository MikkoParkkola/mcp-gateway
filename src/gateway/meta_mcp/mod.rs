//! Meta-MCP implementation — meta-tools for dynamic discovery and playbooks.
//!
//! Module layout:
//! - `mod.rs` — struct + constructors + builders + dispatch + profile tools + tests
//! - `search.rs` — `code_mode_search`, `code_mode_execute`, `execute_chain`, `list_tools`, `search_tools`
//! - `invoke.rs` — `invoke_tool`, `dispatch_to_backend`, stats, kill/revive, playbook, reload
//! - `resources.rs` — `handle_resources_*` and `find_resource_owner`
//! - `protocol.rs` — `handle_prompts_*`, `handle_logging_*`, `current_log_level`
//! - `support.rs` — free functions: tag collection, ranking helpers, `MetaMcpInvoker`, augment

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::backend::BackendRegistry;
use crate::cache::ResponseCache;
use crate::capability::CapabilityBackend;
use crate::config_reload::ReloadContext;
use crate::cost_accounting::CostTracker;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::enforcer::BudgetEnforcer;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::registry::CostRegistry;
use crate::idempotency::{IdempotencyCache, spawn_cleanup_task};
use crate::kill_switch::{CapabilityErrorBudgetConfig, ErrorBudgetConfig, KillSwitch};
use crate::playbook::PlaybookEngine;
use crate::protocol::{
    JsonRpcResponse, LoggingLevel, RequestId, ToolsListResult, negotiate_version,
};
use crate::ranking::SearchRanker;
use crate::routing_profile::{ProfileRegistry, SessionProfileStore};
use crate::stats::UsageStats;
use crate::tool_registry::ToolRegistry;
use crate::transition::TransitionTracker;
use crate::{Error, Result};

use super::meta_mcp_helpers::{
    build_code_mode_tools, build_discovery_preamble, build_initialize_result, build_meta_tools,
    build_routing_instructions, did_you_mean, extract_client_version, extract_required_str,
    wrap_tool_success,
};
use super::webhooks::WebhookRegistry;

mod invoke;
mod protocol;
mod resources;
mod search;
mod support;

// ============================================================================
// MetaMcp struct
// ============================================================================

/// Meta-MCP handler — the central dispatcher for all gateway meta-tools.
pub struct MetaMcp {
    pub(super) backends: Arc<BackendRegistry>,
    pub(super) capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
    pub(super) cache: Option<Arc<ResponseCache>>,
    pub(super) default_cache_ttl: Duration,
    pub(super) idempotency_cache: Option<Arc<IdempotencyCache>>,
    pub(super) stats: Option<Arc<UsageStats>>,
    pub(super) ranker: Option<Arc<SearchRanker>>,
    pub(super) transition_tracker: RwLock<Option<Arc<TransitionTracker>>>,
    pub(super) playbook_engine: RwLock<PlaybookEngine>,
    pub(super) log_level: RwLock<LoggingLevel>,
    pub(super) kill_switch: Arc<KillSwitch>,
    pub(super) error_budget_config: RwLock<ErrorBudgetConfig>,
    pub(super) capability_budget_config: RwLock<CapabilityErrorBudgetConfig>,
    pub(super) webhook_registry: RwLock<Option<Arc<parking_lot::RwLock<WebhookRegistry>>>>,
    pub(super) profile_registry: Arc<ProfileRegistry>,
    pub(super) session_profiles: Arc<SessionProfileStore>,
    pub(super) reload_context: RwLock<Option<Arc<ReloadContext>>>,
    pub(super) code_mode_enabled: bool,
    pub(super) secret_injector: crate::secret_injection::SecretInjector,
    /// Cost tracker — per-session and per-API-key spend accounting.
    pub(super) cost_tracker: Arc<CostTracker>,
    /// Engram-inspired O(1) tool registry with prefetching (optional).
    ///
    /// When `Some`, exact tool lookups short-circuit fuzzy search, and schema
    /// prefetching is triggered after each `gateway_invoke`.
    pub(super) tool_registry: Option<std::sync::Arc<ToolRegistry>>,
    /// Cost governance: pre-invoke budget enforcement engine (feature-gated).
    ///
    /// `None` when the `cost-governance` feature is disabled OR when the
    /// `cost_governance.enabled` config flag is `false`.
    #[cfg(feature = "cost-governance")]
    pub(crate) budget_enforcer: Option<Arc<BudgetEnforcer>>,
    /// Cost governance: tool-cost registry used by enforcer and suggestions.
    #[cfg(feature = "cost-governance")]
    pub(crate) cost_registry: Option<Arc<CostRegistry>>,
}

// ============================================================================
// Constructors
// ============================================================================

impl MetaMcp {
    /// Create a new Meta-MCP handler.
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
            capability_budget_config: RwLock::new(CapabilityErrorBudgetConfig::default()),
            profile_registry: Arc::new(ProfileRegistry::default()),
            session_profiles: Arc::new(SessionProfileStore::new()),
            reload_context: RwLock::new(None),
            code_mode_enabled: false,
            secret_injector: crate::secret_injection::SecretInjector::empty(),
            cost_tracker: Arc::new(CostTracker::new()),
            tool_registry: None,
            #[cfg(feature = "cost-governance")]
            budget_enforcer: None,
            #[cfg(feature = "cost-governance")]
            cost_registry: None,
        }
    }

    /// Create a new Meta-MCP handler with cache, stats, and ranking support.
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
            capability_budget_config: RwLock::new(CapabilityErrorBudgetConfig::default()),
            webhook_registry: RwLock::new(None),
            profile_registry: Arc::new(ProfileRegistry::default()),
            session_profiles: Arc::new(SessionProfileStore::new()),
            reload_context: RwLock::new(None),
            code_mode_enabled: false,
            secret_injector: crate::secret_injection::SecretInjector::empty(),
            cost_tracker: Arc::new(CostTracker::new()),
            tool_registry: None,
            #[cfg(feature = "cost-governance")]
            budget_enforcer: None,
            #[cfg(feature = "cost-governance")]
            cost_registry: None,
        }
    }

    /// Expose the cost tracker for external use (budget configuration, REST handler).
    #[must_use]
    pub fn cost_tracker(&self) -> Arc<CostTracker> {
        Arc::clone(&self.cost_tracker)
    }

    /// Return a [`StatsSnapshot`] for the operator dashboard and other external consumers.
    ///
    /// `total_backend_tools` should be the current sum of cached tools across all backends.
    /// When no stats tracker has been attached (e.g. in tests), a zeroed snapshot is returned.
    #[must_use]
    pub fn stats_snapshot(&self, total_backend_tools: usize) -> crate::stats::StatsSnapshot {
        match self.stats.as_ref() {
            Some(s) => s.snapshot(total_backend_tools),
            None => crate::stats::StatsSnapshot {
                invocations: 0,
                cache_hits: 0,
                cache_hit_rate: 0.0,
                tools_discovered: 0,
                tools_available: total_backend_tools,
                tokens_saved: 0,
                top_tools: vec![],
                total_cached_tokens: 0,
                cached_tokens_by_server: vec![],
            },
        }
    }
}

// ============================================================================
// Builder methods
// ============================================================================

impl MetaMcp {
    /// Attach a routing profile registry.
    #[must_use]
    pub fn with_profile_registry(mut self, registry: ProfileRegistry) -> Self {
        self.profile_registry = Arc::new(registry);
        self
    }

    /// Enable Code Mode — `tools/list` returns only `gateway_search` + `gateway_execute`.
    #[must_use]
    pub fn with_code_mode(mut self, enabled: bool) -> Self {
        self.code_mode_enabled = enabled;
        self
    }

    /// Attach a secret injector for credential brokering.
    #[must_use]
    pub fn with_secret_injector(
        mut self,
        injector: crate::secret_injection::SecretInjector,
    ) -> Self {
        self.secret_injector = injector;
        self
    }

    /// Enable idempotency support with a background cleanup task.
    #[allow(dead_code)]
    pub fn enable_idempotency(&mut self, cache: Arc<IdempotencyCache>, cleanup_interval: Duration) {
        spawn_cleanup_task(Arc::clone(&cache), cleanup_interval);
        self.idempotency_cache = Some(cache);
    }

    /// Attach the webhook registry for `gateway_webhook_status` reporting.
    pub fn set_webhook_registry(&self, registry: Arc<parking_lot::RwLock<WebhookRegistry>>) {
        *self.webhook_registry.write() = Some(registry);
    }

    /// Attach a [`ReloadContext`] to enable the `gateway_reload_config` meta-tool.
    pub fn set_reload_context(&self, ctx: Arc<ReloadContext>) {
        *self.reload_context.write() = Some(ctx);
    }

    /// Attach a `TransitionTracker` for predictive tool prefetch.
    pub fn set_transition_tracker(&self, tracker: Arc<TransitionTracker>) {
        *self.transition_tracker.write() = Some(tracker);
    }

    /// Set the capability backend.
    pub fn set_capabilities(&self, capabilities: Arc<CapabilityBackend>) {
        *self.capabilities.write() = Some(capabilities);
    }

    /// Attach a [`ToolRegistry`] for O(1) tool schema resolution (consuming builder).
    ///
    /// Call this in the construction chain before the `MetaMcp` is wrapped in an `Arc`.
    /// After each `gateway_invoke`, the registry's prefetch engine is triggered to warm
    /// schemas for likely-next tools using the session transition history.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_tool_registry(mut self, registry: std::sync::Arc<ToolRegistry>) -> Self {
        self.tool_registry = Some(registry);
        self
    }

    /// Attach cost-governance enforcer and registry (consuming builder).
    ///
    /// Called from `server.rs` when `cost_governance.enabled = true`.
    #[cfg(feature = "cost-governance")]
    #[must_use]
    pub fn with_cost_governance(
        mut self,
        enforcer: Arc<BudgetEnforcer>,
        registry: Arc<CostRegistry>,
    ) -> Self {
        self.budget_enforcer = Some(enforcer);
        self.cost_registry = Some(registry);
        self
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

    /// Override the error-budget configuration.
    #[allow(dead_code)]
    pub fn set_error_budget_config(&self, config: ErrorBudgetConfig) {
        *self.error_budget_config.write() = config;
    }

    /// Override the per-capability error-budget configuration.
    #[allow(dead_code)]
    pub fn set_capability_budget_config(&self, config: CapabilityErrorBudgetConfig) {
        *self.capability_budget_config.write() = config;
    }
}

// ============================================================================
// Accessor helpers (pub(super) — used by sub-modules)
// ============================================================================

impl MetaMcp {
    pub(super) fn get_webhook_registry(&self) -> Option<Arc<parking_lot::RwLock<WebhookRegistry>>> {
        self.webhook_registry.read().clone()
    }

    pub(super) fn get_reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    /// Public accessor for the reload context — used by UI management endpoints.
    pub fn reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    pub(super) fn get_transition_tracker(&self) -> Option<Arc<TransitionTracker>> {
        self.transition_tracker.read().clone()
    }

    pub(super) fn get_tool_registry(&self) -> Option<std::sync::Arc<ToolRegistry>> {
        self.tool_registry.clone()
    }

    pub(super) fn get_capabilities(&self) -> Option<Arc<CapabilityBackend>> {
        self.capabilities.read().clone()
    }

    /// Resolve the active `RoutingProfile` for a session.
    pub(super) fn active_profile(
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
}

// ============================================================================
// MCP protocol handlers — initialize + tools
// ============================================================================

impl MetaMcp {
    /// Handle `initialize` with version negotiation and optional profile binding.
    pub fn handle_initialize(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        header_profile: Option<&str>,
    ) -> JsonRpcResponse {
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        debug!(
            client = client_version,
            negotiated = negotiated_version,
            "Protocol version negotiation"
        );

        let profile_hint = header_profile.or_else(|| {
            params
                .and_then(|p| p.get("profile"))
                .and_then(serde_json::Value::as_str)
        });

        if let (Some(sid), Some(name)) = (session_id, profile_hint) {
            if self.profile_registry.contains(name) {
                self.session_profiles.set_profile(sid, name);
                debug!(
                    session_id = sid,
                    profile = name,
                    "Session bound to routing profile at initialize"
                );
            } else {
                warn!(
                    session_id = sid,
                    requested = name,
                    "Requested profile not found at initialize; using registry default"
                );
            }
        }

        let instructions = self.build_instructions();
        let result = build_initialize_result(negotiated_version, &instructions);
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    fn build_instructions(&self) -> String {
        let backends = self.backends.all();
        let mut tool_count: usize = backends.iter().map(|b| b.cached_tools_count()).sum();
        let mut server_count = backends.len();

        if let Some(cap) = self.get_capabilities() {
            tool_count += cap.get_tools().len();
            server_count += 1;
        }

        let mut instructions = build_discovery_preamble(tool_count, server_count);

        if let Some(cap) = self.get_capabilities() {
            let caps = cap.list_capabilities();
            let routing = build_routing_instructions(&caps, &cap.name);
            if !routing.is_empty() {
                instructions.push_str(&routing);
            }
        }
        instructions
    }

    /// Compute live (`tool_count`, `server_count`) from the cached backend statuses.
    ///
    /// Uses only the in-memory cache — no I/O.  Both counts are 0 when the
    /// registry is empty (e.g. in unit tests).
    fn backend_counts(&self) -> (usize, usize) {
        let backends = self.backends.all();
        let server_count = backends.len();
        let tool_count = backends.iter().map(|b| b.status().tools_cached).sum();
        (tool_count, server_count)
    }

    /// Handle `tools/list` — Code Mode returns 2 tools; Traditional returns full set.
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        let tools = if self.code_mode_enabled {
            build_code_mode_tools()
        } else {
            let (tool_count, server_count) = self.backend_counts();
            build_meta_tools(
                self.stats.is_some(),
                self.get_webhook_registry().is_some(),
                self.get_reload_context().is_some(),
                true, // cost_report always enabled (tracker is always present)
                tool_count,
                server_count,
            )
        };
        let result = ToolsListResult {
            tools,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `tools/call` — dispatch to the appropriate handler.
    ///
    /// `api_key_name` — the name of the authenticated API key (for cost accounting).
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        api_key_name: Option<&str>,
    ) -> JsonRpcResponse {
        let result = match tool_name {
            "gateway_search" => self.code_mode_search(&arguments, session_id).await,
            "gateway_execute" => self.code_mode_execute(&arguments, session_id).await,
            "gateway_list_servers" => self.list_servers(),
            "gateway_list_tools" => self.list_tools(&arguments, session_id).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id).await,
            "gateway_invoke" => self.invoke_tool(&arguments, session_id, api_key_name).await,
            "gateway_get_stats" => self.get_stats(&arguments).await,
            "gateway_cost_report" => self.get_cost_report(&arguments, session_id).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_list_disabled_capabilities" => self.list_disabled_capabilities(),
            "gateway_set_profile" => self.set_profile(&arguments, session_id),
            "gateway_get_profile" => self.get_profile(session_id),
            "gateway_list_profiles" => self.list_profiles(),
            "gateway_reload_config" => self.reload_config().await,
            _ => {
                const META_TOOLS: &[&str] = &[
                    "gateway_search",
                    "gateway_execute",
                    "gateway_list_servers",
                    "gateway_list_tools",
                    "gateway_search_tools",
                    "gateway_invoke",
                    "gateway_get_stats",
                    "gateway_cost_report",
                    "gateway_webhook_status",
                    "gateway_run_playbook",
                    "gateway_kill_server",
                    "gateway_revive_server",
                    "gateway_list_disabled_capabilities",
                    "gateway_set_profile",
                    "gateway_get_profile",
                    "gateway_list_profiles",
                    "gateway_reload_config",
                ];
                let suggestion = did_you_mean(tool_name, META_TOOLS, 3, 3);
                let msg = match suggestion {
                    Some(hint) => format!("Unknown tool: {tool_name}. {hint}"),
                    None => format!("Unknown tool: {tool_name}"),
                };
                Err(Error::json_rpc(-32601, msg))
            }
        };

        match result {
            Ok(content) => wrap_tool_success(id, &content),
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// `gateway_list_servers` — list all servers with kill-switch and circuit-breaker state.
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
}

// ============================================================================
// Routing profile meta-tools
// ============================================================================

impl MetaMcp {
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

    #[allow(clippy::unnecessary_wraps)]
    fn get_profile(&self, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);
        Ok(json!({
            "profile": profile.name,
            "session_id": session_id,
            "description": profile.describe(),
            "available_profiles": self.profile_registry.profile_names(),
        }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn list_profiles(&self) -> Result<Value> {
        let summaries = self.profile_registry.profile_summaries();
        let total = summaries.len();
        let default_name = self.profile_registry.default_name();
        Ok(json!({ "profiles": summaries, "default": default_name, "total": total }))
    }
}

// ============================================================================
// Tests (extracted to tests.rs for LOC compliance)
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
