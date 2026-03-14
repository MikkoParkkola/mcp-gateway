//! Surfaced-tool management for Meta-MCP.
//!
//! Contains the builder for statically surfaced tools (populated from
//! `MetaMcpConfig::surfaced_tools`), the per-request resolver, and the
//! `gateway_list_servers` handler which is co-located here as it walks
//! the same backend registry as the surfaced-tool resolver.

use std::collections::HashMap;

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::config::SurfacedToolConfig;
use crate::{Result, protocol::Tool};

use super::MetaMcp;

// ============================================================================
// Builder — with_surfaced_tools
// ============================================================================

impl MetaMcp {
    /// Attach statically surfaced tools (consuming builder).
    ///
    /// Validates at construction time that:
    /// 1. No surfaced tool name collides with a meta-tool name.
    /// 2. No tool name appears more than once across all surfaced entries.
    ///
    /// Validation failures are logged as warnings rather than panics so the
    /// gateway always starts — misconfigured surfaced tools are simply dropped.
    #[must_use]
    pub fn with_surfaced_tools(mut self, tools: Vec<SurfacedToolConfig>) -> Self {
        const META_TOOL_NAMES: &[&str] = &[
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

        let mut map: HashMap<String, String> = HashMap::new();
        let mut validated: Vec<SurfacedToolConfig> = Vec::with_capacity(tools.len());

        for cfg in tools {
            if META_TOOL_NAMES.contains(&cfg.tool.as_str()) {
                warn!(
                    tool = %cfg.tool,
                    "Surfaced tool name collides with a meta-tool — skipping"
                );
                continue;
            }
            if map.contains_key(&cfg.tool) {
                warn!(
                    tool = %cfg.tool,
                    "Duplicate surfaced tool name — skipping second occurrence"
                );
                continue;
            }
            map.insert(cfg.tool.clone(), cfg.server.clone());
            validated.push(cfg);
        }

        self.surfaced_tools = validated;
        self.surfaced_tools_map = map;
        self
    }
}

// ============================================================================
// Per-request resolver
// ============================================================================

impl MetaMcp {
    /// Resolve a surfaced tool config to a [`Tool`] schema.
    ///
    /// Returns `None` when:
    /// - The backend is not found in the registry.
    /// - The tool is not present in the backend's tool cache.
    /// - The active routing profile denies access to `(server, tool)`.
    pub(super) fn resolve_surfaced_tool(
        &self,
        surfaced: &SurfacedToolConfig,
        session_id: Option<&str>,
    ) -> Option<Tool> {
        // T2.7: routing profile check.
        let profile = self.active_profile(session_id);
        if profile.check(&surfaced.server, &surfaced.tool).is_err() {
            debug!(
                server = %surfaced.server,
                tool = %surfaced.tool,
                profile = %profile.name,
                "Surfaced tool excluded by routing profile"
            );
            return None;
        }

        let backend = self.backends.get(&surfaced.server)?;
        let tool = backend.get_cached_tool(&surfaced.tool);
        if tool.is_none() {
            debug!(
                server = %surfaced.server,
                tool = %surfaced.tool,
                "Surfaced tool not in backend cache — omitting from tools/list"
            );
        }
        tool
    }
}

// ============================================================================
// gateway_list_servers handler
// ============================================================================

impl MetaMcp {
    /// `gateway_list_servers` — list all servers with kill-switch and circuit-breaker state.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn list_servers(&self) -> Result<Value> {
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
