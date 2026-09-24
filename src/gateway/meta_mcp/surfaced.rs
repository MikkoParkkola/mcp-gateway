// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Surfaced-tool management for Meta-MCP.
//!
//! Contains the builder for statically surfaced tools (populated from
//! `MetaMcpConfig::surfaced_tools`), the per-request resolver, and the
//! `gateway_list_servers` handler which is co-located here as it walks
//! the same backend registry as the surfaced-tool resolver.

use std::collections::HashMap;

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::capability::validator::input_schema_is_structurally_valid;
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
            "gateway_set_state",
            "gateway_reload_config",
            "gateway_reload_capabilities",
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
    /// Return the backend server name for a statically surfaced tool.
    pub(crate) fn surfaced_tool_server(&self, tool_name: &str) -> Option<&str> {
        self.surfaced_tools_map.get(tool_name).map(String::as_str)
    }

    /// Whether a surfaced MCP-backend tool is withheld for a structurally
    /// invalid input schema.
    ///
    /// The disclosure half of this verdict lives in [`Self::resolve_surfaced_tool`];
    /// this is the same schema check asked on the dispatch path, so a tool
    /// withheld from `tools/list` *for its schema* is also refused by name.
    ///
    /// It deliberately does not cover the other reasons `resolve_surfaced_tool`
    /// returns `None`. A cache miss is an unwarmed cache, not a verdict —
    /// `CachedMetadata` holds `None` until the first fetch — so refusing on it
    /// would reject valid calls made before the backend's tool list has been
    /// read.
    pub(super) fn surfaced_schema_withheld(&self, server: &str, tool_name: &str) -> bool {
        self.backends
            .get(server)
            .and_then(|backend| backend.get_cached_tool(tool_name))
            .is_some_and(|tool| !input_schema_is_structurally_valid(&tool.input_schema))
    }

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
        scope: super::InvokeScope<'_>,
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

        // List = invoke (A3): a tool this caller could not call is not shown.
        if self
            .may_invoke(&surfaced.server, &surfaced.tool, scope, session_id)
            .is_err()
        {
            return None;
        }

        // MCP backend path: resolve from the backend's tool cache.
        if let Some(backend) = self.backends.get(&surfaced.server) {
            // INV-2 (MIK-6742): do not surface an isolated backend's tool on a
            // multi-user gateway; omit it from tools/list (fail-closed).
            if self.meta_route_isolation_refused(&backend) {
                debug!(
                    server = %surfaced.server,
                    tool = %surfaced.tool,
                    "Surfaced tool omitted: backend requires per-user OAuth isolation on multi-user gateway"
                );
                return None;
            }
            let tool = backend.get_cached_tool(&surfaced.tool);
            if tool.is_none() {
                debug!(
                    server = %surfaced.server,
                    tool = %surfaced.tool,
                    "Surfaced tool not in backend cache — omitting from tools/list"
                );
            }
            // Structural schema check, the same one the capability loader runs
            // before it will serve a definition. A backend's tool arrives over
            // the wire rather than off disk, so nothing had ever checked it:
            // the gateway disclosed a schema no client could build a call
            // against. Withheld per tool — the backend's healthy siblings stay
            // listed, matching how the loader skips one definition rather than
            // dropping the directory.
            if let Some(t) = &tool
                && !input_schema_is_structurally_valid(&t.input_schema)
            {
                warn!(
                    server = %surfaced.server,
                    tool = %surfaced.tool,
                    "Surfaced tool has a structurally invalid input schema — withholding it"
                );
                return None;
            }
            return tool;
        }

        // Capability backend path: capability tools (e.g. the `fulcrum`
        // capability provider) live in a separate subsystem from MCP backends,
        // so surface them by name from the capability tool set. This gives
        // chat clients direct one-hop access to high-value capabilities
        // (search, weather, travel, ...) instead of the gateway_search +
        // gateway_invoke two-hop, which chat models handle poorly.
        if let Some(cap) = self.get_capabilities() {
            if let Some(tool) = cap
                .get_tools()
                .into_iter()
                .find(|tl| tl.name == surfaced.tool)
            {
                return Some(tool);
            }
            debug!(
                server = %surfaced.server,
                tool = %surfaced.tool,
                "Surfaced capability tool not found — omitting from tools/list"
            );
        }
        None
    }
}

// ============================================================================
// gateway_list_servers handler
// ============================================================================

impl MetaMcp {
    /// `gateway_list_servers` — the servers this caller may reach, with
    /// kill-switch and circuit-breaker state. `tools_count` counts the tools
    /// it could invoke over the warm cache; a cold cache does not hide a server.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) async fn list_servers(
        &self,
        scope: super::InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let mut servers: Vec<Value> = Vec::new();
        for b in self.backends.all() {
            if !self.admits_backend(&b.name, scope, session_id) {
                continue;
            }
            let admitted = b
                .get_cached_tools_snapshot()
                .iter()
                .filter(|t| self.may_invoke(&b.name, &t.name, scope, session_id).is_ok())
                .count();
            let status = b.status();
            let killed = self.kill_switch.is_killed(&status.name);
            let mut entry = json!({
                "name": status.name,
                "running": status.running,
                "transport": status.transport,
                "tools_count": admitted,
                // Consult this before reading tools_count == 0 as "empty".
                "tools_known": status.tools_known,
                "circuit_breaker": status.circuit_state,
                "status": if killed { "disabled" } else { "active" }
            });
            // The era determination rides on the same entry as the rest of the
            // backend's state, so an operator reading one server reads one row.
            if let Some(fields) = entry.as_object_mut() {
                fields.extend(b.era_observation().await.render());
            }
            servers.push(entry);
        }

        if let Some(cap) = self.get_capabilities()
            && self.admits_backend(&cap.name, scope, session_id)
        {
            let admitted = cap
                .get_tools()
                .iter()
                .filter(|t| {
                    self.may_invoke(&cap.name, &t.name, scope, session_id)
                        .is_ok()
                })
                .count();
            let status = cap.status();
            let killed = self.kill_switch.is_killed(&status.name);
            servers.push(json!({
                "name": status.name,
                "running": true,
                "transport": "capability",
                "tools_count": admitted,
                "tools_known": true,
                "circuit_breaker": "closed",
                "status": if killed { "disabled" } else { "active" }
            }));
        }

        Ok(json!({ "servers": servers }))
    }
}
