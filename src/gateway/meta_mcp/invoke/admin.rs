// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Operator controls: cost report, stats, kill/revive, reload, playbooks.

use serde_json::{Value, json};
use tracing::debug;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::support::MetaMcpInvoker;
use crate::gateway::meta_mcp_helpers::{
    build_circuit_breaker_stats_json, build_server_safety_status, build_stats_response,
    extract_bool_or, extract_optional_str, extract_required_str, parse_tool_arguments,
};
use crate::playbook::PlaybookEngine;
use crate::{Error, Result};

impl MetaMcp {
    /// `gateway_cost_report` — per-session and per-API-key spend report.
    #[allow(
        unknown_lints,
        clippy::unnecessary_wraps,
        clippy::unused_async,
        clippy::unused_async_trait_impl
    )]
    pub(in crate::gateway::meta_mcp) async fn get_cost_report(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        let include_all_sessions = extract_bool_or(args, "include_all_sessions", false);
        let include_all_keys = extract_bool_or(args, "include_all_keys", false);

        // Both are documented in this tool's own schema as an admin view, and
        // were read straight from the arguments. Refusing beats quietly
        // narrowing the report: a caller that asked for every session and got
        // one has no way to tell that it was scoped rather than empty.
        if (include_all_sessions || include_all_keys) && !caller.is_admin {
            return Err(crate::Error::Config(
                "include_all_sessions and include_all_keys are admin views and require an \
                 admin credential"
                    .to_string(),
            ));
        }

        // Resolve target session. A non-admin caller may name only its own:
        // taking the argument in preference to the caller's session let any
        // client read any other client's spend by guessing or observing an id.
        let requested = extract_optional_str(args, "session_id");
        if let Some(requested) = requested
            && !caller.is_admin
            && Some(requested) != session_id
        {
            return Err(crate::Error::Config(
                "reporting on another session is an admin view and requires an admin \
                 credential"
                    .to_string(),
            ));
        }
        let target_session_id = requested.or(session_id);

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

        // The gateway-wide total is every caller's spend combined, which is the
        // same cross-tenant view the explicit flags are gated on. Gating those
        // and leaving this open would have made the check cosmetic.
        let aggregate = if caller.is_admin {
            serde_json::to_value(self.cost_tracker.aggregate()).unwrap_or(json!(null))
        } else {
            json!(null)
        };

        // A caller with no session reads its own session-less spend, keyed on
        // its caller key (MIK-7653). A keyless caller has no key, so nothing:
        // every keyless caller would otherwise read one shared breakdown.
        let caller_report = if target_session_id.is_none_or(str::is_empty) {
            caller
                .caller_key
                .and_then(|key| self.cost_tracker.caller_snapshot(key))
                .map_or(json!(null), |s| {
                    serde_json::to_value(s).unwrap_or(json!(null))
                })
        } else {
            json!(null)
        };

        Ok(json!({
            "session": session_report,
            "caller": caller_report,
            "keys": key_report,
            "aggregate": aggregate,
        }))
    }

    /// `gateway_get_stats` — gateway statistics with per-backend error budget
    /// and circuit-breaker status.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub(in crate::gateway::meta_mcp) async fn get_stats(
        &self,
        _args: &Value,
        // The admin flag only decides whether cost figures are included, and
        // that block is feature-gated. Relaxed on the parameter itself, in
        // exactly the build where its one use disappears, so dropping that use
        // under the feature still warns and unrelated bindings stay linted.
        #[cfg_attr(not(feature = "cost-governance"), allow(unused_variables))]
        caller_is_admin: bool,
    ) -> Result<Value> {
        let stats = self
            .stats
            .as_ref()
            .ok_or_else(|| Error::json_rpc(-32603, "Statistics not enabled for this gateway"))?;

        let all_backends = self.backends.all();
        // Publish completeness: an unenumerated backend contributes 0.
        // A truncated drain publishes a lower bound, not a complete total.
        // List and flag under one guard, so a fill landing between the reads
        // cannot pair a truncated count with a clear flag.
        let mut tools_known = true;
        let mut total_tools: usize = 0;
        for b in &all_backends {
            let (tools, truncated) = b.cached_tools_snapshot_and_truncated();
            tools_known &= b.cached_tools_known() && !truncated;
            total_tools += tools.len();
        }
        if let Some(cap) = self.get_capabilities() {
            total_tools += cap.get_tools().len();
        }

        let snapshot = stats.snapshot(total_tools);
        let mut response = build_stats_response(&snapshot, tools_known);

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

        // Cost governance is cross-tenant: budgets and spend for every caller.
        #[cfg(feature = "cost-governance")]
        let include_costs = caller_is_admin;
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = self.budget_enforcer {
            let section = cost_section(&enforcer.snapshot());
            if include_costs && let Value::Object(ref mut map) = response {
                map.insert("cost_governance".to_string(), section);
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
    pub(in crate::gateway::meta_mcp) fn kill_server(&self, args: &Value) -> Result<Value> {
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
    /// Resets the error-budget window AND closes a tripped circuit breaker so
    /// the backend starts with a clean slate. The breaker reset is load-bearing
    /// (MIK-5983): the `CIRCUIT_OPEN` error message directs operators to this
    /// tool, so it must actually recover a breaker-tripped backend.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::gateway::meta_mcp) fn revive_server(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let was_killed = self.kill_switch.is_killed(server);
        self.kill_switch.revive(server);

        let mut breaker_was_open = false;
        if let Some(backend) = self.backends.get(server) {
            breaker_was_open =
                backend.circuit_breaker_stats().state != crate::failsafe::CircuitState::Closed;
            backend.reset_circuit_breaker();
        }

        Ok(json!({
            "server": server,
            "status": "active",
            "was_killed": was_killed,
            "breaker_was_open": breaker_was_open,
            "message": format!("Server '{server}' has been re-enabled")
        }))
    }

    /// `gateway_list_disabled_capabilities` — list capabilities suspended by
    /// the per-capability error budget.
    #[allow(clippy::unnecessary_wraps)]
    /// Filtered by `may_invoke`: a caller learns why its own capability fails,
    /// never that another caller's exists (A3).
    pub(in crate::gateway::meta_mcp) fn list_disabled_capabilities(
        &self,
        scope: super::super::InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let cap_cfg = self.capability_budget_config.read();
        let disabled = self.kill_switch.disabled_capabilities(cap_cfg.cooldown);
        let entries: Vec<Value> = disabled
            .iter()
            .filter_map(|key| {
                let (backend, capability) = key.split_once(':')?;
                self.may_invoke(backend, capability, scope, session_id)
                    .ok()?;
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
    pub(in crate::gateway::meta_mcp) async fn reload_config(&self) -> Result<Value> {
        let ctx = self.get_reload_context().ok_or_else(|| {
            Error::json_rpc(-32603, "Config reload is not enabled on this gateway")
        })?;

        match ctx.reload_outcome().await {
            Ok(outcome) => Ok(json!({
                "status": "ok",
                "changes": outcome.changes,
                "restart_required": outcome.restart_required,
                "restart_reason": outcome.restart_reason,
            })),
            // A refused file is the caller's config refused, as the admin
            // API's 409 says (MIK-8058); anything else is an internal error.
            Err(e) => Err(Error::json_rpc(
                match crate::config_reload::reload_failure(&e) {
                    crate::config_reload::ReloadFailure::ConfigRefused => -32600,
                    _ => -32603,
                },
                e,
            )),
        }
    }

    /// `gateway_reload_capabilities` — re-read every YAML capability file from disk.
    ///
    /// Designed for the agent-self-development hot path: an agent has just
    /// authored or edited a capability YAML and wants it immediately callable
    /// without restarting the gateway. Mirrors the file-watcher hot-reload that
    /// already triggers on disk changes, but exposes it as an MCP tool the
    /// agent can call directly.
    pub(in crate::gateway::meta_mcp) async fn reload_capabilities(&self) -> Result<Value> {
        let backend = {
            let guard = self.capabilities.read();
            guard.clone()
        };
        let backend = backend.ok_or_else(|| {
            Error::json_rpc(-32603, "Capability backend is not enabled on this gateway")
        })?;

        match backend.reload().await {
            Ok(total) => Ok(json!({
                "status": "ok",
                "backend": backend.name,
                "total_capabilities": total,
            })),
            Err(e) => Err(Error::json_rpc(-32603, format!("{e}"))),
        }
    }

    /// `gateway_webhook_status` — webhook endpoint status and delivery stats.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::gateway::meta_mcp) fn webhook_status(&self) -> Result<Value> {
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
    pub(in crate::gateway::meta_mcp) async fn run_playbook(
        &self,
        args: &Value,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        self.refuse_unattested_plan()?;
        let name = extract_required_str(args, "name")?;
        let arguments = parse_tool_arguments(args)?;

        debug!(playbook = name, "Running playbook");

        let definition = if let Some(definition) = caller
            .execution
            .and_then(super::super::admission::SyncLease::playbook_definition)
        {
            definition.clone()
        } else {
            let engine = self.playbook_engine.read();
            engine
                .get(name)
                .cloned()
                .ok_or_else(|| Error::json_rpc(-32602, format!("Playbook not found: {name}")))?
        };

        let invoker = MetaMcpInvoker { meta: self, caller };

        let mut temp_engine = PlaybookEngine::new();
        temp_engine.register(definition);
        let result = temp_engine.execute(name, arguments, &invoker).await?;

        Ok(serde_json::to_value(&result).unwrap_or(json!(null)))
    }
}

/// The admin stats `cost_governance` section, overflow totals included
/// (MIK-8015), so its per-name rows and the global total reconcile.
#[cfg(feature = "cost-governance")]
fn cost_section(snap: &crate::cost_accounting::enforcer::EnforcerSnapshot) -> Value {
    json!({
        "global_daily_spend_usd": snap.global_daily_usd,
        "global_daily_limit_usd": snap.global_daily_limit,
        "tool_daily_spend": snap.tool_daily,
        "tool_daily_limits": snap.tool_limits,
        "key_daily_spend": snap.key_daily,
        "tool_overflow_spend_usd": snap.tool_overflow_usd,
        "key_overflow_spend_usd": snap.key_overflow_usd,
    })
}

#[cfg(all(test, feature = "cost-governance"))]
mod cost_section_tests {
    use super::cost_section;
    use crate::cost_accounting::enforcer::EnforcerSnapshot;

    #[test]
    fn the_cost_section_reports_both_overflow_totals() {
        let snap = EnforcerSnapshot {
            global_daily_usd: 3.0,
            global_daily_limit: None,
            tool_daily: std::collections::HashMap::new(),
            tool_limits: std::collections::HashMap::new(),
            key_daily: std::collections::HashMap::new(),
            key_limits: std::collections::HashMap::new(),
            taken_at: 0,
            tool_overflow_usd: 1.25,
            key_overflow_usd: 0.5,
        };
        let section = cost_section(&snap);
        assert_eq!(section["tool_overflow_spend_usd"], 1.25);
        assert_eq!(section["key_overflow_spend_usd"], 0.5);
    }
}
