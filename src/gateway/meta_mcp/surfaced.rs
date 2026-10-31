// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Surfaced-tool management for Meta-MCP.
//!
//! Contains the builder for statically surfaced tools (populated from
//! `MetaMcpConfig::surfaced_tools`), the per-request resolver, and the
//! `gateway_list_servers` handler which is co-located here as it walks
//! the same backend registry as the surfaced-tool resolver.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::capability::validator::input_schema_is_structurally_valid;
use crate::config::SurfacedToolConfig;
use crate::gateway::task_service::{SurfacedKind, SurfacedTarget};
use crate::{Result, protocol::Tool};

use super::MetaMcp;

// ============================================================================
// Builder — with_surfaced_tools
// ============================================================================

/// How a `tools/call`'s own `arguments` are read (MIK-8154): the one place
/// the decode decision lives. The sanitize step matches on it exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgsPolicy {
    /// A backend tool's: a JSON string is decoded as a whole.
    BackendWhole,
    /// A meta tool whose handler reads its own `arguments` as they are, but
    /// decodes an inner `arguments` itself.
    MetaParsedInner,
    /// [`Self::MetaParsedInner`] whose handler also reads a `chain`, decoding
    /// each step's `arguments` (`gateway_execute`). Only this one has a
    /// `chain` the sanitize step decodes (MIK-8378).
    MetaParsedChain,
    /// A meta tool whose handler reads its own `arguments` as they are.
    MetaOpaque,
}

/// Every meta tool and how its `arguments` are read: the names
/// `call_dispatch`'s meta match routes on, kept equal to its arms by
/// `meta_tool_names_are_the_dispatch_arms`. Surfacing refuses a backend tool
/// under any of them, so a meta name always resolves to the gateway's own
/// handler. A new meta tool takes its row here, with its policy.
pub(crate) const META_TOOLS: &[(&str, ArgsPolicy)] = &[
    ("gateway_search", ArgsPolicy::MetaOpaque),
    ("gateway_execute", ArgsPolicy::MetaParsedChain),
    ("gateway_list_servers", ArgsPolicy::MetaOpaque),
    ("gateway_list_tools", ArgsPolicy::MetaOpaque),
    ("gateway_search_tools", ArgsPolicy::MetaOpaque),
    ("gateway_invoke", ArgsPolicy::MetaParsedInner),
    ("gateway_get_stats", ArgsPolicy::MetaOpaque),
    ("gateway_cost_report", ArgsPolicy::MetaOpaque),
    ("gateway_webhook_status", ArgsPolicy::MetaOpaque),
    ("gateway_run_playbook", ArgsPolicy::MetaParsedInner),
    ("gateway_kill_server", ArgsPolicy::MetaOpaque),
    ("gateway_revive_server", ArgsPolicy::MetaOpaque),
    ("gateway_list_disabled_capabilities", ArgsPolicy::MetaOpaque),
    ("gateway_set_profile", ArgsPolicy::MetaOpaque),
    ("gateway_get_profile", ArgsPolicy::MetaOpaque),
    ("gateway_list_profiles", ArgsPolicy::MetaOpaque),
    ("gateway_set_state", ArgsPolicy::MetaOpaque),
    ("gateway_reload_config", ArgsPolicy::MetaOpaque),
    ("gateway_reload_capabilities", ArgsPolicy::MetaOpaque),
];

/// `name`'s argument policy: a meta tool's row, else a backend tool's.
pub(crate) fn args_policy(name: &str) -> ArgsPolicy {
    META_TOOLS
        .iter()
        .find(|(meta, _)| *meta == name)
        .map_or(ArgsPolicy::BackendWhole, |(_, policy)| *policy)
}

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
    pub fn with_surfaced_tools(self, tools: Vec<SurfacedToolConfig>) -> Self {
        *self.surfaced.write() = Arc::new(validate_surfaced(tools));
        self
    }

    /// MIK-8520: point `tool` at `server` in the live surfaced map, as a
    /// reload of `surfaced_tools` would, so a row can move it between a
    /// replay's admission and its record.
    #[cfg(test)]
    pub(crate) fn resurface_for_test(&self, tool: &str, server: &str) {
        let tools = vec![SurfacedToolConfig {
            server: server.to_owned(),
            tool: tool.to_owned(),
        }];
        *self.surfaced.write() = Arc::new(validate_surfaced(tools));
    }

    /// Apply `tools` as a reload of `surfaced_tools` does, nudge
    /// included, without a config file. Returns whether anything changed.
    #[cfg(test)]
    pub(crate) fn reload_surfaced_for_test(&self, tools: Vec<SurfacedToolConfig>) -> bool {
        let mut config = crate::config::Config::default();
        config.meta_mcp.surfaced_tools = tools;
        apply_surfaced_reload(&self.surfaced, &self.backends, &config)
    }

    /// Withdraw every surfaced name, as a reload to an empty list
    /// would.
    #[cfg(test)]
    pub(crate) fn clear_surfaced_for_test(&self) {
        *self.surfaced.write() = Arc::default();
    }
}

impl MetaMcp {
    /// Where a surfaced `tool` resolves for a task admitted now: its server in
    /// this request's snapshot, and what serves it there. `None` for a
    /// non-surfaced name.
    pub(crate) fn surfaced_target_at_intake(&self, tool: &str) -> Option<SurfacedTarget> {
        let server = self.surfaced_server_unscoped(tool)?;
        Some(SurfacedTarget {
            server: server.to_owned(),
            kind: self.surfaced_kind(server),
        })
    }

    /// What kind of target serves `server` right now: a registered backend of
    /// that name, else the capability fallback. The hold then also requires
    /// the capability set to be named `server` and to hold the tool, the
    /// invoke gate's own test.
    fn surfaced_kind(&self, server: &str) -> SurfacedKind {
        if self
            .backends
            .get_for(super::scoped_backends::Unscoped::Visibility, server)
            .is_some()
        {
            SurfacedKind::Backend
        } else {
            SurfacedKind::Capability
        }
    }

    /// Whether a task's recorded surfaced target still holds,
    /// read memo-blind so a request snapshot cannot hide a reload: the live
    /// map still surfaces `tool` from the recorded server, and the same kind
    /// of target still serves it there: the registered backend, or the
    /// capability set named after that server holding `tool`. A backend
    /// swapped for a same-named capability, or the reverse, is a changed
    /// target. `None` (no recorded target) always holds and resolves live.
    pub(crate) fn surfaced_target_holds(
        &self,
        tool: &str,
        recorded: Option<&SurfacedTarget>,
    ) -> bool {
        let Some(recorded) = recorded else {
            return true;
        };
        let server = recorded.server.as_str();
        self.surfaced_state_live().map.unscoped(tool) == Some(server)
            && self.surfaced_kind(server) == recorded.kind
            && (recorded.kind == SurfacedKind::Backend
                || self
                    .get_capabilities()
                    .is_some_and(|cap| cap.name == server && cap.has_capability(tool)))
    }

    /// Run `dispatch` with `tool` pinned to its recorded server in the active
    /// memo, opening one when none is. The pin closes the gap
    /// between [`Self::surfaced_target_holds`] and the dispatch, where a reload
    /// could land; it is not redundant with that check.
    pub(crate) async fn with_surfaced_pin<F: std::future::Future>(
        &self,
        tool: &str,
        recorded: Option<&SurfacedTarget>,
        dispatch: F,
    ) -> F::Output {
        let Some(server) = recorded.map(|target| super::visible::intern(&target.server)) else {
            return dispatch.await;
        };
        super::visible::memo::with_visibility_memo(async move {
            let _pin = super::visible::memo::pin_surfaced(tool, server);
            dispatch.await
        })
        .await
    }
}

impl MetaMcp {
    /// [`Self::with_surfaced_pin`] for a synchronous read. A surfaced task's
    /// settled result is inspected under the targets of the server that
    /// produced it, even when a reload moved the name during the call.
    pub(crate) fn with_surfaced_pin_sync<R>(
        tool: &str,
        recorded: Option<&SurfacedTarget>,
        read: impl FnOnce() -> R,
    ) -> R {
        match recorded.map(|target| super::visible::intern(&target.server)) {
            Some(server) => super::visible::memo::with_surfaced_pin_sync(tool, server, read),
            None => read(),
        }
    }
}

/// Apply a reloaded config's `surfaced_tools` (under
/// `lock_reload`). The new list is validated as at startup; when the ordered
/// `(tool, server)` list differs from the running one (a reorder changes every
/// served list), the state is swapped and one `tools/list_changed` nudge is
/// sent. An identical list changes and announces nothing. Returns whether
/// anything changed.
pub(super) fn apply_surfaced_reload(
    slot: &parking_lot::RwLock<Arc<super::visible::SurfacedState>>,
    backends: &super::scoped_backends::Registry,
    config: &crate::config::Config,
) -> bool {
    let next = validate_surfaced(config.meta_mcp.surfaced_tools.clone());
    let pairs = |state: &super::visible::SurfacedState| {
        state
            .tools
            .iter()
            .map(|t| (t.tool.clone(), t.server.clone()))
            .collect::<Vec<_>>()
    };
    if pairs(&slot.read()) == pairs(&next) {
        return false;
    }
    for surfaced in &next.tools {
        if backends
            .get_for(
                super::scoped_backends::Unscoped::Visibility,
                &surfaced.server,
            )
            .is_none()
        {
            warn!(
                tool = %surfaced.tool,
                server = %surfaced.server,
                "Surfaced tool names a backend that is not configured"
            );
        }
        // T2.6, as at startup (run.rs): repeated only when the set changed.
        if !config.meta_mcp.warm_start.contains(&surfaced.server) {
            warn!(
                tool = %surfaced.tool,
                server = %surfaced.server,
                "Surfaced tool's backend is not in meta_mcp.warm_start — \
                 schema may be absent until the backend is first used"
            );
        }
    }
    *slot.write() = Arc::new(next);
    backends.nudge_surfaced();
    true
}

/// Validate a surfaced-tools list as startup and every reload do: a name
/// colliding with a meta tool, and a second occurrence of
/// a name, are dropped with a warning. Never fails, so an invalid entry
/// never aborts a reload.
pub(crate) fn validate_surfaced(tools: Vec<SurfacedToolConfig>) -> super::visible::SurfacedState {
    let mut map: HashMap<String, String> = HashMap::new();
    let mut validated: Vec<SurfacedToolConfig> = Vec::with_capacity(tools.len());

    for cfg in tools {
        if args_policy(&cfg.tool) != ArgsPolicy::BackendWhole {
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

    super::visible::SurfacedState {
        tools: validated,
        map: super::visible::SurfacedMap::new(map),
    }
}

// ============================================================================
// Per-request resolver
// ============================================================================

impl MetaMcp {
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
            .get_for(
                crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility,
                server,
            )
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

        // List = invoke (A3), one predicate for every listing (MIK-8340): a
        // tool withheld from this caller is not shown.
        // MIK-8356: judged by the caller's own slot on a per-user backend; a
        // cold caller keeps the shared view (SLOTVIS.6), except where there is
        // none: a backend with per-user sessions only lists the caller's own
        // view, warmed before this list was built.
        if !self.listing_names(
            &surfaced.server,
            &surfaced.tool,
            scope,
            session_id,
            super::listing_view::ColdRule::SharedView,
        ) {
            return None;
        }

        // MCP backend path: resolve from the backend's tool cache.
        if let Some(backend) = self.backends.get_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility,
            &surfaced.server,
        ) {
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
            let tool = self.listing_tool(&backend, &surfaced.tool, scope);
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
    /// A `required` backend this caller has no view of reads as unenumerated:
    /// its shared-slot cache is not this caller's catalogue (#2346).
    /// `tools_count` is null whenever `tools_known` is false, so a backend whose
    /// tools are not known to this caller yet never reads as an empty one
    /// (MIK-8721, from #4040).
    #[allow(clippy::unnecessary_wraps)]
    pub(super) async fn list_servers(
        &self,
        caller: &super::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let scope = caller.scope();
        let proof = Self::proof_of(caller);
        let mut servers: Vec<Value> = Vec::new();
        for b in self
            .backends
            .all_for(crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility)
        {
            if !self.admits_backend(&b.name, scope, session_id) {
                continue;
            }
            let hidden = self.has_no_view_for(&b, proof).await;
            // A per-user backend whose slot is cold for this caller has no
            // count it could vouch for: unenumerated, as a hidden one is.
            let mut cold = false;
            let admitted = if hidden {
                0
            } else {
                // Filled behind this read, as discovery does (MIK-7962);
                // `tools_known` reports the cold slot meanwhile.
                self.refresh_shared_behind_read(&b);
                let view = self.listing_snapshot(&b, scope);
                cold = view.is_none();
                view.map_or(0, |(tools, _)| {
                    tools
                        .iter()
                        .filter(|t| self.shows_tool(&b.name, t, scope, session_id))
                        .count()
                })
            };
            let known = !hidden && !cold && self.listing_known(&b, scope);
            let status = b.status();
            let killed = self.kill_switch.is_killed(&status.name);
            let mut entry = json!({
                "name": status.name,
                "running": status.running,
                "transport": status.transport,
                // Null until this caller's tools are known; tools_known says the same.
                "tools_count": known.then_some(admitted),
                "tools_known": known,
                "circuit_breaker": status.circuit_state,
                "status": if killed { "disabled" } else { "active" }
            });
            // The era determination rides on the same entry as the rest of the
            // backend's state, so an operator reading one server reads one row.
            if let Some(fields) = entry.as_object_mut() {
                if b.shared_slot_refused() {
                    // No shared session, so no shared era or health
                    // to show; say why, rather than an era that never resolves.
                    fields.insert(
                        "sessions".to_string(),
                        json!(crate::backend::PER_USER_SESSIONS),
                    );
                } else {
                    fields.extend(b.era_observation().await.render());
                }
            }
            servers.push(entry);
        }

        if let Some(cap) = self.get_capabilities()
            && self.admits_backend(&cap.name, scope, session_id)
        {
            let admitted = cap
                .get_tools()
                .iter()
                .filter(|t| self.shows_tool(&cap.name, t, scope, session_id))
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

#[cfg(test)]
#[path = "surfaced_reload_tests.rs"]
mod reload_tests;
