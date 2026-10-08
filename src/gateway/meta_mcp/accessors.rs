// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` accessor helpers used by sibling modules.

use super::{
    Arc, CapabilityBackend, MetaMcp, ReloadContext, ToolRegistry, TransitionTracker,
    WebhookRegistry, session_key,
};
#[cfg(feature = "spec-preview")]
use super::{debug, session_fp};

// ============================================================================
// Accessor helpers (pub(super) — used by sub-modules)
// ============================================================================

impl MetaMcp {
    pub(in crate::gateway) fn get_webhook_registry(
        &self,
    ) -> Option<Arc<parking_lot::RwLock<WebhookRegistry>>> {
        self.webhook_registry.read().clone()
    }

    pub(in crate::gateway) fn get_reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    /// Public accessor for the reload context — used by UI management endpoints.
    pub fn reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    pub(in crate::gateway) fn get_transition_tracker(&self) -> Option<Arc<TransitionTracker>> {
        self.transition_tracker.read().clone()
    }

    pub(in crate::gateway) fn get_tool_registry(&self) -> Option<std::sync::Arc<ToolRegistry>> {
        self.tool_registry.clone()
    }

    pub(in crate::gateway) fn get_capabilities(&self) -> Option<Arc<CapabilityBackend>> {
        self.capabilities.read().clone()
    }

    /// Return the full `Tool` objects for all dynamically promoted tools in a session.
    ///
    /// Promotion entries are stored as `"server:tool"` strings.  Each is resolved
    /// against the backend cache; entries whose backend has gone offline (cache empty)
    /// are silently omitted.
    ///
    /// Returns an empty `Vec` when the caller has no session — no id, or the
    /// empty id a modern sessionless connection presents (`session_key`) — and
    /// when the session has no promoted tools.
    ///
    /// The `session_key` filter lives here rather than at the three call sites
    /// (`mod.rs:1266`, `mod.rs:1330`, `spec_preview.rs:112`) so that a future
    /// list-shaping caller inherits it: promotions written under the shared
    /// empty key would otherwise be read back by every other modern connection
    /// (`MIK-7272.ORDER.2`).
    #[cfg(feature = "spec-preview")]
    pub(in crate::gateway) fn promoted_tools_for_session(
        &self,
        session_id: Option<&str>,
    ) -> Vec<(String, crate::protocol::Tool)> {
        let Some(sid) = session_key(session_id) else {
            return Vec::new();
        };
        let Some(entry) = self.session_promoted.get(sid) else {
            return Vec::new();
        };
        entry
            .iter()
            .filter_map(|key| {
                let (server, tool) = key.split_once(':')?;
                let backend = self.backends.get(server)?;
                // INV-2 (MIK-6742): never surface an OAuth-isolated backend's cached
                // tool to another user on a multi-user gateway. Omit (fail closed).
                if self.meta_route_isolation_refused(&backend) {
                    return None;
                }
                Some((server.to_string(), backend.get_cached_tool(tool)?))
            })
            .collect()
    }

    /// Remove all promoted tools for a session (called on session disconnect).
    #[cfg(feature = "spec-preview")]
    pub fn clear_session_promoted(&self, session_id: &str) {
        self.session_promoted.remove(session_id);
        debug!(
            session_id = %session_fp(session_id),
            "Cleared spec-preview promoted tools for session"
        );
    }

    /// Resolve the active `RoutingProfile` for a session.
    ///
    /// A caller with no session gets the default and cannot be given anything
    /// else: see [`session_key`] for why an empty id is no session at all.
    /// This is the one site `surfaced`, `invoke` and `spec_preview` read the
    /// profile through, so closing it closes the read for all three.
    pub(in crate::gateway) fn active_profile(
        &self,
        session_id: Option<&str>,
    ) -> std::sync::Arc<crate::routing_profile::RoutingProfile> {
        let default_name = self.profile_registry.default_name();
        let name = session_key(session_id).map_or_else(
            || default_name.to_string(),
            |sid| self.session_profiles.get_profile_name(sid, default_name),
        );
        self.profile_registry.get_shared(&name)
    }
}
