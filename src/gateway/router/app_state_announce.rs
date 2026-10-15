// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `AppState` tool-change announcements.

use super::{AppState, view_judge};

/// Create the router, folding in routes a caller assembles separately.
///
/// Extra routes are merged **here**, before the origin gate is applied, rather
/// than by the caller afterwards. A layer only covers what is already merged,
/// so a route merged onto the finished router silently skips the gate. That has
/// happened twice: first for the routes merged below, then for the webhook
/// routes merged at the call site. Taking them as a parameter removes the
/// ordering discipline that failed both times.
#[allow(clippy::needless_pass_by_value)] // Arc<T> is idiomatically passed by value
impl AppState {
    /// Announce that the set of available tools has changed.
    ///
    /// Two audiences, one event: sessions attached to the pre-2026 GET stream,
    /// and listeners on `subscriptions/listen`. Kept in one function because
    /// telling only one of them is the failure mode — the capability is
    /// advertised as `listChanged: true` to both.
    ///
    /// Both audiences are scoped to callers who may access `backend` now.
    pub async fn announce_tools_changed(&self, backend: &str) {
        self.proxy_manager
            .broadcast_tools_list_changed_judged(
                backend,
                Some(&view_judge::RouterViewJudge::new(self)),
            )
            .await;
        self.subscriptions.publish_for_backend(
            crate::gateway::subscription_registry::tools_list_changed(),
            backend,
        );
        self.meta_mcp.events_tools_changed(backend);
    }

    /// Announce that some caller's own view of `backend` changed (`MIK-8148`).
    ///
    /// The same two audiences as [`Self::announce_tools_changed`], scoped the
    /// same way, and never wider. The notice carries no tool and no caller:
    /// a listener learns only that some view of `backend` changed, and when,
    /// and its relist returns its own view. The webhook hub is not told: it
    /// reports the backend's shared tools to external subscribers.
    pub async fn announce_backend_view_changed(&self, backend: &str) {
        self.proxy_manager
            .broadcast_tools_list_changed_judged(
                backend,
                Some(&view_judge::RouterViewJudge::new(self)),
            )
            .await;
        self.subscriptions.publish_for_backend(
            crate::gateway::subscription_registry::tools_list_changed(),
            backend,
        );
    }
}
