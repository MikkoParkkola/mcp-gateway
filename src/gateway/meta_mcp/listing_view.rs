// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which catalogue a name-only listing reads for a caller (MIK-8356, design
//! R3.3, R3.4, R4.2).
//!
//! A per-user backend keeps one catalogue per caller. A listing that names
//! tools without fetching (the disabled list, predictions, counts,
//! `list_servers`, spec preview) judges a tool by the caller's own slot,
//! found through the caller-slot index, never by the shared one. Without a
//! warm slot for this caller the backend's tools are withheld, except where
//! the stated SLOTVIS.6 residual keeps today's shared view (the surfaced list
//! in plain `tools/list`).

use std::sync::Arc;

use crate::backend::Backend;
use crate::identity_propagation::PropagationStrategyKind;
use crate::protocol::Tool;

use super::{InvokeScope, MetaMcp};

/// The catalogue a listing reads for this caller on one backend.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListingView {
    /// Not a per-user backend, or this caller has no per-user identity on a
    /// backend that grants a shared view: the shared slot is its catalogue.
    Shared,
    /// A per-user backend whose slot for this caller is not warm, or cannot
    /// be selected at all (a Passthrough backend, or a `required` one with no
    /// principal): nothing is known about this caller's catalogue.
    Cold,
    /// The binding of this caller's own warm slot.
    Caller(String),
}

/// What a listing does with a per-user backend when this caller's view is
/// [`ListingView::Cold`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdRule {
    /// Name nothing (every name-only listing).
    Withhold,
    /// Keep today's shared view (the surfaced list in plain `tools/list`,
    /// SLOTVIS.6's stated residual).
    SharedView,
}

impl MetaMcp {
    /// This caller's [`ListingView`] on `backend`. Synchronous and side-effect
    /// free: no mint, no fill.
    pub(crate) fn listing_view(&self, backend: &Backend, scope: InvokeScope<'_>) -> ListingView {
        let Some(idp) = backend.identity_propagation_config() else {
            return ListingView::Shared;
        };
        if matches!(idp.strategy, PropagationStrategyKind::Passthrough) {
            return ListingView::Cold;
        }
        let Some(principal) = self.principal_for(backend, scope.caller) else {
            return if idp.required {
                ListingView::Cold
            } else {
                ListingView::Shared
            };
        };
        match backend.caller_slot_binding(&principal.stable_actor_id()) {
            Some(binding) => ListingView::Caller(binding),
            None => ListingView::Cold,
        }
    }

    /// Whether a name-only listing names `tool` on `server` to this caller.
    /// Judged by the caller's own catalogue entry on a per-user backend; a
    /// name the caller's warm slot lacks, or holds with an invalid schema, is
    /// not named.
    pub(crate) fn listing_names(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
        cold: ColdRule,
    ) -> bool {
        let Some(backend) = self.backends.get(server) else {
            return self.shows_shared_name(server, tool, scope, session_id);
        };
        match self.listing_view(&backend, scope) {
            ListingView::Shared => self.shows_shared_name(server, tool, scope, session_id),
            ListingView::Cold => match cold {
                ColdRule::Withhold => false,
                ColdRule::SharedView => self.shows_shared_name(server, tool, scope, session_id),
            },
            ListingView::Caller(binding) => backend
                .with_cached_tool_for(Some(&binding), tool, |found| {
                    self.shows_tool(server, found, scope, session_id)
                })
                .unwrap_or(false),
        }
    }

    /// The snapshot a listing walk reads for this caller on `backend`, with
    /// whether it is a truncated drain; `None` when this caller's view is
    /// cold, so the backend contributes nothing it could not vouch for.
    pub(crate) fn listing_snapshot(
        &self,
        backend: &Backend,
        scope: InvokeScope<'_>,
    ) -> Option<(Arc<Vec<Tool>>, bool)> {
        match self.listing_view(backend, scope) {
            ListingView::Shared => Some(backend.cached_tools_snapshot_and_truncated()),
            ListingView::Cold => None,
            ListingView::Caller(binding) => {
                Some(backend.cached_tools_snapshot_and_truncated_for(&binding))
            }
        }
    }

    /// The surfaced tool as this caller's listing shows it: the caller's own
    /// entry on a per-user backend with a warm slot, else the shared one.
    pub(crate) fn listing_tool(
        &self,
        backend: &Backend,
        tool: &str,
        scope: InvokeScope<'_>,
    ) -> Option<Tool> {
        match self.listing_view(backend, scope) {
            ListingView::Caller(binding) => backend.get_cached_tool_for(Some(&binding), tool),
            ListingView::Shared | ListingView::Cold => backend.get_cached_tool(tool),
        }
    }
}
