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
//! SLOTVIS.6 keeps the shared view (the surfaced list in plain `tools/list`).
//! A backend with per-user sessions only has no shared view: its cold
//! caller's own view is warmed before `tools/list` is built.

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
    /// The caller has no view of this `required` per-user backend
    /// (`MetaMcp::has_no_view_for`): no principal, or a managed account with
    /// no current grant. It lacks every tool there, on every surface; never
    /// the cold rule's shared view (lead ruling 2026-10-11; design R3.7).
    NoView,
}

/// What a listing does with a per-user backend when this caller's view is
/// [`ListingView::Cold`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdRule {
    /// Name nothing (every name-only listing).
    Withhold,
    /// Keep the shared view (the surfaced list in plain `tools/list`,
    /// SLOTVIS.6), except on a backend with per-user sessions only, which has
    /// none: there the caller's own view is warmed before the list is built
    /// and withheld until it is.
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
        if self.lacks_principal_on_required(backend, scope.caller) {
            return ListingView::NoView;
        }
        let Some(principal) = self.principal_for(backend, scope.caller) else {
            return ListingView::Shared;
        };
        let id = principal.stable_actor_id();
        if backend.caller_has_no_view(&id) {
            return ListingView::NoView;
        }
        match backend.caller_slot_binding(&id) {
            Some(binding) if Self::held_binding_current(backend, &binding) => {
                ListingView::Caller(binding)
            }
            _ => ListingView::Cold,
        }
    }

    /// Whether `binding`, the caller's held slot on `backend`, is still the
    /// binding this request's account read gave. A rotated grant's slot reads
    /// as cold, never as the old grant's view, however its publish raced the
    /// listing. With no account read in this request there is nothing to
    /// judge it by, and the held slot stands, as a stored read's revalidation
    /// keeps it.
    fn held_binding_current(backend: &Backend, binding: &str) -> bool {
        use super::visible::memo::{DescriptorId, HeldView, held_view_current};
        backend
            .account_descriptor_id()
            .map(|account| DescriptorId(account.to_owned()))
            .is_none_or(|account| {
                held_view_current(&backend.name, &account, binding) != HeldView::Stale
            })
    }

    /// Whether `caller` has no principal on `backend`, a `required` per-user
    /// backend: such a caller can never hold a slot there, so it lacks every
    /// tool on it, on every listing and every call (lead ruling 2026-10-11;
    /// design R3.7). The synchronous half of `has_no_view_for`, read by the
    /// listings, the caller verdict and the dispatch funnel. Passthrough is
    /// judged by its own rule.
    pub(crate) fn lacks_principal_on_required(
        &self,
        backend: &Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) -> bool {
        backend.identity_propagation_config().is_some_and(|idp| {
            idp.required && !matches!(idp.strategy, PropagationStrategyKind::Passthrough)
        }) && self.principal_for(backend, caller).is_none()
    }

    /// MIK-8382 UNIFY.1b: a call answered as an absent name because `backend`
    /// requires identity propagation and the caller has no principal for it
    /// logs one WARN per (backend, caller key) per window (`warn_limit`).
    /// The caller key is the limiter's only; it is never logged. A caller
    /// with no key shares one bucket per backend.
    pub(crate) fn warn_lacked_principal(&self, backend: &str, caller_key: Option<&str>) {
        let due = super::warn_limit::first_warn(
            &mut self.lacked_warned.lock(),
            backend,
            caller_key.unwrap_or("anonymous"),
            std::time::Instant::now(),
        );
        if due {
            tracing::warn!(
                backend,
                missing = "execution principal",
                "call answered as an absent name: the backend requires identity \
                 propagation and the caller has no principal for it"
            );
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
        let Some(backend) = self.backends.get_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility,
            server,
        ) else {
            return self.shows_shared_name(server, tool, scope, session_id);
        };
        match self.listing_view(&backend, scope) {
            ListingView::Shared => self.shows_shared_name(server, tool, scope, session_id),
            ListingView::Cold => match cold {
                ColdRule::SharedView if !backend.shared_slot_refused() => {
                    self.shows_shared_name(server, tool, scope, session_id)
                }
                ColdRule::Withhold | ColdRule::SharedView => false,
            },
            ListingView::NoView => false,
            ListingView::Caller(binding) => backend
                .with_cached_tool_for(Some(&binding), tool, |found| {
                    self.shows_tool(server, found, scope, session_id)
                })
                .unwrap_or(false),
        }
    }

    /// Whether the catalogue this caller's listing reads on `backend` was ever
    /// enumerated: its own slot on a per-user backend, never the shared one
    /// (MIK-8356). A cold or absent view is not known.
    pub(crate) fn listing_known(&self, backend: &Backend, scope: InvokeScope<'_>) -> bool {
        match self.listing_view(backend, scope) {
            ListingView::Shared => backend.cached_tools_known(),
            ListingView::Cold | ListingView::NoView => false,
            ListingView::Caller(binding) => backend.holds_tools_for(Some(&binding)),
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
            ListingView::Shared => Some(backend.cached_tools_snapshot_and_truncated(None)),
            ListingView::Cold | ListingView::NoView => None,
            ListingView::Caller(binding) => {
                Some(backend.cached_tools_snapshot_and_truncated(Some(&binding)))
            }
        }
    }

    /// The surfaced tool as this caller's listing shows it: the caller's own
    /// entry on a per-user backend with a warm slot, else the shared one, and
    /// none on a backend with per-user sessions only, which has no shared one.
    pub(crate) fn listing_tool(
        &self,
        backend: &Backend,
        tool: &str,
        scope: InvokeScope<'_>,
    ) -> Option<Tool> {
        match self.listing_view(backend, scope) {
            ListingView::Caller(binding) => backend.get_cached_tool_for(Some(&binding), tool),
            ListingView::Cold if backend.shared_slot_refused() => None,
            ListingView::Shared | ListingView::Cold => backend.get_cached_tool(tool),
            ListingView::NoView => None,
        }
    }

    /// The session's promoted tools as this caller's listing shows them
    /// (design R3.3, gpt r3 F4): a per-user backend's entry is the caller's
    /// own Tool while its slot is warm, and is omitted while it is cold, so a
    /// promotion never shows the shared catalogue's view of a per-user tool.
    #[cfg(feature = "spec-preview")]
    pub(crate) fn promoted_tools_for_caller(
        &self,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> Vec<(String, Tool)> {
        self.promoted_tools_for_session(session_id)
            .into_iter()
            .filter_map(|(server, tool)| {
                let Some(backend) = self.backends.get_for(
                    crate::gateway::meta_mcp::scoped_backends::Unscoped::Visibility,
                    &server,
                ) else {
                    return Some((server, tool));
                };
                match self.listing_view(&backend, scope) {
                    ListingView::Shared => Some((server, tool)),
                    ListingView::Cold | ListingView::NoView => None,
                    ListingView::Caller(binding) => backend
                        .get_cached_tool_for(Some(&binding), &tool.name)
                        .map(|own| (server, own)),
                }
            })
            .collect()
    }
}
