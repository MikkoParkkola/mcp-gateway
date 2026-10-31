// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387: a scoped key's view of backend names. For a key whose grant is
//! a non-empty list without `*`, a name its scope excludes and a name that is
//! not registered are one thing, absent, and every call-path site answers
//! them alike, so the key cannot learn which backend names exist.
//!
//! PR-B (design `2026-10-17-mik-8387-scoped-backends-boundary.md` §2.3): the
//! registry is reached through [`Registry`], either as one caller's
//! [`ScopedBackends`] view or through an operation that names its
//! [`Unscoped`] class, so every read of it says which kind it is.

use std::collections::HashMap;
use std::sync::Arc;

use super::MetaMcp;
use super::visible::{Visibility, Withholding, memo::recorded_visibility};
use crate::backend::{Backend, BackendRegistry, BackendStatus};
use crate::gateway::authz::BackendGrant;

/// Why a backend name is absent for a scoped caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gateway) enum Absence {
    /// The key's scope excludes it; the scope refusal is what the record keeps.
    OutOfScope,
    /// In scope, but neither a registered backend nor the capability provider.
    Unregistered,
}

/// Why a registry read is not one caller's scoped view. The class is a
/// claim a reviewer checks against `scoped_backends_classes.tsv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gateway) enum Unscoped {
    /// Deciding what a caller may see: listing, search, the visible digest.
    Visibility,
    /// Finding or revalidating a backend's catalogue for any caller.
    Discovery,
    /// Work with no caller: warm starts, change feeds, events.
    Background,
    /// The operator's own views: the admin UI, health.
    Admin,
    /// Startup, registration, reload and stop.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "names the leaf allows of lifecycle code; no Registry operation reads under it"
        )
    )]
    Lifecycle,
}

/// The backend registry, reachable only through a scoped view or a classed
/// operation.
#[derive(Clone)]
pub(in crate::gateway) struct Registry(Arc<BackendRegistry>);

impl Registry {
    pub(in crate::gateway) fn new(inner: Arc<BackendRegistry>) -> Self {
        Self(inner)
    }

    /// The registry as `grant` sees it; `capability` is the capability
    /// provider's name, a registered name for every grant that reaches it.
    pub(in crate::gateway) fn scoped<'a>(
        &'a self,
        grant: BackendGrant<'a>,
        capability: Option<String>,
    ) -> ScopedBackends<'a> {
        ScopedBackends {
            registry: &self.0,
            grant,
            capability,
        }
    }

    pub(in crate::gateway) fn get_for(&self, _why: Unscoped, name: &str) -> Option<Arc<Backend>> {
        #[allow(
            clippy::disallowed_methods,
            clippy::let_and_return,
            reason = "Lifecycle: the classed operation itself"
        )]
        let backend = self.0.get(name);
        backend
    }

    pub(in crate::gateway) fn all_for(&self, _why: Unscoped) -> Vec<Arc<Backend>> {
        #[allow(
            clippy::disallowed_methods,
            clippy::let_and_return,
            reason = "Lifecycle: the classed operation itself"
        )]
        let backends = self.0.all();
        backends
    }

    pub(in crate::gateway) fn membership_for<R>(
        &self,
        _why: Unscoped,
        read: impl FnOnce(u64) -> R,
    ) -> R {
        #[allow(
            clippy::disallowed_methods,
            clippy::let_and_return,
            reason = "Lifecycle: the classed operation itself"
        )]
        let answer = self.0.with_membership(read);
        answer
    }

    pub(in crate::gateway) fn statuses_for(
        &self,
        _why: Unscoped,
    ) -> HashMap<String, BackendStatus> {
        #[allow(
            clippy::disallowed_methods,
            clippy::let_and_return,
            reason = "Lifecycle: the classed operation itself"
        )]
        let statuses = self.0.statuses();
        statuses
    }

    pub(in crate::gateway) fn subscribe_started_for(
        &self,
        _why: Unscoped,
    ) -> tokio::sync::broadcast::Receiver<String> {
        #[allow(
            clippy::disallowed_methods,
            clippy::let_and_return,
            reason = "Lifecycle: the classed operation itself"
        )]
        let started = self.0.subscribe_started();
        started
    }

    /// Report a surfaced-tools change from a config reload.
    pub(in crate::gateway) fn nudge_surfaced(&self) {
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: the classed operation itself"
        )]
        self.0.nudge_surfaced();
    }

    pub(in crate::gateway) fn nudge_catalogue_for(&self, _why: Unscoped, name: &str) {
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: the classed operation itself"
        )]
        self.0.nudge_catalogue(name);
    }

    /// The raw registry, for test fixtures only.
    #[cfg(test)]
    pub(in crate::gateway) fn for_test(&self) -> &Arc<BackendRegistry> {
        &self.0
    }
}

/// Backend names as one caller's grant sees them.
pub(in crate::gateway) struct ScopedBackends<'a> {
    registry: &'a BackendRegistry,
    grant: BackendGrant<'a>,
    /// The capability provider's name, owned: read once when the view is
    /// built, as the registry is.
    capability: Option<String>,
}

impl MetaMcp {
    /// The stored registry, for the router choke point (design §2.5).
    pub(in crate::gateway) fn registry(&self) -> &Registry {
        &self.backends
    }

    /// The registry as `grant` sees it, with this gateway's capability
    /// provider.
    pub(in crate::gateway) fn scoped<'a>(&'a self, grant: BackendGrant<'a>) -> ScopedBackends<'a> {
        ScopedBackends {
            registry: &self.backends.0,
            grant,
            // A provider hidden from the caller is not this view's.
            capability: self
                .get_capabilities()
                .map(|cap| cap.name.clone())
                .filter(|name| !super::hiding::hidden(name)),
        }
    }
    /// The view of a caller with no scope, for tests that judge a target
    /// with no request around it.
    #[cfg(test)]
    pub(in crate::gateway) fn unscoped_for_test(&self) -> ScopedBackends<'_> {
        self.scoped(BackendGrant::Unscoped)
    }
}

impl ScopedBackends<'_> {
    /// Why `name` is absent, judged live; `None` unless the grant is
    /// [`BackendGrant::Scoped`]. An empty grant keeps its own named message,
    /// and an unscoped caller keeps today's answers. `OutOfScope` wins: the
    /// scope is the real reason.
    pub(in crate::gateway) fn absence(&self, name: &str) -> Option<Absence> {
        let BackendGrant::Scoped(granted) = self.grant else {
            return None;
        };
        if !granted.iter().any(|backend| backend == name) {
            return Some(Absence::OutOfScope);
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "Visibility: the scoped view's own lookup, after its grant check"
        )]
        let registered =
            self.registry.get(name).is_some() || self.capability.as_deref() == Some(name);
        // A backend hidden from the caller is one it cannot tell from an
        // unregistered name (`super::hiding`).
        (!registered || super::hiding::hidden(name)).then_some(Absence::Unregistered)
    }

    /// Whether a requested target is absent for this request: recorded so by
    /// an earlier site, or absent now. The record comes first, so one
    /// judgement holds for the request: a reload that registers the name
    /// after it was judged absent cannot reach a dispatch.
    pub(in crate::gateway) fn absent_step(&self, server: &str, tool: &str) -> bool {
        recorded_visibility(server, tool) == Some(Visibility::Withheld(Withholding::Absent))
            || self.absence(server).is_some()
    }

    /// The scoped read: `name`'s backend, or `None` when it is absent for
    /// this grant. Named apart from `BackendRegistry::get`, so its receiver
    /// follows from the name wherever the view is bound.
    pub(in crate::gateway) fn scoped_get(&self, name: &str) -> Option<Arc<Backend>> {
        // A scoped key's hidden name is already `absence`'s; an unscoped
        // caller's misses here, as an unregistered name does.
        if self.absence(name).is_some()
            || (!matches!(self.grant, BackendGrant::Scoped(_)) && super::hiding::hidden(name))
        {
            return None;
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "Visibility: the scoped view's own lookup, after its grant check"
        )]
        self.registry.get(name)
    }
}
