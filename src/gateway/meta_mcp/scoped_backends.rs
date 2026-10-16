// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387: a scoped key's view of backend names. For a key whose grant is
//! a non-empty list without `*`, a name its scope excludes and a name that is
//! not registered are one thing, absent, and every call-path site answers
//! them alike, so the key cannot learn which backend names exist.

use super::MetaMcp;
use super::visible::{Visibility, Withholding, recorded_visibility};
use crate::gateway::authz::BackendGrant;

/// Why a backend name is absent for a scoped caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gateway) enum Absence {
    /// The key's scope excludes it; the scope refusal is what the record keeps.
    OutOfScope,
    /// In scope, but neither a registered backend nor the capability provider.
    Unregistered,
}

/// Backend names as one caller's grant sees them.
pub(in crate::gateway) struct ScopedBackends<'a> {
    meta: &'a MetaMcp,
    grant: BackendGrant<'a>,
}

impl MetaMcp {
    /// The registry as `grant` sees it.
    pub(in crate::gateway) fn scoped<'a>(&'a self, grant: BackendGrant<'a>) -> ScopedBackends<'a> {
        ScopedBackends { meta: self, grant }
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
        let capability = self.meta.get_capabilities();
        let registered = self.meta.backends.get(name).is_some()
            || capability.is_some_and(|cap| cap.name == name);
        (!registered).then_some(Absence::Unregistered)
    }

    /// Whether a requested target is absent for this request: recorded so by
    /// an earlier site, or absent now. The record comes first, so one
    /// judgement holds for the request: a reload that registers the name
    /// after it was judged absent cannot reach a dispatch.
    pub(in crate::gateway) fn absent_step(&self, server: &str, tool: &str) -> bool {
        recorded_visibility(server, tool) == Some(Visibility::Withheld(Withholding::Absent))
            || self.absence(server).is_some()
    }
}
