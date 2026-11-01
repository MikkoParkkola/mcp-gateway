// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the sanitize exemption (MIK-8154 SAN.1, option (a)) reads about the
//! backends a call can reach: a backend's `passthrough` flag, and the servers
//! a playbook's steps run on, with the digest of the definition judged.

use super::MetaMcp;

impl MetaMcp {
    /// The registered `passthrough: true` instance of `server`, if it is one.
    /// The exemption is judged on this one instance and recorded with it
    /// (MIK-8154 F2), so the send can refuse any other: no name means no
    /// exemption, so the request is sanitized. Judged through the caller's
    /// `grant` (MIK-8387 S0): a backend outside a scoped key's scope is never
    /// exempt, so it is sanitized as a missing name is.
    pub(crate) fn passthrough_instance(
        &self,
        grant: crate::gateway::authz::BackendGrant<'_>,
        server: &str,
    ) -> Option<std::sync::Arc<crate::backend::Backend>> {
        // MIK-8441: an empty grant reaches no backend, so none is exempt and
        // every name it names is sanitized alike (`absence` is `None` under
        // an empty grant, which keeps its own refusal).
        if matches!(grant, crate::gateway::authz::BackendGrant::Empty) {
            return None;
        }
        if self.scoped(grant).absence(server).is_some() {
            return None;
        }
        // A name the capability provider answers runs there, outside any
        // backend instance and its send check, so it is never exempt.
        if self
            .caller_capabilities()
            .is_some_and(|caps| caps.name == server)
        {
            return None;
        }
        self.scoped(grant)
            .scoped_get(server)
            .filter(|backend| backend.passthrough())
    }

    /// The servers playbook `name`'s steps run on, and the digest of the live
    /// definition they were read from (the digest a run must still see, C2e).
    /// `None` for a name the engine does not hold.
    pub(crate) fn playbook_step_servers(&self, name: &str) -> Option<(Vec<String>, String)> {
        let engine = self.playbook_engine.read();
        let definition = engine.get(name)?;
        let servers = definition
            .steps
            .iter()
            .map(|step| step.server.clone())
            .collect();
        Some((servers, playbook_digest(definition)))
    }
}

/// The digest a playbook definition is pinned by: the one admission folds
/// into a keyed run's operation.
pub(crate) fn playbook_digest(definition: &crate::playbook::PlaybookDefinition) -> String {
    serde_json::to_value(definition)
        .map(|value| crate::hashing::canonical_json_sha256(&value))
        .unwrap_or_default()
}
