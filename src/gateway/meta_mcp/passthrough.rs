// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the sanitize exemption (MIK-8154 SAN.1, option (a)) reads about the
//! backends a call can reach: a backend's `passthrough` flag, and the servers
//! a playbook's steps run on, with the digest of the definition judged.

use super::MetaMcp;

impl MetaMcp {
    /// Whether `server` is a registered backend with `passthrough: true`. A
    /// name with no backend is not passthrough, so the request is sanitized.
    pub(crate) fn backend_is_passthrough(&self, server: &str) -> bool {
        self.backends
            .get(server)
            .is_some_and(|backend| backend.passthrough())
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
