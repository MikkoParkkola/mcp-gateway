// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Access to capability definitions without cloning them (#2110, MIK-8014).

use super::CapabilityBackend;
use crate::capability::CapabilityDefinition;

impl CapabilityBackend {
    /// Run `f` on a capability by name without cloning it. Per-tool
    /// visibility checks call this for every tool on every `initialize` and
    /// `tools/list`, where a clone per call was the #2110 p99 regression.
    /// `f` runs under the read lock, so it must not call back into `self`.
    pub(crate) fn with_definition<R>(
        &self,
        name: &str,
        f: impl FnOnce(&CapabilityDefinition) -> R,
    ) -> Option<R> {
        self.capabilities.read().get(name).map(f)
    }

    /// Each capability's name, category and chain hints, in insertion order:
    /// what the initialize guide reads, without copying the rest of each
    /// definition (MIK-8014 PERF.8a).
    pub(crate) fn routing_fields(&self) -> Vec<(String, String, Vec<String>)> {
        self.capabilities
            .read()
            .entries
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    c.metadata.category.clone(),
                    c.metadata.chains_with.clone(),
                )
            })
            .collect()
    }
}
