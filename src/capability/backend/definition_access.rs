// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Access to capability definitions without cloning them (#2110, MIK-8014).

use super::CapabilityBackend;
use crate::capability::CapabilityDefinition;

#[cfg(test)]
thread_local! {
    /// Capability calls that reached execution on this thread: a
    /// `#[tokio::test]` runs on its own thread, so a row reads its own.
    static EXECUTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl CapabilityBackend {
    /// The definition and the MCP revocation generation, read under one lock so
    /// an unload cannot fall between them. Read once per execution, first.
    pub(super) fn get_with_generation(&self, name: &str) -> Option<(CapabilityDefinition, u64)> {
        #[cfg(test)]
        EXECUTED.with(|n| n.set(n.get() + 1));
        let caps = self.capabilities.read();
        let generation = self.executor.mcp_generation(name);
        caps.get(name).cloned().map(|def| (def, generation))
    }

    /// Capability calls that reached execution on this thread.
    #[cfg(test)]
    pub(crate) fn executed_for_test() -> usize {
        EXECUTED.with(std::cell::Cell::get)
    }

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
