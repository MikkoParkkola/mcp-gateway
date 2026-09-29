// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Borrowed access to one capability definition (#2110).

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
}
