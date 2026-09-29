// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether the startup capability scan has finished (MIK-7268).
//!
//! Startup installs the backend empty so the listener binds before a large
//! capability directory is read. Until the scan has loaded every directory the
//! catalogue is empty or partial, so `/readyz` and `/health` wait on this.

use super::CapabilityBackend;

impl CapabilityBackend {
    /// Record that the startup scan has loaded every configured directory.
    pub(crate) fn mark_initial_scan_complete(&self) {
        // Release pairs with the Acquire below: a probe that sees `true` also
        // sees every capability the scan registered before marking.
        self.initial_scan
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether [`Self::mark_initial_scan_complete`] has run.
    #[must_use]
    pub(crate) fn initial_scan_complete(&self) -> bool {
        self.initial_scan.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Debug builds only: names a gate file. The startup scan holds until it exists,
/// so a process test can observe the loading state deterministically (#2376).
/// Compiled out of release builds; the release job checks the name is absent.
#[cfg(debug_assertions)]
const HOLD_SCAN_UNTIL: &str = "MCP_GATEWAY_TEST_HOLD_CAPABILITY_SCAN";

impl CapabilityBackend {
    /// Wait before the startup scan reads any directory: the pause that lets
    /// the listener bind first, then (debug builds) the test gate.
    pub(crate) async fn settle_before_initial_scan(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        #[cfg(debug_assertions)]
        if let Some(gate) = std::env::var_os(HOLD_SCAN_UNTIL) {
            while !std::path::Path::new(&gate).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::CapabilityExecutor;
    use super::*;

    #[test]
    fn a_fresh_backend_has_not_finished_its_scan() {
        let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        assert!(!backend.initial_scan_complete());
        assert!(!backend.status().loaded);

        backend.mark_initial_scan_complete();
        assert!(backend.initial_scan_complete());
        assert!(backend.status().loaded);
    }
}
