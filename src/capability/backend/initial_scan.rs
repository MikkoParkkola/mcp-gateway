// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether the startup capability scan has finished (MIK-7268).
//!
//! Startup installs the backend empty so the listener binds before a large
//! capability directory is read. Until the scan has loaded every directory the
//! catalogue is empty or partial, so `/readyz` and `/health` wait on this.
//!
//! A backend is born complete. Only the gateway's startup, which loads in the
//! background, opts in to waiting with [`CapabilityBackend::begin_initial_scan`];
//! an embedder that loads its own backend synchronously never needs to.

use super::CapabilityBackend;

/// `initial_scan` bits: the scan has loaded every directory; a directory
/// failed to load.
const COMPLETE: u8 = 0b01;
const FAILED: u8 = 0b10;

impl CapabilityBackend {
    /// Mark the backend as still scanning, until
    /// [`Self::mark_initial_scan_complete`] runs. Called by startup before it
    /// spawns the background load.
    pub(crate) fn begin_initial_scan(&self) {
        self.initial_scan
            .store(0, std::sync::atomic::Ordering::Release);
    }

    /// Record that the startup scan has loaded every configured directory.
    pub(crate) fn mark_initial_scan_complete(&self) {
        // Release pairs with the Acquire below: a probe that sees `true` also
        // sees every capability the scan registered before marking.
        self.initial_scan
            .fetch_or(COMPLETE, std::sync::atomic::Ordering::Release);
    }

    /// Record that a configured directory could not be loaded: what the
    /// scan registered is partial.
    pub(crate) fn mark_initial_scan_failed(&self) {
        self.initial_scan
            .fetch_or(FAILED, std::sync::atomic::Ordering::Release);
    }

    /// Whether [`Self::mark_initial_scan_complete`] has run.
    #[must_use]
    pub(crate) fn initial_scan_complete(&self) -> bool {
        self.initial_scan.load(std::sync::atomic::Ordering::Acquire) & COMPLETE != 0
    }

    /// Whether every configured directory loaded (meaningful once the scan
    /// is complete): a failed one leaves the catalogue partial.
    #[must_use]
    pub(crate) fn initial_scan_loaded_every_directory(&self) -> bool {
        self.initial_scan.load(std::sync::atomic::Ordering::Acquire) & FAILED == 0
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
    pub(crate) async fn settle_before_initial_scan() {
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
    fn an_embedded_backend_is_loaded_without_any_marking() {
        let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        assert!(backend.initial_scan_complete());
        assert!(backend.status().loaded);
    }

    #[test]
    fn a_backend_that_begins_its_scan_is_not_loaded_until_marked() {
        let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        backend.begin_initial_scan();
        assert!(!backend.initial_scan_complete());
        assert!(!backend.status().loaded);

        backend.mark_initial_scan_complete();
        assert!(backend.initial_scan_complete());
        assert!(backend.status().loaded);
    }
}

#[cfg(test)]
mod failed_tests {
    use std::sync::Arc;

    use super::super::CapabilityExecutor;
    use super::*;

    #[test]
    fn a_failed_directory_marks_the_scan_partial_even_once_complete() {
        let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        backend.begin_initial_scan();
        backend.mark_initial_scan_failed();
        assert!(!backend.initial_scan_complete(), "still scanning");
        backend.mark_initial_scan_complete();
        assert!(backend.initial_scan_complete());
        assert!(!backend.initial_scan_loaded_every_directory());
        let clean = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        assert!(clean.initial_scan_loaded_every_directory());
    }
}
