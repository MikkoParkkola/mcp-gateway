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
/// A capability reload arrived before the scan completed and awaits its turn.
const RELOAD_HELD: u8 = 0b100;

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

    /// A capability reload arrived: hold it if the scan has not completed.
    /// `true` means it is held and [`Self::take_held_reload`] hands it over
    /// once the scan is done; `false` means the scan is already complete and
    /// the caller applies the reload now. One atomic step, so a reload cannot
    /// slip between the check and the hold.
    pub(crate) fn hold_reload_until_scan_complete(&self) -> bool {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        self.initial_scan
            .try_update(AcqRel, Acquire, |bits| {
                (bits & COMPLETE == 0).then_some(bits | RELOAD_HELD)
            })
            .is_ok()
    }

    /// Whether a reload was held during the scan; clears the hold.
    pub(crate) fn take_held_reload(&self) -> bool {
        self.initial_scan
            .fetch_and(!RELOAD_HELD, std::sync::atomic::Ordering::AcqRel)
            & RELOAD_HELD
            != 0
    }

    /// Whether [`Self::mark_initial_scan_complete`] has run.
    #[must_use]
    pub(crate) fn initial_scan_complete(&self) -> bool {
        self.initial_scan.load(std::sync::atomic::Ordering::Acquire) & COMPLETE != 0
    }

    /// Whether every configured directory loaded (meaningful once the scan
    /// is complete): a failed one leaves the catalogue partial. A reload
    /// rewrites this for the catalogue it installs (MIK-8028), so it always
    /// describes the current catalogue.
    #[must_use]
    pub(crate) fn initial_scan_loaded_every_directory(&self) -> bool {
        self.initial_scan.load(std::sync::atomic::Ordering::Acquire) & FAILED == 0
    }

    /// Record whether the catalogue a reload is installing misses a
    /// directory. Called under the capabilities write lock, with the swap.
    pub(crate) fn set_catalogue_partial(&self, partial: bool) {
        use std::sync::atomic::Ordering::AcqRel;
        if partial {
            self.initial_scan.fetch_or(FAILED, AcqRel);
        } else {
            self.initial_scan.fetch_and(!FAILED, AcqRel);
        }
    }

    /// The catalogue generation: it moves at every catalogue write
    /// (MIK-8037), so an equal value read twice means no write between.
    pub(crate) fn catalogue_generation(&self) -> u64 {
        self.catalogue_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// With the write, under its lock: `_held` is that lock's guard, so the
    /// bump cannot be made outside it.
    pub(super) fn bump_catalogue_generation(
        &self,
        _held: &parking_lot::RwLockWriteGuard<'_, super::IndexedCapabilities>,
    ) {
        self.catalogue_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Record `name` as read but refused by the account gate (MIK-8037): a
    /// catalogue write, so the generation moves. Takes the write lock: call
    /// it holding no capabilities guard. An admission forgets it again.
    pub(super) fn note_refused(&self, name: &str) {
        let mut caps = self.capabilities.write();
        caps.refused.insert(name.to_owned());
        self.bump_catalogue_generation(&caps);
    }

    /// The capabilities and whether every directory loaded, read under one
    /// lock, so a reload cannot change one without the other (MIK-8028).
    pub(crate) fn catalogue_snapshot(&self) -> (Vec<super::CapabilityDefinition>, bool) {
        let (catalogue, complete, ..) = self.catalogue_snapshot_at();
        (catalogue, complete)
    }

    /// [`Self::catalogue_snapshot`], the generation it was read at and the
    /// names the account gate refused from the directories read, all under
    /// the one lock (MIK-8037).
    pub(crate) fn catalogue_snapshot_at(
        &self,
    ) -> (Vec<super::CapabilityDefinition>, bool, u64, Vec<String>) {
        let caps = self.capabilities.read();
        (
            caps.entries.clone(),
            self.initial_scan_loaded_every_directory(),
            self.catalogue_generation(),
            caps.refused.iter().cloned().collect(),
        )
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

#[cfg(test)]
mod held_reload_tests {
    use std::sync::Arc;

    use super::super::CapabilityExecutor;
    use super::*;

    /// A reload before the scan completes is held once and handed over once;
    /// after completion nothing is held and the caller applies it itself.
    #[test]
    fn a_reload_is_held_only_while_the_scan_runs() {
        let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
        backend.begin_initial_scan();
        assert!(!backend.take_held_reload(), "nothing held yet");
        assert!(backend.hold_reload_until_scan_complete());
        assert!(
            backend.hold_reload_until_scan_complete(),
            "held again, still one"
        );
        backend.mark_initial_scan_complete();
        assert!(backend.take_held_reload(), "handed over");
        assert!(!backend.take_held_reload(), "only once");
        assert!(
            !backend.hold_reload_until_scan_complete(),
            "complete: the caller applies it now"
        );
        assert!(!backend.take_held_reload(), "and nothing was left held");
    }
}
