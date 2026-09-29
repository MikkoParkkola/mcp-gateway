// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2300: only a caller that will use a slot may create one. A read-only
//! probe of a caller's metadata cache (freshness, refresh cooldown) used to
//! mint the `PerUser` slot it asked about, so probes alone could fill the
//! identity-slot cap. A probe of a slot that does not exist answers "cold".

use super::slot_eviction_tests::{per_user_backend, slot};

/// GIVEN a propagating backend with no slot for `probe`
/// WHEN the tool-cache freshness and refresh-cooldown probes ask about `probe`
/// THEN both answer "not fresh / not cooling" and no slot is created.
#[test]
fn a_metadata_probe_creates_no_identity_slot() {
    let backend = per_user_backend("probe");

    assert!(!backend.has_cached_tools_for(Some("probe")));
    assert!(!backend.stale_refresh_cooling(Some("probe")));

    assert!(
        !backend.pool_has_slot_for_test(&slot("probe")),
        "a read-only probe minted an identity slot"
    );
}

impl super::Backend {
    /// Test-only: how many `PerUser` slots the pool holds.
    pub(crate) fn per_user_slots_for_test(&self) -> usize {
        self.per_user_slot_bindings_for_test().len()
    }

    /// Test-only: the bindings of the `PerUser` slots the pool holds, sorted.
    pub(crate) fn per_user_slot_bindings_for_test(&self) -> Vec<String> {
        let mut bindings: Vec<String> = self
            .pool
            .iter()
            .filter_map(|slot| match slot.key() {
                super::PoolKey::PerUser { binding } => Some(binding.clone()),
                super::PoolKey::Shared => None,
            })
            .collect();
        bindings.sort();
        bindings
    }
}
