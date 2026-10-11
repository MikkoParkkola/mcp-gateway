// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which pool slot a caller's own catalogue lives in (MIK-8356, design R3.5).
//!
//! STUB: the API is pinned here first so the index rows (test plan I2a-d) are
//! seen red before anything writes the index. Nothing records yet, so every
//! lookup answers `None`; the implementation commit fills this in.

use super::Backend;

impl Backend {
    /// The binding of the slot that holds `principal_id`'s own catalogue on
    /// this backend, if that slot is warm. No side effects: no mint, no fill,
    /// no slot creation.
    pub(crate) fn caller_slot_binding(&self, _principal_id: &str) -> Option<String> {
        None
    }

    /// Every binding the index currently points at (test plan I2e).
    #[cfg(test)]
    pub(crate) fn indexed_bindings_for_test(&self) -> Vec<String> {
        Vec::new()
    }

    /// Mark per-user slot `binding`'s held list as a truncated drain, as a
    /// paging fill past its budget leaves it (test plan L11).
    #[cfg(test)]
    pub(crate) fn mark_per_user_truncated_for_test(&self, binding: &str) {
        let key = super::PoolKey::PerUser {
            binding: binding.to_string(),
        };
        self.pool
            .get(&key)
            .expect("a filled per-user slot")
            .tools_truncated
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The bindings of per-user slots whose catalogue has ever been stored:
    /// the census I2e holds the index against.
    #[cfg(test)]
    pub(crate) fn populated_per_user_bindings_for_test(&self) -> Vec<String> {
        self.pool
            .iter()
            .filter_map(|entry| match entry.key() {
                super::PoolKey::PerUser { binding }
                    if entry.value().tools_cache.ever_populated() =>
                {
                    Some(binding.clone())
                }
                _ => None,
            })
            .collect()
    }
}
