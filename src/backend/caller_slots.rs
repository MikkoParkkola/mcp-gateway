// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which pool slot a caller's own catalogue lives in (MIK-8356, design R3.5).
//!
//! A caller's binding is born where its credential is resolved, which may
//! mint. A name-only reader is synchronous and must never mint, so it cannot
//! re-derive the binding; it reads it here instead. An entry is written when
//! a fill has stored the caller's catalogue into its slot, and removed with
//! that slot (`retire`, both pool-eviction paths). Reads also check the slot
//! is still the live one, so a removal that loses a race to a late write can
//! never point a caller at a retired slot or at another caller's.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use super::Backend;
use super::pool::{PoolKey, PooledEntry};

/// One caller's index entry on this backend.
#[derive(Debug)]
pub(crate) enum CallerSlot {
    /// The caller's own catalogue is stored in this per-user slot.
    Held {
        binding: String,
        entry: Weak<PooledEntry>,
    },
    /// The caller has no view of this backend (a managed account with no
    /// current grant), as the last listing entry's check found it. Written
    /// only from `MetaMcp::has_no_view_for` (MIK-8356, design R3.7).
    NoView,
    /// A stored read claimed the attempt to re-establish this caller's cold
    /// view (MIK-8392 B'): a lease, so one reader resolves per window. A
    /// failed or abandoned attempt only delays the next one until `until`;
    /// a success, or any fill of the caller's own slot, replaces it.
    ColdTried { until: tokio::time::Instant },
}

/// What a claim on a cold view decided (MIK-8392).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdClaim {
    /// This reader holds the lease and resolves.
    Won,
    /// Another reader's lease is still running: answer retryable.
    Leased,
    /// The view is not cold (a live slot): nothing to claim.
    Warm,
}

impl CallerSlot {
    /// The binding, while its slot is still the live, unretired one.
    fn live_binding(&self) -> Option<&str> {
        let CallerSlot::Held { binding, entry } = self else {
            return None;
        };
        let entry = entry.upgrade()?;
        (!entry.retired.load(Ordering::SeqCst)).then_some(binding.as_str())
    }
}

impl Backend {
    /// Record that `principal_id`'s own catalogue is the one stored in per-user
    /// slot `binding`. A slot that is gone or never filled is not recorded, so
    /// a refused admission or a failed fill leaves no entry. A slot retired
    /// after the lookup may still be recorded: every read re-checks
    /// `retired` ([`CallerSlot::live_binding`]), so such an entry reads as
    /// absent, and its only effect is to withhold until the next fill.
    pub(crate) fn record_caller_slot(&self, principal_id: &str, binding: &str) {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        let Some(entry) = self.pool.get(&key).map(|slot| Arc::clone(slot.value())) else {
            return;
        };
        if !entry.tools_cache.ever_populated() {
            return;
        }
        self.caller_slots.insert(
            principal_id.to_string(),
            CallerSlot::Held {
                binding: binding.to_string(),
                entry: Arc::downgrade(&entry),
            },
        );
    }

    /// Record that `principal_id` has no view of this backend. Replaced by
    /// the next fill of its own slot, or cleared when a later check finds a
    /// view again.
    pub(crate) fn record_no_view(&self, principal_id: &str) {
        self.caller_slots
            .insert(principal_id.to_string(), CallerSlot::NoView);
    }

    /// Whether the index records that `principal_id` has no view here.
    pub(crate) fn caller_has_no_view(&self, principal_id: &str) -> bool {
        self.caller_slots
            .get(principal_id)
            .is_some_and(|slot| matches!(*slot, CallerSlot::NoView))
    }

    /// Whether `binding`'s slot holds a listed catalogue, an empty one
    /// included: what a caller's listing on that slot can vouch for.
    pub(crate) fn holds_tools_for(&self, binding: Option<&str>) -> bool {
        self.held_tools_for(binding).is_some()
    }

    /// The binding of the slot that holds `principal_id`'s own catalogue on
    /// this backend, if that slot is still live. No side effects: no mint, no
    /// fill, no slot creation.
    pub(crate) fn caller_slot_binding(&self, principal_id: &str) -> Option<String> {
        self.caller_slots
            .get(principal_id)
            .and_then(|slot| slot.live_binding().map(str::to_owned))
    }

    /// Forget `principal_id`'s entry: its current grant no longer yields the
    /// indexed binding (a rotated or revoked managed grant).
    pub(crate) fn forget_caller_principal(&self, principal_id: &str) {
        self.caller_slots.remove(principal_id);
    }

    /// Forget every entry pointing at `evicted`, which has just left the pool.
    /// Compared by identity, never by binding: a replacement slot readmitted
    /// under the same binding keeps its entry (gpt r3 F8).
    pub(super) fn forget_caller_slot(&self, evicted: &Arc<PooledEntry>) {
        self.caller_slots.retain(|_, slot| match slot {
            CallerSlot::Held { entry, .. } => !std::ptr::eq(entry.as_ptr(), Arc::as_ptr(evicted)),
            CallerSlot::NoView | CallerSlot::ColdTried { .. } => true,
        });
    }

    /// Claim the attempt to re-establish `principal_id`'s cold view, under
    /// one shard guard (MIK-8392 B', muse F7): the expiry is checked inside
    /// the same entry, and nothing awaits while it is held. A dead or retired
    /// slot's entry, a `NoView` entry (the caller checked the grant is live
    /// again) and an expired lease are claimable.
    pub(crate) fn claim_cold_view(
        &self,
        principal_id: &str,
        lease: std::time::Duration,
    ) -> ColdClaim {
        let now = tokio::time::Instant::now();
        let fresh = CallerSlot::ColdTried { until: now + lease };
        match self.caller_slots.entry(principal_id.to_string()) {
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(fresh);
                ColdClaim::Won
            }
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let decision = match occupied.get() {
                    held @ CallerSlot::Held { .. } if held.live_binding().is_some() => {
                        ColdClaim::Warm
                    }
                    CallerSlot::ColdTried { until } if now < *until => ColdClaim::Leased,
                    _ => ColdClaim::Won,
                };
                if decision == ColdClaim::Won {
                    occupied.insert(fresh);
                }
                decision
            }
        }
    }

    /// Mark the live slot `binding` used now, so a caller reading its stored
    /// results keeps it from idle eviction (MIK-8392 touch-on-read). No mint,
    /// no fill; a slot that is gone is left alone.
    pub(crate) fn touch_caller_slot(&self, binding: &str) {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        if let Some(entry) = self.pool.get(&key) {
            entry.value().touch();
        }
    }

    /// Every binding the index currently points at (test plan I2e).
    #[cfg(test)]
    pub(crate) fn indexed_bindings_for_test(&self) -> Vec<String> {
        self.caller_slots
            .iter()
            .filter_map(|slot| slot.live_binding().map(str::to_owned))
            .collect()
    }

    /// Mark per-user slot `binding`'s held list as a truncated drain, as a
    /// paging fill past its budget leaves it (test plan L11).
    #[cfg(test)]
    pub(crate) fn mark_per_user_truncated_for_test(&self, binding: &str) {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        self.pool
            .get(&key)
            .expect("a filled per-user slot")
            .tools_truncated
            .store(true, Ordering::SeqCst);
    }

    /// The bindings of per-user slots whose catalogue has ever been stored:
    /// the census I2e holds the index against.
    #[cfg(test)]
    pub(crate) fn populated_per_user_bindings_for_test(&self) -> Vec<String> {
        self.pool
            .iter()
            .filter_map(|entry| match entry.key() {
                PoolKey::PerUser { binding } if entry.value().tools_cache.ever_populated() => {
                    Some(binding.clone())
                }
                _ => None,
            })
            .collect()
    }
}
