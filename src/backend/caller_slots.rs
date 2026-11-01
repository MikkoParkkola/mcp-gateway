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
    /// a success, or any fill of the caller's own slot, replaces it. An
    /// expired lease nobody reads again stays until the caller's slot is
    /// next claimed, filled or recorded, which replaces it: at most one
    /// entry per caller principal per backend.
    ColdTried {
        until: tokio::time::Instant,
        /// Which claim this is: only its own winner may publish over it.
        generation: u64,
        /// Whether the claim's lookup or fill still runs. A settled attempt
        /// (failed, or cut short) keeps `until` as the retry backoff, but no
        /// listing waits on it: nothing will store before it ends.
        running: bool,
    },
}

/// Lease generations. One counter for the process: unique per backend too,
/// which is all the conditional publication needs (MIK-8392 d1).
static COLD_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// What a claim on a cold view decided (MIK-8392).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdClaim {
    /// This reader holds the lease, under this generation, and resolves.
    Won(u64),
    /// Another reader's lease is still running for `remaining`: answer
    /// retryable.
    Leased { remaining: std::time::Duration },
    /// The view is not cold (a live slot): nothing to claim.
    Warm,
    /// A `NoView` entry while the account is not live: it stays absent.
    NoView,
}

/// A caller's Held entry as one warm read saw it: forgotten later only if it
/// is still that same entry (MIK-8392 d1, conditional forget).
pub(crate) struct HeldEntry {
    binding: String,
    entry: Weak<PooledEntry>,
}

impl HeldEntry {
    pub(crate) fn binding(&self) -> &str {
        &self.binding
    }
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
        self.caller_slot_stored.notify_waiters();
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

    /// `principal_id`'s live Held entry, captured for a later conditional
    /// forget.
    pub(crate) fn caller_slot_held(&self, principal_id: &str) -> Option<HeldEntry> {
        let slot = self.caller_slots.get(principal_id)?;
        let binding = slot.live_binding()?.to_owned();
        let CallerSlot::Held { entry, .. } = &*slot else {
            return None;
        };
        Some(HeldEntry {
            binding,
            entry: entry.clone(),
        })
    }

    /// Forget `principal_id`'s entry only while it is still `seen` (same
    /// binding, same slot): a lease or a fresher fill that replaced it stays
    /// (MIK-8392 d1, muse F4).
    pub(crate) fn forget_caller_held(&self, principal_id: &str, seen: &HeldEntry) {
        self.caller_slots.remove_if(principal_id, |_, slot| {
            matches!(slot, CallerSlot::Held { binding, entry }
                if *binding == seen.binding && Weak::ptr_eq(entry, &seen.entry))
        });
    }

    /// Publish a cold view's winner: `principal_id`'s entry becomes `Held` on
    /// `binding` only while it is still this winner's own lease (MIK-8392 d1,
    /// muse F6). A fill or a newer claim that landed meanwhile stands, and
    /// this result is dropped. A slot that is gone or never filled is not
    /// published, as [`Self::record_caller_slot`].
    pub(crate) fn publish_cold_view(&self, principal_id: &str, generation: u64, binding: &str) {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        let Some(entry) = self.pool.get(&key).map(|slot| Arc::clone(slot.value())) else {
            return;
        };
        if !entry.tools_cache.ever_populated() {
            return;
        }
        if let Some(mut slot) = self.caller_slots.get_mut(principal_id)
            && matches!(*slot, CallerSlot::ColdTried { generation: own, .. } if own == generation)
        {
            *slot = CallerSlot::Held {
                binding: binding.to_string(),
                entry: Arc::downgrade(&entry),
            };
            drop(slot);
            self.caller_slot_stored.notify_waiters();
        }
    }

    /// Extend `principal_id`'s lease of claim `generation` to `bound` from
    /// now, as its fill starts: the claim's lease covered the credential
    /// lookup, this covers the fill, so a slow lookup cannot leave the fill
    /// publishing over a lease already gone. Only the claim's own lease, and
    /// never shortened.
    pub(crate) fn extend_cold_lease(
        &self,
        principal_id: &str,
        generation: u64,
        bound: std::time::Duration,
    ) {
        if let Some(mut slot) = self.caller_slots.get_mut(principal_id)
            && let CallerSlot::ColdTried {
                until,
                generation: own,
                ..
            } = &mut *slot
            && *own == generation
        {
            *until = (*until).max(tokio::time::Instant::now() + bound);
        }
    }

    /// Settle `principal_id`'s claim `generation` as it ends without a
    /// publish: its lease stays as the retry backoff, and the listings
    /// waiting on it are woken. Only the claim's own lease: a newer claim, or
    /// a view stored meanwhile, is left as it is.
    pub(crate) fn settle_cold_attempt(&self, principal_id: &str, generation: u64) {
        if let Some(mut slot) = self.caller_slots.get_mut(principal_id)
            && let CallerSlot::ColdTried {
                generation: own,
                running,
                ..
            } = &mut *slot
            && *own == generation
            && *running
        {
            *running = false;
            drop(slot);
            self.caller_slot_stored.notify_waiters();
        }
    }

    /// Drop `principal_id`'s claim `generation` outright, as its fill ends
    /// with a result the grant has moved past: no retry backoff stands, so
    /// the next reader claims afresh under the current grant, and the
    /// listings waiting on it are woken. Only the claim's own lease.
    pub(crate) fn release_cold_attempt(&self, principal_id: &str, generation: u64) {
        let removed = self.caller_slots.remove_if(principal_id, |_, slot| {
            matches!(slot, CallerSlot::ColdTried { generation: own, .. } if *own == generation)
        });
        if removed.is_some() {
            self.caller_slot_stored.notify_waiters();
        }
    }

    /// Wait while `principal_id`'s cold lease has a lookup or fill running:
    /// until its winner (or any fill of the caller's own slot) stores, the
    /// attempt settles, or the lease ends.
    pub(crate) async fn wait_cold_lease(&self, principal_id: &str) {
        loop {
            let stored = self.caller_slot_stored.notified();
            tokio::pin!(stored);
            // Registered before the check, so a store or a settle between the
            // check and the wait still wakes it.
            stored.as_mut().enable();
            let Some(remaining) = self.cold_fill_remaining(principal_id) else {
                return;
            };
            let _ = tokio::time::timeout(remaining, stored).await;
        }
    }

    /// How long `principal_id`'s cold lease still has, if one stands: the
    /// retry backoff, whether or not its attempt still runs.
    pub(crate) fn cold_lease_remaining(&self, principal_id: &str) -> Option<std::time::Duration> {
        let now = tokio::time::Instant::now();
        match *self.caller_slots.get(principal_id)? {
            CallerSlot::ColdTried { until, .. } if now < until => Some(until - now),
            _ => None,
        }
    }

    /// How long `principal_id`'s cold lease still has while its lookup or
    /// fill runs: what a listing may wait on. A settled attempt has nothing
    /// left to store.
    pub(crate) fn cold_fill_remaining(&self, principal_id: &str) -> Option<std::time::Duration> {
        let now = tokio::time::Instant::now();
        match *self.caller_slots.get(principal_id)? {
            CallerSlot::ColdTried {
                until,
                running: true,
                ..
            } if now < until => Some(until - now),
            _ => None,
        }
    }

    /// Claim the attempt to re-establish `principal_id`'s cold view, under
    /// one shard guard (MIK-8392 B', muse F7): the expiry is checked inside
    /// the same entry, and nothing awaits while it is held. Claimable: no
    /// entry, a dead or retired slot's entry, an expired lease, and a
    /// `NoView` entry only when `account_live` (the grant came back, d1).
    pub(crate) fn claim_cold_view(
        &self,
        principal_id: &str,
        lease: std::time::Duration,
        account_live: bool,
    ) -> ColdClaim {
        let now = tokio::time::Instant::now();
        let generation = COLD_GENERATION.fetch_add(1, Ordering::SeqCst);
        let fresh = CallerSlot::ColdTried {
            until: now + lease,
            generation,
            running: true,
        };
        match self.caller_slots.entry(principal_id.to_string()) {
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(fresh);
                ColdClaim::Won(generation)
            }
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let decision = match occupied.get() {
                    held @ CallerSlot::Held { .. } if held.live_binding().is_some() => {
                        ColdClaim::Warm
                    }
                    CallerSlot::ColdTried { until, .. } if now < *until => ColdClaim::Leased {
                        remaining: *until - now,
                    },
                    CallerSlot::NoView if !account_live => ColdClaim::NoView,
                    _ => ColdClaim::Won(generation),
                };
                if decision == ColdClaim::Won(generation) {
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

    /// Remove and retire per-user slot `binding` while its index entry
    /// stays, as a removal racing an index write leaves it: the entry is
    /// Held on a retired slot (MIK-8392 L3).
    #[cfg(test)]
    pub(crate) fn retire_per_user_slot_for_test(&self, binding: &str) {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        let (_, entry) = self.pool.remove(&key).expect("a pooled per-user slot");
        entry.retired.store(true, Ordering::SeqCst);
    }

    /// Remove per-user slot `binding`'s pooled entry WITHOUT retiring it or
    /// touching the index, handing the entry back so the caller holds it
    /// (MIK-8392 F3): the index entry stays live (its `Weak` still
    /// upgrades, unretired) while a pool lookup by binding finds nothing,
    /// as a slot evicted between the listing view and the catalogue read
    /// leaves it. The caller must hold the returned entry for the index to
    /// keep reading as held.
    #[cfg(test)]
    pub(crate) fn unpool_per_user_slot_for_test(&self, binding: &str) -> Option<Arc<PooledEntry>> {
        let key = PoolKey::PerUser {
            binding: binding.to_string(),
        };
        self.pool.remove(&key).map(|(_, entry)| entry)
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
