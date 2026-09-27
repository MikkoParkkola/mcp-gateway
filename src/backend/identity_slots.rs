// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-backend cap on identity slots (MIK-7547).
//!
//! Every identified caller of a propagating backend gets its own `PerUser`
//! pool slot, and on a stdio backend its own child process. Without a cap, N
//! identities in a burst means N transports until idle eviction reclaims them.
//! The cap refuses a new identity instead; it never falls back to the shared
//! slot, which would serve one caller with another's session (#727).
//!
//! The count follows live slots, not map entries: a reservation is a
//! [`SlotLease`] stored inside the `PooledEntry` it admitted, and dropping the
//! entry drops the lease. Every removal path (idle eviction, identity
//! revocation, a reload dropping the whole pool) is covered that way, and an
//! evicted entry still held by an in-flight request keeps its slot until the
//! request ends, which is the resource the cap bounds.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::Backend;
use crate::identity_propagation::DEFAULT_MAX_IDENTITY_SLOTS;
use crate::{Error, Result};

/// The live `PerUser` slot count of one backend.
#[derive(Debug, Default)]
pub(crate) struct IdentitySlots {
    used: AtomicUsize,
    /// Test-only: parks each reservation between reading the count and
    /// claiming it, so a test can force two reservations to race for the
    /// last slot.
    #[cfg(test)]
    pub(super) reserve_barrier: std::sync::Mutex<Option<Arc<std::sync::Barrier>>>,
}

/// One reserved identity slot. Dropping it frees the slot.
#[derive(Debug)]
pub(crate) struct SlotLease(Arc<IdentitySlots>);

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Backend {
    /// The configured `identity_propagation.max_identity_slots`.
    fn identity_slot_cap(&self) -> usize {
        self.config
            .identity_propagation
            .as_ref()
            .map_or(DEFAULT_MAX_IDENTITY_SLOTS, |c| c.max_identity_slots)
    }

    /// Reserve one identity slot, or refuse at the cap.
    ///
    /// A compare-and-swap loop rather than a load and a store: two identities
    /// racing for the last slot both read `cap - 1`, and only one may win.
    /// Runs under the pool's shard guard, so it never awaits.
    pub(super) fn reserve_identity_slot(&self) -> Result<SlotLease> {
        let cap = self.identity_slot_cap();
        let slots = &self.identity_slots;
        let mut used = slots.used.load(Ordering::SeqCst);
        #[cfg(test)]
        {
            let barrier = slots.reserve_barrier.lock().expect("barrier lock").clone();
            if let Some(barrier) = barrier {
                barrier.wait();
            }
        }
        loop {
            if used >= cap {
                telemetry_metrics::counter!(
                    "identity_slots_refused_total",
                    "backend" => self.name.clone()
                )
                .increment(1);
                return Err(Error::IdentitySlotsExhausted {
                    backend: self.name.clone(),
                    cap,
                });
            }
            match slots
                .used
                .compare_exchange(used, used + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(SlotLease(Arc::clone(slots))),
                Err(now) => used = now,
            }
        }
    }

    /// Test-only: the live identity-slot count.
    #[cfg(test)]
    pub(crate) fn identity_slots_in_use_for_test(&self) -> usize {
        self.identity_slots.used.load(Ordering::SeqCst)
    }

    /// Test-only: a handle on the counter that outlives this `Backend`, so a
    /// reload test can watch the old backend's slots drain.
    #[cfg(test)]
    pub(crate) fn identity_slots_handle_for_test(&self) -> Arc<IdentitySlots> {
        Arc::clone(&self.identity_slots)
    }
}

#[cfg(test)]
impl IdentitySlots {
    pub(crate) fn in_use(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
}
