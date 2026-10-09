// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Taking per-user slots out of the pool: a grant revocation and the idle
//! reaper, the only two removal sites.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::super::Backend;
use super::{PoolKey, PooledEntry, now_unix_secs};
use crate::transport::Transport;

impl Backend {
    /// Drop every per-user slot whose binding starts with `binding_prefix`,
    /// and with each slot its transport and all four metadata caches
    /// (MIK-7530, `MIK-7334.CATALOGUE.1` revocation conjunct). Returns the
    /// number of slots removed.
    ///
    /// `starts_with`, never `contains`: the audience is an operator-set string
    /// and can carry another subject's complete prefix at a nonzero offset, so
    /// containment would let one caller's revocation evict another's slot (C7).
    ///
    /// REMOVAL IS UNCONDITIONAL AND IS THE ATOMIC POINT; the CLOSE is
    /// conditional. [`Backend::evict_idle_per_user_entries`] conflates the two
    /// because for the reaper they have the same answer, and copying its
    /// `in_flight == 0` predicate into the `remove_if` here would be the
    /// `Vec::is_empty` trap one rung over: every catalogue fill holds an
    /// in-flight claim for the whole duration of its fetch, so the predicate
    /// would decline during exactly the window a revocation races — and unlike
    /// the reaper, which re-sweeps every 60s, a revocation fires once.
    ///
    /// Removal alone harms nothing: an orphaned `PooledEntry` is a state
    /// `ensure_entry_started` already detects by `Arc::ptr_eq` and recovers
    /// from. A request already on the transport holds its own `Arc` and
    /// finishes — it was authorized before the revocation landed, on a
    /// connection opened before it. A fill still on the wire writes into the
    /// orphan's cache, which nobody can reach.
    ///
    /// `in_flight` is incremented under the transport READ guard
    /// (`claim_pooled_entry`), so it is re-checked here under the transport
    /// WRITE guard. Reading it before taking that guard would reintroduce a
    /// TOCTOU the reaper's atomic `remove_if` never had: with the removal now
    /// unconditional, the write guard is the only remaining mutual exclusion
    /// against a claim landing mid-eviction.
    pub fn evict_identity_slots(&self, binding_prefix: &str) -> usize {
        // First pass: collect matching keys without holding a shard guard
        // across the removals, mirroring the reaper's two-pass shape.
        let candidates: Vec<PoolKey> = self
            .pool
            .iter()
            .filter(|entry| match entry.key() {
                PoolKey::PerUser { binding } => binding.starts_with(binding_prefix),
                // Never the shared slot: it backs init, metadata and
                // single-tenant traffic, and a grant revocation is per-identity.
                PoolKey::Shared => false,
            })
            .map(|entry| entry.key().clone())
            .collect();

        let mut evicted = 0;
        for key in candidates {
            // Under `stop`'s lock: shutdown takes this slot or drains its close.
            let mut cleanups = self.replaced_transport_cleanups.lock();
            let Some((_, entry)) = self.pool.remove_if(&key, |_, entry| retire(entry)) else {
                // A concurrent reaper or eviction took it first; it is gone
                // either way, which is what this call is for.
                continue;
            };
            evicted += 1;
            self.nudge_slot_closed(&key, crate::backend::tools_nudge::SlotEvent::Revoked);

            let idle_transport = {
                let mut transport = entry.transport.write();
                if entry.in_flight.load(Ordering::SeqCst) == 0 {
                    transport.take()
                } else {
                    // Busy. Leave the transport on the orphan: ownership reaps
                    // it when the last in-flight request drops its `Arc`.
                    None
                }
            };
            if let Some(transport) = idle_transport {
                self.close_evicted(&mut cleanups, transport);
            }
        }

        if evicted > 0 {
            tracing::info!(
                backend = %self.name,
                evicted,
                live_slots = self.pool.len(),
                "Identity-keyed slot eviction removed per-user slots"
            );
        }
        evicted
    }

    /// Test-only: whether the pool currently maps `key`, WITHOUT creating it.
    ///
    /// §3.1 Rule 1: every cache accessor routes through `tools_slot` →
    /// `pooled_entry` → `or_insert_with`, so it creates the slot it then
    /// reports empty. `pooled_transport_for_test` does not create, but answers
    /// `None` for both "slot absent" and "slot present, transport unstarted".
    /// This is the one probe that distinguishes them.
    /// Test-only: empty every slot's tool catalogue, so the next R2 check
    /// on any slot is cold (F13 cells for a slot emptied between rounds).
    #[cfg(test)]
    pub(crate) fn empty_tool_catalogues_for_test(&self) {
        for entry in &self.pool {
            entry.value().tools_cache.invalidate_if(|_| true);
        }
    }

    #[cfg(test)]
    pub(crate) fn pool_has_slot_for_test(&self, key: &PoolKey) -> bool {
        self.pool.get(key).is_some()
    }

    /// Close an evicted transport off the caller's path (#2245), capped in
    /// count and counted when abandoned (#2300, `IdentitySlots::spawn_close`).
    /// `stop` drains the task with the replaced-transport cleanups.
    fn close_evicted(
        &self,
        cleanups: &mut super::super::CleanupState,
        transport: Arc<dyn Transport>,
    ) {
        let (backend, budget) = (self.name.clone(), self.budgets.close_stage);
        if let Some(handle) = self.identity_slots.spawn_close(backend, budget, transport) {
            cleanups.handles.retain(|h| !h.is_finished());
            cleanups.handles.push(handle);
        }
    }

    /// Idle-evict per-user pool slots whose last use predates `idle_ttl`,
    /// scheduling a bounded background close of their transports. The canonical
    /// [`PoolKey::Shared`] slot is never evicted. Returns the number of slots
    /// evicted, not closed: a close may still be running (MIK-6735 POOL.2).
    pub fn evict_idle_per_user_entries(&self, idle_ttl: Duration) -> usize {
        let cutoff = idle_ttl.as_secs();

        // First pass: collect candidate keys without holding a guard across the
        // removals. Skip the shared slot outright.
        let candidates: Vec<PoolKey> = self
            .pool
            .iter()
            .filter(|entry| !matches!(entry.key(), PoolKey::Shared))
            .map(|entry| entry.key().clone())
            .collect();

        let mut closed = 0;
        for key in candidates {
            // Atomically remove only if STILL idle — re-checked inside the shard
            // lock so a request that touched the slot after the first pass keeps
            // it alive and is never torn down mid-flight. Cleanup lock: as above.
            let mut cleanups = self.replaced_transport_cleanups.lock();
            let removed = self.pool.remove_if(&key, |k, entry| {
                // in_flight is checked INSIDE the shard lock, alongside the
                // timestamp. A relaxed timestamp alone is not enough: a request
                // can hold this entry and have incremented in_flight while the
                // clock still reads stale - notably while it waits on the backend
                // semaphore, where it holds the entry but has not touched it.
                // Evicting then closes the transport underneath a live request.
                let idle = !matches!(k, PoolKey::Shared)
                    && entry.in_flight.load(Ordering::SeqCst) == 0
                    && now_unix_secs().saturating_sub(entry.last_used.load(Ordering::Relaxed))
                        >= cutoff;
                idle && retire(entry)
            });
            if let Some((key, entry)) = removed {
                self.nudge_slot_closed(&key, crate::backend::tools_nudge::SlotEvent::Idle);
                let transport = entry.transport.write().take();
                if let Some(transport) = transport {
                    self.close_evicted(&mut cleanups, transport);
                }
                closed += 1;
            }
        }
        if closed > 0 {
            // MIK-6735 fix 3: gauge + log the live slot count after eviction,
            // mirroring the creation-side observability in `pooled_entry`.
            #[allow(clippy::cast_precision_loss)] // pool size is never remotely close to 2^52
            let live = self.pool.len() as f64;
            telemetry_metrics::gauge!(
                "mcp_backend_pool_slots",
                "backend" => self.name.clone()
            )
            .set(live);
            tracing::debug!(
                backend = %self.name,
                evicted = closed,
                live_slots = live,
                "Idle per-user pool slots evicted"
            );
        }
        closed
    }
}

/// Mark `entry` as no longer served, under its transport WRITE guard and while
/// the pool's shard lock still holds it (MIK-7643). Called from both removal
/// closures, so no reader ever sees an entry that has left the map but is not
/// yet retired. Always `true`, for use as a removal predicate.
fn retire(entry: &PooledEntry) -> bool {
    let _slot = entry.transport.write();
    entry.retired.store(true, Ordering::SeqCst);
    true
}
