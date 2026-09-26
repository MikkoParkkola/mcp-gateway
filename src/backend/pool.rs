// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-identity transport/session pool (MIK-6735): [`PoolKey`], [`PooledEntry`],
//! and the [`super::Backend`] methods that create, look up, and idle-evict
//! pool slots.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::Mutex;

use super::Backend;
use super::cached_metadata::CachedMetadata;
use crate::failsafe::Failsafe;
use crate::transport::Transport;

/// Seconds since the Unix epoch, saturating to 0 on a pre-epoch clock.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Identifies one transport/session slot in a backend's connection pool
/// (MIK-6735).
///
/// A backend always owns the canonical [`PoolKey::Shared`] slot — the
/// single-tenant default that also backs init, metadata, and canonical traffic.
/// When `identity_propagation` is configured (either `session_mode`) and a
/// caller identity is present, the backend additionally owns one
/// [`PoolKey::PerUser`] slot per stable identity binding, so two distinct users
/// never share a backend transport or its upstream MCP session (IDP.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PoolKey {
    /// The canonical single-tenant slot. Every backend without identity
    /// propagation, and every propagating request that lacks a resolved
    /// identity, collapses here so single-tenant behavior is preserved
    /// byte-for-byte (IDP.5).
    Shared,
    /// A per-user slot keyed by the caller's stable identity binding
    /// (`PropagatedCredential::cache_binding`, MIK-6784).
    PerUser { binding: String },
}

/// One pooled transport slot: its lazily started transport, a start lock that
/// serializes connection setup for that slot, a last-used clock driving idle
/// eviction of per-user slots, and this slot's own failsafe mechanisms.
///
/// The failsafe (circuit breaker + rate limiter + retry policy + health
/// tracker) is owned per-slot, not per-backend (MIK-6735 fix 1, adversarial
/// review of commit bfd62b91). Gating `request_with_headers` on a single
/// backend-wide `Failsafe` meant one caller identity's transport failing
/// enough tripped the breaker for every OTHER identity sharing the same
/// backend too — the exact cross-tenant blast radius the per-user pool
/// exists to eliminate. Each slot now fails independently: the Shared slot
/// keeps its own failsafe (behavior for backends without identity
/// propagation is byte-for-byte unchanged), and each `PerUser` slot gets a fresh one the moment it is
/// first created.
pub(crate) struct PooledEntry {
    pub(crate) transport: RwLock<Option<Arc<dyn Transport>>>,
    pub(crate) start_lock: Mutex<()>,
    pub(crate) last_used: AtomicU64,
    /// Set when the reaper stopped this slot for idleness, cleared when it is
    /// started again.
    ///
    /// Dormant must be a recorded fact, not an inference. Inferring it from
    /// "opted in, no transport, breaker closed" misreports a backend whose FIRST
    /// start failed: nothing has updated the failsafe yet, so it still looks
    /// healthy, and a backend that never came up would be shown as sleeping.
    pub(crate) stopped_when_idle: std::sync::atomic::AtomicBool,
    /// Client requests currently executing against this slot.
    ///
    /// `last_used` records when a request STARTED, so it cannot answer "is work
    /// happening right now". Without this counter a call outliving the idle
    /// deadline has its transport closed mid-flight.
    pub(crate) in_flight: AtomicUsize,
    pub(crate) failsafe: Failsafe,
    /// The four metadata caches, and the set derived from the first of them.
    ///
    /// CO-LOCATED WITH THE SLOT, NOT THE BACKEND (MIK-7334.CATALOGUE.1). A
    /// backend-wide cache means one identity's catalogue is served to every
    /// other identity sharing that backend — the same cross-tenant blast radius
    /// the per-slot `failsafe` above was moved here to eliminate (MIK-6735 fix
    /// 1), one rung further in. Because the cache and the transport now live
    /// behind the same `Arc<PooledEntry>`, the bytes in slot K's cache were
    /// fetched over slot K's transport, and no expression pairs one slot's cache
    /// with another slot's transport.
    pub(crate) tools_cache: CachedMetadata<Vec<crate::protocol::Tool>>,
    /// Tools this slot's upstream declared resend-safe, as of its last
    /// `tools/list`.
    ///
    /// DERIVED FROM `tools_cache`, SO IT LIVES WHERE `tools_cache` LIVES. Left
    /// on `Backend` it would be a set coarser than its own source: one
    /// identity's catalogue fill would decide another identity's retry policy,
    /// and membership is the only thing that grants a `tools/call` permission to
    /// be resent (ADR-012 A1). Absent means deny, so an unfilled slot denies
    /// every resend, which is the safe direction.
    pub(crate) resend_permitted: RwLock<std::collections::HashSet<String>>,
    /// Set when the last tools-cache drain (MIK 7570 PAGING.1) stopped before
    /// the upstream catalogue was exhausted (page cap, repeated cursor, or the
    /// fill budget). Cleared by the next fill that drains to completion.
    /// Tools only — the other three families keep their pages either way.
    pub(crate) tools_truncated: AtomicBool,
    /// When this slot's last tools fill ended without storing (F13): a drain,
    /// parse or start error, a `CallTimeout` expiry, or a voided store. Fills
    /// within `LIST_FILL_COOLDOWN` of it fail fast. Tokio's `Instant`, so a
    /// paused test clock advances it with the timeouts. Tools only.
    pub(crate) tools_fill_failed_at: parking_lot::Mutex<Option<tokio::time::Instant>>,
    pub(crate) resources_cache: CachedMetadata<Vec<crate::protocol::Resource>>,
    pub(crate) resource_templates_cache: CachedMetadata<Vec<crate::protocol::ResourceTemplate>>,
    pub(crate) prompts_cache: CachedMetadata<Vec<crate::protocol::Prompt>>,
}

/// RAII marker for one in-flight client request against a pool slot.
///
/// Construction is the single place that writes the idle clock. `last_used`
/// means "when did a CLIENT last use this backend", deliberately excluding
/// internal health probes and metadata refreshes — an earlier attempt let
/// `ensure_entry_started` touch it, and the 10s default health interval then
/// refreshed it forever against a 300s deadline, so the feature was a silent
/// no-op.
///
/// Ordering, and it took two rejected reviews to get this right: the count is
/// claimed while holding the transport READ guard, and [`Backend::stop_if_idle`]
/// checks it while holding the transport WRITE guard. The `RwLock` — not the
/// atomic — is what makes the two mutually exclusive. `SeqCst` on its own cannot
/// help here, because it does not make the reaper's earlier read conditional on
/// a claim that happens later; the reaper would pass its check and close the
/// transport anyway.
///
/// So exactly one of two things happens. Either the claim lands first, the
/// reaper sees a non-zero count and declines; or the reaper takes the transport
/// AND records `stopped_when_idle` under the same write guard, so a claim
/// arriving afterwards observes a slot that is unambiguously stopped rather than
/// one that merely looks unstarted.
pub(crate) struct ActivityGuard {
    entry: Arc<PooledEntry>,
    /// Whether dropping this guard counts as client activity. False for internal
    /// leases, which protect the transport without deferring the idle deadline.
    touch_on_drop: bool,
}

impl ActivityGuard {
    /// Adopt a slot whose `in_flight` count has ALREADY been claimed by
    /// [`Backend::claim_pooled_entry`].
    ///
    /// Claiming and adopting are separate on purpose. The claim has to happen
    /// while the pool's shard guard and the transport read guard are both held,
    /// which only the pool can arrange; this constructor merely takes ownership
    /// of the resulting count so `Drop` releases it exactly once. Incrementing
    /// here instead would double-count, and incrementing after the guards were
    /// released is the bug this whole split exists to remove.
    fn adopt_claimed(entry: Arc<PooledEntry>, touch_on_drop: bool) -> Self {
        Self {
            entry,
            touch_on_drop,
        }
    }

    /// The slot this lease holds.
    ///
    /// The metadata path reads its cache through this rather than looking the
    /// slot up a second time, so the cache it fills and the transport it is
    /// holding open are the same object by construction rather than by two
    /// lookups agreeing (MIK-7334.CATALOGUE.1 §3.1).
    pub(super) fn entry(&self) -> &Arc<PooledEntry> {
        &self.entry
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        // Touch on the way out too: a long CLIENT request should leave the slot
        // looking used as of its COMPLETION, not its start. Internal leases skip
        // this so they never defer the idle deadline.
        if self.touch_on_drop {
            self.entry.touch();
        }
        self.entry.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl PooledEntry {
    pub(crate) fn new(name: &str, failsafe_config: &crate::config::FailsafeConfig) -> Self {
        Self {
            transport: RwLock::new(None),
            start_lock: Mutex::new(()),
            last_used: AtomicU64::new(now_unix_secs()),
            stopped_when_idle: std::sync::atomic::AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            failsafe: Failsafe::new(name, failsafe_config),
            tools_cache: CachedMetadata::new(),
            resend_permitted: RwLock::default(),
            tools_truncated: AtomicBool::new(false),
            tools_fill_failed_at: parking_lot::Mutex::new(None),
            resources_cache: CachedMetadata::new(),
            resource_templates_cache: CachedMetadata::new(),
            prompts_cache: CachedMetadata::new(),
        }
    }

    /// Mark this slot as used now, deferring its idle eviction.
    pub(crate) fn touch(&self) {
        self.last_used.store(now_unix_secs(), Ordering::Relaxed);
    }
}

impl Backend {
    /// The backend's configured session mode, if identity propagation is set.
    pub(super) fn session_mode(&self) -> Option<crate::identity_propagation::SessionMode> {
        self.config
            .identity_propagation
            .as_ref()
            .map(|c| c.session_mode)
    }

    /// Derive the pool slot for a request carrying `identity_key`.
    ///
    /// A backend configured for identity propagation gets a private slot for
    /// every caller that resolved a concrete binding, whatever its
    /// `session_mode`. Everything else — no identity propagation at all, or a
    /// propagating backend whose caller resolved no identity — collapses to the
    /// shared canonical slot, preserving single-tenant behavior byte-for-byte
    /// (IDP.5, which ADR-007 scopes to ABSENT propagation config).
    ///
    /// THE TWO IDENTITY-PROPAGATING ARMS ARE ONE ARM ON PURPOSE
    /// (MIK-7334.CATALOGUE.1). `stateless` used to collapse here, so a caller
    /// who had minted a credential still read the entry every caller reads and
    /// `get_cached_list_for` dropped the minted headers on the way — the
    /// catalogue was fetched under the gateway's own account and answered to
    /// everybody. `stateless` is a permission to share one transport, not a
    /// statement that the catalogue does not vary by caller (ADR-007 §84-93),
    /// and declining a permitted share is wasteful rather than unsafe. Matching
    /// on `Some(_)` also means no session mode added later can collapse here by
    /// omission; what the arm must never lose is the `Some(binding)`, because a
    /// mode without a caller would mint a slot named after nobody.
    pub(super) fn pool_key_for(&self, identity_key: Option<&str>) -> PoolKey {
        match (self.session_mode(), identity_key) {
            (Some(_), Some(binding)) => PoolKey::PerUser {
                binding: binding.to_string(),
            },
            _ => PoolKey::Shared,
        }
    }

    /// Whether a metadata fetch made for `binding` will actually carry that
    /// caller's minted credential upstream.
    ///
    /// THE ISOLATION VERDICT'S ONLY HONEST INPUT (MIK-7544). `get_cached_list_for`
    /// drops the minted headers on every slot but `PerUser`, because one shared
    /// entry answers every caller. A guard that asks "did the caller resolve a
    /// credential?" therefore admits a `stateless` backend whose fetch then runs
    /// under the gateway's own login — the gateway-account-to-every-caller leak.
    /// Asking the slot instead makes verdict and fetch one derivation, exactly as
    /// the fill's `identity_key` already is.
    ///
    /// A predicate rather than a widened `pool_key_for`: the question a gate has
    /// is a boolean, and `PoolKey` matching stays inside `crate::backend`.
    pub(crate) fn fetch_carries_caller_identity(&self, binding: Option<&str>) -> bool {
        matches!(self.pool_key_for(binding), PoolKey::PerUser { .. })
    }

    /// Fetch (or lazily create) the pooled entry for `key`, running `under_guard`
    /// before the `DashMap` shard guard is released.
    ///
    /// The callback is the entire point of this shape. Cloning the `Arc` out and
    /// *then* acting on it leaves a window in which
    /// [`Backend::evict_idle_per_user_entries`] can remove and close the slot:
    /// the caller ends up holding an orphan, and the evictor closes a transport
    /// out from under a live request. Re-checking `in_flight` inside `remove_if`
    /// does not fix that — the claim has to be inside the same guard that handed
    /// out the `Arc`, or the two are simply not ordered. Anything that must be
    /// atomic with respect to removal belongs in `under_guard`.
    ///
    /// Telemetry stays OUTSIDE the guard: `self.pool.len()` walks every shard, so
    /// calling it while holding one is asking for trouble.
    ///
    /// Logs + gauges the live slot count on creation only (MIK-6735 fix 3) —
    /// minimal observability into per-user pool growth without a per-request
    /// cost on the (overwhelmingly more common) cache-hit path.
    fn pooled_entry_with<R>(
        &self,
        key: &PoolKey,
        under_guard: impl FnOnce(&Arc<PooledEntry>) -> R,
    ) -> (Arc<PooledEntry>, R) {
        let mut created = false;
        let (entry, out) = {
            let slot = self.pool.entry(key.clone()).or_insert_with(|| {
                created = true;
                Arc::new(PooledEntry::new(&self.name, &self.failsafe_config))
            });
            let entry = Arc::clone(slot.value());
            let out = under_guard(&entry);
            (entry, out)
        };
        if created {
            #[allow(clippy::cast_precision_loss)] // pool size is never remotely close to 2^52
            let live = self.pool.len() as f64;
            telemetry_metrics::gauge!(
                "mcp_backend_pool_slots",
                "backend" => self.name.clone()
            )
            .set(live);
            tracing::debug!(backend = %self.name, ?key, live_slots = live, "Pool slot created");
        }
        (entry, out)
    }

    /// Fetch (or lazily create) the pooled entry for `key`. The `Arc` is cloned
    /// out so the `DashMap` shard guard is released before any `.await`.
    ///
    /// Callers that intend to USE the slot's transport want
    /// [`Backend::claim_pooled_entry`] instead: this one hands back an entry the
    /// evictor is still free to remove.
    pub(super) fn pooled_entry(&self, key: &PoolKey) -> Arc<PooledEntry> {
        self.pooled_entry_with(key, |_| ()).0
    }

    /// Fetch (or lazily create) the entry for `key` AND claim one in-flight slot
    /// on it, without releasing the shard guard in between.
    ///
    /// Two locks are held for the claim, each excluding a different teardown
    /// path, and both are necessary:
    ///
    /// - the shard guard excludes `evict_idle_per_user_entries`, whose
    ///   `remove_if` predicate reads `in_flight` under that same guard;
    /// - the transport read guard excludes [`Backend::stop_if_idle`], which
    ///   checks `in_flight` under the transport write guard.
    ///
    /// Lock order is shard → transport, matching every other nesting in this
    /// module (`shared_transport`, `stop_all`), so no cycle exists. The read
    /// guard is scoped to the claim itself and never survives to an `.await`.
    fn claim_pooled_entry(&self, key: &PoolKey) -> Arc<PooledEntry> {
        self.pooled_entry_with(key, |entry| {
            let _transport = entry.transport.read();
            entry.in_flight.fetch_add(1, Ordering::SeqCst);
        })
        .0
    }

    /// The canonical shared slot's `PooledEntry`. Inserted at construction and
    /// never evicted (`evict_idle_per_user_entries` explicitly skips it), so
    /// this is always present — used by status/metrics/health-loop accessors
    /// that intentionally report the backend-wide, single-tenant view
    /// regardless of how many per-user slots exist (MIK-6735 fix 1).
    pub(super) fn shared_entry(&self) -> Arc<PooledEntry> {
        Arc::clone(
            self.pool
                .get(&PoolKey::Shared)
                .expect("PoolKey::Shared is inserted at construction and never evicted")
                .value(),
        )
    }

    /// Clone the canonical shared slot's live transport, if started.
    pub(super) fn shared_transport(&self) -> Option<Arc<dyn Transport>> {
        self.pool
            .get(&PoolKey::Shared)
            .and_then(|entry| entry.value().transport.read().clone())
    }

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
    pub async fn evict_identity_slots(&self, binding_prefix: &str) -> usize {
        // First pass: collect matching keys without holding a shard guard
        // across the async close(), mirroring the reaper's two-pass shape.
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
            let Some((_, entry)) = self.pool.remove(&key) else {
                // A concurrent reaper or eviction took it first; it is gone
                // either way, which is what this call is for.
                continue;
            };
            evicted += 1;

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
                let _ = transport.close().await;
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
    #[cfg(test)]
    pub(crate) fn pool_has_slot_for_test(&self, key: &PoolKey) -> bool {
        self.pool.get(key).is_some()
    }

    /// Idle-evict per-user pool slots whose last use predates `idle_ttl`,
    /// closing their transports. The canonical [`PoolKey::Shared`] slot is never
    /// evicted (it backs init, metadata, and single-tenant traffic). Returns the
    /// number of slots closed (MIK-6735 POOL.2).
    pub async fn evict_idle_per_user_entries(&self, idle_ttl: Duration) -> usize {
        let cutoff = idle_ttl.as_secs();

        // First pass: collect candidate keys without holding a guard across the
        // async close(). Skip the shared slot outright.
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
            // it alive and is never torn down mid-flight.
            let removed = self.pool.remove_if(&key, |k, entry| {
                // in_flight is checked INSIDE the shard lock, alongside the
                // timestamp. A relaxed timestamp alone is not enough: a request
                // can hold this entry and have incremented in_flight while the
                // clock still reads stale - notably while it waits on the backend
                // semaphore, where it holds the entry but has not touched it.
                // Evicting then closes the transport underneath a live request.
                !matches!(k, PoolKey::Shared)
                    && entry.in_flight.load(Ordering::SeqCst) == 0
                    && now_unix_secs().saturating_sub(entry.last_used.load(Ordering::Relaxed))
                        >= cutoff
            });
            if let Some((_, entry)) = removed {
                let transport = entry.transport.write().take();
                if let Some(transport) = transport {
                    let _ = transport.close().await;
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

    #[cfg(test)]
    pub(crate) fn set_transport_for_test(&self, transport: Arc<dyn Transport>) {
        let entry = self.pooled_entry(&PoolKey::Shared);
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: inject a transport into a specific pool slot so isolation
    /// tests can seed distinct per-user sessions (MIK-6735 POOL.4).
    #[cfg(test)]
    pub(crate) fn set_pooled_transport_for_test(
        &self,
        key: &PoolKey,
        transport: Arc<dyn Transport>,
    ) {
        let entry = self.pooled_entry(key);
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: clone the transport `Arc` stored in a specific pool slot, so
    /// isolation tests can assert distinct instances via `Arc::ptr_eq`.
    #[cfg(test)]
    pub(crate) fn pooled_transport_for_test(&self, key: &PoolKey) -> Option<Arc<dyn Transport>> {
        self.pool
            .get(key)
            .and_then(|entry| entry.value().transport.read().clone())
    }

    /// Test-only: the consecutive and lifetime unserved probe counts, which
    /// rows 10 to 11b assert are two different values with two different reset
    /// rules.
    #[cfg(test)]
    pub(crate) fn unserved_counts_for_test(&self) -> (u64, u64) {
        (
            self.unserved_consecutive
                .load(std::sync::atomic::Ordering::SeqCst),
            self.unserved_total
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// Test-only: trip this backend's canonical Shared-slot circuit breaker
    /// open, by the same route the health probe's unserved escalation uses.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test(&self) {
        self.trip_circuit_breaker("test-trip");
    }

    /// Test-only: record enough failed requests on the canonical Shared slot
    /// that its health tracker reports the backend down, as a real outage does.
    #[cfg(test)]
    pub(crate) fn fail_requests_for_test(&self) {
        let entry = self.shared_entry();
        for _ in 0..3 {
            entry
                .failsafe
                .record_failure("test-failure", std::time::Duration::ZERO);
        }
    }

    /// Test-only: trip an arbitrary pool slot's circuit breaker open
    /// (MIK-6735 fix 1) — generalizes [`Self::trip_circuit_breaker_for_test`]
    /// (Shared-only) to any [`PoolKey`], so cross-tenant isolation tests can
    /// trip one identity's slot without touching another's.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test_key(&self, key: &PoolKey) {
        let entry = self.pooled_entry(key);
        let threshold = entry.failsafe.circuit_breaker.stats().failure_threshold;
        for _ in 0..threshold {
            entry
                .failsafe
                .circuit_breaker
                .record_failure("test-trip", std::time::Duration::ZERO);
        }
    }
}

impl Backend {
    /// How long this backend may sit unused before its process is stopped.
    /// `None` means never.
    pub fn stop_when_idle_for(&self) -> Option<Duration> {
        self.config.stop_when_idle_for
    }

    /// Mark the start of a client request against `key`, returning a guard that
    /// protects the slot from being stopped until dropped. The only caller-facing
    /// way to write the idle clock.
    pub(super) fn begin_activity(&self, key: &PoolKey) -> ActivityGuard {
        self.last_used.store(now_unix_secs(), Ordering::Relaxed);
        let entry = self.claim_pooled_entry(key);
        entry.touch();
        ActivityGuard::adopt_claimed(entry, true)
    }

    /// Hold the shared slot's transport open for internal work without claiming
    /// client activity.
    ///
    /// Internal work — metadata refreshes, health probes — must not defer
    /// stopping, or `last_used` stops meaning "a client used this" and the
    /// feature silently never fires. But such work still holds a live transport
    /// and must not have it closed mid-call. Those are two separate concerns and
    /// this lease covers only the second.
    ///
    /// Metadata refreshes call `ensure_started()` and then separately reach for
    /// the transport. Without a lease the reaper can take it in between, and the
    /// caller sees a spurious `BackendUnavailable` for a backend that is fine.
    pub(super) fn begin_internal_activity(&self) -> ActivityGuard {
        self.begin_internal_activity_for(&PoolKey::Shared)
    }

    /// The slot-scoped form of [`Self::begin_internal_activity`].
    ///
    /// Claims `key`'s slot rather than the canonical one, so a per-identity
    /// metadata fill holds open the transport it is actually fetching over. It
    /// uses `claim_pooled_entry`, never `pooled_entry`: the unclaimed lookup
    /// hands back an entry `evict_idle_per_user_entries` is still free to
    /// remove, which would close the transport under the fetch
    /// (MIK-7334.CATALOGUE.1 R3).
    pub(super) fn begin_internal_activity_for(&self, key: &PoolKey) -> ActivityGuard {
        ActivityGuard::adopt_claimed(self.claim_pooled_entry(key), false)
    }

    /// Stop this backend's process if it has been unused past
    /// `stop_when_idle_for`. Returns `true` if a live transport was closed.
    ///
    /// The pool entry deliberately STAYS in the pool; only the transport is
    /// released. `shared_entry()` expects the entry to always be present and
    /// panics otherwise, and the entry owns the circuit breaker and health
    /// metrics, which must survive being stopped.
    /// `ensure_entry_started` treats a `None`-or-disconnected transport as
    /// "start it", so the next request transparently restarts the process.
    ///
    /// Synchronisation is the transport `RwLock`, NOT `start_lock`.
    /// `ensure_entry_started` clones a connected transport under a READ guard on
    /// its fast path, before it ever awaits `start_lock` — so `start_lock` cannot
    /// exclude that clone, and a reaper holding only `start_lock` could close a
    /// transport a caller had just been handed. `Arc` would keep the Rust object
    /// alive but not the child process or its pipes, so the caller would fail
    /// spuriously. Taking the WRITE guard excludes the fast-path read outright.
    ///
    /// In-flight work is refused rather than drained: if a request is running the
    /// sweep simply declines and the next one retries. That holds the same
    /// invariant as a drain — never terminate work in progress — without holding
    /// a half-stopped state that every other path would then have to understand.
    pub async fn stop_if_idle(&self) -> bool {
        let Some(idle_for) = self.config.stop_when_idle_for else {
            return false; // never stop this backend
        };
        // Sub-second deadlines would truncate to a 0 cutoff, making every slot
        // eligible on every sweep including one used this same second.
        let cutoff = idle_for.as_secs().max(1);
        let entry = self.shared_entry();

        let taken = {
            let mut guard = entry.transport.write();

            if entry.in_flight.load(Ordering::SeqCst) > 0 {
                return false; // work in progress; retry next sweep
            }
            if now_unix_secs().saturating_sub(entry.last_used.load(Ordering::Relaxed)) < cutoff {
                return false; // used recently
            }
            let taken = guard.take();
            if taken.is_some() {
                // Recorded INSIDE the write guard, atomic with the take.
                // Storing it after the close() below leaves a window where the
                // slot has no transport and is not yet flagged as deliberately
                // stopped. A health probe entering there sees a backend that
                // looks merely unstarted, calls ensure_started(), and restarts
                // the very process this sweep just stopped — a periodic silent
                // no-op, which is the failure this feature exists to prevent.
                entry.stopped_when_idle.store(true, Ordering::SeqCst);
            }
            taken
        };

        let Some(transport) = taken else {
            return false; // already stopped
        };
        // BOUNDED, for the same reason `close_pooled_transports` is bounded at
        // shutdown: `close()` has no deadline of its own — `StdioTransport::close`
        // waits on the writer mutex, which a request blocked writing to a child
        // that stopped reading can hold indefinitely. The sweep visits backends
        // one after another in a single task, so an unbounded close here does
        // not merely delay THIS backend: it wedges the whole sweep, and every
        // other backend then idles forever without being stopped. The transport
        // is already out of the pool, so abandoning the wait cannot strand a
        // caller — only, at worst, the child process, which is exactly what the
        // failure branch below already reports.
        let close = tokio::time::timeout(self.budgets.close_stage, transport.close()).await;
        match close {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                // The slot is stopped either way — it no longer holds a transport,
                // and re-clearing the flag would report Running for a slot with
                // nothing to talk to, which is strictly worse. But a failed close
                // means the child may have outlived the gateway's handle to it, so
                // Dormant is not proof the process died. Say so rather than imply
                // a clean stop.
                tracing::warn!(
                    backend = %self.name,
                    %error,
                    "Idle backend transport failed to close cleanly; child process may be orphaned"
                );
                telemetry_metrics::counter!(
                    "mcp_backend_idle_stop_close_failures",
                    "backend" => self.name.clone()
                )
                .increment(1);
            }
            Err(_) => {
                tracing::warn!(
                    backend = %self.name,
                    budget_secs = self.budgets.close_stage.as_secs(),
                    "Idle backend transport did not close within its budget; \
                     abandoning the close so the sweep keeps running. Child process may be orphaned"
                );
                telemetry_metrics::counter!(
                    "mcp_backend_idle_stop_close_failures",
                    "backend" => self.name.clone()
                )
                .increment(1);
            }
        }

        tracing::info!(
            backend = %self.name,
            idle_for_secs = cutoff,
            "Stopped idle backend; next request will restart it"
        );
        true
    }
}
