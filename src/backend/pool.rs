// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-identity transport/session pool (MIK-6735): [`PoolKey`], [`PooledEntry`],
//! and the [`super::Backend`] methods that create, look up, and idle-evict
//! pool slots.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::Mutex;

use super::Backend;
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
/// When `identity_propagation.session_mode = per_user` is configured and a
/// caller identity is present, the backend additionally owns one
/// [`PoolKey::PerUser`] slot per stable identity binding, so two distinct users
/// never share a backend transport or its upstream MCP session (IDP.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PoolKey {
    /// The canonical single-tenant slot. Every non-per-user backend, and every
    /// per-user backend request that lacks a resolved identity, collapses here
    /// so single-tenant behavior is preserved byte-for-byte (IDP.5).
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
/// keeps its own failsafe (behavior for non-per-user backends is byte-for-
/// byte unchanged), and each `PerUser` slot gets a fresh one the moment it is
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
/// Ordering: the count is incremented BEFORE the caller acquires the transport
/// read guard, and [`Backend::stop_if_idle`] reads it while holding the transport
/// WRITE guard. Either the increment lands first and stopping backs off, or
/// stopping wins and the caller then observes `None` and starts a new transport.
/// No interleaving hands a caller a transport that is being closed.
pub(crate) struct ActivityGuard {
    entry: Arc<PooledEntry>,
    /// Whether dropping this guard counts as client activity. False for internal
    /// leases, which protect the transport without deferring the idle deadline.
    touch_on_drop: bool,
}

impl ActivityGuard {
    fn new(entry: Arc<PooledEntry>) -> Self {
        entry.in_flight.fetch_add(1, Ordering::SeqCst);
        entry.touch();
        Self {
            entry,
            touch_on_drop: true,
        }
    }

    /// A lease that protects the slot from being stopped WITHOUT claiming client
    /// activity.
    ///
    /// Internal work - metadata refreshes, health probes - must not defer
    /// stopping, or the idle clock stops meaning "a client used this" and the
    /// feature silently never fires. But such work still holds a live transport
    /// and must not have it closed mid-call. Those are two separate concerns and
    /// this guard covers only the second.
    fn internal(entry: Arc<PooledEntry>) -> Self {
        entry.in_flight.fetch_add(1, Ordering::SeqCst);
        Self {
            entry,
            touch_on_drop: false,
        }
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
    /// Only a `per_user` backend with a concrete caller identity gets its own
    /// slot; every other case — no identity propagation, `stateless`, or
    /// `per_user` without a resolved identity — collapses to the shared
    /// canonical slot, preserving single-tenant behavior byte-for-byte (IDP.5).
    pub(super) fn pool_key_for(&self, identity_key: Option<&str>) -> PoolKey {
        use crate::identity_propagation::SessionMode;
        match (self.session_mode(), identity_key) {
            (Some(SessionMode::PerUser), Some(binding)) => PoolKey::PerUser {
                binding: binding.to_string(),
            },
            _ => PoolKey::Shared,
        }
    }

    /// Fetch (or lazily create) the pooled entry for `key`. The `Arc` is cloned
    /// out so the `DashMap` shard guard is released before any `.await`.
    ///
    /// Logs + gauges the live slot count on creation only (MIK-6735 fix 3) —
    /// minimal observability into per-user pool growth without a per-request
    /// cost on the (overwhelmingly more common) cache-hit path.
    pub(super) fn pooled_entry(&self, key: &PoolKey) -> Arc<PooledEntry> {
        let mut created = false;
        let entry = Arc::clone(
            self.pool
                .entry(key.clone())
                .or_insert_with(|| {
                    created = true;
                    Arc::new(PooledEntry::new(&self.name, &self.failsafe_config))
                })
                .value(),
        );
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
        entry
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

    /// Test-only: trip this backend's canonical Shared-slot circuit breaker
    /// open by recording `failure_threshold` consecutive failures.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test(&self) {
        self.trip_circuit_breaker_for_test_key(&PoolKey::Shared);
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
        ActivityGuard::new(self.pooled_entry(key))
    }

    /// Hold the shared slot's transport open for internal work without claiming
    /// client activity.
    ///
    /// Metadata refreshes call `ensure_started()` and then separately reach for
    /// the transport. Without a lease the reaper can take it in between, and the
    /// caller sees a spurious `BackendUnavailable` for a backend that is fine.
    pub(super) fn begin_internal_activity(&self) -> ActivityGuard {
        ActivityGuard::internal(self.pooled_entry(&PoolKey::Shared))
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
            guard.take()
        };

        let Some(transport) = taken else {
            return false; // already stopped
        };
        let _ = transport.close().await;
        entry.stopped_when_idle.store(true, Ordering::SeqCst);

        tracing::info!(
            backend = %self.name,
            idle_for_secs = cutoff,
            "Stopped idle backend; next request will restart it"
        );
        true
    }
}
