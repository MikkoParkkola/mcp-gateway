// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend status/runtime-status report types and the [`BackendRegistry`]
//! that owns all configured backends by name.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::warn;

use super::Backend;
use crate::runtime::{RuntimeDenyReason, RuntimeLicenseTier, RuntimeProviderKind};

/// Coarse lifecycle state of a backend, distinct from its health.
///
/// A backend stopped ON PURPOSE is neither healthy nor failed. Without a third
/// state it has to be reported as one of them: as healthy it hides a stopped
/// process, and as failed it trips circuit breakers and lights dashboards red
/// for a backend that is behaving exactly as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendLifecycle {
    /// Transport is up and usable.
    Running,
    /// Deliberately stopped after being idle. Available on demand: the next
    /// request restarts it. Must NOT trip or heal a circuit breaker, and must
    /// not be probed by the health loop.
    Dormant,
    /// Expected to be usable and is not - crashed, failing probes, or breaker
    /// open.
    Unhealthy,
    /// Never started. The gateway starts backends lazily, so this is the normal
    /// state for a configured backend nothing has used yet.
    NotStarted,
}

impl std::fmt::Display for BackendLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Running => "running",
            Self::Dormant => "dormant",
            Self::Unhealthy => "unhealthy",
            Self::NotStarted => "not_started",
        };
        f.write_str(s)
    }
}

/// Backend status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendStatus {
    /// Backend name
    pub name: String,
    /// Whether backend is running
    pub running: bool,
    /// Lifecycle state. Distinguishes "stopped on purpose because it was idle"
    /// from "should be running and is not", which `running: bool` alone cannot.
    pub lifecycle: BackendLifecycle,
    /// Transport type
    pub transport: String,
    /// Number of cached tools
    pub tools_cached: usize,
    /// Circuit breaker state
    pub circuit_state: String,
    /// Total request count
    pub request_count: u64,
    /// Health-tracker liveness (flips false after consecutive failures, e.g.
    /// timeouts under load, *before* the circuit breaker trips Open). `/health`
    /// must consider this so it does not report healthy while a backend is
    /// silently timing out (see issue #5080 / MIK-5080).
    pub healthy: bool,
    /// Consecutive failures recorded by the health tracker.
    pub consecutive_failures: u64,
    /// 95th percentile latency in milliseconds, if any samples exist.
    pub latency_p95_ms: Option<u64>,
    /// Runtime profile lifecycle state for admin/operator surfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<BackendRuntimeStatus>,
}

/// Runtime profile status information exposed through backend status.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct BackendRuntimeStatus {
    /// Runtime profile selected by this backend.
    pub profile: String,
    /// Provider selected by the compiled runtime plan.
    pub provider: RuntimeProviderKind,
    /// Policy id used for audit correlation.
    pub policy_id: String,
    /// License tier that owns this runtime provider capability.
    pub license_tier: RuntimeLicenseTier,
    /// Whether the runtime plan is ready, denied, or waiting for approval.
    pub state: BackendRuntimeState,
    /// Fail-closed denial reasons, when any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_reasons: Vec<RuntimeDenyReason>,
    /// Confirmation ids required before live start or provider apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirmation_ids: Vec<String>,
    /// Maximum restart attempts from the compiled policy.
    pub restart_max_attempts: u32,
    /// Restart backoff from the compiled policy.
    pub restart_backoff_secs: u64,
    /// Provider-specific health check instruction or command.
    pub health_check: String,
    /// Provider-specific restart command hint, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_command_hint: Option<String>,
    /// Rollback instruction for this runtime plan.
    pub rollback_step: String,
}

/// Compiled runtime plan state for a backend.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendRuntimeState {
    /// Policy passed without pending human gates.
    Ready,
    /// Policy requires explicit human approval before execution.
    ConfirmationRequired,
    /// Policy denied execution and must fail closed.
    Denied,
}

/// Backend registry - manages all backends
pub struct BackendRegistry {
    /// Backends by name
    backends: DashMap<String, Arc<Backend>>,
    /// Whether shutdown has begun. Set once by [`BackendRegistry::stop_all`] and
    /// never cleared.
    ///
    /// A LOCK, not an atomic, and that distinction is the whole point.
    /// `register` holds it across its check AND its insert; `stop_all` holds it
    /// across setting the flag AND taking its snapshot. Those are the two
    /// operations that must not interleave, so making each of them atomic
    /// individually - which two `SeqCst` checks around an insert do NOT achieve
    /// - is not enough.
    ///
    /// The earlier check-then-insert version failed on same-name registrations:
    /// A inserts, B replaces it and returns success, A's second check passes,
    /// shutdown snapshots B, and B's own check then removes it. Shutdown stops
    /// B, the map is empty, and A - which its caller was told was registered,
    /// and may have started - was never in the snapshot at all. No amount of
    /// re-checking fixes that; only mutual exclusion does.
    ///
    /// Held only across map operations, never across an `.await`.
    ///
    /// NOT covered by a behavioural test, and the attempt is instructive: a
    /// test that holds this lock and asserts `stop_all` blocks passes whether
    /// or not the latch and the snapshot share one hold, because `stop_all`
    /// blocks on the latch either way. It looked like a window-positioned test
    /// and was not. Driving the real interleaving needs a registration paused
    /// between its check and its insert, which nothing outside `register` can
    /// arrange. The guarantee here is by construction - one critical section on
    /// each side - not by demonstration.
    stopping: parking_lot::Mutex<bool>,

    /// Serializes config-reload transactions (#397).
    ///
    /// A reload stops the old instance of a modified backend and then registers
    /// a replacement. Those two steps are not atomic, and `register` replaces by
    /// name, so two reloads running at once can each register a replacement and
    /// the second insert discards the first without stopping it. If ordinary
    /// traffic started the discarded one in between, its child process is
    /// orphaned. Held across the whole reload transaction - reading the config
    /// file, comparing it against the live one, applying the difference, and
    /// publishing the result - so reloads queue instead of interleaving.
    /// Holding it only across the apply step is not enough: both reloads would
    /// have compared against the same stale live config before they queued, and
    /// both would still register.
    ///
    /// A `tokio` mutex, not `parking_lot`: the critical section awaits
    /// `Backend::stop`.
    reload: tokio::sync::Mutex<()>,
}

impl BackendRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: DashMap::new(),
            stopping: parking_lot::Mutex::new(false),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    /// Take the reload lock, so one config-reload transaction runs at a time.
    ///
    /// Taken by each config-reload entry point before it reads the config file,
    /// and held until the new config is published. See the `reload` field for
    /// why it has to start that early. Callers that mutate the registry as a
    /// transaction (stop-then-register) must take it; single operations do not.
    pub async fn lock_reload(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.reload.lock().await
    }

    /// Register a backend
    ///
    /// Refused once shutdown has begun: a backend registered after `stop_all`
    /// has taken its snapshot would never be stopped, and its process would
    /// outlive the gateway. Returns `false` when the registration was refused
    /// for that reason.
    ///
    /// The check and the insert happen under one hold of the shutdown lock, so
    /// a registration that returns `true` has completed its insert before any
    /// snapshot `stop_all` takes afterwards. That cannot be built from separate
    /// atomic operations, which is why this is a lock.
    ///
    /// The guarantee stops there, and the limit is worth stating because it is
    /// easy to over-read: this says the entry is IN the map when the snapshot is
    /// taken, not that it survives until then. Registering the same name again
    /// REPLACES it - `DashMap::insert` discards the displaced value - so a
    /// backend that was started and then displaced is stopped by nobody.
    ///
    /// That displacement was reachable (#397): `ReloadContext::reload_outcome`
    /// had no serialization and is called from three concurrent HTTP paths - the
    /// `gateway_reload_config` meta-tool, the admin UI reload, and every admin
    /// UI backend edit via `write_config_and_reload_outcome`. The config-file
    /// watcher is a fourth caller; it is not an HTTP path, but it races with
    /// those three all the same. Two concurrent
    /// reloads could both stop backend A and then register replacements B and C;
    /// ordinary traffic could start B in between; C's insert then discarded B
    /// without stopping it, orphaning that process.
    ///
    /// Fixed by serializing the reload transaction rather than by changing the
    /// semantics here: every reload entry point takes
    /// `BackendRegistry::lock_reload` before it reads the config file and holds
    /// it until the new config is published, so the stop and the re-register of
    /// one reload complete before the next reload even reads its input.
    /// Replace-by-name is still what this function does, and a caller
    /// that registers a duplicate name outside that lock still displaces
    /// silently. The only such callers today are startup, which runs before the
    /// gateway serves, and tests.
    #[must_use = "a refused registration means the backend is NOT registered"]
    pub fn register(&self, backend: Arc<Backend>) -> bool {
        let stopping = self.stopping.lock();
        if *stopping {
            warn!(
                backend = %backend.name,
                "Refusing to register a backend during shutdown; it would never be stopped"
            );
            return false;
        }
        self.backends.insert(backend.name.clone(), backend);
        true
    }

    /// Get a backend by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<Backend>> {
        self.backends.get(name).map(|b| Arc::clone(&*b))
    }

    /// Get all backends
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Backend>> {
        self.backends.iter().map(|b| Arc::clone(&*b)).collect()
    }

    /// Get all backend statuses
    #[must_use]
    pub fn statuses(&self) -> HashMap<String, BackendStatus> {
        self.backends
            .iter()
            .map(|b| (b.name.clone(), b.status()))
            .collect()
    }

    /// Remove a backend by name (deregister without stopping).
    ///
    /// If the backend must be stopped before removal, call `backend.stop()`
    /// first.  Returns `true` when the backend was present and removed.
    pub fn remove(&self, name: &str) -> bool {
        self.backends.remove(name).is_some()
    }

    /// Stop all backends, concurrently.
    ///
    /// Concurrent rather than sequential because `Backend::stop` is bounded but
    /// not instant - it waits for in-flight starts to resolve and for replaced
    /// transports to be closed. Stopping N backends one after another
    /// multiplies that bound by N, so a gateway with a couple of dozen backends
    /// could spend minutes shutting down in the worst case. Backends own
    /// independent processes, sessions and locks, so there is nothing to
    /// serialise: total shutdown is now bounded by the slowest single backend
    /// rather than the sum of all of them.
    pub async fn stop_all(&self) {
        // The latch and the snapshot are taken under ONE hold of the shutdown
        // lock, which `register` also holds across its check and insert. So a
        // registration either completes entirely before this snapshot and is in
        // it, or finds the latch already set and is refused. There is no
        // interleaving in which a caller is told its backend was registered and
        // shutdown never sees it.
        //
        // No await inside: the stops happen after the guard is dropped.
        let backends: Vec<std::sync::Arc<Backend>> = {
            let mut stopping = self.stopping.lock();
            *stopping = true;
            self.backends
                .iter()
                .map(|entry| std::sync::Arc::clone(entry.value()))
                .collect()
        };

        futures::future::join_all(backends.into_iter().map(|backend| async move {
            if let Err(e) = backend.stop().await {
                warn!(backend = %backend.name, error = %e, "Failed to stop backend");
            }
        }))
        .await;
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::{BackendConfig, TransportConfig};

    fn stdio_backend(name: &str) -> Arc<Backend> {
        let cfg = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "/nonexistent-mcp-binary".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        };
        Arc::new(Backend::new(
            name,
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    }

    // A backend registered after shutdown has taken its snapshot would never be
    // stopped, and its process would outlive the gateway. Config reload can
    // genuinely race shutdown, so the registry refuses late registrations
    // rather than accepting one it cannot honour.
    #[tokio::test]
    async fn a_backend_registered_after_shutdown_is_refused() {
        let registry = BackendRegistry::new();
        assert!(
            registry.register(stdio_backend("before")),
            "registration before shutdown must be accepted"
        );

        registry.stop_all().await;

        assert!(
            !registry.register(stdio_backend("after")),
            "the registry accepted a backend after shutdown; nothing will ever \
             stop it"
        );
        assert!(
            registry.get("after").is_none(),
            "a backend refused during shutdown must not be in the registry"
        );
    }

    // A refused registration must not disturb an entry someone else registered
    // successfully under the same name.
    #[tokio::test]
    async fn a_refused_registration_does_not_evict_an_existing_one() {
        let registry = BackendRegistry::new();
        let original = stdio_backend("shared-name");
        assert!(registry.register(Arc::clone(&original)));

        registry.stop_all().await;

        assert!(
            !registry.register(stdio_backend("shared-name")),
            "a registration during shutdown must be refused"
        );
        let still_there = registry
            .get("shared-name")
            .expect("the refused registration evicted an entry it did not create");
        assert!(
            Arc::ptr_eq(&still_there, &original),
            "the entry under this name is not the one that was registered"
        );
    }
}
