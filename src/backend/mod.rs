// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend management

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Semaphore;

use crate::config::BackendConfig;
use crate::protocol::{Prompt, Resource, ResourceTemplate, Tool};
use crate::runtime::RuntimePlan;

mod annotations;
mod cached_metadata;
mod era;
mod lifecycle;
mod metadata;
mod ops;
mod pool;
mod registry;

use cached_metadata::CachedMetadata;
use pool::{PoolKey, PooledEntry};

pub(crate) use annotations::prepare_tool_metadata;
pub use lifecycle::runtime_plan_for_backend;
pub use registry::{
    BackendLifecycle, BackendRegistry, BackendRuntimeState, BackendRuntimeStatus, BackendStatus,
};

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// Configuration
    config: BackendConfig,
    /// Runtime plan compiled from the backend's configured runtime profile.
    runtime_plan: Option<RuntimePlan>,
    /// Per-identity transport/session pool (MIK-6735). Always holds the
    /// canonical [`PoolKey::Shared`] slot; gains one [`PoolKey::PerUser`] slot
    /// per caller identity when `session_mode = per_user`. Each slot carries its
    /// own transport and start lock, so concurrent warm-start/client requests do
    /// not spawn duplicate connections for the same slot and distinct users
    /// never share a session (IDP.7).
    pool: DashMap<PoolKey, Arc<PooledEntry>>,
    /// Failsafe configuration, cloned so a freshly created pool slot
    /// (`pooled_entry`) can build its own independent `Failsafe` (MIK-6735
    /// fix 1). The per-backend `Failsafe` this replaced is gone; every slot,
    /// including Shared, now owns one.
    failsafe_config: crate::config::FailsafeConfig,
    /// Protocol era of the peer on the other end of this backend's
    /// transport (MIK-7217). Resolved once per start by a `server/discover`
    /// probe and shared with the detached re-probe task, which outlives the
    /// request that triggered it — hence `Arc`.
    era: Arc<crate::protocol::era::EraCache>,
    /// Cached tools
    tools_cache: CachedMetadata<Vec<Tool>>,
    /// Cached resources
    resources_cache: CachedMetadata<Vec<Resource>>,
    /// Cached resource templates
    resource_templates_cache: CachedMetadata<Vec<ResourceTemplate>>,
    /// Cached prompts
    prompts_cache: CachedMetadata<Vec<Prompt>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Last used timestamp
    last_used: AtomicU64,
    /// Concurrency limiter
    semaphore: Semaphore,
    /// Request counter
    request_count: AtomicU64,
    /// Cleanup tasks for transports that `force_restart` replaced while
    /// requests were still using them, plus the shutdown latch that stops new
    /// ones being created.
    ///
    /// Each task waits for its transport's last owner to let go and then closes
    /// it. The handles are kept rather than detached so [`Backend::stop`] can
    /// drain them: a replaced transport is no longer reachable through `pool`,
    /// so shutdown would otherwise close only the CURRENT transport and let the
    /// runtime exit with the old one's `close()` unrun — skipping an HTTP
    /// backend's session DELETEs at exactly the reload and shutdown boundaries
    /// where they matter.
    ///
    /// `stopping` and `handles` share one lock because they are one decision:
    /// whether more cleanup work can still appear. Without the latch,
    /// `force_restart` racing shutdown can register a cleanup after the final
    /// drain — or worse, start a whole new child process after `stop()` has
    /// torn the backend down, leaving an orphan nothing will ever close.
    replaced_transport_cleanups: parking_lot::Mutex<CleanupState>,
    /// Serialises whole lifecycle transitions against each other.
    ///
    /// The `stopping` latch alone is not enough: `force_restart` reads it, then
    /// does async work, so it can pass the check BEFORE `stop()` latches and
    /// then register a cleanup - or start a whole new child - AFTER shutdown's
    /// final drain. A flag cannot close that window because the check and the
    /// work it guards are not one operation.
    ///
    /// So restarts take this shared, and `stop()` takes it exclusively: a
    /// restart either finishes entirely before shutdown begins, or starts
    /// afterwards and sees the latch. Shared rather than exclusive for restarts
    /// because concurrent restarts are already serialised by the slot's
    /// `start_lock`; this is only about excluding shutdown.
    lifecycle: tokio::sync::RwLock<()>,
    /// Makes [`Backend::stop`] single-flight.
    ///
    /// Without it, two concurrent callers both run the teardown and whichever
    /// takes the cleanup list first is the only one that waits - the other
    /// returns while transports are still closing. For a shutdown API that is
    /// the wrong contract: "stop returned" has to mean "everything is closed",
    /// or a caller can let the runtime exit with children still alive. The
    /// repository exposes several concurrent reload and shutdown entry points,
    /// so "callers must not race" was not a contract anyone could honour.
    ///
    /// A second caller blocks here, then observes `stopped` and returns - so it
    /// waits for the SAME completion the first caller produced.
    stop_once: tokio::sync::Mutex<()>,
    /// Set when a `stop()` has run to completion.
    stopped: std::sync::atomic::AtomicBool,
    /// Shutdown stage budgets, overridable so tests can reach windows that the
    /// production values close by accident.
    ///
    /// The single-flight contract is a case in point: with the shipped budgets
    /// a second caller's lifecycle wait (15s) always outlasts the first
    /// caller's close stage (10s), so the difference between having the gate
    /// and not having it is unobservable. That is a coincidence of two
    /// unrelated constants, not a guarantee, and a test that cannot see the
    /// difference cannot stop someone reordering them later.
    /// Starts that have spawned a process (or opened a session) but have not yet
    /// either published it or been refused.
    ///
    /// A counter rather than the lifecycle lock, because `start_entry` is
    /// reached from inside `force_restart`, which already holds that lock's read
    /// side - and `tokio::sync::RwLock` reads are not reentrant when a writer is
    /// queued, so nesting them would deadlock against `stop()`.
    ///
    /// `stop()` waits for this to reach zero. Refusing to publish is not enough
    /// on its own: a start that has spawned its child and is waiting on the MCP
    /// handshake owns a live process, and shutdown returning before that
    /// resolves leaves the process running for as long as the handshake takes.
    starts_in_flight: std::sync::atomic::AtomicUsize,
    pub(crate) budgets: ShutdownBudgets,
}

/// How long each stage of [`Backend::stop`] may take before it gives up.
///
/// Bounds SHUTDOWN, never a request: exceeding any of these abandons cleanup
/// rather than closing anything under a live caller, so none of them can cut a
/// request short.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShutdownBudgets {
    /// How long to wait to exclude a restart already in flight. Sized above a
    /// typical backend start, and finite so a hung one cannot hang shutdown.
    pub(crate) lifecycle_wait: Duration,
    /// How long the whole pooled-transport close stage may take.
    pub(crate) close_stage: Duration,
    /// How long to wait for in-flight starts, and then for replaced-transport
    /// cleanups. Each gets this much, starting when that wait begins.
    pub(crate) drain: Duration,
}

impl Default for ShutdownBudgets {
    fn default() -> Self {
        Self {
            lifecycle_wait: Duration::from_secs(15),
            close_stage: Duration::from_secs(10),
            drain: Duration::from_secs(10),
        }
    }
}

/// Decrements [`Backend::starts_in_flight`] however its start ends - published,
/// refused, failed, or unwound by an error further up.
pub(crate) struct StartGuard<'a>(&'a std::sync::atomic::AtomicUsize);

impl StartGuard<'_> {
    pub(crate) fn new(counter: &std::sync::atomic::AtomicUsize) -> StartGuard<'_> {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        StartGuard(counter)
    }
}

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// What [`Backend::force_restart`] actually did.
///
/// Distinguishing "rebuilt" from "skipped" matters because the admin revive
/// endpoint reports it to a human: an `Ok` that meant "did nothing because we
/// are shutting down" was being rendered as `transport_rebuilt: true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcome {
    /// The transport was replaced with a freshly started one.
    Rebuilt,
    /// Nothing was done: the backend is shutting down.
    SkippedStopping,
}

/// Deferred-cleanup bookkeeping for [`Backend`], behind a single lock.
#[derive(Default)]
pub(crate) struct CleanupState {
    /// Set by [`Backend::stop`] before it tears anything down, and never
    /// cleared: **a stopped `Backend` is terminal.** Do not add a reset. Both
    /// config-reload paths (`src/config_reload/mod.rs`) stop the old instance
    /// and construct a NEW one rather than reviving it, so a latch that never
    /// clears is the accurate model. Clearing it would reintroduce the window
    /// where a start publishes into a pool shutdown has already emptied.
    pub(crate) stopping: bool,
    /// Cleanup tasks awaiting their transport's last owner.
    pub(crate) handles: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod tests;
