// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend management

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Semaphore;

use crate::config::BackendConfig;
use crate::runtime::RuntimePlan;

/// Pages drained from one backend's paginated `*/list` fill before the drain
/// stops and marks the slot truncated (MIK 7570 PAGING.1, design §2.C).
/// The direct route's `DIRECT_LIST_MAX_PAGES` is defined from this constant
/// so the two independent drains share one cap.
pub(crate) const LIST_MAX_PAGES: usize = 32;

/// Wall-clock budget for one paginated `*/list` fill, across every page
/// (design §2.G, revision 2). Checked between pages, never mid-request, so
/// the in-flight permit is held for at most this plus one page's timeout.
const CACHE_LIST_DRAIN_BUDGET: Duration = Duration::from_secs(120);

mod annotations;
mod cached_metadata;
mod descriptor_gate;
mod era;
mod fill_check;
mod identity_slots;
mod input_keys;
mod lifecycle;
mod list_drain;
pub(crate) mod listen;
mod metadata;
mod oauth_client;
mod ops;
mod pool;
mod probe;
mod registry;
mod repin;
mod restart;
mod runtime_launch;
mod status;
mod stdio_start;
mod stop;

impl Backend {
    /// This backend's signature chain policy (ASI07 inc3, design D1): the
    /// mode, the accepted origin key ids and the required last signer.
    pub(crate) fn chain_policy(&self) -> (crate::config::ChainMode, &[String], Option<&str>) {
        let config = &self.config;
        (
            config.signature_chain,
            &config.chain_origins,
            config.chain_signer.as_deref(),
        )
    }
}

#[cfg(test)]
pub(crate) use pool::PoolKey;
#[cfg(not(test))]
use pool::PoolKey;
use pool::PooledEntry;

pub(crate) use annotations::prepare_tool_metadata;
#[cfg(test)]
pub(crate) use descriptor_gate::descriptor_digest;
pub(crate) use descriptor_gate::{Judging, Listing};
pub(crate) use fill_check::{LIST_FILL_COOLDOWN, text_absent};
pub(crate) use identity_slots::passthrough_binding;
pub use registry::{
    BackendLifecycle, BackendRegistry, BackendRuntimeState, BackendRuntimeStatus, BackendStatus,
};
pub use runtime_launch::runtime_plan_for_backend;

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// `name` as the `backend` metric label, shared so that recording a
    /// metric costs a reference count, not a copy of the name (MIK-8014.PERF.5).
    metric_label: telemetry_metrics::SharedString,
    /// Configuration
    config: BackendConfig,
    /// Runtime plan compiled from the backend's configured runtime profile.
    runtime_plan: Option<RuntimePlan>,
    /// Per-identity transport/session pool (MIK-6735). Always holds the
    /// canonical [`PoolKey::Shared`] slot; gains one [`PoolKey::PerUser`] slot
    /// per caller identity when identity propagation is configured, whatever
    /// its `session_mode`. Each slot carries its
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
    /// Consecutive health-probe answers this peer declined to serve
    /// (MIK-7217, OUTBOUND.2).
    ///
    /// A refusal is neither health nor a fault: the peer answered, so nothing
    /// is broken, but it did not serve the probe. Counting them is what lets
    /// the probe leave a declining peer alone without leaving a peer that
    /// declines *everything* wedged and green for ever. Reset by a served
    /// answer and by the fault and timeout arms, which restart on their own
    /// terms and so start the count afresh against a new transport.
    unserved_consecutive: AtomicU64,
    /// Lifetime unserved answers, the in-process value behind
    /// `mcp_health_probe_unserved_total` for this backend.
    unserved_total: AtomicU64,
    /// Set while a health probe is on the wire (MIK-7217, OUTBOUND.2).
    ///
    /// "Consecutive unserved" counts answers, not ticks, and a peer that is
    /// slow rather than broken would otherwise have a second probe sent at it
    /// while the first is still outstanding - inflating the count toward a
    /// restart the peer never earned, and doubling the traffic to a backend
    /// already struggling to answer.
    probe_in_flight: std::sync::atomic::AtomicBool,
    /// Cached tools
    // The four metadata caches and the resend set derived from the first of
    // them USED TO LIVE HERE. They are fields on `PooledEntry` now
    // (MIK-7334.CATALOGUE.1): a backend-wide cache serves one identity's
    // catalogue to every other identity sharing the backend, and a
    // backend-wide resend set lets one identity's fill decide another's retry
    // policy. Deleting them rather than adding a keyed path beside them is
    // deliberate — it is what makes the compiler enumerate every reader.
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
    /// Admitted `PerUser` slots and eviction-close permits (#2300).
    identity_slots: Arc<identity_slots::IdentitySlots>,
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
    /// Tools withheld for a blocking tool-poisoning finding, across every
    /// caller slot, and the log lines already written for them (#1441).
    descriptor_gate: descriptor_gate::DescriptorGate,
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
    /// The one admitted start an events subscribe runs to learn the HTTP
    /// transport, shared by every subscribe waiting on it (MIK-7969).
    events_resolution: parking_lot::Mutex<Option<listen::Resolution>>,
    /// Resolution tasks spawned so far: one per in-flight start, not one per
    /// waiting subscribe (MIK-7969 M2).
    #[cfg(test)]
    events_resolutions: std::sync::atomic::AtomicUsize,
    /// Where this backend's transports may connect; stamped by its registry.
    /// Unstamped means `Configured`: a backend no config governs.
    destination: std::sync::OnceLock<crate::security::ssrf::DestinationPolicy>,
    /// Set, and never cleared, when a start began before any stamp: whatever
    /// that start built may still be alive somewhere (pooled, closing, held
    /// by a request), so a hardened pairing refuses this backend (MIK-7700).
    connected_unpinned: std::sync::atomic::AtomicBool,
    /// The one interactive login at a time every start of this backend
    /// shares (MIK-7982).
    pub(crate) login_gate: Arc<crate::oauth::login_gate::LoginGate>,
    /// A test's pause point in an HTTP start, after it read the policy it
    /// builds under and before it builds anything from it or
    /// [`Backend::begin_connecting`] checks and marks.
    #[cfg(test)]
    mark_window_gate: parking_lot::Mutex<Option<Arc<MarkWindowGate>>>,
    /// A test's stand-ins for the user's token store and browser, used by the
    /// OAuth client [`Backend::create_oauth_client`] builds.
    #[cfg(test)]
    oauth_test_seam: parking_lot::Mutex<Option<OAuthTestSeam>>,
    pub(crate) budgets: ShutdownBudgets,
}

/// Where a test backend's OAuth client keeps tokens, and who plays the
/// browser it hands the authorization URL to.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct OAuthTestSeam {
    pub(crate) storage_dir: std::path::PathBuf,
    pub(crate) open_browser: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

/// Holds a start in the window before it marks: the start signals `reached`
/// and waits for `release`.
#[cfg(test)]
#[derive(Default)]
struct MarkWindowGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Backend {
    /// Set by [`BackendRegistry`]; the first stamp wins.
    pub(crate) fn stamp_destination(&self, policy: crate::security::ssrf::DestinationPolicy) {
        let _ = self.destination.set(policy);
    }

    /// How long this backend's catalogue lists stay fresh (`meta_mcp.cache_ttl`).
    pub(crate) fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// Whether a start began on this HTTP or WebSocket backend before any
    /// destination policy was stamped on it. What that start built was not
    /// pinned and cannot be re-pinned in place (closing it would itself send
    /// to the address), so pairing refuses instead (MIK-7700).
    pub(crate) fn started_unpinned(&self) -> bool {
        self.destination_bound()
            && self.destination.get().is_none()
            && self
                .connected_unpinned
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether this backend's transports connect under its destination
    /// policy. A stdio child reaches no network destination of its own; every
    /// other transport does, an A2A agent included (MIK-8063).
    pub(crate) fn destination_bound(&self) -> bool {
        !matches!(
            self.config.transport,
            crate::config::TransportConfig::Stdio { .. }
        )
    }

    /// Start the outbound A2A bridge (MIK-8063) under `destination`: the agent
    /// becomes one tool behind the same funnel as every backend. Like the HTTP
    /// arm, the configured address is checked before anything connects and
    /// every request goes through the guarded client. An agent has no
    /// server-initiated stream, so the caller sets no listener. The caller has
    /// marked the backend connecting and passed `begin_connecting` first.
    #[cfg(feature = "a2a")]
    async fn start_a2a(
        &self,
        destination: crate::security::ssrf::DestinationPolicy,
    ) -> crate::Result<Arc<crate::a2a::transport::A2aTransport>> {
        let crate::config::TransportConfig::A2a {
            a2a_url,
            a2a_agent_card_path,
        } = &self.config.transport
        else {
            return Err(crate::Error::Config(format!(
                "backend '{}' is not an A2A backend",
                self.name
            )));
        };
        crate::a2a::transport::A2aTransport::start(
            a2a_url,
            a2a_agent_card_path.as_deref(),
            &self.config.headers,
            self.config.timeout,
            destination,
        )
        .await
    }

    /// Start a WebSocket transport under `destination`, the policy the start
    /// read when it marked the backend.
    async fn start_websocket(
        &self,
        ws_url: &str,
        protocol_version: Option<String>,
        destination: crate::security::ssrf::DestinationPolicy,
    ) -> crate::Result<Arc<crate::transport::websocket::WebSocketTransport>> {
        crate::transport::websocket::WebSocketTransport::start_with_destination(
            ws_url,
            &self.config.headers,
            self.config.timeout,
            protocol_version,
            destination,
        )
        .await
    }

    /// The policy this backend's transports connect under.
    pub(crate) fn destination(&self) -> crate::security::ssrf::DestinationPolicy {
        self.destination
            .get()
            .copied()
            .unwrap_or(crate::security::ssrf::DestinationPolicy::Configured)
    }
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

// The cells read counters from a local Prometheus render.
#[cfg(test)]
#[path = "blocked_names_tests.rs"]
mod blocked_names_tests;
#[cfg(test)]
#[path = "descriptor_withholding_tests.rs"]
mod descriptor_withholding_tests;
#[cfg(all(test, feature = "metrics"))]
mod f13_fill_tests;
#[cfg(test)]
mod list_paging_tests;
#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "resend_isolation_tests.rs"]
mod resend_isolation_tests;

#[cfg(test)]
#[path = "slot_eviction_tests.rs"]
mod slot_eviction_tests;

#[cfg(test)]
#[path = "grant_reload_eviction_tests.rs"]
mod grant_reload_eviction_tests;

#[cfg(test)]
#[path = "eviction_close_bound_tests.rs"]
mod eviction_close_bound_tests;

#[cfg(test)]
#[path = "eviction_close_cap_tests.rs"]
mod eviction_close_cap_tests;

#[cfg(test)]
#[path = "identity_slot_probe_tests.rs"]
mod identity_slot_probe_tests;

#[cfg(test)]
#[path = "start_failure_slot_tests.rs"]
mod start_failure_slot_tests;

#[cfg(test)]
#[path = "era_stale_probe_tests.rs"]
mod era_stale_probe_tests;

#[cfg(all(test, unix))]
#[path = "frame_limit_start_tests.rs"]
mod frame_limit_start_tests;

#[cfg(test)]
#[path = "stateless_tools_slot_tests.rs"]
mod stateless_tools_slot_tests;

#[cfg(test)]
#[path = "websocket_backend_tests.rs"]
mod websocket_backend_tests;

#[cfg(test)]
mod destination_tests;

#[cfg(test)]
#[path = "stop_race_tests.rs"]
mod stop_race_tests;
