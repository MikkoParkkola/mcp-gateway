// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend warm-start orchestration shared by HTTP and stdio server modes.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::Error;
use crate::backend::{Backend, BackendRegistry};
use crate::config::Config;
use crate::config_reload::{OnRegistered, RegisteredChange};

/// Schedule for retrying warm-start until a backend's tools are cached.
///
/// Two phases. The **fast** one covers the ordinary case this exists for: a
/// sibling daemon launched in the same second as the gateway that has not
/// finished binding its port. The **slow** one covers the case a deadline
/// cannot — a dependency that comes back minutes later — because nothing else
/// in the gateway ever revisits an empty tool cache, and a backend with an
/// empty cache is invisible to `gateway_search` for the whole process lifetime.
#[derive(Clone)]
pub(super) struct WarmStartPolicy {
    /// How long the fast phase lasts, measured from the first attempt.
    pub fast_deadline: Duration,
    /// Gap before the second attempt; doubles from there.
    pub initial_gap: Duration,
    /// Ceiling for the doubling gaps in the fast phase.
    pub max_gap: Duration,
    /// Fixed gap once the fast phase is over.
    pub slow_gap: Duration,
    /// FLOOR for one attempt, so a hung call cannot consume the phase.
    ///
    /// Only a floor: the real ceiling is derived per backend from the
    /// operator's own `timeout` (see `effective_attempt_timeout`). A fixed
    /// value here would silently cut short any backend configured to take
    /// longer, and a backend whose every attempt is cut short never becomes
    /// discoverable — this change's own bug, reintroduced by its safety valve.
    pub attempt_timeout: Duration,
}

impl Default for WarmStartPolicy {
    fn default() -> Self {
        Self {
            fast_deadline: Duration::from_secs(180),
            initial_gap: Duration::from_secs(2),
            max_gap: Duration::from_secs(30),
            slow_gap: Duration::from_secs(60),
            attempt_timeout: Duration::from_secs(120),
        }
    }
}

/// The gap to wait before `attempt` (1-based), before jitter is applied.
///
/// Keyed on ELAPSED time rather than attempt count. An attempt count says
/// nothing about wall-clock when a single attempt can itself block for its own
/// timeout, so counting attempts would end the fast phase at an unpredictable
/// moment.
fn gap_before_attempt(policy: &WarmStartPolicy, attempt: u32, elapsed: Duration) -> Duration {
    if attempt <= 1 {
        return Duration::ZERO;
    }
    if elapsed >= policy.fast_deadline {
        return policy.slow_gap;
    }

    // Saturating rather than `2u32.pow(n)`: the slow phase means this is called
    // with unbounded attempt numbers, and a panic in a background task would be
    // an outage that looks like silence.
    let mut gap = policy.initial_gap;
    for _ in 2..attempt {
        gap = gap.saturating_mul(2);
        if gap >= policy.max_gap {
            return policy.max_gap;
        }
    }
    gap.min(policy.max_gap)
}

/// Whether an error can mean "this backend is not ready yet".
///
/// Deliberately enumerated rather than delegated to `chains::retry_step`: that
/// predicate asks whether a chain step may be retried, this one whether a
/// backend is not up yet, and `BackendUnavailable` is what `start_entry`
/// returns while a backend is mid-lifecycle. Since the slow phase runs indefinitely,
/// anything not listed here must stop the loop: no amount of waiting turns an
/// unsupported protocol version into a working backend.
///
/// The transport reports what it knows. `TransportPermanent` is the transport
/// saying "this cannot work as configured" -- a missing command path, a file
/// that is not executable, a request the server calls malformed -- and plain
/// `Transport` remains "failed, cause unknown", which is the honest answer at
/// most of its construction sites and stays retryable here.
///
/// Not every permanent failure is classified yet: only the sites that
/// genuinely know map to the permanent variant, and the rest still arrive as
/// `Transport` and are still retried. That is the safe direction of error --
/// an unknown failure retrying costs a request a minute, while a recoverable
/// one wrongly called permanent needs a gateway restart to notice.
fn is_readiness_error(error: &Error) -> bool {
    // `TransportPermanent` is deliberately unlisted: it is the transport saying
    // the configuration cannot work, so retrying respawns a typo once a minute
    // forever. It falls through to the catch-all below.
    match error {
        // `TransportConnect` is a narrowing of `Transport`, so it classifies
        // identically here: a backend that cannot yet be connected to is the
        // canonical "not up yet".
        Error::Transport(_)
        | Error::TransportConnect(_)
        | Error::BackendTimeout(_)
        | Error::BackendUnavailable(_)
        // A stopped instance answers NotFound (`start_entry`'s shutdown-race
        // path); the next attempt re-resolves the name, reaching the instance
        // a reload put in its place.
        | Error::BackendNotFound(_) => true,
        Error::Io(e) => is_transient_io(e.kind()),
        // A response arrived, so the backend is up; only connect/timeout shapes
        // mean "not yet". A 4xx is the operator's configuration talking back.
        Error::Http(e) => e.is_connect() || e.is_timeout() || e.is_request(),
        _ => false,
    }
}

/// Whether an I/O failure describes a backend that may yet come up.
///
/// `NotFound` and `PermissionDenied` head the excluded list: waiting never fixes
/// either. See `is_readiness_error` for why that exclusion does not yet reach
/// stdio spawn failures, which arrive pre-flattened into a string.
const fn is_transient_io(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// How many times warm-start re-asks a backend that answered with no tools.
///
/// The budget is per warmer, and a warmer is bound to one backend instance
/// (`MIK-8054`): a replacement gets its own warmer with a fresh count.
///
/// A backend may register its tools a moment after it starts answering, so the
/// first empty list is not proof. It may also genuinely have none, so this is
/// bounded rather than endless -- polling and restarting a resource-only
/// backend for the gateway's lifetime would be the mirror mistake.
const EMPTY_TOOL_LISTS_BEFORE_ACCEPTING: u32 = 3;

/// How many consecutive rounds warm-start yields to the idle reaper before it
/// insists on one more fetch.
///
/// At the slow cadence this is five minutes of deference. Long enough that a
/// backend resting normally is left alone; short enough that "dormant with an
/// empty cache" cannot become permanent invisibility.
const DORMANT_YIELDS_BEFORE_RETRY: u32 = 5;

/// What warm-start should do about a backend the idle reaper has stopped.
#[derive(Debug, PartialEq, Eq)]
enum DormantAction {
    /// Someone else populated the cache; warm-start is finished.
    Done(usize),
    /// Leave it stopped this round and look again later.
    Yield,
    /// Deferring has not helped; fetch once more even though it restarts it.
    FetchAnyway,
}

/// Decide between deferring to the idle reaper and insisting on a fetch.
///
/// Two failure modes bracket this, and the first draft of this change hit one
/// of them. Treating dormancy as PERMANENT abandons a backend the reaper
/// stopped between two failed attempts, leaving its cache empty for the process
/// lifetime — the exact outage this change removes. Yielding FOREVER is the
/// mirror image: warm-start politely polls a backend it never fetches, and the
/// backend stays invisible until unrelated traffic happens to populate it.
///
/// So deference is bounded. Note that dormancy is already rare during the fast
/// phase, since the reaper needs an idle timeout to elapse first.
fn dormant_action(cached_tools: usize, consecutive_yields: u32) -> DormantAction {
    if cached_tools > 0 {
        return DormantAction::Done(cached_tools);
    }
    if consecutive_yields < DORMANT_YIELDS_BEFORE_RETRY {
        return DormantAction::Yield;
    }
    DormantAction::FetchAnyway
}

/// How many single-request timeouts one warm-start attempt is allowed.
///
/// Deliberately far above any plausible warm start. An attempt is not one
/// request — it connects or spawns, negotiates, may perform an authorization
/// exchange, and only then asks for the tool list — and review walked this
/// number up twice, first from 2, then from 6, each time with another phase
/// nobody had counted. Modelling the phases is the wrong fix: the count depends
/// on transport, auth and protocol version, and any number derived that way is
/// one unlisted phase away from being wrong again.
///
/// So this is not a budget for legitimate work. It is a HANG DETECTOR, set so
/// that only an attempt which has stopped making progress can trip it. The cost
/// of it being too large is one task sleeping longer before its next try; the
/// cost of it being too small is a backend that never becomes discoverable at
/// all, because every attempt is cancelled just before it succeeds.
const ATTEMPT_REQUEST_BUDGET: u32 = 20;

/// The ceiling to put on one warm-start attempt for a given backend.
///
/// A fixed global ceiling is a trap: it silently pre-empts any backend the
/// operator configured to take longer. So the ceiling is derived from the
/// operator's own setting, with the fixed value acting only as a floor for
/// backends configured faster than it.
///
/// The bound is kept rather than dropped in favour of the transport's own
/// timeouts, because a hang that outlives those is exactly what was observed on
/// this machine: the gateway logged `Health probe timed out` against hebb 29
/// times. An attempt that never returns is an attempt that never retries.
fn effective_attempt_timeout(floor: Duration, backend_timeout: Duration) -> Duration {
    floor.max(backend_timeout.saturating_mul(ATTEMPT_REQUEST_BUDGET))
}

/// Spread a gap uniformly over `[0, bound]`.
///
/// Every warm-start task is spawned in the same instant, so without this they
/// retry in lockstep and hit a machine that is already busy booting with a
/// synchronised burst.
fn jittered(bound: Duration) -> Duration {
    if bound.is_zero() {
        return bound;
    }
    let millis = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::random_range(0..=millis))
}

/// Call `attempt` until it caches tools or fails permanently.
///
/// Returns the number of tools cached, or `None` when the backend failed in a
/// way that waiting cannot fix.
///
/// There is no "give up" branch for readiness failures on purpose: the caller
/// runs this inside a `select!` against shutdown, so cancellation — not a
/// deadline — is what ends an endlessly unreachable backend. Putting a bound
/// here instead would recreate the original defect, where one missed attempt
/// left a backend undiscoverable until the gateway restarted.
async fn retry_warm_start_attempts<F, Fut, C>(
    name: &str,
    policy: &WarmStartPolicy,
    mut ceiling: C,
    mut attempt: F,
) -> Option<usize>
where
    C: FnMut() -> Duration,
    F: FnMut() -> Fut,
    Fut: Future<Output = crate::Result<usize>>,
{
    let started = tokio::time::Instant::now();
    let mut n = 0u32;
    let mut empty_lists = 0u32;

    loop {
        n += 1;
        let gap = jittered(gap_before_attempt(policy, n, started.elapsed()));
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }

        // Recomputed per attempt, not frozen at task start. A config reload can
        // replace a backend with one the operator allowed more time, and a
        // ceiling inherited from the old instance would cut every attempt short
        // — leaving the replacement permanently undiscoverable. Taken BEFORE the
        // call, so it never moves under a request already in flight.
        let attempt_ceiling = ceiling();
        match tokio::time::timeout(attempt_ceiling, attempt()).await {
            // An EMPTY tool list is not yet an answer. Discovery skips a backend
            // with an empty cache, so accepting the first empty result reports
            // "warm-started" about a backend nobody can find.
            //
            // Bounded, and it now RE-ASKS rather than re-reading: an empty
            // result is cached with a fresh timestamp like any other, so the
            // earlier version of this retry read the same cached emptiness back
            // within microseconds and never reached the backend at all. The
            // caller invalidates before each reconfirmation, which is the whole
            // reason `invalidate_tools_cache` exists.
            Ok(Ok(0)) if empty_lists < EMPTY_TOOL_LISTS_BEFORE_ACCEPTING => {
                empty_lists += 1;
                debug!(
                    backend = %name,
                    attempt = n,
                    "Backend reports no tools; re-asking rather than accepting a cached empty list"
                );
            }
            Ok(Ok(0)) => {
                debug!(
                    backend = %name,
                    attempt = n,
                    "Backend consistently reports no tools; accepting that it has none"
                );
                return Some(0);
            }
            Ok(Ok(tools)) => return Some(tools),
            // Superseded or shutting down: a quiet stop, not a failure.
            Ok(Err(Error::Shutdown)) => return None,
            Ok(Err(e)) if is_readiness_error(&e) => {
                debug!(backend = %name, attempt = n, error = %e, "Warm-start not ready, retrying");
            }
            Ok(Err(e)) => {
                warn!(
                    backend = %name,
                    attempt = n,
                    error = %e,
                    "Warm-start failed permanently; not retrying"
                );
                return None;
            }
            Err(_elapsed) => {
                debug!(
                    backend = %name,
                    attempt = n,
                    // The ceiling actually applied, not the policy floor: an
                    // operator debugging a slow backend needs the real deadline.
                    timeout_ms = attempt_ceiling.as_millis(),
                    "Warm-start attempt timed out, retrying"
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum WarmStartMode {
    Http,
    Stdio,
}

pub(super) fn build_warm_start_list(
    backends: &BackendRegistry,
    configured: &[String],
    announce_selection: bool,
) -> Vec<String> {
    resolve_warm_start_names(
        configured,
        backends
            .all()
            .iter()
            .map(|backend| backend.name.clone())
            .collect(),
        announce_selection,
    )
}

/// Whether a successful warm-start should immediately prefetch (and cache) the
/// backend's tool list.
///
/// Tool discovery (`gateway_search` / `tools/list`) only surfaces backends with
/// a populated tool cache; an empty cache is skipped. Subprocess backends
/// (codex, other stdio command servers) therefore stay invisible unless their
/// tools are prefetched here. This must happen in **both** transport modes —
/// the gateway is commonly run via `serve --stdio` (how Claude Code / Codex
/// connect), and gating prefetch on HTTP-only left every stdio-mode subprocess
/// backend with zero discoverable tools (MIK-4649).
const fn warm_start_prefetches_tools(mode: WarmStartMode) -> bool {
    // Both modes prefetch: stdio-mode subprocess backends were previously left
    // with empty tool caches and zero discoverable tools (MIK-4649).
    matches!(mode, WarmStartMode::Http | WarmStartMode::Stdio)
}

/// The one owner of every warm-start task, boot and hot reload alike
/// (`MIK-8054`): at most one warmer per backend name, each bound to the
/// instance it was scheduled for.
///
/// Held through [`WarmerGuard`]; reload hooks hold only a `Weak`, so dropping
/// the guard cancels every warmer on any exit path. Warm-start retries
/// indefinitely while a cache is empty, so a task that outlived the gateway
/// would keep contacting backends after it was gone.
pub(super) struct ReloadWarmer {
    backends: Arc<BackendRegistry>,
    mode: WarmStartMode,
    shutdown: Option<tokio::sync::broadcast::Sender<()>>,
    policy: Arc<WarmStartPolicy>,
    inner: std::sync::Mutex<WarmerInner>,
}

#[derive(Default)]
struct WarmerInner {
    /// Set by `cancel`, by dropping the guard, or by the first admission after
    /// the shutdown broadcast; nothing is scheduled once shutdown has begun.
    sealed: bool,
    /// Taken when the warmer is built, before anything can be sent, so it holds
    /// every shutdown broadcast. Read under this lock by every admission: a
    /// reload past its last stop check can still call the hook after the
    /// broadcast, and a task subscribed then would never hear it (`MIK-8128`).
    shutdown_seen: Option<tokio::sync::broadcast::Receiver<()>>,
    tasks: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl WarmerInner {
    /// Whether admission is closed: sealed, or shutdown already broadcast.
    fn closed(&mut self) -> bool {
        if !self.sealed
            && let Some(seen) = self.shutdown_seen.as_mut()
            && !matches!(
                seen.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            )
        {
            // A message, a lag or a closed channel all mean shutdown has begun.
            self.sealed = true;
        }
        self.sealed
    }
}

impl ReloadWarmer {
    fn lock(&self) -> std::sync::MutexGuard<'_, WarmerInner> {
        // A panic while scheduling leaves a map of handles, still usable.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Warm `names` now, replacing any earlier warmer per name. Returns the
    /// names scheduled.
    fn warm_locked(&self, inner: &mut WarmerInner, names: Vec<String>) -> Vec<String> {
        if inner.closed() {
            return Vec::new();
        }
        let mut scheduled = Vec::new();
        for name in names {
            let Some(instance) = self.backends.get(&name) else {
                if matches!(self.mode, WarmStartMode::Http) {
                    warn!(backend = %name, "Backend not found for warm-start");
                }
                continue;
            };
            let task = self.spawn(name.clone(), Arc::downgrade(&instance));
            if let Some(old) = inner.tasks.insert(name.clone(), task) {
                old.abort();
            }
            scheduled.push(name);
        }
        scheduled
    }

    /// A fully applied reload: stop the warmer of every replaced or removed
    /// backend FIRST, then warm the registered ones the published config
    /// selects. An excluded replacement is left with no warmer at all.
    fn apply(&self, change: &RegisteredChange, config: &Config) -> Vec<String> {
        let mut inner = self.lock();
        if inner.closed() {
            return Vec::new();
        }
        for name in change.registered.iter().chain(&change.removed) {
            if let Some(old) = inner.tasks.remove(name) {
                old.abort();
            }
        }
        let wanted = &config.meta_mcp.warm_start;
        let selected = change
            .registered
            .iter()
            .filter(|name| wanted.is_empty() || wanted.contains(name))
            .cloned()
            .collect();
        self.warm_locked(&mut inner, selected)
    }

    /// Seal, then abort every task, without waiting for them to unwind.
    fn seal_and_abort(&self) {
        let mut inner = self.lock();
        inner.sealed = true;
        for (_, task) in inner.tasks.drain() {
            task.abort();
        }
    }

    fn spawn(&self, name: String, instance: Weak<Backend>) -> tokio::task::JoinHandle<()> {
        let backends = Arc::clone(&self.backends);
        let policy = Arc::clone(&self.policy);
        let mode = self.mode;
        // Each task needs its own receiver; stdio mode has no channel at all and
        // is cancelled by aborting these handles instead.
        let mut shutdown = self
            .shutdown
            .as_ref()
            .map(tokio::sync::broadcast::Sender::subscribe);
        tokio::spawn(async move {
            let work = warm_start_until_cached(&backends, &name, &policy, mode, &instance);
            match shutdown.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        () = work => {}
                        _ = rx.recv() => {
                            debug!(backend = %name, "Warm-start cancelled by shutdown");
                        }
                    }
                }
                None => work.await,
            }
        })
    }
}

/// Owns the [`ReloadWarmer`]; dropping it seals the warmer and aborts every
/// task, whatever still holds a reload hook.
#[must_use = "dropping the guard aborts warm-start immediately"]
pub(super) struct WarmerGuard(Arc<ReloadWarmer>);

impl WarmerGuard {
    pub(super) fn new(
        backends: &Arc<BackendRegistry>,
        mode: WarmStartMode,
        shutdown: Option<&tokio::sync::broadcast::Sender<()>>,
    ) -> Self {
        Self(Arc::new(ReloadWarmer {
            backends: Arc::clone(backends),
            mode,
            shutdown: shutdown.cloned(),
            policy: Arc::new(WarmStartPolicy::default()),
            inner: std::sync::Mutex::new(WarmerInner {
                shutdown_seen: shutdown.map(tokio::sync::broadcast::Sender::subscribe),
                ..WarmerInner::default()
            }),
        }))
    }

    /// Warm `names` (boot). Returns the names scheduled.
    pub(super) fn warm(&self, names: Vec<String>) -> Vec<String> {
        let mut inner = self.0.lock();
        self.0.warm_locked(&mut inner, names)
    }

    /// The hook a reload context reports to. Holds the warmer weakly: once the
    /// guard is gone the hook does nothing.
    pub(super) fn hook(&self) -> OnRegistered {
        let warmer = Arc::downgrade(&self.0);
        Arc::new(move |change: &RegisteredChange, config: &Config| {
            if let Some(warmer) = warmer.upgrade() {
                warmer.apply(change, config);
            }
        })
    }

    /// Seal, abort every task, and wait for them to finish unwinding.
    ///
    /// Callers about to stop the backends use this rather than the `Drop`
    /// impl: an abort is asynchronous, so a task mid-`ensure_started` would
    /// otherwise still be starting a backend while shutdown drains it.
    pub(super) async fn cancel(self) {
        let tasks: Vec<_> = {
            let mut inner = self.0.lock();
            inner.sealed = true;
            inner.tasks.drain().map(|(_, task)| task).collect()
        };
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            // A cancelled task reports `JoinError::Cancelled`; expected here.
            let _ = task.await;
        }
    }

    #[cfg(test)]
    pub(super) fn abort_handles(&self) -> Vec<tokio::task::AbortHandle> {
        self.0
            .lock()
            .tasks
            .values()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect()
    }
}

impl Drop for WarmerGuard {
    fn drop(&mut self) {
        self.0.seal_and_abort();
    }
}

/// Retry until this backend's tools are cached, or until retrying is pointless.
///
/// The exit condition is **cache presence**, not process liveness, because that
/// is what discovery reads: `backend_tools_for_discovery` returns a backend's
/// tools only if the cache is non-empty, and a plain semantic query fills an
/// empty one only in the background, after it has answered.
async fn warm_start_until_cached(
    backends: &Arc<BackendRegistry>,
    name: &str,
    policy: &WarmStartPolicy,
    mode: WarmStartMode,
    instance: &Weak<Backend>,
) {
    // Prefetch is what fills the cache, so without it there is nothing for this
    // loop to wait for. Handled before the loop rather than inside it: an
    // attempt that cannot produce tools would otherwise retry forever against a
    // condition it can never satisfy.
    if !warm_start_prefetches_tools(mode) {
        if let Some(backend) = backends.get(name)
            && let Err(e) = backend.ensure_started().await
        {
            warn!(backend = %name, error = %e, "Warm-start failed");
        }
        return;
    }

    // Shared rather than borrowed: each attempt is an async block that outlives
    // the closure call, so a plain `&mut` counter cannot escape into it.
    let dormant_yields = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // Set when an attempt came back with no tools, so the NEXT attempt knows to
    // discard the cached emptiness and actually re-ask.
    let saw_empty_list = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let outcome = retry_warm_start_attempts(
        name,
        policy,
        // Recomputed per attempt against whichever instance is registered now,
        // so a reload that raises a backend's timeout raises this ceiling too.
        || {
            backends.get(name).map_or(policy.attempt_timeout, |backend| {
                effective_attempt_timeout(policy.attempt_timeout, backend.request_timeout())
            })
        },
        || {
            let dormant_yields = Arc::clone(&dormant_yields);
            let saw_empty_list = Arc::clone(&saw_empty_list);
            async move {
            // Resolved per attempt, never captured: a config reload can replace
            // the instance under us, and a task holding the old `Arc` would keep
            // reviving a discarded object while the live one stayed empty.
            let backend = backends
                .get(name)
                .ok_or_else(|| Error::BackendUnavailable(name.to_string()))?;
            // Bound to the instance it was scheduled for (`MIK-8054`): a newer
            // one has its own warmer, or none if the reload excluded it, so this
            // task must never act on it. The `Weak` keeps the allocation, so the
            // address cannot be reused by another instance.
            if !std::ptr::eq(instance.as_ptr(), Arc::as_ptr(&backend)) {
                debug!(backend = %name, "Warm-start superseded by a newer instance");
                return Err(Error::Shutdown);
            }

            // Deference to the idle reaper, bounded. Restarting a backend it
            // deliberately stopped fights it; deferring forever leaves the
            // backend invisible, since a cache nobody fetches is a cache
            // discovery skips.
            let ordering = std::sync::atomic::Ordering::SeqCst;
            if backend.lifecycle() == crate::backend::BackendLifecycle::Dormant {
                match dormant_action(backend.cached_tools_count(), dormant_yields.load(ordering)) {
                    DormantAction::Done(tools) => return Ok(tools),
                    DormantAction::Yield => {
                        dormant_yields.fetch_add(1, ordering);
                        return Err(Error::BackendUnavailable(format!(
                            "{name} is dormant; yielding to the idle reaper"
                        )));
                    }
                    DormantAction::FetchAnyway => {
                        dormant_yields.store(0, ordering);
                        debug!(
                            backend = %name,
                            "Dormant with an empty tool cache; fetching once rather than staying invisible"
                        );
                    }
                }
            } else {
                dormant_yields.store(0, ordering);
            }

            // `ensure_started`, never `start`: the latter builds a fresh
            // transport unconditionally, so a retry could replace a transport
            // that ordinary traffic established between attempts and spawn a
            // duplicate subprocess.
            backend.ensure_started().await?;

            // Reconfirming an empty list means ASKING again. Without this the
            // cached empty answer is served straight back, and the bounded retry
            // above observes nothing it has not already seen.
            if saw_empty_list.swap(false, ordering) {
                backend.invalidate_tools_cache();
            }
            let count = backend.warm_tools().await.map(|tools| tools.len())?;
            if count == 0 {
                saw_empty_list.store(true, ordering);
            }
            Ok(count)
            }
        },
    )
    .await;

    if let Some(tools) = outcome {
        info!(backend = %name, tools, "Warm-started + tools cached");
    }
}

fn resolve_warm_start_names(
    configured: &[String],
    all_names: Vec<String>,
    announce_selection: bool,
) -> Vec<String> {
    if configured.is_empty() {
        if announce_selection {
            info!(
                "Warm-starting ALL {} backends (tool prefetch)",
                all_names.len()
            );
        }
        all_names
    } else {
        if announce_selection {
            info!("Warm-starting backends: {:?}", configured);
        }
        configured.to_vec()
    }
}

#[cfg(test)]
mod hot_reload_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod warmer_tests;
