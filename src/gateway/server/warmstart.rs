// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend warm-start orchestration shared by HTTP and stdio server modes.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::Error;
use crate::backend::BackendRegistry;

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
/// Deliberately enumerated rather than delegated to `chains::retry_step`, whose
/// predicate rejects `BackendUnavailable` — the variant `start_entry` returns
/// while a backend is mid-lifecycle. Since the slow phase runs indefinitely,
/// anything not listed here must stop the loop: no amount of waiting turns an
/// unsupported protocol version into a working backend.
///
/// KNOWN LIMITATION, measured rather than assumed. The transport layer flattens
/// its failures into `Error::Transport(String)` — `stdio.rs` maps a spawn
/// failure to `Transport("Failed to spawn: …")` — so a mistyped command path is
/// indistinguishable here from a port that is not listening yet, and both are
/// retried. Classifying it properly means preserving typed errors across the
/// transport boundary, which is a change to every backend call path rather than
/// to warm-start. Filed, not bodged: string-matching the message would be a
/// guess that breaks the first time the wording changes.
///
/// The `Io` narrowing below therefore protects only the paths that do surface a
/// typed error today. It is correct, and it is not the whole story.
fn is_readiness_error(error: &Error) -> bool {
    match error {
        Error::Transport(_) | Error::BackendTimeout(_) | Error::BackendUnavailable(_) => true,
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

/// Aborts the warm-start tasks it owns when dropped.
///
/// Stdio mode has no broadcast shutdown channel, so the tasks are cancelled by
/// aborting their handles. Aborting them at the EOF path alone is not enough:
/// an embedded host that cancels `run_stdio` never reaches that line, and the
/// handles are simply dropped, which DETACHES the tasks rather than stopping
/// them. Since warm-start now retries indefinitely while a tool cache is empty,
/// a detached task keeps the backend registry alive and keeps contacting
/// backends after the gateway is gone. Tying the abort to the guard's lifetime
/// makes every exit path — return, error, cancellation — behave the same.
pub(super) struct WarmStartTasks(Vec<tokio::task::JoinHandle<()>>);

impl WarmStartTasks {
    /// Abort the retry tasks and wait for them to finish unwinding.
    ///
    /// Callers that are about to stop the backends should use this rather than
    /// relying on the `Drop` impl: an abort is asynchronous, so a task that is
    /// mid-`ensure_started` would otherwise still be starting a backend while
    /// shutdown drains it, delaying the drain and logging starts nobody wants.
    pub(super) async fn cancel(mut self) {
        for handle in &self.0 {
            handle.abort();
        }
        for handle in std::mem::take(&mut self.0) {
            // A cancelled task reports `JoinError::Cancelled`; that is the
            // expected outcome here, not a failure.
            let _ = handle.await;
        }
    }
}

impl Drop for WarmStartTasks {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Returns a guard that must be held for as long as warm-start should run:
/// dropping it aborts every retry task.
#[must_use = "dropping the returned guard aborts warm-start immediately"]
pub(super) fn spawn_warm_start_task(
    backends: &Arc<BackendRegistry>,
    warm_start_list: Vec<String>,
    mode: WarmStartMode,
    shutdown: Option<&tokio::sync::broadcast::Sender<()>>,
) -> WarmStartTasks {
    let policy = Arc::new(WarmStartPolicy::default());
    let mut handles = Vec::new();

    for name in warm_start_list {
        let backends = Arc::clone(backends);
        let policy = Arc::clone(&policy);
        // Each task needs its own receiver; stdio mode has no channel at all and
        // is cancelled by aborting these handles instead.
        let mut shutdown = shutdown.map(tokio::sync::broadcast::Sender::subscribe);

        handles.push(tokio::spawn(async move {
            if backends.get(&name).is_none() {
                if matches!(mode, WarmStartMode::Http) {
                    warn!(backend = %name, "Backend not found for warm-start");
                }
                return;
            }

            let work = warm_start_until_cached(&backends, &name, &policy, mode);

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
        }));
    }

    WarmStartTasks(handles)
}

/// Retry until this backend's tools are cached, or until retrying is pointless.
///
/// The exit condition is **cache presence**, not process liveness, because that
/// is what discovery reads: `backend_tools_for_discovery` returns a backend's
/// tools only if the cache is non-empty, and a plain semantic query never fills
/// an empty one.
async fn warm_start_until_cached(
    backends: &Arc<BackendRegistry>,
    name: &str,
    policy: &WarmStartPolicy,
    mode: WarmStartMode,
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
            let count = backend.get_tools_shared().await.map(|tools| tools.len())?;
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
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::{
        ATTEMPT_REQUEST_BUDGET, DORMANT_YIELDS_BEFORE_RETRY, DormantAction,
        EMPTY_TOOL_LISTS_BEFORE_ACCEPTING, WarmStartMode, WarmStartPolicy, dormant_action,
        effective_attempt_timeout, gap_before_attempt, is_readiness_error,
        resolve_warm_start_names, retry_warm_start_attempts, spawn_warm_start_task,
        warm_start_prefetches_tools,
    };
    use crate::Error;

    /// The per-attempt ceiling for tests that are not exercising it.
    fn no_extra_ceiling() -> impl FnMut() -> Duration {
        || WarmStartPolicy::default().attempt_timeout
    }

    /// A backend that refuses `refusals` times, then answers with `tools` tools.
    fn flaky(
        refusals: u32,
        tools: usize,
    ) -> (
        Arc<AtomicU32>,
        impl FnMut() -> std::future::Ready<crate::Result<usize>>,
    ) {
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let f = move || {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if n < refusals {
                Err(Error::Transport("connection refused".to_string()))
            } else {
                Ok(tools)
            })
        };
        (calls, f)
    }

    #[test]
    fn warm_start_prefetches_tools_in_both_modes() {
        // Tool prefetch must happen regardless of transport mode. Gating it on
        // HTTP-only left every stdio-mode subprocess backend (e.g. codex) with
        // an empty tool cache, so its tools never appeared in discovery
        // (MIK-4649).
        assert!(
            warm_start_prefetches_tools(WarmStartMode::Http),
            "HTTP mode must prefetch tools"
        );
        assert!(
            warm_start_prefetches_tools(WarmStartMode::Stdio),
            "Stdio mode must prefetch tools (MIK-4649: codex tools were invisible)"
        );
    }

    #[test]
    fn resolve_warm_start_names_uses_all_backends_when_config_is_empty() {
        let resolved = resolve_warm_start_names(&[], vec!["a".to_string(), "b".to_string()], false);

        assert_eq!(resolved, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn resolve_warm_start_names_prefers_configured_list() {
        let resolved = resolve_warm_start_names(
            &["configured".to_string()],
            vec!["a".to_string(), "b".to_string()],
            false,
        );

        assert_eq!(resolved, vec!["configured".to_string()]);
    }

    // ── Case 10/17: which errors mean "not ready yet" ────────────────────────

    #[test]
    fn readiness_errors_are_retried() {
        // All five can mean the sibling daemon has not finished booting. The two
        // observed in production were Transport (hebb, netdata) and
        // BackendTimeout (context7); BackendUnavailable comes from start_entry's
        // shutdown-race path, which `chains::retry_step` would have treated as
        // permanent -- the reason that helper was not reused.
        for e in [
            Error::Transport("refused".to_string()),
            Error::BackendTimeout("hebb".to_string()),
            Error::BackendUnavailable("hebb".to_string()),
            // The shape hebb actually produced: the port was not yet bound.
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
        ] {
            assert!(is_readiness_error(&e), "{e} must be retried");
        }
    }

    #[test]
    fn permanent_errors_stop_the_loop() {
        // The slow phase runs indefinitely. Without this, a misconfigured or
        // unauthenticated backend would be contacted -- or respawned -- forever.
        for e in [
            Error::Config("no such command".to_string()),
            Error::Protocol("unsupported version".to_string()),
            // The two that matter most: a mistyped command path and a binary
            // that is not executable. Both arrive as Io and both are forever.
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such file",
            )),
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not executable",
            )),
        ] {
            assert!(!is_readiness_error(&e), "{e} must not be retried");
        }
    }

    // ── Case 3/8: the schedule ───────────────────────────────────────────────

    #[test]
    fn fast_phase_gaps_double_up_to_the_cap() {
        let p = WarmStartPolicy::default();

        assert_eq!(gap_before_attempt(&p, 1, Duration::ZERO), Duration::ZERO);
        assert_eq!(gap_before_attempt(&p, 2, Duration::ZERO), p.initial_gap);
        assert_eq!(gap_before_attempt(&p, 3, Duration::ZERO), p.initial_gap * 2);
        assert_eq!(
            gap_before_attempt(&p, 20, Duration::ZERO),
            p.max_gap,
            "doubling must saturate at the cap, not overflow"
        );
    }

    #[test]
    fn past_the_deadline_the_schedule_switches_to_the_slow_gap() {
        // The switch is keyed on ELAPSED time, not attempt count: an attempt
        // count says nothing about wall-clock when each attempt can itself
        // block for its own timeout.
        let p = WarmStartPolicy::default();

        assert_eq!(
            gap_before_attempt(&p, 3, p.fast_deadline + Duration::from_secs(1)),
            p.slow_gap
        );
        assert_ne!(
            gap_before_attempt(&p, 3, Duration::from_secs(1)),
            p.slow_gap,
            "still inside the fast phase"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_reachable_backend_makes_exactly_one_attempt() {
        let (calls, attempt) = flaky(0, 3);

        let cached = retry_warm_start_attempts(
            "ready",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(cached, Some(3));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no retry when the first attempt works"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_becomes_reachable_later_is_still_cached() {
        // The production race: hebb-serve was loading ONNX models while the
        // gateway made its single attempt, so the tool cache stayed empty for
        // the whole 1.5-day process lifetime.
        let (calls, attempt) = flaky(4, 7);

        let cached = retry_warm_start_attempts(
            "hebb",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(cached, Some(7));
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_tool_list_is_re_asked_a_bounded_number_of_times() {
        // A backend may register its tools a moment after it starts answering,
        // so the first empty list is not proof. It may also genuinely have none,
        // so the re-asking is bounded rather than endless.
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let attempt = move || {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(if n < 2 { 0 } else { 4 }))
        };

        let cached = retry_warm_start_attempts(
            "late-registrar",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(
            cached,
            Some(4),
            "the tools that appeared late must be picked up"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_really_has_no_tools_is_accepted() {
        // The mirror case: a resource-only backend must not be re-asked and
        // restarted for the gateway's lifetime just because it exposes no tools.
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let attempt = move || {
            seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(0))
        };

        let cached = retry_warm_start_attempts(
            "resources-only",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(cached, Some(0));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            EMPTY_TOOL_LISTS_BEFORE_ACCEPTING + 1,
            "bounded: a few chances to register tools, then believed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanently_broken_backend_stops_without_looping() {
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let attempt = move || {
            seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(Error::Config("bad command".to_string())))
        };

        let cached = retry_warm_start_attempts(
            "broken",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(cached, None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a permanent error is not retried"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_attempt_is_timed_out_and_retried() {
        // A hung attempt must not be mistaken for success, and must not pin the
        // loop forever: the wrapper bounds it and the next attempt proceeds.
        let calls = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&calls);
        let attempt = move || {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    // Outlives attempt_timeout, so the wrapper cancels it.
                    tokio::time::sleep(Duration::from_secs(600)).await;
                }
                Ok(2)
            }
        };

        let cached = retry_warm_start_attempts(
            "hung",
            &WarmStartPolicy::default(),
            no_extra_ceiling(),
            attempt,
        )
        .await;

        assert_eq!(cached, Some(2));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the hung attempt was retried, not accepted as success"
        );
    }

    // ── Case 15: dormancy yields, and must never abandon ─────────────────────

    #[test]
    fn the_attempt_ceiling_follows_the_operators_backend_timeout() {
        // A fixed ceiling pre-empts any backend configured to take longer, and a
        // backend whose every attempt is cut short never becomes discoverable --
        // this change's own bug, reintroduced by the valve meant to bound it.
        let floor = WarmStartPolicy::default().attempt_timeout;

        assert_eq!(
            effective_attempt_timeout(floor, Duration::from_secs(5)),
            floor,
            "a backend whose whole budget fits under the floor does not lower it"
        );
        assert_eq!(
            effective_attempt_timeout(floor, Duration::from_secs(30)),
            Duration::from_secs(30) * ATTEMPT_REQUEST_BUDGET,
            "hebb's own 30s config gets a hang-detector ceiling, not a budget \
             sized to a guess about how many requests a start makes"
        );
        assert_eq!(
            effective_attempt_timeout(floor, Duration::from_secs(300)),
            Duration::from_secs(300) * ATTEMPT_REQUEST_BUDGET,
            "a backend configured slower than the floor raises the ceiling"
        );
        assert_eq!(
            effective_attempt_timeout(floor, Duration::MAX),
            Duration::MAX,
            "doubling must saturate rather than overflow"
        );
    }

    #[test]
    fn a_dormant_backend_with_an_empty_cache_is_retried_not_abandoned() {
        // REGRESSION. The first draft returned a permanent error here, so a
        // backend the idle reaper stopped between two failed attempts was
        // abandoned with an empty cache -- reintroducing the exact
        // process-lifetime invisibility this change removes.
        assert_eq!(dormant_action(0, 0), DormantAction::Yield);
    }

    #[test]
    fn deference_to_the_idle_reaper_is_bounded() {
        // The mirror failure, raised in final review: yielding forever means
        // warm-start politely polls a backend it never fetches, so the backend
        // stays invisible until unrelated traffic happens to populate it.
        assert_eq!(
            dormant_action(0, DORMANT_YIELDS_BEFORE_RETRY),
            DormantAction::FetchAnyway,
            "after bounded deference, warm-start must fetch rather than poll forever"
        );
    }

    #[test]
    fn a_dormant_backend_whose_cache_was_filled_elsewhere_finishes() {
        // Ordinary traffic may populate the cache while warm-start waits. The
        // exit condition is cache presence, so that ends the loop -- continuing
        // would restart a backend the reaper deliberately stopped.
        assert_eq!(dormant_action(4, 0), DormantAction::Done(4));
        assert_eq!(
            dormant_action(4, DORMANT_YIELDS_BEFORE_RETRY),
            DormantAction::Done(4),
            "a populated cache wins regardless of how long deference has run"
        );
    }

    // ── Case 16: the guard cancels, on every exit path ───────────────────────

    #[tokio::test]
    async fn dropping_the_guard_aborts_the_retry_tasks() {
        // REGRESSION for a trap this change introduced: warm-start now retries
        // indefinitely, so a handle that is dropped rather than aborted leaves a
        // detached task holding the registry and contacting backends after the
        // gateway is gone. Stdio mode has no shutdown channel, so the guard is
        // the only thing that stops them.
        let backends = Arc::new(crate::backend::BackendRegistry::new());
        assert!(backends.register(unreachable_backend("never-up")));

        let guard = spawn_warm_start_task(
            &backends,
            vec!["never-up".to_string()],
            WarmStartMode::Http,
            None,
        );
        let probes: Vec<_> = guard
            .0
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect();
        assert_eq!(probes.len(), 1);

        tokio::task::yield_now().await;
        assert!(
            !probes[0].is_finished(),
            "the task must still be retrying an unreachable backend"
        );

        drop(guard);
        tokio::task::yield_now().await;

        assert!(
            probes[0].is_finished(),
            "dropping the guard must abort the task, not detach it"
        );
    }

    /// A backend that is reachable in principle but has nothing listening, so
    /// every attempt fails as "not ready yet" and the loop keeps going.
    ///
    /// Deliberately NOT a nonexistent command: that now fails permanently (a
    /// mistyped path is not a readiness problem), so the retry loop would exit
    /// and this fixture would prove nothing about cancellation.
    fn unreachable_backend(name: &str) -> Arc<crate::backend::Backend> {
        let cfg = crate::config::BackendConfig {
            transport: crate::config::TransportConfig::Http {
                // Port 1 on loopback: refused immediately, no timeout wait.
                http_url: "http://127.0.0.1:1/mcp".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        };
        Arc::new(crate::backend::Backend::new(
            name,
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    }
}
