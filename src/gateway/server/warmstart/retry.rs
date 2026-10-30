// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How warm-start retries a backend until its tools are cached: the policy,
//! the gap before each attempt, which errors mean "not up yet", the empty-list
//! and dormant budgets, and the attempt loop. Moved from `warmstart.rs` for the
//! file-size ceiling.

use std::future::Future;
use std::time::Duration;

use tracing::{debug, warn};

use crate::Error;
use crate::jitter::full_jitter;

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
pub(super) fn gap_before_attempt(
    policy: &WarmStartPolicy,
    attempt: u32,
    elapsed: Duration,
) -> Duration {
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
pub(super) fn is_readiness_error(error: &Error) -> bool {
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
/// The budget is per warmer, and a warmer is bound to one backend instance:
/// a replacement gets its own warmer with a fresh count.
///
/// A backend may register its tools a moment after it starts answering, so the
/// first empty list is not proof. It may also genuinely have none, so this is
/// bounded rather than endless -- polling and restarting a resource-only
/// backend for the gateway's lifetime would be the mirror mistake.
pub(super) const EMPTY_TOOL_LISTS_BEFORE_ACCEPTING: u32 = 3;

/// How many consecutive rounds warm-start yields to the idle reaper before it
/// insists on one more fetch.
///
/// At the slow cadence this is five minutes of deference. Long enough that a
/// backend resting normally is left alone; short enough that "dormant with an
/// empty cache" cannot become permanent invisibility.
pub(super) const DORMANT_YIELDS_BEFORE_RETRY: u32 = 5;

/// What warm-start should do about a backend the idle reaper has stopped.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DormantAction {
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
pub(super) fn dormant_action(cached_tools: usize, consecutive_yields: u32) -> DormantAction {
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
pub(super) const ATTEMPT_REQUEST_BUDGET: u32 = 20;

/// The ceiling to put on one warm-start attempt for a given backend.
///
/// A fixed global ceiling is a trap: it silently pre-empts any backend the
/// operator configured to take longer. So the ceiling is derived from the
/// operator's own setting, with the fixed value acting only as a floor for
/// backends configured faster than it.
///
/// The bound is kept rather than dropped in favour of the transport's own
/// timeouts, because a hang that outlives those is exactly what was observed on
/// this machine: the gateway logged `Health probe timed out` against a memory backend 29
/// times. An attempt that never returns is an attempt that never retries.
pub(super) fn effective_attempt_timeout(floor: Duration, backend_timeout: Duration) -> Duration {
    floor.max(backend_timeout.saturating_mul(ATTEMPT_REQUEST_BUDGET))
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
pub(super) async fn retry_warm_start_attempts<F, Fut, C>(
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
        let gap = full_jitter(gap_before_attempt(policy, n, started.elapsed()));
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
