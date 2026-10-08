// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::{
    ATTEMPT_REQUEST_BUDGET, DORMANT_YIELDS_BEFORE_RETRY, DormantAction,
    EMPTY_TOOL_LISTS_BEFORE_ACCEPTING, WarmStartMode, WarmStartPolicy, WarmerGuard, dormant_action,
    effective_attempt_timeout, gap_before_attempt, is_readiness_error, resolve_warm_start_names,
    retry_warm_start_attempts, warm_start_prefetches_tools,
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
    // Each can mean the sibling daemon has not finished booting. The two
    // observed in production were Transport (hebb, netdata) and
    // BackendTimeout (context7); BackendNotFound comes from start_entry's
    // shutdown-race path (a stopped, replaced instance), which
    // `chains::retry_step` would have treated as permanent -- the reason that
    // helper was not reused.
    for e in [
        Error::Transport("refused".to_string()),
        Error::BackendTimeout("hebb".to_string()),
        Error::BackendUnavailable("hebb".to_string()),
        Error::BackendNotFound("hebb".to_string()),
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
fn a_transport_failure_the_transport_calls_permanent_stops_the_loop() {
    // The whole point of the typed variant. Before it, a mistyped command
    // path arrived as plain `Transport` and was respawned once a minute for
    // the life of the process, with nothing saying the config was wrong.
    let e = Error::TransportPermanent("Failed to spawn: no such file".to_string());

    assert!(
        !is_readiness_error(&e),
        "a permanent transport failure must stop the loop"
    );
}

#[test]
fn an_unclassified_transport_failure_is_still_retried() {
    // The safe direction of error: most of the ~59 construction sites do not
    // know whether their failure is permanent, so they still say `Transport`
    // and are still retried. A recoverable failure wrongly called permanent
    // would need a gateway restart to notice.
    let e = Error::Transport("connection refused".to_string());

    assert!(
        is_readiness_error(&e),
        "an unknown transport failure must stay retryable"
    );
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

/// MIK-7217.DISCOVER.6 — warm-start keeps its existing retry schedule when
/// `server/discover` replaces the probe.
///
/// Absolute values on purpose. The tests either side of this one assert
/// RELATIONSHIPS (`gap == p.initial_gap`, `gap == p.initial_gap * 2`), so
/// they hold no matter what the defaults become — changing `initial_gap`
/// from two seconds to sixty passes every one of them. Discovery makes each
/// probe cheaper, which is exactly the argument someone will use for
/// probing more often; this is what makes that a decision rather than a
/// drift.
#[test]
fn ac_discover_6_the_retry_schedule_is_pinned_in_seconds() {
    let p = WarmStartPolicy::default();

    assert_eq!(p.fast_deadline, Duration::from_secs(180));
    assert_eq!(p.initial_gap, Duration::from_secs(2));
    assert_eq!(p.max_gap, Duration::from_secs(30));
    assert_eq!(p.slow_gap, Duration::from_secs(60));
    assert_eq!(p.attempt_timeout, Duration::from_secs(120));

    // The fast phase, attempt by attempt, before jitter.
    let fast: Vec<u64> = (1..=8)
        .map(|n| gap_before_attempt(&p, n, Duration::ZERO).as_secs())
        .collect();
    assert_eq!(
        fast,
        vec![0, 2, 4, 8, 16, 30, 30, 30],
        "the fast phase doubles from two seconds and holds at the cap"
    );

    // And after the deadline, one gap regardless of attempt number.
    for n in [2, 5, 50] {
        assert_eq!(
            gap_before_attempt(&p, n, p.fast_deadline).as_secs(),
            60,
            "past the deadline every gap is the slow gap"
        );
    }
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

    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    assert_eq!(guard.warm(vec!["never-up".to_string()]), ["never-up"]);
    let probes = guard.abort_handles();
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
            streamable_http: Some(false),
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
