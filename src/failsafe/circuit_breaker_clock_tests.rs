// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b rows B4 and B4o (runtime-red): the breaker's open-state age is
//! monotonic, and a trip it cannot date is rendered "unknown".

use super::*;
use crate::clock::test_clock;

fn one_failure_trips(reset_timeout: Duration) -> CircuitBreaker {
    CircuitBreaker::new(
        "clock",
        &CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            reset_timeout,
        },
    )
}

/// MIK-8202 AC.2, P4b design r1 B4 (kept by r4): breaker timing moves to a
/// monotonic instant, so an open breaker half-opens after its reset timeout
/// while the wall clock reads before 1970. Required seam: the open-state age
/// is measured on `tokio::time::Instant`, which paused time advances.
///
/// Red on base: base dates the transition by reading the wall clock directly;
/// paused time does not move it and real time barely moves during the test,
/// so after the paused advance the breaker is still open and the post-advance
/// assertion fails.
///
/// Mutant B4m (the open-state age read from `crate::clock`'s wall clock): on the
/// dark clock an error taken as "not elapsed" never half-opens (killed by the
/// post-advance assertion); one taken as an ancient stamp half-opens at once
/// (killed by the pre-advance negative).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_open_breaker_half_opens_after_its_timeout_while_the_clock_is_dark() {
    let _clock = test_clock::before_epoch();
    let reset_timeout = Duration::from_secs(30);
    let cb = one_failure_trips(reset_timeout);
    cb.record_failure("down", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Open);

    tokio::time::advance(reset_timeout.saturating_sub(Duration::from_secs(1))).await;
    assert!(
        !cb.can_proceed(),
        "B4 pre-advance: an open breaker stays open before its reset timeout"
    );
    assert_eq!(cb.state(), CircuitState::Open);

    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        cb.can_proceed(),
        "B4: an open breaker half-opens after its reset timeout though the wall clock is dark"
    );
    assert_eq!(cb.state(), CircuitState::HalfOpen);
}

/// MIK-8202 AC.2, P4b design r1 B4 (stats/error text): a trip on a dark clock
/// has no wall-clock time, and the blocked-request message says "unknown"
/// instead of a time measured from 0.
///
/// Red on base: base stamps the trip by reading the wall clock directly, so
/// the stats carry a real time and the message reads "Opened ~0ms ago"; the
/// "unknown" assertion fails.
///
/// Mutant B4om (the trip stamped 0 on Err): the renderer treats 0 as a time
/// ("Opened ~0ms ago"), killed by the "unknown" assertion.
#[test]
fn a_trip_on_a_dark_clock_is_reported_at_an_unknown_time() {
    let _clock = test_clock::before_epoch();
    let cb = one_failure_trips(Duration::from_secs(30));
    cb.record_failure("down", Duration::ZERO);
    let stats = cb.stats();
    assert_eq!(stats.state, CircuitState::Open);
    let message = build_circuit_breaker_error("clock", &stats);
    assert!(
        message.contains("unknown"),
        "B4o: an undated trip is rendered unknown: {message}"
    );
}

/// Z-breaker (MIK-8202 P4b, lead): the breaker keeps an undated trip as an
/// internal 0, which is safe only if no read path ever reports that 0 as a
/// date. A dated trip reads back as its time; a later trip on a dark clock
/// reads back as no time (never 0, never the old time) in the stats and the
/// error text (the status JSON copies the stats field verbatim), and a clock
/// that reads again afterwards does not date it.
/// Mutant: `stats()` maps the stored 0 to `Some(0)`: killed at "a dark trip
/// is reported undated".
#[test]
fn no_read_path_reports_the_undated_trip_placeholder_as_a_date() {
    const T: u64 = 1_700_000_000;
    let cb = one_failure_trips(Duration::ZERO);
    {
        let _clock = test_clock::at_secs(T);
        cb.record_failure("down", Duration::ZERO);
        assert_eq!(
            cb.stats().last_trip_ms,
            Some(T * 1_000),
            "premise: a dated trip"
        );
        assert!(cb.can_proceed(), "premise: a zero reset half-opens at once");
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed, "premise: closed again");
    }
    {
        let _clock = test_clock::before_epoch();
        cb.record_failure("down", Duration::ZERO);
        let stats = cb.stats();
        assert_eq!(stats.last_trip_ms, None, "a dark trip is reported undated");
        let message = build_circuit_breaker_error("clock", &stats);
        assert!(
            message.contains("Opened an unknown time ago") && !message.contains("Opened ~"),
            "error text: {message}"
        );
    }
    let _clock = test_clock::at_secs(T + 60);
    assert_eq!(
        cb.stats().last_trip_ms,
        None,
        "a later reading dated the dark trip"
    );
}
