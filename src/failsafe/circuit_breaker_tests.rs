// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Circuit-breaker state machine, thresholds, half-open probing and error classification tests.

use super::*;

fn make_config(failure_threshold: u32) -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    }
}

// ── CircuitState::as_str ──────────────────────────────────────────────

#[test]
fn circuit_state_as_str_returns_lowercase_snake_case() {
    assert_eq!(CircuitState::Closed.as_str(), "closed");
    assert_eq!(CircuitState::Open.as_str(), "open");
    assert_eq!(CircuitState::HalfOpen.as_str(), "half_open");
}

/// B6: the wire form is pinned to literals, variant by variant, and agrees
/// with `as_str`. `kebab-case` would change only `HalfOpen`, which a check
/// on `Open` alone misses; literals also catch `as_str` moving with it.
#[test]
fn circuit_state_serialises_as_its_label() {
    let cases = [
        (CircuitState::Closed, "closed"),
        (CircuitState::Open, "open"),
        (CircuitState::HalfOpen, "half_open"),
    ];
    for (state, wire) in cases {
        assert_eq!(serde_json::to_value(state).unwrap(), wire);
        assert_eq!(state.as_str(), wire);
    }
}

// ── stats snapshot ────────────────────────────────────────────────────

#[test]
fn reset_closes_an_open_breaker_and_allows_requests() {
    // GIVEN: a breaker tripped open by hitting the failure threshold
    let cb = CircuitBreaker::new("test", &make_config(3));
    for _ in 0..3 {
        cb.record_failure("test", Duration::ZERO);
    }
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.can_proceed());

    // WHEN: the operator resets it (gateway_revive_server path, MIK-5983)
    cb.reset();

    // THEN: closed, counters cleared, requests flow again
    let s = cb.stats();
    assert_eq!(s.state, CircuitState::Closed);
    assert_eq!(s.current_failures, 0);
    assert!(cb.can_proceed());
}

#[test]
fn reset_in_closed_state_clears_accumulated_failures() {
    // GIVEN: a closed breaker with a half-accumulated failure window
    let cb = CircuitBreaker::new("test", &make_config(5));
    cb.record_failure("test", Duration::ZERO);
    cb.record_failure("test", Duration::ZERO);
    assert_eq!(cb.stats().current_failures, 2);

    // WHEN
    cb.reset();

    // THEN: window cleared, still closed
    assert_eq!(cb.stats().current_failures, 0);
    assert_eq!(cb.state(), CircuitState::Closed);
}

#[test]
fn stats_initial_state_is_closed_with_zero_trips() {
    let cb = CircuitBreaker::new("test", &make_config(3));
    let s = cb.stats();
    assert_eq!(s.state, CircuitState::Closed);
    assert_eq!(s.trips_count, 0);
    assert_eq!(s.last_trip_ms, None);
    assert_eq!(s.retry_after_ms, 0);
    assert_eq!(s.current_failures, 0);
    assert_eq!(s.failure_threshold, 3);
}

#[test]
fn stats_trips_count_increments_on_each_open() {
    // Use zero reset_timeout so the circuit transitions to HalfOpen immediately
    // on the next can_proceed() call, allowing us to test the full trip cycle.
    let cfg = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        reset_timeout: Duration::ZERO,
    };
    let cb = CircuitBreaker::new("test", &cfg);

    // GIVEN: a fresh circuit breaker
    assert_eq!(cb.stats().trips_count, 0);

    // WHEN: a failure triggers the first trip
    cb.record_failure("test", Duration::ZERO);

    // THEN: trips_count == 1 and last_trip_ms is set
    assert_eq!(cb.stats().trips_count, 1);
    assert!(cb.stats().last_trip_ms.is_some());

    // Recover: zero timeout means can_proceed() immediately transitions to HalfOpen
    assert!(cb.can_proceed(), "zero timeout should allow HalfOpen probe");
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // One success closes the circuit (success_threshold = 1)
    cb.record_success();
    assert_eq!(cb.stats().state, CircuitState::Closed);

    // WHEN: another failure trips the circuit again
    cb.record_failure("test", Duration::ZERO);

    // THEN: trips_count == 2
    assert_eq!(cb.stats().trips_count, 2);
}

#[test]
fn stats_retry_after_ms_is_nonzero_when_open() {
    let cfg = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        reset_timeout: Duration::from_secs(60),
    };
    let cb = CircuitBreaker::new("test", &cfg);
    cb.record_failure("test", Duration::ZERO);
    let s = cb.stats();
    assert_eq!(s.state, CircuitState::Open);
    assert!(
        s.retry_after_ms > 0,
        "retry_after_ms should be >0 when open"
    );
    assert!(
        s.retry_after_ms <= 60_000,
        "retry_after_ms must not exceed reset_timeout"
    );
}

#[test]
fn stats_retry_after_ms_is_zero_when_closed() {
    let cb = CircuitBreaker::new("test", &make_config(3));
    assert_eq!(cb.stats().retry_after_ms, 0);
}

// ── existing behaviour preserved ──────────────────────────────────────

#[test]
fn circuit_starts_closed_and_allows_requests() {
    let cb = CircuitBreaker::new("test", &make_config(3));
    assert!(cb.can_proceed());
    assert_eq!(cb.state(), CircuitState::Closed);
}

#[test]
fn circuit_opens_after_failure_threshold_reached() {
    let cb = CircuitBreaker::new("test", &make_config(3));
    cb.record_failure("test", Duration::ZERO);
    cb.record_failure("test", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure("test", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.can_proceed());
}

#[test]
fn breaker_open_event() {
    // MIK-6119 AC.1: tripping the breaker captures a structured open-event
    // with all four fields, retrievable without parsing logs.
    let cb = CircuitBreaker::new("hebb", &make_config(3));
    assert!(cb.last_open_event().is_none(), "no event before any trip");
    cb.record_failure("connect timeout", Duration::from_millis(250));
    cb.record_failure("connect timeout", Duration::from_millis(250));
    assert!(
        cb.last_open_event().is_none(),
        "no event before the threshold is reached"
    );
    cb.record_failure("connect timeout", Duration::from_millis(250));
    assert_eq!(cb.state(), CircuitState::Open);

    let ev = cb.last_open_event().expect("open event captured on trip");
    assert_eq!(ev.backend, "hebb");
    assert_eq!(ev.reason, "connect timeout");
    assert_eq!(ev.latency_ms, 250);
    assert_eq!(ev.consecutive_fail_count, 3);
}

// ── build_circuit_breaker_error ───────────────────────────────────────

#[test]
fn circuit_breaker_error_open_state_includes_trips_and_retry() {
    // GIVEN: an open circuit breaker stats snapshot
    let stats = CircuitBreakerStats {
        state: CircuitState::Open,
        trips_count: 2,
        last_trip_ms: Some(
            crate::clock::unix_millis()
                .unwrap_or_default()
                .saturating_sub(500),
        ),
        retry_after_ms: 29_500,
        current_failures: 3,
        failure_threshold: 3,
    };
    // WHEN: building the error message
    let msg = build_circuit_breaker_error("my-backend", &stats);
    // THEN: it mentions open state, trip count, and retry info
    assert!(msg.contains("my-backend"), "must include server name");
    assert!(msg.contains("open"), "must include state");
    assert!(msg.contains("2 time(s)"), "must include trip count");
    assert!(msg.contains("Retry probe"), "must mention retry info");
}

#[test]
fn circuit_breaker_error_half_open_state_is_generic() {
    // GIVEN: a half-open circuit breaker stats snapshot
    let stats = CircuitBreakerStats {
        state: CircuitState::HalfOpen,
        trips_count: 1,
        last_trip_ms: Some(crate::clock::unix_millis().unwrap_or_default()),
        retry_after_ms: 0,
        current_failures: 0,
        failure_threshold: 3,
    };
    // WHEN: building the error message
    let msg = build_circuit_breaker_error("my-backend", &stats);
    // THEN: it mentions the state but no retry probe timing
    assert!(msg.contains("my-backend"));
    assert!(msg.contains("half_open"));
    assert!(
        !msg.contains("Retry probe"),
        "half_open does not need retry timing"
    );
}

#[test]
fn circuit_breaker_error_closed_state_is_generic() {
    // GIVEN: a closed circuit breaker (unusual to error, but handled)
    let stats = CircuitBreakerStats {
        state: CircuitState::Closed,
        trips_count: 0,
        last_trip_ms: None,
        retry_after_ms: 0,
        current_failures: 0,
        failure_threshold: 3,
    };
    // WHEN: building the error message
    let msg = build_circuit_breaker_error("my-backend", &stats);
    // THEN: it mentions closed state
    assert!(msg.contains("my-backend"));
    assert!(msg.contains("closed"));
}
