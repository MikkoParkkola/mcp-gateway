// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b row B4o (compile-red): the breaker's wall-clock stats field is
//! an `Option`, `None` for a trip made on a dark clock.

use super::*;
use crate::clock::test_clock;

/// MIK-8202 AC.2, P4b design r1 B4 ("the wall-clock fields in stats are
/// `Option`"): `CircuitBreakerStats::last_trip_ms` is `None` for a trip on a
/// clock before 1970, `Some` for one on a readable clock; the monotonic
/// `retry_after_ms` is still reported.
///
/// Compile-red on base: `last_trip_ms` is a `u64`.
///
/// Mutant B4om (the trip stamped `Some(0)` on Err): killed by the `None`
/// assertion.
#[test]
fn a_trip_on_a_dark_clock_has_no_trip_time() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 1,
        success_threshold: 1,
        reset_timeout: Duration::from_secs(30),
    };
    let dark = CircuitBreaker::new("dark", &config);
    {
        let _clock = test_clock::before_epoch();
        dark.record_failure("down", Duration::ZERO);
    }
    let stats = dark.stats();
    assert_eq!(stats.state, CircuitState::Open);
    assert_eq!(stats.last_trip_ms, None, "B4o: an undated trip");
    assert!(
        stats.retry_after_ms > 0,
        "the monotonic retry delay still reads"
    );

    let dated = CircuitBreaker::new("dated", &config);
    {
        let _clock = test_clock::at_secs(1_000_000);
        dated.record_failure("down", Duration::ZERO);
    }
    assert_eq!(dated.stats().last_trip_ms, Some(1_000_000_000));
}
