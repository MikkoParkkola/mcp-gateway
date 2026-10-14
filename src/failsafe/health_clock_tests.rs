// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b rows B5 and B5f: a success or failure on a dark clock keeps
//! the last real time instead of writing 0.

use super::*;
use crate::clock::test_clock;

/// A readable clock at this many seconds after the epoch; the tracker stores
/// milliseconds.
const T: u64 = 1_000_000;

/// MIK-8202 AC.2, P4b design r1 B5 (kept by r4): `last_success` is left
/// unchanged on a clock before 1970, so the last real time stays.
///
/// Red on base: base reads the wall clock directly, so the forced clock never
/// reaches it; both successes are stamped with the real time and the final
/// assertion (`== T` in ms) fails.
///
/// Mutant B5m (0 written on Err): `last_success_ms == 0`, killed by the same
/// assertion.
#[test]
fn a_success_on_a_dark_clock_keeps_the_last_success_time() {
    let tracker = HealthTracker::new("clock");
    {
        let _clock = test_clock::at_secs(T);
        tracker.record_success(Duration::from_millis(5));
    }
    let _clock = test_clock::before_epoch();
    tracker.record_success(Duration::from_millis(5));
    let metrics = tracker.metrics();
    assert_eq!(metrics.success_count, 2, "the dark success still counts");
    assert_eq!(
        metrics.last_success_ms,
        T * 1_000,
        "B5: the dark success keeps the last real success time"
    );
}

/// MIK-8202 AC.2, P4b design r1 B5 (test plan r2 row B5f): `last_failure` is
/// left unchanged on a clock before 1970.
///
/// Red on base: base reads the wall clock directly, so both failures carry the
/// real time and the final assertion (`== T` in ms) fails.
///
/// Mutant B5m (0 written on Err, failure path): `last_failure_ms == 0`, killed
/// by the same assertion.
#[test]
fn a_failure_on_a_dark_clock_keeps_the_last_failure_time() {
    let tracker = HealthTracker::new("clock");
    {
        let _clock = test_clock::at_secs(T);
        tracker.record_failure();
    }
    let _clock = test_clock::before_epoch();
    tracker.record_failure();
    let metrics = tracker.metrics();
    assert_eq!(metrics.failure_count, 2, "the dark failure still counts");
    assert_eq!(
        metrics.last_failure_ms,
        T * 1_000,
        "B5f: the dark failure keeps the last real failure time"
    );
}
