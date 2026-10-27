// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Slow verdict: a server's recent p95 against its own decaying baseline.
//! Counted in successful calls, never in time, so every case is a plain
//! sequence of samples.

use std::time::Duration;

use super::HealthTracker;

fn feed(tracker: &HealthTracker, calls: usize, ms: u64) {
    for _ in 0..calls {
        tracker.record_success(Duration::from_millis(ms));
    }
}

/// A tracker whose baseline is warm at exactly `ms`: five full batches.
fn warm_at(ms: u64) -> HealthTracker {
    let tracker = HealthTracker::new("slow-test");
    feed(&tracker, 500, ms);
    tracker
}

#[test]
fn api4_2_no_verdict_before_the_baseline_is_warm() {
    let tracker = HealthTracker::new("slow-test");
    feed(&tracker, 400, 100);
    // A tenfold spike in the fifth batch, one call short of completing it.
    feed(&tracker, 99, 1000);
    assert_eq!(tracker.slow(), None, "499 calls: the baseline is not warm");
    // The 500th call completes the fifth batch: warm, and the spike shows.
    feed(&tracker, 1, 1000);
    let (recent, usual) = tracker.slow().expect("warm, and far over its usual");
    assert_eq!(recent, 1000);
    assert!(usual < 334, "usual {usual}");
}

#[test]
fn api4_2_slow_is_strictly_over_three_times_the_usual() {
    let at_three = warm_at(100);
    // 99 calls: the window's p95 is theirs, and no batch completes, so the
    // baseline stays exactly 100.
    feed(&at_three, 99, 300);
    assert_eq!(at_three.slow(), None, "exactly three times is not slow");

    let over = warm_at(100);
    feed(&over, 99, 301);
    assert_eq!(over.slow(), Some((301, 100)));
}

#[test]
fn api4_2_a_fast_server_under_the_floor_is_never_slow() {
    let tracker = warm_at(2);
    feed(&tracker, 99, 49);
    assert_eq!(tracker.slow(), None, "49 ms is under the 50 ms floor");

    let at_floor = warm_at(2);
    feed(&at_floor, 99, 50);
    assert_eq!(at_floor.slow(), Some((50, 2)));
}

#[test]
fn api4_2_a_sustained_slowdown_becomes_the_new_usual() {
    let tracker = warm_at(100);
    feed(&tracker, 100, 400);
    assert!(tracker.slow().is_some(), "the first slow batch shows");
    // Eight batches lift the baseline past a third of 400.
    feed(&tracker, 600, 400);
    assert!(tracker.slow().is_some(), "still slow after seven batches");
    feed(&tracker, 100, 400);
    assert_eq!(tracker.slow(), None, "400 ms is the new usual");
}

#[test]
fn api4_2_a_reset_needs_a_new_warm_up() {
    let tracker = warm_at(100);
    tracker.reset();
    feed(&tracker, 400, 100);
    feed(&tracker, 99, 1000);
    assert_eq!(tracker.slow(), None, "a reset starts the warm-up again");
}

#[test]
fn api4_2_a_faster_server_lowers_its_usual_without_underflow() {
    let tracker = warm_at(400);
    // Twenty batches at a quarter of the usual: the baseline only falls.
    feed(&tracker, 2000, 100);
    assert_eq!(tracker.slow(), None, "faster than usual is never slow");
    // Back to 400 ms: well under three times the lowered usual.
    feed(&tracker, 99, 400);
    assert_eq!(tracker.slow(), None);
}

#[test]
fn api4_2_a_tenfold_slowdown_shows_for_nineteen_batches() {
    let tracker = warm_at(100);
    feed(&tracker, 1900, 1000);
    assert!(
        tracker.slow().is_some(),
        "still slow after nineteen batches"
    );
    feed(&tracker, 100, 1000);
    assert_eq!(
        tracker.slow(),
        None,
        "1000 ms is the new usual after twenty"
    );
}
