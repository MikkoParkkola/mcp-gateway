// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Slow verdict: a server's recent p95 against its own decaying baseline.
//! Counted in successful calls, never in time, so every case is a plain
//! sequence of samples.

use std::time::Duration;

use super::{HealthTracker, Slow};

fn seen(recent_ms: u64, usual_ms: u64) -> Slow {
    Slow {
        recent_ms,
        usual_ms,
    }
}

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
    let slow = tracker.slow().expect("warm, and far over its usual");
    assert_eq!(slow.recent_ms, 1000);
    assert!(slow.usual_ms < 334, "usual {}", slow.usual_ms);
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
    assert_eq!(over.slow(), Some(seen(301, 100)));
}

#[test]
fn api4_2_a_fast_server_under_the_floor_is_never_slow() {
    let tracker = warm_at(2);
    feed(&tracker, 99, 49);
    assert_eq!(tracker.slow(), None, "49 ms is under the 50 ms floor");

    let at_floor = warm_at(2);
    feed(&at_floor, 99, 50);
    assert_eq!(at_floor.slow(), Some(seen(50, 2)));
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

#[test]
fn api4_2_small_steps_still_move_the_usual() {
    // Twenty batches at 110 ms: plain integer averaging would never move a
    // 100 ms baseline by a 10 ms step; the fixed point does.
    let up = warm_at(100);
    feed(&up, 2000, 110);
    feed(&up, 99, 2000);
    assert_eq!(up.slow(), Some(seen(2000, 102)));

    // And down: twenty batches at 100 ms from a 400 ms usual.
    let down = warm_at(400);
    feed(&down, 2000, 100);
    feed(&down, 99, 2000);
    assert_eq!(down.slow(), Some(seen(2000, 319)));
}

#[test]
fn api4_2_the_window_p95_is_its_ninety_sixth_value() {
    // Five slow calls in the last hundred reach the p95; four do not.
    let five = warm_at(100);
    feed(&five, 94, 100);
    feed(&five, 5, 1000);
    assert_eq!(five.slow(), Some(seen(1000, 100)));

    let four = warm_at(100);
    feed(&four, 95, 100);
    feed(&four, 4, 1000);
    assert_eq!(four.slow(), None);
}

#[test]
fn api4_2_throttled_replies_never_warm_the_usual() {
    let tracker = HealthTracker::new("slow-test");
    for _ in 0..500 {
        tracker.record_throttled(Duration::from_millis(10));
    }
    feed(&tracker, 5, 1000);
    assert_eq!(
        tracker.slow(),
        None,
        "five answered calls are not a baseline"
    );

    // The same through the failsafe's rate-limit path.
    let failsafe =
        crate::failsafe::Failsafe::new("slow-test", &crate::config::FailsafeConfig::default());
    for _ in 0..500 {
        failsafe.record_rate_limited("429", Duration::from_millis(10));
    }
    feed(&failsafe.health_tracker, 5, 1000);
    assert_eq!(failsafe.health_tracker.slow(), None);
}

#[test]
fn api4_2_throttles_on_a_warm_server_move_nothing() {
    let tracker = warm_at(100);
    feed(&tracker, 5, 1000);
    for _ in 0..100 {
        tracker.record_throttled(Duration::from_millis(1));
        tracker.record_throttled(Duration::from_millis(5000));
    }
    assert_eq!(
        tracker.slow(),
        Some(seen(1000, 100)),
        "throttles neither expire answered calls nor enter the window"
    );
    // 95 more answered calls close the batch the five opened: the usual moves
    // once, by (6400 - 100 + 1000) / 64.
    feed(&tracker, 95, 100);
    assert_eq!(tracker.slow(), Some(seen(1000, 114)));
}

#[test]
fn api4_2_reading_metrics_between_calls_changes_nothing() {
    let tracker = HealthTracker::new("slow-test");
    let call = |ms: u64| {
        tracker.record_success(Duration::from_millis(ms));
        let _ = tracker.metrics();
    };
    // Every batch holds 25 each of four latencies: its p95 is 100.
    for i in 0..500 {
        call([100, 20, 60, 40][i % 4]);
    }
    // A spike batch: the usual becomes (6400 - 100 + 1000) / 64.
    for _ in 0..100 {
        call(1000);
    }
    for i in 0..99 {
        call([400, 20, 60][i % 3]);
    }
    // The last 100 calls hold one 1000 and 33 each of 400, 60 and 20: their
    // p95 is 400. The 100 largest samples would read 1000.
    assert_eq!(
        tracker.slow(),
        Some(seen(400, 114)),
        "the window keeps call order"
    );
}

#[test]
fn api4_2_a_spike_leaves_the_window() {
    let tracker = warm_at(100);
    feed(&tracker, 99, 1000);
    assert_eq!(tracker.slow(), Some(seen(1000, 100)));
    feed(&tracker, 100, 100);
    assert_eq!(tracker.slow(), None, "a hundred usual calls push it out");
}

#[test]
fn api4_2_a_reset_partway_through_a_batch_restarts_the_batch() {
    let tracker = warm_at(100);
    feed(&tracker, 50, 100);
    tracker.reset();
    feed(&tracker, 400, 100);
    feed(&tracker, 99, 1000);
    assert_eq!(tracker.slow(), None, "only four batches since the reset");
}

#[test]
fn api4_2_the_panel_and_the_window_agree_on_the_same_calls() {
    let tracker = HealthTracker::new("slow-test");
    // 1 to 100 ms, each once, out of order (37 and 100 share no factor).
    for i in 0..100_u64 {
        tracker.record_success(Duration::from_millis((i * 37) % 100 + 1));
    }
    let window = tracker.latencies.read().recent_p95();
    assert_eq!(tracker.metrics().latency_p95_ms, Some(window));
    assert_eq!(window, 96, "the 96th of 100 sorted values");
}
