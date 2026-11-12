// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP stop budget: exact arithmetic on absolute deadlines.

use std::time::Duration;

use tokio::time::Instant;

use super::{BelowMinimum, HTTP_MIN_TOTAL, StopBudget};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn at(total: Duration) -> (Instant, StopBudget) {
    let t0 = Instant::now();
    (t0, StopBudget::http(t0, total).expect("an accepted total"))
}

#[test]
fn exactly_nine_seconds_is_accepted() {
    assert!(StopBudget::http(Instant::now(), HTTP_MIN_TOTAL).is_ok());
    assert_eq!(HTTP_MIN_TOTAL, ms(9_000));
}

#[test]
fn eight_point_nine_nine_nine_seconds_is_refused_with_an_actionable_message() {
    let err = StopBudget::http(Instant::now(), ms(8_999)).expect_err("below the minimum");
    assert_eq!(
        err,
        BelowMinimum {
            configured: ms(8_999),
            minimum: ms(9_000)
        }
    );
    let text = err.to_string();
    assert!(text.contains("server.shutdown_timeout"), "{text}");
    assert!(text.contains("8.999") && text.contains('9'), "{text}");
}

#[test]
fn the_deadlines_at_the_minimum_total() {
    let (t0, b) = at(ms(9_000));
    assert_eq!(b.listener_end(), t0 + ms(100), "Dl");
    assert_eq!(b.post_listener_end(), t0 + ms(350), "Dp");
    assert_eq!(b.backend_end(), t0 + ms(6_750), "Db");
    assert_eq!(b.runtime_end(), t0 + ms(7_000), "Dr");
    assert_eq!(b.end(), t0 + ms(9_000), "D");
}

#[test]
fn the_deadlines_at_the_default_thirty_seconds() {
    let (t0, b) = at(Duration::from_secs(30));
    assert_eq!(b.listener_end(), t0 + ms(21_100), "Dl");
    assert_eq!(b.post_listener_end(), t0 + ms(21_350), "Dp");
    assert_eq!(b.backend_end(), t0 + ms(27_750), "Db");
    assert_eq!(b.runtime_end(), t0 + ms(28_000), "Dr");
    assert_eq!(b.end(), t0 + ms(30_000), "D");
}

#[test]
fn the_listener_grace_is_dl_from_the_trigger() {
    let (_, nine) = at(ms(9_000));
    assert_eq!(nine.listener_grace(), ms(100));
    let (_, thirty) = at(Duration::from_secs(30));
    assert_eq!(thirty.listener_grace(), ms(21_100));
}

#[test]
fn a_stage_window_is_capped_and_then_shrinks_with_the_clock() {
    let (t0, b) = at(Duration::from_secs(30));
    let cap = Duration::from_secs(10);
    assert_eq!(
        b.stage_window(t0 + ms(21_100), cap),
        ms(250),
        "all of P left"
    );
    assert_eq!(b.stage_window(t0, cap), cap, "far from Dp the cap rules");
    assert_eq!(
        b.stage_window(t0 + ms(12_000), cap),
        ms(9_350),
        "Dp - now, under the cap"
    );
}

#[test]
fn early_completion_flows_time_forward_and_late_work_never_resets_it() {
    let (t0, b) = at(Duration::from_secs(30));
    let cap = Duration::from_secs(60);
    let early = b.stage_window(t0 + ms(1_000), cap);
    let later = b.stage_window(t0 + ms(6_000), cap);
    assert_eq!(
        early.checked_sub(later),
        Some(ms(5_000)),
        "the window shrinks by exactly the time spent"
    );
    assert_eq!(
        b.stage_window(t0 + ms(21_350), cap),
        Duration::ZERO,
        "at Dp"
    );
    assert_eq!(
        b.stage_window(t0 + ms(25_000), cap),
        Duration::ZERO,
        "after Dp: zero, not renewed"
    );
}

/// A stage that never ends, to be cut by its window.
async fn stuck() {
    std::future::pending::<()>().await;
}

#[tokio::test(start_paused = true)]
async fn a_stuck_stage_with_a_huge_cap_still_ends_at_dp() {
    let (t0, b) = at(Duration::from_secs(30));
    let out = b.stage("stuck", Duration::from_secs(600), stuck()).await;
    assert!(out.is_none(), "a stuck stage is cut");
    assert_eq!(
        Instant::now(),
        b.post_listener_end(),
        "at Dp, not at the cap"
    );
    assert_eq!(Instant::now() - t0, ms(21_350));
}

#[tokio::test(start_paused = true)]
async fn a_stage_far_from_dp_is_cut_by_its_own_cap() {
    let (t0, b) = at(Duration::from_secs(30));
    let out = b.stage("stuck", Duration::from_secs(10), stuck()).await;
    assert!(out.is_none());
    assert_eq!(Instant::now() - t0, Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn a_second_stage_after_dp_gets_no_time_and_dp_is_not_renewed() {
    let (t0, b) = at(Duration::from_secs(30));
    assert!(
        b.stage("first", Duration::from_secs(600), stuck())
            .await
            .is_none()
    );
    let at_dp = Instant::now();
    assert!(
        b.stage("second", Duration::from_secs(600), stuck())
            .await
            .is_none()
    );
    assert_eq!(Instant::now(), at_dp, "the second stage waited for nothing");
    assert_eq!(Instant::now() - t0, ms(21_350));
}

#[tokio::test(start_paused = true)]
async fn a_stage_that_finishes_early_hands_its_time_to_the_next() {
    let (t0, b) = at(Duration::from_secs(30));
    let quick = b
        .stage("quick", Duration::from_secs(10), async {
            tokio::time::sleep(ms(1_000)).await;
            7
        })
        .await;
    assert_eq!(
        quick,
        Some(7),
        "a stage that finishes inside its window returns its value"
    );
    assert_eq!(Instant::now() - t0, ms(1_000));
    // The next stage's cap is far larger than the 10 s the first had: it may use
    // everything the first left, up to Dp.
    assert!(
        b.stage("slow", Duration::from_secs(600), stuck())
            .await
            .is_none()
    );
    assert_eq!(
        Instant::now() - t0,
        ms(21_350),
        "the freed time was available"
    );
}

#[test]
fn the_listener_grace_for_a_total_is_what_the_budget_would_give() {
    for (total, grace) in [
        (ms(9_000), ms(100)),
        (ms(30_000), ms(21_100)),
        (ms(600_000), ms(591_100)),
    ] {
        let (_, budget) = at(total);
        assert_eq!(
            StopBudget::listener_grace_for(total),
            grace,
            "total {total:?}"
        );
        assert_eq!(budget.listener_grace(), grace, "total {total:?}");
    }
}

#[test]
fn the_post_listener_offset_for_a_total_is_dp_from_the_trigger() {
    for (total, offset) in [(ms(9_000), ms(350)), (ms(30_000), ms(21_350))] {
        let (t0, budget) = at(total);
        assert_eq!(
            StopBudget::post_listener_offset(total),
            offset,
            "total {total:?}"
        );
        assert_eq!(budget.post_listener_end() - t0, offset, "total {total:?}");
    }
}

/// A stage that starts at or after Dp has no time at all: its work is not even
/// polled once, so it cannot do synchronous work that outlasts the deadline.
#[tokio::test(start_paused = true)]
async fn a_stage_that_starts_after_dp_does_not_poll_its_work() {
    let (_t0, b) = at(Duration::from_secs(30));
    tokio::time::advance(b.post_listener_end() - Instant::now() + ms(1)).await;
    let polled = std::sync::atomic::AtomicBool::new(false);
    let out = b
        .stage("late", Duration::from_secs(10), async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
    assert!(out.is_none(), "a late stage reports that it ran out");
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "the late stage's work was polled once"
    );
}

/// Exactly at Dp the window is zero too.
#[tokio::test(start_paused = true)]
async fn a_stage_that_starts_exactly_at_dp_does_not_poll_its_work() {
    let (_t0, b) = at(Duration::from_secs(30));
    tokio::time::advance(b.post_listener_end() - Instant::now()).await;
    let polled = std::sync::atomic::AtomicBool::new(false);
    let out = b
        .stage("at dp", Duration::from_secs(10), async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
    assert!(out.is_none());
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}

/// The listener has returned, so the start check already accepted the total:
/// the budget is built without a second refusal that would skip the whole stop.
#[test]
fn the_budget_after_the_listener_never_refuses_and_never_goes_before_the_trigger() {
    for total in [ms(0), ms(1), ms(8_999), ms(9_000), Duration::from_secs(30)] {
        let t0 = Instant::now();
        let b = StopBudget::fixed_at(t0, total);
        assert!(b.listener_end() >= t0, "Dl for {total:?}");
        assert!(b.listener_end() <= b.post_listener_end(), "Dl <= Dp for {total:?}");
        assert!(b.post_listener_end() <= b.backend_end(), "Dp <= Db for {total:?}");
        assert!(b.backend_end() <= b.end(), "Db <= D for {total:?}");
        assert_eq!(b.end(), t0 + total, "D for {total:?}");
    }
    let t0 = Instant::now();
    let accepted = StopBudget::http(t0, ms(9_000)).expect("accepted");
    let fixed = StopBudget::fixed_at(t0, ms(9_000));
    assert_eq!(fixed.post_listener_end(), accepted.post_listener_end());
    assert_eq!(fixed.backend_end(), accepted.backend_end());
}

/// A step that must finish before the backends are listed may use the time up
/// to Db, even after Dp, but never past it.
#[tokio::test(start_paused = true)]
async fn a_step_before_the_backends_may_use_the_time_left_to_db_and_no_more() {
    let (t0, b) = at(Duration::from_secs(30));
    tokio::time::advance(b.post_listener_end() - Instant::now() + ms(1_000)).await;
    let done = b
        .stage_until_backend_end("late but allowed", async {
            tokio::time::sleep(ms(2_000)).await;
            9
        })
        .await;
    assert_eq!(done, Some(9), "two seconds fit between Dp and Db");
    let out = b.stage_until_backend_end("stuck", stuck()).await;
    assert!(out.is_none());
    assert_eq!(Instant::now(), b.backend_end(), "cut exactly at Db");
    assert_eq!(Instant::now() - t0, ms(27_750));
}

/// After Db there is no time left for it either: its work is not polled.
#[tokio::test(start_paused = true)]
async fn a_step_before_the_backends_does_not_poll_after_db() {
    let (_t0, b) = at(Duration::from_secs(30));
    tokio::time::advance(b.backend_end() - Instant::now() + ms(1)).await;
    let polled = std::sync::atomic::AtomicBool::new(false);
    let out = b
        .stage_until_backend_end("after db", async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
    assert!(out.is_none());
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
}
