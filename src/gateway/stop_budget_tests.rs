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
        early - later,
        ms(5_000),
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
