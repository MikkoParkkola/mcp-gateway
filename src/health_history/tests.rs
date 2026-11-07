// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the gateway's own health history: each series on a fixed clock,
//! the save and restore round trip, and the restart and coverage accounting
//! behind the uptime strip.

use super::*;
use crate::gateway::health_metrics::ErrorKind;

/// A unix-aligned half-hour start well after the epoch.
const T0: u64 = 1_800 * 1_000_000;

fn fresh(now: u64) -> HealthHistory {
    HealthHistory::start(None, Restores::Counted(0), now).0
}

/// H1: a known set of added latencies in one half-hour gives the p95 bucket's
/// upper bound: 95 calls at 3 ms and 5 at 40 ms put the 95th percentile in
/// the 5 ms bucket (bounds 1, 2.5, 5, 10, 25, 50 ms, ...).
#[test]
fn h1_the_p95_is_the_upper_bound_of_its_bucket() {
    let h = fresh(T0);
    for _ in 0..95 {
        h.record_latency(0.003, T0 + 10);
    }
    for _ in 0..5 {
        h.record_latency(0.040, T0 + 20);
    }
    assert_eq!(h.p95(T0, T0 + HALF), P95::Ms(5.0));
}

/// H1b: a p95 in the overflow bucket is `AboveMs(2500)`; a window with no
/// call is `NoData`, never 0.
#[test]
fn h1b_overflow_and_no_data_are_distinct() {
    let h = fresh(T0);
    for _ in 0..10 {
        h.record_latency(9.0, T0 + 5);
    }
    assert_eq!(h.p95(T0, T0 + HALF), P95::AboveMs(2_500.0));
    assert_eq!(h.p95(T0 + HALF, T0 + 2 * HALF), P95::NoData);
}

/// H2: a span merges the half-hours inside it, and only those: the hour
/// before is the two half-hours ending at its exact `to` second.
#[test]
fn h2_a_span_merges_exactly_its_half_hours() {
    let h = fresh(T0);
    for _ in 0..20 {
        h.record_latency(0.0008, T0 + 1); // 1 ms bucket
    }
    for _ in 0..20 {
        h.record_latency(0.2, T0 + HALF + 1); // 250 ms bucket
    }
    for _ in 0..20 {
        h.record_latency(2.0, T0 + 2 * HALF); // 2500 ms bucket, next half-hour
    }
    h.tick(T0 + 2 * HALF + 1);
    // 40 calls in [T0, T0 + 2 HALF): the 95th percentile is in 250 ms.
    assert_eq!(h.p95(T0, T0 + 2 * HALF), P95::Ms(250.0));
    assert_eq!(h.p95(T0, T0 + HALF), P95::Ms(1.0));
    assert_eq!(h.p95(T0 + 2 * HALF, T0 + 3 * HALF), P95::Ms(2_500.0));
}

/// H3: errors count per kind; the gateway-errors figure is auth, request and
/// internal, not backend; an observed window with none is 0, not null.
#[test]
fn h3_gateway_errors_exclude_backend_and_zero_is_observed() {
    let h = fresh(T0);
    h.record_error(ErrorKind::Auth, T0 + 1);
    h.record_error(ErrorKind::Request, T0 + 2);
    h.record_error(ErrorKind::Internal, T0 + 3);
    h.record_error(ErrorKind::Backend, T0 + 4);
    h.tick(T0 + 2 * HALF + 1);
    assert_eq!(h.errors(T0, T0 + HALF), Some(3));
    assert_eq!(h.errors(T0 + HALF, T0 + 2 * HALF), Some(0));
}

/// H4: memory and sessions keep the largest sample in their half-hour; H4b:
/// no resident-memory reading is null, not 0.
#[test]
fn h4_gauges_keep_the_bucket_maximum_and_a_missing_reading_is_null() {
    let h = fresh(T0);
    h.sample(Some(100), 2, T0 + 60);
    h.sample(Some(300), 7, T0 + 120);
    h.sample(Some(200), 3, T0 + 180);
    h.sample(None, 1, T0 + HALF + 60);
    let first = h.half(T0).expect("first half-hour");
    assert_eq!((first.memory_max, first.sessions_max), (Some(300), Some(7)));
    let second = h.half(T0 + HALF).expect("second half-hour");
    assert_eq!((second.memory_max, second.sessions_max), (None, Some(1)));
}

/// H5: a half-hour the gateway was not running in is unobserved: errors null
/// and no view; an observed idle one has 0 errors and no latency.
#[test]
fn h5_unobserved_is_null_observed_idle_is_zero() {
    let h = fresh(T0 + 3 * HALF);
    h.tick(T0 + 4 * HALF + 1);
    assert_eq!(h.errors(T0, T0 + HALF), None, "before observation began");
    assert_eq!(h.errors(T0 + 3 * HALF, T0 + 4 * HALF), Some(0));
    assert_eq!(h.p95(T0 + 3 * HALF, T0 + 4 * HALF), P95::NoData);
    assert!(h.half(T0).is_none());
}

/// H6: save and restore keep every series, the coverage and the restarts.
#[test]
fn h6_save_and_restore_keep_everything() {
    let h = fresh(T0);
    h.record_latency(0.003, T0 + 1);
    h.record_error(ErrorKind::Internal, T0 + 2);
    h.sample(Some(500), 4, T0 + 3);
    h.tick(T0 + 100);
    h.stop(T0 + 100);
    let bytes = h.encode(T0 + 100);
    let (back, started) = HealthHistory::start(Some(&bytes), Restores::Counted(1), T0 + 160);
    assert!(!started.fresh);
    assert_eq!(back.p95(T0, T0 + HALF), P95::Ms(5.0));
    assert_eq!(back.errors(T0, T0 + HALF), Some(1));
    let half = back.half(T0).expect("restored half-hour");
    assert_eq!((half.memory_max, half.sessions_max), (Some(500), Some(4)));
    let (restarts, truncated) = back.restarts(T0, T0 + BLOCK);
    assert_eq!(restarts.len(), 1);
    assert!(!truncated);
}

/// Run one gateway life: start from `previous` at `start`, run until `end`,
/// and return the saved bytes; a clean stop writes the shutdown save.
fn life(previous: Option<&[u8]>, counters: u64, start: u64, end: u64, clean: bool) -> Vec<u8> {
    let (h, _) = HealthHistory::start(previous, Restores::Counted(counters), start);
    h.tick(end);
    if clean {
        h.stop(end);
    }
    h.encode(end)
}

/// H7: a clean stop then a start: one restart, measured, its downtime the
/// start minus the stop.
#[test]
fn h7_a_clean_stop_then_a_start_is_measured() {
    let saved = life(None, 0, T0, T0 + 600, true);
    let (h, started) = HealthHistory::start(Some(&saved), Restores::Counted(1), T0 + 630);
    let restart = started.restart.expect("a restart");
    assert_eq!(restart.downtime_source, DowntimeSource::Measured);
    assert_eq!(
        (restart.stopped_at, restart.started_at),
        (T0 + 600, T0 + 630)
    );
    assert_eq!(h.uptime(T0, T0 + BLOCK).down_seconds, 30);
}

/// H8: a kill (no shutdown save) then a start: estimated, from the last
/// save's time, the last moment the gateway was known alive.
#[test]
fn h8_a_kill_then_a_start_is_estimated_from_the_last_save() {
    let saved = life(None, 0, T0, T0 + 300, false);
    let (_, started) = HealthHistory::start(Some(&saved), Restores::Counted(1), T0 + 500);
    let restart = started.restart.expect("a restart");
    assert_eq!(restart.downtime_source, DowntimeSource::Estimated);
    assert_eq!(restart.stopped_at, T0 + 300);
}

/// H8b: a clean stop is used once. After it, a start that saves and is then
/// killed must not reuse that stop: the next restart is estimated.
#[test]
fn h8b_a_clean_stop_is_consumed_once() {
    let first = life(None, 0, T0, T0 + 600, true);
    let second = life(Some(&first), 1, T0 + 630, T0 + 900, false);
    let (_, started) = HealthHistory::start(Some(&second), Restores::Counted(2), T0 + 1_000);
    let restart = started.restart.expect("a restart");
    assert_eq!(restart.downtime_source, DowntimeSource::Estimated);
    assert_eq!(restart.stopped_at, T0 + 900);
}

/// H9: 10 000 restarts inside the strip keep at most `MAX_RESTARTS` details,
/// flagged truncated, while the block rollups still count every restart and
/// second of downtime; the saved file stays bounded.
#[test]
fn h9_restart_details_are_capped_and_rollups_count_everything() {
    let mut saved = life(None, 0, T0, T0 + 2, true);
    let mut at = T0 + 2;
    for n in 1..=10_000u64 {
        // Up for 1 s, down for 1 s: 10 000 restarts inside one six-hour block.
        saved = life(Some(&saved), n, at + 1, at + 2, true);
        at += 2;
    }
    let (h, _) = HealthHistory::start(Some(&saved), Restores::Counted(10_001), at + 1);
    let (details, truncated) = h.restarts(T0, T0 + 2 * BLOCK);
    assert!(
        details.len() <= MAX_RESTARTS && truncated,
        "{}",
        details.len()
    );
    let blocks = h.blocks();
    let restarts: u64 = blocks.iter().map(|b| u64::from(b.restarts)).sum();
    let down: u64 = blocks.iter().map(|b| b.down_seconds).sum();
    assert_eq!((restarts, down), (10_001, 10_001));
    assert!(
        saved.len() < 64 * 1024,
        "health.json grew to {}",
        saved.len()
    );
}

/// H9b: a restart whose downtime spans a six-hour boundary splits it between
/// the two blocks.
#[test]
fn h9b_downtime_across_a_block_boundary_splits() {
    let edge = T0 + BLOCK - (T0 % BLOCK);
    let saved = life(None, 0, edge - 600, edge - 100, true);
    let (h, _) = HealthHistory::start(Some(&saved), Restores::Counted(1), edge + 50);
    let blocks = h.blocks();
    let before = blocks
        .iter()
        .find(|b| b.start == edge - BLOCK)
        .expect("block before");
    let after = blocks
        .iter()
        .find(|b| b.start == edge)
        .expect("block after");
    assert_eq!((before.down_seconds, after.down_seconds), (100, 50));
}

/// H9c: a wall clock set backward between runs never makes a negative
/// interval: the restart counts zero downtime and is marked estimated.
#[test]
fn h9c_a_clock_set_backward_counts_no_negative_downtime() {
    let saved = life(None, 0, T0, T0 + 600, true);
    let (h, started) = HealthHistory::start(Some(&saved), Restores::Counted(1), T0 + 100);
    let restart = started.restart.expect("a restart");
    assert_eq!(restart.downtime_source, DowntimeSource::Estimated);
    assert_eq!(h.uptime(T0, T0 + BLOCK).down_seconds, 0);
}

/// H10: no file is a fresh start that claims no downtime; a corrupt file is
/// set aside and the history starts again from now, also without a restart.
#[test]
fn h10_a_missing_or_corrupt_file_starts_clean() {
    let (_, started) = HealthHistory::start(None, Restores::Counted(5), T0);
    assert!(started.fresh && started.restart.is_none());
    let (h, started) = HealthHistory::start(Some(b"{not json"), Restores::Counted(5), T0);
    assert!(started.set_aside && started.restart.is_none());
    assert_eq!(h.errors(T0 - HALF, T0), None);
}

/// Every string anywhere in `v`.
fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// H11: the saved file holds only numbers, the fixed restart fields and the
/// two downtime kinds: no string a caller could have chosen.
#[test]
fn h11_the_saved_file_holds_only_numbers_and_fixed_words() {
    let h = fresh(T0);
    h.record_latency(0.003, T0 + 1);
    h.record_error(ErrorKind::Auth, T0 + 2);
    h.sample(Some(1), 1, T0 + 3);
    h.stop(T0 + 10);
    let value: serde_json::Value = serde_json::from_slice(&h.encode(T0 + 10)).expect("json");
    let mut found = Vec::new();
    strings(&value, &mut found);
    assert!(
        found.iter().all(|s| s == "measured" || s == "estimated"),
        "{found:?}"
    );
}

/// H13: covered = running + known downtime, percent = running / covered;
/// no coverage is null, never 100%.
#[test]
fn h13_percent_is_running_over_covered() {
    let saved = life(None, 0, T0, T0 + 900, true);
    let (h, _) = HealthHistory::start(Some(&saved), Restores::Counted(1), T0 + 1_000);
    h.tick(T0 + 1_900);
    let up = h.uptime(T0, T0 + 1_900);
    assert_eq!((up.running_seconds, up.down_seconds), (1_800, 100));
    assert_eq!(up.covered_seconds, 1_900);
    let percent = up.percent.expect("covered time");
    assert!(
        (percent - 1_800.0 / 1_900.0 * 100.0).abs() < 1e-9,
        "{percent}"
    );
    assert_eq!(fresh(T0).uptime(T0 - BLOCK, T0 - HALF).percent, None);
}

/// H14: a Restart marker in counters.json that health.json does not know of
/// is a missed run: the gap is unaccounted (not downtime) and the stored
/// clean stop is discarded.
#[test]
fn h14_a_missed_run_is_unaccounted_not_downtime() {
    let saved = life(None, 0, T0, T0 + 600, true);
    // Two markers since: this start's own, and one health.json never saw.
    let (h, started) = HealthHistory::start(Some(&saved), Restores::Counted(2), T0 + 5_000);
    assert!(started.missed_run && started.restart.is_none());
    let up = h.uptime(T0, T0 + 5_000);
    assert_eq!(up.down_seconds, 0);
    assert!(!up.coverage_complete);
}

/// H16: restart details are filtered to the requested interval; H16b: a
/// restart in the current block is listed once that block is in range.
#[test]
fn h16_restart_details_follow_the_interval() {
    let saved = life(None, 0, T0, T0 + 600, true);
    let (h, _) = HealthHistory::start(Some(&saved), Restores::Counted(1), T0 + 700);
    h.tick(T0 + 2 * BLOCK);
    assert!(h.restarts(T0 + BLOCK, T0 + 2 * BLOCK).0.is_empty());
    assert_eq!(h.restarts(T0, T0 + BLOCK).0.len(), 1);
}

/// H18: a clock set backward cannot hide a missed run: the check counts
/// markers, not timestamps.
#[test]
fn h18_a_backward_clock_does_not_hide_a_missed_run() {
    let saved = life(None, 0, T0 + 10_000, T0 + 10_600, true);
    let (_, started) = HealthHistory::start(Some(&saved), Restores::Counted(3), T0 + 100);
    assert!(started.missed_run);
}

/// H19: a restore count lower than expected (an older binary rewrote
/// counters.json without it) is a missed run too, never a measured restart.
#[test]
fn h19_a_lower_restore_count_is_a_missed_run() {
    let first = life(None, 0, T0, T0 + 600, true);
    let second = life(Some(&first), 1, T0 + 630, T0 + 900, true);
    let (_, started) = HealthHistory::start(Some(&second), Restores::Counted(1), T0 + 1_000);
    assert!(started.missed_run && started.restart.is_none());
}

/// H21b: a restarted count is a missed run even when it lines up with the
/// history's own count (seen 1, restarted at 2 = seen + 1); the next start
/// is in step again.
#[test]
fn h21b_a_restarted_count_is_a_missed_run() {
    let first = life(None, 1, T0, T0 + 600, true);
    let (h, started) = HealthHistory::start(Some(&first), Restores::Restarted(2), T0 + 1_000);
    assert!(started.missed_run && started.restart.is_none());
    let saved = h.encode(T0 + 1_100);
    let (_, next) = HealthHistory::start(Some(&saved), Restores::Counted(3), T0 + 1_200);
    assert!(
        !next.missed_run,
        "the count is in step again after the reset"
    );
}

/// H8c: a save that cannot be written marks this run's history incomplete;
/// the first save that succeeds clears it.
#[test]
fn h8c_a_failed_save_marks_the_run_incomplete_until_one_succeeds() {
    let h = fresh(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let blocker = dir.path().join("a-file");
    std::fs::write(&blocker, b"x").expect("blocker");
    assert!(!file::save(
        &h,
        &blocker.join("sub").join("health.json"),
        T0 + 1
    ));
    assert!(h.incomplete());
    assert!(file::save(&h, &dir.path().join("health.json"), T0 + 2));
    assert!(!h.incomplete());
}
