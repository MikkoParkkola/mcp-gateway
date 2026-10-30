// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Latency reads (test plan rows 31, 32, 34, 36-38).

use std::time::Duration;

use chrono::Utc;

use super::*;
use crate::counters::{Call, CounterStore, End, Label, Tally};

const T0: u64 = 1_800 * 1_000_000;

fn call(server: &str) -> Call<'_> {
    Call {
        caller: "key:a",
        server: Label::Known(server),
        tool: Label::Known("t"),
        tally: Tally::default(),
    }
}

fn timed(store: &CounterStore, server: &str, at: u64, ms: u64, end: End) {
    store.record_timed(
        &call(server),
        at,
        &Utc,
        Some((Duration::from_millis(ms), end)),
    );
}

/// Row 31: 24h points are half-hour starts, carry their counts, and leave
/// out slots without calls; no server reads the global series.
#[test]
fn series_latency_p95_shape() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100, End::Answered);
    timed(&store, "alpha", T0 + 20, 100, End::TimedOut);
    timed(&store, "beta", T0 + 3 * HALF + 10, 900, End::Failed);
    let now = T0 + 4 * HALF;
    let alpha = store.latency_series(Some("alpha"), Window::Day, false, now, &Utc);
    assert!(!alpha.folded);
    assert_eq!(alpha.points.len(), 1, "{:?}", alpha.points);
    let p = alpha.points[0];
    assert_eq!((p.t, p.calls, p.timed_out, p.failed), (T0, 2, 1, 0));
    assert_eq!(
        p.v,
        Some(super::super::latency::bin_ms(
            super::super::latency::bin_of(Duration::from_millis(100))
        ))
    );
    let all = store.latency_series(None, Window::Day, false, now, &Utc);
    assert_eq!(
        all.points.iter().map(|p| p.t).collect::<Vec<_>>(),
        [T0, T0 + 3 * HALF]
    );
}

/// Row 31: 30-day points are local-day starts.
#[test]
fn series_latency_month_points_are_day_starts() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 50, End::Answered);
    let view = store.latency_series(Some("alpha"), Window::Month, false, T0 + 20, &Utc);
    assert_eq!(view.points.len(), 1);
    assert_eq!(view.points[0].t % 86_400, 0, "a UTC day start");
}

/// Row 32: the previous 24 hours, read from the same ring.
#[test]
fn series_latency_compare_prev() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100, End::Answered);
    let now = T0 + 50 * HALF;
    let view = store.latency_series(Some("alpha"), Window::Day, true, now, &Utc);
    assert!(view.points.is_empty(), "today has no calls");
    let previous = view.previous.expect("asked for");
    assert_eq!(previous.len(), 1);
    assert_eq!(previous[0].t, T0);
}

/// Row 34: a server the store does not hold reads folded, no points.
#[test]
fn series_latency_folded() {
    let store = CounterStore::new(T0);
    let view = store.latency_series(Some("ghost"), Window::Day, false, T0 + 10, &Utc);
    assert!(view.folded && view.points.is_empty());
}

/// Row 36: the Overview hour, slowest first, bounded by the two slots.
#[test]
fn overview_names_slowest() {
    let store = CounterStore::new(T0);
    for _ in 0..30 {
        timed(&store, "fast", T0 + HALF + 10, 10, End::Answered);
        timed(&store, "slow", T0 + 10, 2_000, End::Answered);
    }
    let hour = store.latency_hour(T0 + HALF + 20);
    let names: Vec<&str> = hour.servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["slow", "fast"]);
    assert_eq!(hour.slowest.map(|s| s.name), Some("slow".to_owned()));
    assert_eq!((hour.from, hour.to), (T0, T0 + 2 * HALF));
}

/// Row 37: 20 calls do not name a server slowest; 21 do.
#[test]
fn overview_slowest_floor_21() {
    let store = CounterStore::new(T0);
    for _ in 0..20 {
        timed(&store, "slow", T0 + 10, 2_000, End::Answered);
    }
    assert_eq!(store.latency_hour(T0 + 20).slowest, None);
    timed(&store, "slow", T0 + 10, 2_000, End::Answered);
    assert_eq!(
        store.latency_hour(T0 + 20).slowest.map(|s| s.calls),
        Some(21)
    );
}

/// Row 38: the slowest server is found over every server, and an idle one's
/// stale live slots do not count.
#[test]
fn overview_hour_reads_the_clock_not_stale_slots() {
    let store = CounterStore::new(T0);
    for _ in 0..30 {
        timed(&store, "idle", T0 + 10, 5_000, End::Answered);
    }
    // Five slots later the idle server's samples are outside the hour.
    let hour = store.latency_hour(T0 + 5 * HALF);
    assert!(hour.servers.is_empty(), "{:?}", hour.servers);
    assert_eq!(hour.slowest, None);
}

/// Row 12: the server past the cap records into the overflow's latency; once
/// the held labels age out a sweep frees a slot, and the new label's latency
/// starts empty (only its own sample).
#[test]
fn server_cap_overflow_and_sweep() {
    let cap = super::super::MAX_LABELS;
    let store = CounterStore::new(T0);
    for i in 0..cap {
        timed(&store, &format!("srv-{i}"), T0 + 10, 100, End::Answered);
    }
    timed(&store, "late", T0 + 10, 100, End::Answered);
    assert!(store.latency_series(Some("late"), Window::Day, false, T0 + 20, &Utc).folded);
    assert!(!store.snapshot().server.overflow.latency.is_empty(), "overflow holds it");
    let aged = T0 + 31 * 86_400;
    timed(&store, "fresh", aged, 900, End::Failed);
    assert_eq!(store.sweeps(), 1);
    let view = store.latency_series(Some("fresh"), Window::Day, false, aged + 10, &Utc);
    assert!(!view.folded);
    let [point] = view.points.as_slice() else {
        panic!("one slot for the new label: {:?}", view.points);
    };
    assert_eq!((point.calls, point.failed), (1, 1));
}
