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

fn timed_in<Tz: chrono::TimeZone>(store: &CounterStore, server: &str, at: u64, ms: u64, zone: &Tz) {
    store.record_timed(&call(server), at, zone, Some((Duration::from_millis(ms), End::Answered)));
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

/// Row 34: a server not held while its dimension is full reads folded (its
/// calls may be in the overflow); with room left, and no overflow latency in
/// the window, it reads empty and not folded, as U1's counts do.
#[test]
fn series_latency_folded() {
    let store = CounterStore::new(T0);
    let view = store.latency_series(Some("ghost"), Window::Day, false, T0 + 10, &Utc);
    assert!(!view.folded && view.points.is_empty(), "room left: not folded");
    for i in 0..super::super::MAX_LABELS {
        timed(&store, &format!("srv-{i}"), T0 + 10, 100, End::Answered);
    }
    let view = store.latency_series(Some("ghost"), Window::Day, false, T0 + 20, &Utc);
    assert!(view.folded && view.points.is_empty(), "full: folded");
}

/// Review F5: compare=prev maps each slot to the same local wall-clock time
/// on the previous local date (U1's rule), so across a DST change it reads
/// the previous day's slot, not the one 24 hours back.
#[test]
fn series_latency_compare_prev_follows_local_wall_time() {
    use chrono_tz::Europe::Amsterdam;
    // Amsterdam falls back on 2026-10-25 at 03:00: 12:00 local on the 25th is
    // 11:00 UTC, and 12:00 local on the 24th (summer time) is 10:00 UTC, 25
    // hours earlier. 24 hours back is 13:00 local on the 24th.
    let noon_25 = 1_792_926_000; // 2026-10-25T11:00:00Z
    let noon_24 = noon_25 - 25 * 3_600; // 2026-10-24T10:00:00Z, 12:00 CEST
    let one_pm_24 = noon_25 - 24 * 3_600; // 2026-10-24T11:00:00Z, 13:00 CEST
    let store = CounterStore::new(noon_24 - 3_600);
    timed_in(&store, "alpha", noon_24 + 10, 100, &Amsterdam);
    timed_in(&store, "alpha", one_pm_24 + 10, 900, &Amsterdam);
    // Read with now in the noon slot only, so today's window ends there.
    let view = store.latency_series(Some("alpha"), Window::Day, true, noon_25 + 20, &Amsterdam);
    let previous = view.previous.expect("asked for");
    let last = previous.last().expect("the previous period's newest slot");
    assert_eq!(last.t, noon_24, "noon maps to the previous date's noon: {previous:?}");
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
    assert!(store.sweeps() > 0, "the full dimension was swept");
    assert_eq!(store.labels(super::super::Dim::Server), 1, "every aged label freed");
    let view = store.latency_series(Some("fresh"), Window::Day, false, aged + 10, &Utc);
    assert!(!view.folded);
    let [point] = view.points.as_slice() else {
        panic!("one slot for the new label: {:?}", view.points);
    };
    assert_eq!((point.calls, point.failed), (1, 1));
}

/// Review F6: a server admitted 12 hours ago, whose previous day had latency
/// in the server overflow, draws no previous point from before it was
/// admitted and says the period is incomplete, as U1's counts do.
#[test]
fn previous_period_omits_what_the_overflow_may_hold() {
    let now = T0 + 3 * 86_400;
    let store = CounterStore::new(T0);
    let stray = Call {
        caller: "key:a",
        server: Label::Untrusted,
        tool: Label::Known("t"),
        tally: Tally::default(),
    };
    let sample = Some((Duration::from_millis(50), End::Answered));
    store.record_timed(&stray, now - 36 * 3_600, &Utc, sample);
    let admitted = now - 12 * 3_600;
    timed(&store, "alpha", admitted, 100, End::Answered);
    let view = store.latency_series(Some("alpha"), Window::Day, true, now, &Utc);
    assert!(!view.folded, "the server's own points are exact");
    assert!(!view.previous_complete, "the overflow may hold its previous calls");
    let start = admitted - admitted % HALF;
    assert!(
        view.previous.expect("asked for").iter().all(|p| p.t >= start),
        "no previous point from before it was admitted"
    );
}

/// Review F8: after the clock stepped back, a live slot ahead of the hour is
/// not merged into it.
#[test]
fn overview_hour_ignores_slots_ahead_of_the_clock() {
    let store = CounterStore::new(T0);
    for _ in 0..30 {
        timed(&store, "ahead", T0 + 5 * HALF + 10, 5_000, End::Answered);
    }
    let hour = store.latency_hour(T0 + 10);
    assert!(hour.servers.is_empty(), "{:?}", hour.servers);
}
