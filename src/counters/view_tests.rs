// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854 previous period and coverage (test plan T34, T35, T39): the
//! previous period maps by local wall-clock time, with its own `t` values,
//! and nothing is drawn before coverage began.

use chrono::TimeZone;
use chrono_tz::{Europe::Amsterdam, UTC};

use super::*;

const HALF_SECS: u64 = HALF;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;
/// 2026-10-20T00:00:00Z.
const T0: u64 = 1_792_454_400;

fn call() -> Call<'static> {
    Call {
        caller: "key:a",
        server: Label::Known("s"),
        tool: Label::Known("t"),
        tally: Tally::default(),
    }
}

fn at<Tz: TimeZone>(zone: &Tz, (y, mo, d, h, mi): (i32, u32, u32, u32, u32)) -> u64 {
    let local = chrono::NaiveDate::from_ymd_opt(y, mo, d)
        .unwrap()
        .and_hms_opt(h, mi, 0)
        .unwrap();
    u64::try_from(
        zone.from_local_datetime(&local)
            .earliest()
            .unwrap()
            .timestamp(),
    )
    .unwrap()
}

fn compare(store: &CounterStore, now: u64, zone: &impl TimeZone) -> SeriesView {
    let mut query = Query::new(Metric::Calls, Window::Day, Filter::All);
    query.compare = true;
    store.series(&query, now, zone)
}

/// T34: the previous period is the same clock times a day earlier, each
/// point with its own `t`, and a count where one was recorded.
#[test]
fn t34_the_previous_period_has_its_own_times_and_counts() {
    let store = CounterStore::new(T0);
    let now = T0 + 2 * DAY + 12 * HOUR;
    store.record(&call(), now, &UTC);
    store.record(&call(), now, &UTC);
    for _ in 0..3 {
        store.record(&call(), now - DAY, &UTC);
    }
    let view = compare(&store, now, &UTC);
    assert!(view.previous.is_some(), "the previous period was asked for");
    let previous = view.previous.unwrap();
    assert_eq!(view.points.len(), 48);
    assert_eq!(previous.len(), 48);
    assert!(view.previous_complete);
    let bucket = now - now % HALF_SECS;
    assert_eq!(view.points.last(), Some(&Point { t: bucket, v: 2 }));
    assert_eq!(
        previous.last(),
        Some(&Point {
            t: bucket - DAY,
            v: 3
        })
    );
    for (point, before) in view.points.iter().zip(&previous) {
        assert_eq!(point.t - before.t, DAY, "own t values, a day earlier");
    }
}

/// T35: on the day after the fall-back, the repeated wall time gives two
/// previous points; at the 48-hour edge, what the ring no longer holds is
/// absent, not zero, and the period is flagged incomplete.
#[test]
fn t35_the_fall_back_day_maps_by_wall_time() {
    let since = at(&Amsterdam, (2026, 10, 22, 0, 0));
    let store = CounterStore::new(since);
    // 02:15 on 2026-10-25 happened twice: CEST (00:15Z), then CET (01:15Z).
    let first = at(&Amsterdam, (2026, 10, 25, 2, 15));
    let second = first + HOUR;
    store.record(&call(), first, &Amsterdam);
    for _ in 0..2 {
        store.record(&call(), second, &Amsterdam);
    }
    let now = at(&Amsterdam, (2026, 10, 26, 3, 10));
    store.record(&call(), now, &Amsterdam);
    let view = compare(&store, now, &Amsterdam);
    assert!(view.previous.is_some(), "the previous period was asked for");
    let previous = view.previous.unwrap();
    let repeated: Vec<Point> = previous
        .iter()
        .copied()
        .filter(|p| p.t == first - 15 * 60 || p.t == second - 15 * 60)
        .collect();
    assert_eq!(
        repeated,
        vec![
            Point {
                t: first - 15 * 60,
                v: 1
            },
            Point {
                t: second - 15 * 60,
                v: 2
            },
        ],
        "02:00 local on the 25th maps to both of its buckets"
    );
    let late = at(&Amsterdam, (2026, 10, 26, 23, 40));
    store.record(&call(), late, &Amsterdam);
    let view = compare(&store, late, &Amsterdam);
    assert!(
        !view.previous_complete,
        "part of the period is past the ring"
    );
    let held_from = (late / HALF_SECS - 95) * HALF_SECS;
    assert!(
        view.previous.unwrap().iter().all(|p| p.t >= held_from),
        "nothing outside the ring is shown, not even as zero"
    );
}

/// T35: on the day after the spring-forward, the skipped wall times give no
/// previous point, and the period is still complete.
#[test]
fn t35_the_spring_forward_day_skips_the_missing_hour() {
    let since = at(&Amsterdam, (2027, 3, 25, 0, 0));
    let store = CounterStore::new(since);
    let now = at(&Amsterdam, (2027, 3, 29, 12, 0));
    store.record(&call(), now, &Amsterdam);
    let view = compare(&store, now, &Amsterdam);
    assert!(view.previous.is_some(), "the previous period was asked for");
    let previous = view.previous.unwrap();
    assert_eq!(view.points.len(), 48);
    assert_eq!(
        previous.len(),
        46,
        "02:00 and 02:30 did not exist on the 28th"
    );
    assert!(view.previous_complete);
}

/// T39: before coverage began there are no points; after it, an empty bucket
/// is a zero.
#[test]
fn t39_no_points_before_since_and_zeros_after() {
    let now = T0 + 10 * HOUR;
    let since = now - 3 * HOUR;
    let store = CounterStore::new(since);
    store.record(&call(), now, &UTC);
    let points = store
        .series(
            &Query::new(Metric::Calls, Window::Day, Filter::All),
            now,
            &UTC,
        )
        .points;
    assert_eq!(
        points.len(),
        7,
        "the bucket holding since, and six after it"
    );
    assert!(points.iter().all(|p| p.t + HALF_SECS > since));
    assert_eq!(points.iter().filter(|p| p.v == 0).count(), 6);
}
