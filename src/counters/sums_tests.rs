// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Batch window sums (U11 T2, T2b, T7, T11): one lock for any label count,
//! the same totals as the series read where a period is complete, and
//! `None` exactly where a count could be low.

use chrono::TimeZone;
use chrono_tz::{Europe::Amsterdam, UTC};

use super::*;

const HOUR: u64 = 3600;
/// 2026-10-20T00:00:00Z.
const T0: u64 = 1_792_454_400;

fn record(store: &CounterStore, tool: Label<'_>, at: u64) {
    let call = Call {
        caller: "key:a",
        server: Label::Known("s"),
        tool,
        tally: Tally::default(),
    };
    store.record(&call, at, &UTC);
}

fn tool(name: &str) -> Filter<'_> {
    Filter::Tool("s", name)
}

fn local<Tz: TimeZone>(zone: &Tz, (y, mo, d, h, mi): (i32, u32, u32, u32, u32)) -> u64 {
    let wall = chrono::NaiveDate::from_ymd_opt(y, mo, d)
        .unwrap()
        .and_hms_opt(h, mi, 0)
        .unwrap();
    u64::try_from(
        zone.from_local_datetime(&wall)
            .earliest()
            .unwrap()
            .timestamp(),
    )
    .unwrap()
}

/// T1c: at a fixed clock 10 minutes into a half hour, the current window
/// holds only that half hour's elapsed part, while the previous period holds
/// its whole twin, including a call at a wall time today has not reached.
#[test]
fn t1c_the_current_bucket_is_partial_and_its_twin_whole() {
    let now = T0 + 7 * HOUR + 600;
    let store = CounterStore::new(0);
    record(&store, Label::Known("t"), now - 590);
    record(&store, Label::Known("t"), now - 86_400 - 590);
    record(&store, Label::Known("t"), now - 86_400 + 1_100);
    let sums = store.window_sums(&[tool("t")], now, &UTC);
    assert_eq!(sums.counts, vec![(Some(1), Some(2))]);
}

/// T2c: after the clock steps back, a series whose newest bucket is ahead of
/// `now` has dropped the previous period's oldest buckets from its ring: the
/// previous count reads `None`, while the current one stays exact.
#[test]
fn t2c_a_clock_step_back_loses_the_oldest_previous_buckets() {
    let now = T0 + 7 * HOUR;
    let store = CounterStore::new(0);
    record(&store, Label::Known("t"), now - HOUR);
    record(&store, Label::Known("t"), now + 10 * HOUR);
    let sums = store.window_sums(&[tool("t")], now, &UTC);
    assert_eq!(sums.counts, vec![(Some(1), None)]);
}

/// T7: one batch read takes the lock once, for 3 labels or 300.
#[test]
fn t7_one_lock_whatever_the_label_count() {
    for count in [3, 300] {
        let store = CounterStore::new(0);
        let names: Vec<String> = (0..count).map(|n| format!("t{n}")).collect();
        let labels: Vec<Filter<'_>> = names.iter().map(|n| tool(n)).collect();
        let before = store.reads_for_test();
        let sums = store.window_sums(&labels, T0, &UTC);
        assert_eq!(store.reads_for_test() - before, 1, "{count} labels");
        assert_eq!(sums.counts.len(), count);
    }
}

/// T11: where a period is complete and nothing overflowed, each sum is the
/// series read's total, in UTC and across both Amsterdam DST changes.
#[test]
fn t11_sums_match_the_series_read() {
    let amsterdam_spring = local(&Amsterdam, (2026, 3, 30, 12, 15));
    // The fall-back day itself: the current window crosses the repeated hour.
    let amsterdam_fall = local(&Amsterdam, (2026, 10, 25, 12, 15));
    let cases: [(u64, bool); 3] = [
        (T0 + 7 * HOUR + 600, false),
        (amsterdam_spring, true),
        (amsterdam_fall, true),
    ];
    for (now, dst) in cases {
        let store = CounterStore::new(0);
        for k in 0..96 {
            let at = now - k * 1_800 + 60;
            if at <= now {
                record(&store, Label::Known("t"), at);
                if k % 3 == 0 {
                    record(&store, Label::Known("t"), at);
                }
            }
        }
        let query = Query {
            metric: Metric::Calls,
            window: Window::Day,
            filter: tool("t"),
            compare: true,
        };
        let (series, sums) = if dst {
            (
                store.series(&query, now, &Amsterdam),
                store.window_sums(&[tool("t")], now, &Amsterdam),
            )
        } else {
            (
                store.series(&query, now, &UTC),
                store.window_sums(&[tool("t")], now, &UTC),
            )
        };
        assert!(!series.folded && series.previous_complete, "{now}");
        let day: u64 = series.points.iter().map(|p| p.v).sum();
        let prev: u64 = series.previous.expect("compared").iter().map(|p| p.v).sum();
        assert_eq!(sums.counts, vec![(Some(day), Some(prev))], "{now}");
    }
}

/// T2: a label not held while its dimension is full reads `None` in both
/// periods.
#[test]
fn t2_an_unheld_label_in_a_full_dimension_is_unknown() {
    let store = CounterStore::new(0);
    for n in 0..MAX_LABELS {
        record(&store, Label::Known(&format!("t{n}")), T0 - HOUR);
    }
    let sums = store.window_sums(&[tool("not-held"), tool("t0")], T0, &UTC);
    assert_eq!(sums.counts[0], (None, None));
    assert_eq!(sums.counts[1], (Some(1), Some(0)));
}

/// T2: overflow calls only in the previous period make only the previous
/// count unknown for a label not held; the current count stays exact.
#[test]
fn t2_overflow_in_the_previous_period_only_nulls_that_period() {
    let store = CounterStore::new(0);
    record(&store, Label::Untrusted, T0 - 36 * HOUR);
    let sums = store.window_sums(&[tool("quiet")], T0, &UTC);
    assert_eq!(sums.counts, vec![(Some(0), None)]);
}

/// T2: overflow calls in the current period make a label not held unknown
/// there, while a label held all along keeps its exact count.
#[test]
fn t2_overflow_in_the_current_period_nulls_only_unheld_labels() {
    let store = CounterStore::new(0);
    record(&store, Label::Known("held"), T0 - 40 * HOUR);
    record(&store, Label::Known("held"), T0 - HOUR);
    record(&store, Label::Untrusted, T0 - 2 * HOUR);
    let sums = store.window_sums(&[tool("held"), tool("quiet")], T0, &UTC);
    // Its admission call at T0 - 40 h is in the previous period.
    assert_eq!(sums.counts[0], (Some(1), Some(1)));
    assert_eq!(sums.counts[1], (None, Some(0)));
}

/// T2: overflow calls earlier in the half hour a label was admitted in may be
/// its own, so that period reads `None`.
#[test]
fn t2_overflow_in_the_admission_half_hour_is_not_attributed() {
    let store = CounterStore::new(0);
    let admitted = T0 - HOUR + 900;
    record(&store, Label::Untrusted, admitted - 300);
    record(&store, Label::Known("late"), admitted);
    let sums = store.window_sums(&[tool("late")], T0, &UTC);
    assert_eq!(sums.counts[0].0, None);
}

/// T3: a store younger than both periods reads numbers, not `None`: no call
/// is hidden, the store did not exist yet.
#[test]
fn t3_a_young_store_reads_numbers() {
    let since = T0 - 3 * HOUR;
    let store = CounterStore::new(since);
    record(&store, Label::Known("t"), T0 - HOUR);
    let sums = store.window_sums(&[tool("t")], T0, &UTC);
    assert_eq!(sums.counts, vec![(Some(1), Some(0))]);
    assert_eq!(sums.since, since);
}

/// T2b: the day after a fall-back, the previous date is 25 hours long and
/// its first hours lie past the 48-hour ring: the previous count reads
/// `None` while the current one stays exact.
#[test]
fn t2b_previous_buckets_past_the_ring_are_unknown() {
    let now = local(&Amsterdam, (2026, 10, 26, 12, 15));
    let store = CounterStore::new(0);
    record(&store, Label::Known("t"), now - HOUR);
    let sums = store.window_sums(&[tool("t")], now, &Amsterdam);
    assert_eq!(sums.counts, vec![(Some(1), None)]);
}

/// T7b: labels the store does not hold all get the same answer, worked out
/// once: the walks do not grow with the number of misses.
#[test]
fn t7b_unheld_labels_share_one_walk() {
    let now = T0 + 7 * HOUR;
    let store = CounterStore::new(0);
    record(&store, Label::Known("held"), now - HOUR);
    let names: Vec<String> = (0..600).map(|i| format!("ghost-{i:03}")).collect();
    let labels: Vec<Filter<'_>> = names.iter().map(|n| Filter::Server(n)).collect();
    let before = store.window_walks_for_test();

    let sums = store.window_sums(&labels, now, &UTC);

    assert!(sums.counts.iter().all(|c| *c == (Some(0), Some(0))));
    assert!(
        store.window_walks_for_test() - before <= 1,
        "{} walks for 600 unheld labels",
        store.window_walks_for_test() - before
    );
}
