// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tracker's local-day totals and its keyless series.
//! Each spend fixes this thread's clock and zone, so the dates come from the
//! zone database and never from where the test runs.

use chrono::{NaiveDate, TimeZone};
use chrono_tz::{Asia, Europe, Tz};

use super::CostTracker;
use crate::clock::test_clock::at_secs;
use crate::local_day::test_zone;

/// Unix seconds of local `day` at `hh:mm` in `tz`; the instant must exist
/// and be unambiguous.
fn local(tz: Tz, day: NaiveDate, (hh, mm): (u32, u32)) -> u64 {
    let wall = day.and_hms_opt(hh, mm, 0).expect("a wall time");
    let at = tz.from_local_datetime(&wall).single();
    let at = at.unwrap_or_else(|| panic!("{tz}: {wall} is not one instant"));
    u64::try_from(at.timestamp()).expect("after the epoch")
}

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("a date")
}

/// One call costing `n` tokens and `n` micro-USD at `at`, as `key`.
fn spend(tracker: &CostTracker, key: Option<&str>, at: u64, n: u64) {
    let _clock = at_secs(at);
    tracker.record("", key, "srv", "t", n, 1.0);
}

/// S2: in a UTC+5:30 zone, 23:50 and 00:10 local fall in the same UTC hour:
/// one hour bucket holds both, and they land on two local dates.
/// Mutant: the day add dropped from the record path.
#[test]
fn a_local_midnight_inside_a_utc_hour_splits_the_days_not_the_hour() {
    let _zone = test_zone(Asia::Kolkata);
    let before = local(Asia::Kolkata, date(2026, 11, 20), (23, 50));
    let after = local(Asia::Kolkata, date(2026, 11, 21), (0, 10));
    assert_eq!(before / 3600, after / 3600, "premise: one UTC hour");

    let tracker = CostTracker::new();
    spend(&tracker, Some("k"), before, 3);
    spend(&tracker, Some("k"), after, 5);

    let series = tracker.key_series("k").expect("the key has a series");
    assert_eq!(series.hours.rows(), vec![(before / 3600, 8, 8)]);
    assert_eq!(
        series.days.rows(),
        vec![(date(2026, 11, 20), 3, 3), (date(2026, 11, 21), 5, 5)]
    );
}

/// Spend 1 just before local `day`, 2 at its first second, 4 at its last
/// second and 8 at the next day's first second; `day` must total 6.
fn one_day_holds_its_own_spend(day: NaiveDate, hours: u64) {
    let _zone = test_zone(Europe::Helsinki);
    let (before, next) = (
        day.pred_opt().expect("a date"),
        day.succ_opt().expect("a date"),
    );
    let start = local(Europe::Helsinki, day, (0, 0));
    let end = local(Europe::Helsinki, next, (0, 0));
    assert_eq!(end - start, hours * 3600, "premise: a {hours}-hour day");

    let tracker = CostTracker::new();
    for (at, n) in [(start - 1, 1), (start, 2), (end - 1, 4), (end, 8)] {
        spend(&tracker, Some("k"), at, n);
    }
    let days = tracker.key_series("k").expect("the key").days.rows();
    assert_eq!(days, vec![(before, 1, 1), (day, 6, 6), (next, 8, 8)]);
}

/// S3: Helsinki's 25-hour autumn day and 23-hour spring day each total
/// exactly their own spend. Mutant: days cut every 86 400 s from midnight.
#[test]
fn a_dst_day_totals_exactly_its_own_spend() {
    one_day_holds_its_own_spend(date(2026, 10, 25), 25);
    one_day_holds_its_own_spend(date(2026, 3, 29), 23);
}

/// S9: a dated call with no API key adds to the keyless series alone (no key
/// entry is made for it), and the gateway's series counts it with the keys'.
/// Mutant: an unkeyed record dropped instead of added to the keyless series.
#[test]
fn spend_with_no_key_is_in_the_keyless_series_and_the_gateway_total() {
    let at = local(Tz::UTC, date(2026, 11, 21), (12, 0));
    let tracker = CostTracker::new();
    spend(&tracker, None, at, 7);
    spend(&tracker, Some("k"), at, 2);

    assert_eq!(
        tracker.aggregate().key_count,
        1,
        "only the real key has an entry"
    );
    let keyless = tracker.keyless_series();
    assert_eq!(keyless.hours.rows(), vec![(at / 3600, 7, 7)]);
    assert_eq!(keyless.days.rows(), vec![(date(2026, 11, 21), 7, 7)]);
    let gateway = tracker.gateway_series();
    assert_eq!(gateway.hours.rows(), vec![(at / 3600, 9, 9)]);
    assert_eq!(gateway.days.rows(), vec![(date(2026, 11, 21), 9, 9)]);
}
