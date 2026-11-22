// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tracker's local-day totals, its keyless series and the idle sweep.
//! Each spend fixes this thread's clock and zone, so the dates come from the
//! zone database and never from where the test runs.

use chrono::{NaiveDate, TimeZone};
use chrono_tz::{Asia, Europe, Pacific, Tz};

use super::CostTracker;
use crate::clock::test_clock::at_secs;
use crate::local_day::test_zone;

/// Unix seconds of local `day` at `hh:mm` in `tz`; the instant must exist
/// and be unambiguous.
pub(super) fn local(tz: Tz, day: NaiveDate, (hh, mm): (u32, u32)) -> u64 {
    let wall = day.and_hms_opt(hh, mm, 0).expect("a wall time");
    let at = tz.from_local_datetime(&wall).single();
    let at = at.unwrap_or_else(|| panic!("{tz}: {wall} is not one instant"));
    u64::try_from(at.timestamp()).expect("after the epoch")
}

pub(super) fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("a date")
}

/// One call costing `n` tokens and `n` micro-USD at `at`, as `key`.
pub(super) fn spend(tracker: &CostTracker, key: Option<&str>, at: u64, n: u64) {
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
    let gateway = tracker.gateway_series(at);
    assert_eq!(gateway.hours.rows(), vec![(at / 3600, 9, 9)]);
    assert_eq!(gateway.days.rows(), vec![(date(2026, 11, 21), 9, 9)]);
}

/// Whether `k` still has an entry after a sweep at `at`. `setup` runs on a
/// fresh tracker; the sweep is then armed and a record on another key at
/// `at` runs it.
fn kept_after_sweep_at(at: u64, setup: impl FnOnce(&CostTracker)) -> bool {
    let tracker = CostTracker::new();
    setup(&tracker);
    tracker
        .next_key_sweep
        .store(0, std::sync::atomic::Ordering::Relaxed);
    spend(&tracker, Some("poke"), at, 1);
    tracker.key_snapshot("k").is_some()
}

/// S15: in Pacific/Chatham, April 2026 has a 25-hour day (the DST change on
/// the 5th), so the thirty local dates from April 1st span 721 hours. One
/// spend at 00:01 local on April 1st: its hour leaves the window before its
/// date does, and the entry must stay until both have gone. Red with the
/// 30-day sweep (gone from 10:16 UTC on the 30th), with an hour-only sweep
/// (gone from 11:00 UTC) and with one date past the cut (kept at midnight).
#[test]
fn the_sweep_keeps_a_key_until_its_day_window_expires_too() {
    let tz = Pacific::Chatham;
    let _zone = test_zone(tz);
    let spent = local(tz, date(2026, 4, 1), (0, 1));
    let midnight = local(tz, date(2026, 5, 1), (0, 0));
    let first = local(tz, date(2026, 4, 1), (0, 0));
    assert_eq!(midnight - first, 721 * 3600, "premise: 721 hours");
    assert!(
        midnight / 3600 > spent / 3600 + 720,
        "premise: the hour cut comes first"
    );

    let spend_k = |tracker: &CostTracker| spend(tracker, Some("k"), spent, 1);
    assert!(
        kept_after_sweep_at(midnight - 1, spend_k),
        "the last second of April 30th (local) swept a key whose date is still held"
    );
    assert!(
        !kept_after_sweep_at(midnight, spend_k),
        "local midnight of May 1st kept a key with both windows expired"
    );
}

/// S18: a key is born active. An entry with no spend yet survives a sweep at
/// its creation instant and one an hour later. Red with a rule that sweeps
/// keys whose windows are empty.
#[test]
fn a_key_just_created_is_not_swept() {
    let born = local(Tz::UTC, date(2026, 11, 21), (12, 0));
    let insert = |tracker: &CostTracker| {
        let _clock = at_secs(born);
        let key = std::sync::Arc::new(super::KeyCost::new("k"));
        tracker.per_key.insert("k".to_owned(), key);
    };
    assert!(kept_after_sweep_at(born, insert), "swept at birth");
    assert!(
        kept_after_sweep_at(born + 3600, insert),
        "swept an hour later"
    );
}

/// Clock table rows 1 and 2: a clock that ran 40 days ahead, then stepped
/// back. A key and the keyless series each spend 5 at the later time, then 2
/// at the corrected one; both series keep all 7, over hours and dates, and
/// none of their slots is dated after the corrected time. Red before: the
/// window ran from the held later slot, and the 2 was dropped.
#[test]
fn spend_after_a_clock_steps_back_past_the_window_is_kept() {
    let _zone = test_zone(Tz::UTC);
    let fixed = local(Tz::UTC, date(2026, 11, 21), (12, 0));
    let ahead = fixed + 40 * 24 * 3600;
    let tracker = CostTracker::new();
    for key in [Some("k"), None] {
        spend(&tracker, key, ahead, 5);
    }
    for key in [Some("k"), None] {
        spend(&tracker, key, fixed, 2);
    }
    let keyed = tracker.key_series("k").expect("the key");
    let day = date(2026, 11, 21);
    for (name, series) in [("keyed", keyed), ("keyless", tracker.keyless_series())] {
        assert_eq!(series.hours.rows(), vec![(fixed / 3600, 7, 7)], "{name}");
        assert_eq!(series.days.rows(), vec![(day, 7, 7)], "{name}");
    }
}

/// Both seats on the clock table: the gateway's series sums every key's. One
/// key spent while the clock ran 40 days ahead and another at the corrected
/// time; the total read at the corrected time holds both. Red before: the
/// sum ended its window at the later key's slot and lost the other's spend.
#[test]
fn the_gateway_total_keeps_a_key_behind_another_keys_later_slot() {
    let _zone = test_zone(Tz::UTC);
    let fixed = local(Tz::UTC, date(2026, 11, 21), (12, 0));
    let tracker = CostTracker::new();
    spend(&tracker, Some("ran-ahead"), fixed + 40 * 24 * 3600, 5);
    spend(&tracker, Some("current"), fixed, 2);
    let ahead_before = tracker.key_series("ran-ahead").expect("the key");
    let total = tracker.gateway_series(fixed);
    assert_eq!(total.hours.rows(), vec![(fixed / 3600, 7, 7)]);
    assert_eq!(total.days.rows(), vec![(date(2026, 11, 21), 7, 7)]);
    // The sum settles copies: the key's own series keeps its later slot.
    let ahead_after = tracker.key_series("ran-ahead").expect("the key");
    assert_eq!(ahead_after.hours.rows(), ahead_before.hours.rows());
    assert_eq!(ahead_after.days.rows(), ahead_before.days.rows());
}
