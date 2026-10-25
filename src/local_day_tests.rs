// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Local-day bounds on DST days and fractional-offset zones (MIK-8901).
//! Instants computed independently with Python's `zoneinfo`.

use super::*;
use chrono_tz::{America, Asia, Europe, Pacific};

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("a valid date")
}

/// 2026-10-25 in Amsterdam lasts 25 hours: 00:00 CEST (22:00 UTC the day
/// before) to 00:00 CET (23:00 UTC), and both copies of 02:30 belong to it.
#[test]
fn the_autumn_change_day_is_25_hours_and_holds_the_repeated_hour() {
    let day = local_day(&Europe::Amsterdam, 1_792_879_200);
    assert_eq!(day.date, date(2026, 10, 25));
    assert_eq!((day.start, day.end), (1_792_879_200, 1_792_969_200));
    assert_eq!(day.end - day.start, 90_000);
    for repeated_0230 in [1_792_888_200, 1_792_891_800] {
        assert_eq!(local_day(&Europe::Amsterdam, repeated_0230), day);
    }
    assert_eq!(
        local_day(&Europe::Amsterdam, 1_792_879_199).date,
        date(2026, 10, 24)
    );
    assert_eq!(local_day(&Europe::Amsterdam, 1_792_969_199), day);
    assert_eq!(
        local_day(&Europe::Amsterdam, 1_792_969_200).date,
        date(2026, 10, 26)
    );
}

/// 2027-03-28 in Amsterdam lasts 23 hours; 01:59:59 and 03:00:00 local are
/// one second apart and on the same day.
#[test]
fn the_spring_change_day_is_23_hours() {
    let day = local_day(&Europe::Amsterdam, 1_806_188_400);
    assert_eq!(day.date, date(2027, 3, 28));
    assert_eq!((day.start, day.end), (1_806_188_400, 1_806_271_200));
    assert_eq!(day.end - day.start, 82_800);
    assert_eq!(local_day(&Europe::Amsterdam, 1_806_195_599), day);
    assert_eq!(local_day(&Europe::Amsterdam, 1_806_195_600), day);
    assert_eq!(
        local_day(&Europe::Amsterdam, 1_806_188_399).date,
        date(2027, 3, 27)
    );
}

/// Half- and quarter-hour offsets: local midnight is not on a UTC hour.
#[test]
fn fractional_offset_zones_start_the_day_off_the_hour() {
    let kolkata = local_day(&Asia::Kolkata, 1_792_866_600);
    assert_eq!(kolkata.date, date(2026, 10, 25));
    assert_eq!(
        (kolkata.start, kolkata.end),
        (1_792_866_600, 1_792_866_600 + 86_400)
    );
    let kathmandu = local_day(&Asia::Kathmandu, 1_792_865_700 + 3_600);
    assert_eq!(kathmandu.date, date(2026, 10, 25));
    assert_eq!(kathmandu.start, 1_792_865_700);
    assert_eq!(
        local_day(&Asia::Kathmandu, 1_792_865_699).date,
        date(2026, 10, 24)
    );
}

/// Where a zone skips midnight, the day starts at the first valid instant.
/// America/Havana sprang from 00:00 to 01:00 on 2023-03-12, so that day began
/// at 01:00 CDT (05:00 UTC) and lasted 23 hours.
#[test]
fn a_skipped_midnight_starts_the_day_at_the_first_valid_instant() {
    let day = local_day(&America::Havana, 1_678_597_200);
    assert_eq!(day.date, date(2023, 3, 12));
    assert_eq!(day.start, 1_678_597_200);
    assert_eq!(day.end - day.start, 82_800);
    // The day before ends where this one starts: no gap, no overlap.
    assert_eq!(local_day(&America::Havana, day.start - 1).end, day.start);
    // `start` is in the day it opens, never in the day before (MIK-8854 U1).
    assert_eq!(local_day(&America::Havana, day.start).date, day.date);
    assert_eq!(
        local_day(&America::Havana, day.start - 1).date,
        date(2023, 3, 11)
    );
    assert_eq!(local_day(&America::Havana, day.start + 43_200), day);
}

/// U1 walks a chart back one day at a time from `start - 1`: across the
/// 25-hour day each step lands on the previous date, none repeated or skipped.
#[test]
fn walking_back_from_start_visits_every_date_once() {
    let mut day = local_day(&Europe::Amsterdam, 1_794_783_600); // 2026-11-16 00:00 CET
    for _ in 0..30 {
        let previous = local_day(&Europe::Amsterdam, day.start - 1);
        assert_eq!(previous.date.succ_opt(), Some(day.date));
        assert_eq!(previous.end, day.start);
        day = previous;
    }
    assert_eq!(day.date, date(2026, 10, 17));
}

/// A date the zone skipped whole (Pacific/Apia, 2011-12-30) never appears:
/// the 29th ends where the 31st starts.
#[test]
fn a_skipped_date_leaves_no_gap() {
    let before = local_day(&Pacific::Apia, 1_325_239_199);
    assert_eq!(before.date, date(2011, 12, 29));
    let after = local_day(&Pacific::Apia, before.end);
    assert_eq!(after.date, date(2011, 12, 31));
    assert_eq!(after.start, before.end);
}

/// UTC days are the old `secs / 86_400` days.
#[test]
fn utc_days_match_the_epoch_day_count() {
    for secs in [0, 86_399, 86_400, 1_792_879_200] {
        let day = local_day(&chrono_tz::Tz::UTC, secs);
        assert_eq!(day.start, secs / 86_400 * 86_400);
        assert_eq!(day.end, day.start + 86_400);
    }
}

/// Tests count in UTC unless a test names a zone, and the override ends with
/// its guard.
#[test]
fn the_test_zone_defaults_to_utc_and_is_scoped() {
    assert_eq!(host_zone_name(), "UTC");
    {
        let _amsterdam = test_zone(Europe::Amsterdam);
        assert_eq!(host_zone_name(), "Europe/Amsterdam");
    }
    assert_eq!(host_zone_name(), "UTC");
}

/// The system zone reads once into a zone that names itself.
#[test]
fn the_system_zone_reads_as_a_named_zone() {
    let zone = system_zone();
    assert_eq!(zone.name().parse::<chrono_tz::Tz>(), Ok(zone));
    assert_eq!(system_zone(), zone);
}
