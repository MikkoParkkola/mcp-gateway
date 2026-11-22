// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8000: the counters stay bounded whatever the call rate, and the
//! windows read what the per-call records used to.

use super::*;

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;
const MONTH: u64 = 30 * DAY;

/// A clock well past the epoch, not on an hour boundary.
const NOW: u64 = 1_000 * DAY + 1_234;

#[test]
fn windows_count_only_spend_inside_them() {
    let mut hours = HourBuckets::default();
    // GIVEN: spend 23 h, 25 h, 29 days and 31 days ago (one token each)
    for ago in [23 * HOUR, 25 * HOUR, 29 * DAY, 31 * DAY] {
        hours.add(NOW - ago, NOW, 1, 1);
    }
    // THEN: each window counts what lies inside it; 31 days ago was dropped
    assert_eq!(hours.totals(NOW, DAY).0, 1);
    assert_eq!(hours.totals(NOW, 7 * DAY).0, 2);
    assert_eq!(hours.totals(NOW, MONTH).0, 3);
    assert_eq!(hours.len(), 3);
}

#[test]
fn the_cutoff_hour_of_the_month_still_counts() {
    let mut hours = HourBuckets::default();
    // GIVEN: spend exactly at the 30-day cutoff, then a call now
    hours.add(NOW - MONTH, NOW - MONTH, 5, 0);
    hours.add(NOW, NOW, 1, 0);
    // THEN: the cutoff bucket is kept and counted
    assert_eq!(hours.totals(NOW, MONTH).0, 6);
    assert_eq!(hours.len(), 2);
}

#[test]
fn spend_every_hour_for_longer_than_a_month_keeps_at_most_721_buckets() {
    let mut hours = HourBuckets::default();
    let start = NOW - 800 * HOUR;
    // GIVEN: one token in each of 800 consecutive hours, up to now
    for h in 0..=800 {
        let at = start + h * HOUR;
        hours.add(at, at, 1, 0);
    }
    // THEN: the bound holds and the month window still counts its hours
    assert_eq!(hours.len(), usize::try_from(BUCKET_HOURS + 1).unwrap());
    assert_eq!(hours.totals(NOW, MONTH).0, BUCKET_HOURS + 1);
}

#[test]
fn a_clock_stepping_back_lands_in_its_own_hour() {
    let mut hours = HourBuckets::default();
    // GIVEN: spend now, then spend stamped two hours earlier
    hours.add(NOW, NOW, 1, 0);
    hours.add(NOW - 2 * HOUR, NOW - 2 * HOUR, 1, 0);
    // THEN: two buckets in order, the older one outside a one-hour window
    assert_eq!(hours.len(), 2);
    assert_eq!(hours.totals(NOW, HOUR).0, 1);
    assert_eq!(hours.totals(NOW, DAY).0, 2);
    // AND: spend stamped before the month, behind the newest bucket, is dropped
    // here, by the buckets alone; `Series::add`, the live add, settles the
    // series first and keeps it (the rows below).
    hours.add(NOW - MONTH - 2 * HOUR, NOW - MONTH - 2 * HOUR, 1, 0);
    assert_eq!(hours.len(), 2);
}

#[test]
fn tools_past_the_cap_share_one_other_row_with_exact_totals() {
    let mut tally = ToolTally::default();
    // GIVEN: 300 distinct tools, one call each, then one more call on the first
    for i in 0..300 {
        tally.add("srv", &format!("t{i}"), 1, 0);
    }
    tally.add("srv", "t0", 1, 0);
    let (by_backend, by_tool, totals) = tally.breakdown();
    // THEN: 256 rows plus (other), and nothing is lost
    assert_eq!(tally.len(), MAX_TOOL_ROWS + 1);
    let other = by_tool.iter().find(|row| row.tool_key == OTHER).unwrap();
    assert_eq!(other.call_count, 300 - 256);
    let t0 = by_tool.iter().find(|row| row.tool_key == "srv:t0").unwrap();
    assert_eq!(
        t0.call_count, 2,
        "a saturated tally still counts a known row"
    );
    assert_eq!(totals, [301, 301, 0]);
    assert_eq!(by_backend.iter().map(|b| b.call_count).sum::<u64>(), 301);
}

#[test]
fn only_the_first_caller_past_the_due_time_sweeps() {
    let next = AtomicU64::new(0);
    assert!(sweep_due(&next, 100));
    assert!(!sweep_due(&next, 100 + SWEEP_EVERY - 1));
    assert!(sweep_due(&next, 100 + SWEEP_EVERY));
}

#[test]
fn a_real_tool_named_other_stays_apart_from_the_overflow_row() {
    let mut tally = ToolTally::default();
    // GIVEN: a real (other)/(other) pair, then 300 more tools to force overflow
    tally.add(OTHER, OTHER, 1, 0);
    for i in 0..300 {
        tally.add("srv", &format!("t{i}"), 1, 0);
    }
    let (_, by_tool, _) = tally.breakdown();
    // THEN: the real pair keeps its own key; the overflow row is separate
    let calls = |key: &str| {
        by_tool
            .iter()
            .find(|t| t.tool_key == key)
            .map(|t| t.call_count)
    };
    assert_eq!(calls("(other):(other)"), Some(1));
    assert_eq!(calls(OTHER), Some(300 - 255));
}

#[test]
fn a_name_pair_past_the_byte_limit_counts_in_other() {
    let mut tally = ToolTally::default();
    // GIVEN: one pair exactly at the byte limit, one a byte past it
    let at_limit = "x".repeat(MAX_ROW_NAME_BYTES - "srv".len());
    let past_limit = "y".repeat(MAX_ROW_NAME_BYTES - "srv".len() + 1);
    tally.add("srv", &at_limit, 3, 5);
    tally.add("srv", &past_limit, 7, 11);
    // THEN: the first keeps a row; the second is in (other) with its totals
    let (_, by_tool, totals) = tally.breakdown();
    let row = |key: &str| {
        by_tool
            .iter()
            .find(|t| t.tool_key == key)
            .map(|t| t.token_count)
    };
    assert_eq!(row(&format!("srv:{at_limit}")), Some(3));
    assert_eq!(row(OTHER), Some(7));
    assert_eq!(totals, [2, 10, 16]);
}

#[test]
fn a_tally_logs_its_first_overflow_once() {
    const LINE: &str = "reached its row or name-size limit";
    let records = crate::test_log_capture::records(|| {
        let mut tally = ToolTally::default();
        for i in 0..MAX_TOOL_ROWS {
            tally.add("srv", &format!("t{i}"), 1, 0);
        }
        // Calls on known rows after the cap, then many overflowed calls
        tally.add("srv", "t0", 1, 0);
        for i in 0..50 {
            tally.add("srv", &format!("extra{i}"), 1, 0);
            tally.add("srv", "t1", 1, 0);
        }
    });
    assert_eq!(crate::test_log_capture::count(&records, "WARN", LINE), 1);
}

/// `MIK-8081.CEIL.1`: a positive cost rounds up to the next whole micro-USD,
/// a cost already whole in micro-USD keeps its value despite float noise, and
/// zero stays zero.
#[test]
fn a_positive_cost_rounds_up_to_whole_micro_usd() {
    assert_eq!(micro(1e-7), 1, "a sub-micro cost counted as free");
    assert_eq!(micro(1.5e-6), 2, "a fractional micro was dropped");
    // 0.07 * 1e6 is 70000.00000000001 in f64: it must not become 70001.
    assert_eq!(micro(0.07), 70_000);
    assert_eq!(micro(0.01), 10_000);
    // A genuine fraction of a micro-USD on a large price still rounds up.
    assert_eq!(micro(500.000_000_1), 500_000_001);
    assert_eq!(micro(0.0), 0);
    assert_eq!(micro(-0.07), 0);
    // A negative fraction must not round up to a positive charge.
    assert_eq!(micro(-1.5e-6), 0);
    assert_eq!(micro(f64::NAN), 0);
}

/// `MIK-8081.CEIL.1`: the price one float step either side of a whole
/// micro-USD rounds up above it and keeps the whole below it, even where the
/// multiplication by a million loses the fraction.
#[test]
fn the_float_next_to_a_whole_micro_rounds_the_right_way() {
    let whole: f64 = 0.000_15;
    let above = f64::from_bits(whole.to_bits() + 1);
    let below = f64::from_bits(whole.to_bits() - 1);
    assert_eq!(micro(whole), 150);
    assert_eq!(micro(above), 151, "a fraction above 150 micro-USD was lost");
    assert_eq!(micro(below), 150);
}

/// Micro-USD summed over a series' hours, and over its dates.
fn sums(series: &Series) -> (u64, u64) {
    let hourly = series.hours.rows().into_iter().map(|(_, _, m)| m);
    let daily = series.days.rows().into_iter().map(|(_, _, m)| m);
    (hourly.sum(), daily.sum())
}

/// Clock table row 3 (series level): spend now, two hours back, then a month
/// back, each at its own clock. Every amount is kept; the month-back record,
/// which a window measured from the newest held slot would drop, settles the
/// held slots into its own hour and date first. Red before: it was dropped.
#[test]
fn a_series_keeps_spend_recorded_a_month_behind_its_newest_slot() {
    let mut series = Series::default();
    for at in [NOW, NOW - 2 * HOUR, NOW - MONTH - 2 * HOUR] {
        series.add(at, at, 1, 1);
    }
    assert_eq!(sums(&series), (3, 3), "{series:?}");
    let back = NOW - MONTH - 2 * HOUR;
    assert_eq!(series.hours.newest(), Some(back / HOUR));
    assert_eq!(series.days.newest(), Some(local_date(back)));
}

/// Clock table row 4 (lead): two records across an hour boundary that take
/// the lock out of order, 11:00:00 first and 10:59:59 after it, both stay in
/// their own hours. A race is never re-dated.
#[test]
fn records_racing_an_hour_boundary_keep_their_own_hours() {
    let boundary = (NOW / HOUR + 1) * HOUR;
    let mut series = Series::default();
    series.add(boundary, boundary, 1, 1);
    series.add(boundary - 1, boundary - 1, 1, 1);
    let hours: Vec<u64> = series.hours.rows().iter().map(|r| r.0).collect();
    assert_eq!(hours, vec![boundary / HOUR - 1, boundary / HOUR]);
    assert_eq!(sums(&series), (2, 2));
}

/// Clock table row 5 (lead), under the chosen trigger: a step back of five
/// hours, more than one slot but less than a window, drops nothing, and the
/// held later hour keeps its date (only a record the window would drop
/// settles the series).
#[test]
fn a_step_back_inside_the_window_drops_nothing_and_moves_nothing() {
    let mut series = Series::default();
    series.add(NOW, NOW, 1, 1);
    series.add(NOW - 5 * HOUR, NOW - 5 * HOUR, 1, 1);
    let hours: Vec<u64> = series.hours.rows().iter().map(|r| r.0).collect();
    assert_eq!(hours, vec![NOW / HOUR - 5, NOW / HOUR]);
    assert_eq!(sums(&series), (2, 2));
}

/// Clock table row 6, the correction to a seat's "smaller step" case: a
/// record 100 hours ahead ages the series from its own clock (the forward
/// jump), and after the step back nothing more is lost: the later record
/// keeps its spend and the slot the jump left stays.
#[test]
fn after_a_jump_ahead_and_back_only_the_jump_aged_anything() {
    let mut series = Series::default();
    for at in [NOW - 700 * HOUR, NOW - 600 * HOUR, NOW, NOW + 100 * HOUR] {
        series.add(at, at, 1, 1);
    }
    // The jump aged out 700 hours back (older than 100 + 720 hours ago).
    assert_eq!(series.hours.len(), 3);
    series.add(NOW + HOUR, NOW + HOUR, 1, 1);
    let held: Vec<u64> = series.hours.rows().iter().map(|r| r.0).collect();
    let base = NOW / HOUR;
    assert_eq!(held, vec![base - 600, base, base + 1, base + 100]);
}

/// gpt table review: the hour trigger alone. Pacific/Chatham's April has a
/// 25-hour day, so local midnight on the 1st and 23:59 on the 30th are 721
/// hour slots apart (past the hour window) yet only 29 dates apart (inside
/// the date window). The earlier record settles the series by its hour, and
/// nothing is lost over the hours or the dates.
#[test]
fn a_record_past_only_the_hour_window_settles_the_series() {
    use crate::cost_accounting::spend_history_tests::{date, local};
    let tz = chrono_tz::Pacific::Chatham;
    let _zone = crate::local_day::test_zone(tz);
    let late = local(tz, date(2026, 4, 30), (23, 59));
    let early = local(tz, date(2026, 4, 1), (0, 0));
    assert_eq!(late / HOUR - early / HOUR, 721, "premise: 721 slots");
    let dates = local_date(late) - local_date(early);
    assert_eq!(dates.num_days(), 29, "premise: 29 dates");
    let mut series = Series::default();
    series.add(late, late, 1, 1);
    series.add(early, early, 1, 1);
    assert_eq!(sums(&series), (2, 2), "{series:?}");
    assert_eq!(series.hours.newest(), Some(early / HOUR));
}

/// The windows' shared edge: a record 29 dates and 696 hours behind the
/// newest held one is inside both windows and is inserted in its own hour
/// and date, with nothing settled.
#[test]
fn a_record_inside_both_windows_keeps_its_own_slots() {
    let _zone = crate::local_day::test_zone(chrono_tz::Tz::UTC);
    let late = 1_000 * DAY + 23 * HOUR;
    let early = late - 29 * DAY;
    let mut series = Series::default();
    series.add(late, late, 1, 1);
    series.add(early, early, 1, 1);
    let hours: Vec<u64> = series.hours.rows().iter().map(|r| r.0).collect();
    assert_eq!(hours, vec![early / HOUR, late / HOUR]);
    assert_eq!(series.days.len(), 2);
}

/// gpt table review: the date trigger alone. In UTC, a record 719.5 hours
/// behind the newest held one is inside the hour window but 30 dates back,
/// past the date window, so it settles the series by its date; nothing is
/// lost over the hours or the dates.
#[test]
fn a_record_past_only_the_date_window_settles_the_series() {
    let _zone = crate::local_day::test_zone(chrono_tz::Tz::UTC);
    let late = 1_000 * DAY + 23 * HOUR;
    let early = late - 30 * DAY + HOUR / 2;
    let mut series = Series::default();
    series.add(late, late, 1, 1);
    series.add(early, early, 1, 1);
    assert_eq!(sums(&series), (2, 2), "{series:?}");
    assert_eq!(series.days.newest(), Some(local_date(early)));
}

/// gpt table review: two corrections in a row, 80 days ahead, then 40, then
/// the true time; each settles the series again, and every amount is kept.
#[test]
fn repeated_steps_back_keep_every_amount() {
    let mut series = Series::default();
    for at in [NOW + 80 * DAY, NOW + 40 * DAY, NOW] {
        series.add(at, at, 1, 1);
    }
    assert_eq!(sums(&series), (3, 3), "{series:?}");
    assert_eq!(series.hours.rows(), vec![(NOW / HOUR, 3, 3)]);
}

/// gpt delta 3 improvement: `settle` on a series holding an expired slot, the
/// oldest kept slot, the cut's own slot and two later ones (one at the
/// largest amount) keeps the window, counts the later slots in the cut's
/// slot with saturating sums, and changes nothing when run again.
#[test]
fn settle_keeps_the_window_and_counts_later_slots_in_the_cut() {
    let cut = NOW / HOUR;
    let held = [
        (cut - BUCKET_HOURS - 1, 1, 1),
        (cut - BUCKET_HOURS, 2, 2),
        (cut, 3, 3),
        (cut + 1, 4, u64::MAX),
        (cut + 5, 5, 5),
    ];
    let mut hours: HourBuckets = Buckets(std::collections::VecDeque::from(held));
    hours.settle(cut);
    let once = hours.rows();
    assert_eq!(once, vec![(cut - BUCKET_HOURS, 2, 2), (cut, 12, u64::MAX)]);
    hours.settle(cut);
    assert_eq!(hours.rows(), once, "a second settle changed the series");
}
