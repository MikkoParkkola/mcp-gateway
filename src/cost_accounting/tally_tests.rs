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
    assert_eq!(micro(0.0), 0);
}
