// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pager progress rows: a log the page has advanced nothing in assembles one
//! record even past the budget (by at most one assembly window per log read),
//! so paging never repeats a cursor; a log that has advanced keeps the strict
//! budget.

use serde_json::Map;

use super::answer_fixture::Fixture;
use super::reader::{Cursor, Limits, Look, Page, Seen, read_page_joined};
use crate::security::audit::{AuditEnvelope, AuditWho};
use crate::security::transparency_log::pager::ASSEMBLY_WINDOW;

const MIB: u64 = 1 << 20;

fn page(fx: &Fixture, gov: Option<&std::path::Path>, cursor: Option<&Cursor>, bytes: u64) -> Page {
    page_of(fx, gov, cursor, bytes, 10_000)
}

fn page_of(
    fx: &Fixture,
    gov: Option<&std::path::Path>,
    cursor: Option<&Cursor>,
    bytes: u64,
    matches: usize,
) -> Page {
    let limits = Limits { matches, bytes };
    let look = Look::Carried(Seen {
        above: 0,
        head_covered: true,
    });
    read_page_joined(&fx.path, gov, cursor, limits, look, |_, _| true).unwrap()
}

/// A record of 2 MiB, under the 4 MiB record cap.
fn pad(fx: &Fixture) {
    let mut pad = Map::new();
    pad.insert("event".into(), "pad".into());
    pad.insert("pad".into(), "x".repeat(2 << 20).into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    fx.logger.append_event(pad, &envelope).unwrap();
}

/// Page until the log is read, at most `limit` times; every page must move
/// the cursor or return a line.
fn drain(fx: &Fixture, mut cursor: Option<Cursor>, bytes: u64, limit: usize) -> usize {
    let mut rows = 0;
    for _ in 0..limit {
        let p = page(fx, None, cursor.as_ref(), bytes);
        assert!(
            !p.lines.is_empty() || p.next != cursor,
            "a page returned no row and the same cursor"
        );
        rows += p.lines.len();
        match p.next {
            Some(next) => cursor = Some(next),
            None => return rows,
        }
    }
    panic!("the log was not read in {limit} pages");
}

#[test]
fn r43c_two_logs_with_a_big_newest_record_page_to_the_end() {
    let (inv, gov) = (Fixture::new(None), Fixture::new(None));
    for fx in [&inv, &gov] {
        fx.call("gw-c");
        pad(fx);
    }
    let mut cursor: Option<Cursor> = None;
    let mut pads = 0;
    for _ in 0..8 {
        let p = page(&inv, Some(&gov.path), cursor.as_ref(), 8 * MIB);
        assert!(
            !p.lines.is_empty() || p.next != cursor,
            "a page returned no row and the same cursor"
        );
        pads += p.lines.iter().filter(|l| l.entry["event"] == "pad").count();
        match p.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(pads, 2, "the big record of each log is reached");
}

#[test]
fn r43e_a_resume_with_under_five_mib_still_advances() {
    let fx = Fixture::new(None);
    pad(&fx);
    fx.call("gw-c");
    // One row, so the cursor sits just above the 2 MiB record.
    let first = page_of(&fx, None, None, 8 * MIB, 1);
    let cursor = first.next.expect("resumable");
    let second = page(&fx, None, Some(&cursor), 4 * MIB + MIB / 2);
    assert!(
        !second.lines.is_empty() || second.next.as_ref() != Some(&cursor),
        "the resume made no progress"
    );
    assert!(drain(&fx, Some(cursor), 4 * MIB + MIB / 2, 6) >= 1);
}

/// A record near the 4 MiB cap (the logger counts the newline too).
fn max_record(fx: &Fixture) {
    let mut big = Map::new();
    big.insert("event".into(), "big".into());
    big.insert("pad".into(), "x".repeat((4 << 20) - 1024).into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    fx.logger.append_event(big, &envelope).unwrap();
}

#[test]
fn r43d_an_unadvanced_page_peaks_at_budget_plus_the_record_cap() {
    let fx = Fixture::new(None);
    fx.call("gw-c");
    max_record(&fx);
    let budget = 2 * MIB;
    let p = page(&fx, None, None, budget);
    assert!(!p.lines.is_empty(), "the page made no progress");
    assert!(
        p.bytes_examined <= budget + ASSEMBLY_WINDOW,
        "{}",
        p.bytes_examined
    );
}

/// Small records fill the first window, so the page has advanced before it
/// meets the 2 MiB record: the strict budget applies and the page stops.
#[test]
fn r43b_a_page_that_has_advanced_keeps_the_strict_budget() {
    let fx = Fixture::new(None);
    fx.call("gw-c");
    pad(&fx);
    let mut small = Map::new();
    small.insert("event".into(), "small".into());
    small.insert("pad".into(), "y".repeat(1000).into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    for _ in 0..1200 {
        fx.logger.append_event(small.clone(), &envelope).unwrap();
    }
    let budget = 4 * MIB + MIB / 2;
    let p = page(&fx, None, None, budget);
    assert!(!p.lines.is_empty(), "premise: the page advanced");
    assert!(p.bytes_examined <= budget, "{}", p.bytes_examined);
    assert!(p.scan_exhausted && p.next.is_some());
}

/// Append `bytes` to the log file as they are, outside the logger.
fn raw_append(fx: &Fixture, bytes: &[u8]) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&fx.path)
        .unwrap();
    f.write_all(bytes).unwrap();
}

#[test]
fn r43f_two_unadvanced_logs_peak_at_budget_plus_one_cap_each() {
    let inv = Fixture::new(None);
    let gov = Fixture::new(None);
    inv.call("gw-c");
    max_record(&inv);
    max_record(&gov);
    let budget = 2 * MIB;
    let p = page(&inv, Some(&gov.path), None, budget);
    assert!(!p.lines.is_empty(), "the page made no progress");
    assert!(
        p.bytes_examined <= budget + 2 * ASSEMBLY_WINDOW,
        "{}",
        p.bytes_examined
    );
}

#[test]
fn r43g_an_incomplete_newest_line_does_not_buy_a_second_assembly() {
    let fx = Fixture::new(None);
    fx.call("gw-c");
    max_record(&fx);
    raw_append(&fx, &vec![b'x'; (4 << 20) - 1]);
    let budget = 2 * MIB;
    let p = page(&fx, None, None, budget);
    assert!(
        p.bytes_examined <= budget + ASSEMBLY_WINDOW,
        "one log assembled twice: {}",
        p.bytes_examined
    );
}

#[test]
fn r43h_an_assembled_record_over_the_cap_is_unreadable() {
    let fx = Fixture::new(None);
    std::fs::write(&fx.path, b"").unwrap();
    let body = "x".repeat(usize::try_from(ASSEMBLY_WINDOW).expect("the cap fits in usize") - 9);
    let line = format!("{{\"a\":\"{body}\"}}\n");
    assert_eq!(
        line.len() as u64,
        ASSEMBLY_WINDOW,
        "premise: cap plus one byte"
    );
    raw_append(&fx, line.as_bytes());
    let p = page(&fx, None, None, 2 * MIB);
    assert!(
        p.lines.is_empty(),
        "an over-cap record was read as an entry"
    );
    assert_eq!(p.unreadable.len(), 1, "{:?}", p.unreadable.len());
}
