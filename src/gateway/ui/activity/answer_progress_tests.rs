// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pager progress rows: a page that has advanced nothing assembles one record
//! even past its budget (by at most the record cap), so paging never repeats a
//! cursor; a page that has advanced keeps the strict budget.

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
