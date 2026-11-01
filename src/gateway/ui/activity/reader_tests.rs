// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P2-P7 of the U2 test plan: paging both logs newest first, across segment
//! seams and rotations, merged, bounded.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use super::{Cursor, Limits, Line, LogPos, Which, read_page};
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::segments::{list_segments, sealed_path};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

thread_local! {
    /// Run once, the next time a log position is resolved (P2a).
    static AFTER_RESOLVE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    /// Run once, just before a segment's file is opened.
    static BEFORE_OPEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

/// The reader's seam between checking whether a segment is sealed and
/// opening it by name.
pub(super) fn before_open() {
    if let Some(hook) = BEFORE_OPEN.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// The reader's seam between resolving a log's position and opening its file.
pub(super) fn after_resolve() {
    if let Some(hook) = AFTER_RESOLVE.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

const ALL: Limits = Limits {
    matches: 50,
    bytes: 8 << 20,
};

fn logger(path: &Path, retain: u32) -> TransparencyLogger {
    TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        rotation: RotationConfig {
            max_segment_bytes: 4096,
            max_segment_age_secs: 0,
            retain_segments: retain,
            on_disk_full: OnDiskFull::ExpireOldest,
        },
    }))
    .unwrap()
}

fn call(l: &TransparencyLogger, i: usize) {
    l.log_invocation(
        "s",
        "c",
        "srv",
        &format!("tool_{i}"),
        "sha256:aa",
        "sha256:bb",
    )
    .unwrap();
}

/// A call record's index, from its tool name; housekeeping records are not calls.
fn call_index(line: &Line) -> Option<usize> {
    line.entry
        .get("tool")?
        .as_str()?
        .strip_prefix("tool_")?
        .parse()
        .ok()
}

fn is_call(line: &Line) -> bool {
    call_index(line).is_some()
}

/// Every call index on every page from `cursor` on, and the page count.
fn drain(
    inv: &Path,
    gov: Option<&Path>,
    cursor: Option<Cursor>,
    limits: Limits,
) -> (Vec<usize>, usize) {
    let mut seen = Vec::new();
    let mut cursor = cursor;
    let mut pages = 0;
    loop {
        let page = read_page(inv, gov, cursor.as_ref(), limits, is_call).unwrap();
        pages += 1;
        assert!(!page.cursor_reset);
        seen.extend(page.lines.iter().filter_map(call_index));
        match page.next {
            Some(next) => cursor = Some(next),
            None => return (seen, pages),
        }
        assert!(pages < 10_000, "paging never ends");
    }
}

fn log_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test]
fn p2_pages_every_call_once_newest_first_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    for i in 0..250 {
        call(&l, i);
    }
    assert!(
        list_segments(&path).unwrap().len() >= 3,
        "fixture spans segments"
    );
    let (seen, _) = drain(&path, None, None, ALL);
    let expected: Vec<usize> = (0..250).rev().collect();
    assert_eq!(seen, expected);
}

#[test]
fn p2_a_full_page_holds_exactly_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    for i in 0..250 {
        call(&l, i);
    }
    let page = read_page(&path, None, None, ALL, is_call).unwrap();
    let got: Vec<usize> = page.lines.iter().filter_map(call_index).collect();
    assert_eq!(got, (200..250).rev().collect::<Vec<_>>());
    assert!(page.next.is_some());
}

#[test]
fn p2a_rotation_between_pages_neither_skips_nor_repeats() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    for i in 0..30 {
        call(&l, i);
    }
    let limits = Limits {
        matches: 5,
        bytes: 8 << 20,
    };
    let first = read_page(&path, None, None, limits, is_call).unwrap();
    assert_eq!(
        first
            .lines
            .iter()
            .filter_map(call_index)
            .collect::<Vec<_>>(),
        vec![29, 28, 27, 26, 25]
    );
    // Seal the active file the cursor points into.
    let before = list_segments(&path).unwrap().len();
    let mut i = 30;
    while list_segments(&path).unwrap().len() == before {
        call(&l, i);
        i += 1;
    }
    let (rest, _) = drain(&path, None, first.next, limits);
    assert_eq!(rest, (0..25).rev().collect::<Vec<_>>());
}

#[test]
fn p2a_rotation_inside_one_request_reads_the_sealed_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = Arc::new(logger(&path, 1000));
    for i in 0..8 {
        call(&l, i);
    }
    let before = list_segments(&path).unwrap().len();
    let rotating = Arc::clone(&l);
    let seal_path = path.clone();
    AFTER_RESOLVE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            let mut i = 1000;
            while list_segments(&seal_path).unwrap().len() == before {
                call(&rotating, i);
                i += 1;
            }
        }));
    });
    let page = read_page(&path, None, None, ALL, |line| {
        call_index(line).is_some_and(|i| i < 1000)
    })
    .unwrap();
    let got: Vec<usize> = page.lines.iter().filter_map(call_index).collect();
    assert_eq!(got, (0..8).rev().collect::<Vec<_>>());
}

/// The log rotates inside resolving the newest page, after it has named the
/// active segment and before reading anything of it: the page reads that
/// segment from its own end, not from the new active file's shorter length.
#[test]
fn a_rotation_while_resolving_the_newest_page_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = Arc::new(logger(&path, 1000));
    for i in 0..8 {
        call(&l, i);
    }
    let before = list_segments(&path).unwrap().len();
    let rotating = Arc::clone(&l);
    let seal_path = path.clone();
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        let mut i = 1000;
        while list_segments(&seal_path).unwrap().len() == before {
            call(&rotating, i);
            i += 1;
        }
    });

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = read_page(&path, None, cursor.as_ref(), ALL, |line| {
            call_index(line).is_some_and(|i| i < 1000)
        })
        .unwrap();
        seen.extend(page.lines.iter().filter_map(call_index));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    assert_eq!(seen, (0..8).rev().collect::<Vec<_>>());
}

/// The only file of the log goes after the newest page has resolved it: the
/// page fails rather than read as a log never written.
#[test]
fn a_newest_segment_removed_while_resolving_fails_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    call(&l, 0);
    let gone = path.clone();
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        std::fs::remove_file(&gone).unwrap();
    });

    assert!(read_page(&path, None, None, ALL, is_call).is_err());
}

/// Retention takes a cursor's segment between resolving and opening: the
/// page fails, and the same cursor retried restarts at the newest record,
/// flagged.
#[test]
fn a_cursor_expiring_while_resolving_fails_then_restarts_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    for i in 0..250 {
        call(&l, i);
    }
    let oldest = list_segments(&path).unwrap()[0].seq;
    let cursor = Cursor {
        inv: Some(LogPos {
            segment: oldest,
            offset: 10,
        }),
        gov: None,
        gov_bound: None,
    };
    let doomed = sealed_path(&path, oldest);
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        std::fs::remove_file(&doomed).unwrap();
    });

    assert!(read_page(&path, None, Some(&cursor), ALL, is_call).is_err());
    let retried = read_page(&path, None, Some(&cursor), ALL, is_call).unwrap();
    assert!(retried.cursor_reset);
    assert_eq!(retried.lines.first().and_then(call_index), Some(249));
}

/// Retention removes the segment a cursor names after the page resolved it:
/// the page fails rather than read the active file, a different segment, in
/// its place.
#[test]
fn a_segment_removed_after_resolving_fails_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 1000);
    for i in 0..30 {
        call(&l, i);
    }
    let limits = Limits {
        matches: 5,
        bytes: 8 << 20,
    };
    let first = read_page(&path, None, None, limits, is_call).unwrap();
    // Seal the active file the cursor points into.
    let before = list_segments(&path).unwrap().len();
    let mut i = 30;
    while list_segments(&path).unwrap().len() == before {
        call(&l, i);
        i += 1;
    }
    let gone = path.clone();
    AFTER_RESOLVE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            for segment in list_segments(&gone).unwrap() {
                std::fs::remove_file(sealed_path(&gone, segment.seq)).unwrap();
            }
        }));
    });
    let page = read_page(&path, None, first.next.as_ref(), limits, is_call);
    assert!(page.is_err(), "read another segment instead: {page:?}");
}

/// Write hand-made lines; the reader parses JSON and needs no chain.
fn write_lines(path: &Path, lines: &[Value]) {
    let body: String = lines.iter().map(|v| v.to_string() + "\n").collect();
    std::fs::write(path, body).unwrap();
}

fn entry(id: &str, ts: Option<&str>) -> Value {
    json!({"tool": format!("tool_{id}"), "timestamp": ts})
}

#[test]
fn p3_a_record_at_the_cap_is_assembled_across_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let mut big = json!({"tool": "tool_1", "pad": ""});
    let base = big.to_string().len();
    // The logger's cap counts the record's newline, so the largest record it
    // writes holds one byte less than 4 MiB.
    big["pad"] = "x".repeat(4 * 1024 * 1024 - 1 - base).into();
    assert_eq!(
        big.to_string().len() + 1,
        4 * 1024 * 1024,
        "exactly the cap"
    );
    write_lines(&path, &[entry("0", None), big, entry("2", None)]);
    let page = read_page(&path, None, None, ALL, is_call).unwrap();
    assert_eq!(
        page.lines.iter().filter_map(call_index).collect::<Vec<_>>(),
        vec![2, 1, 0]
    );
    assert!(page.unreadable.is_empty());
}

/// One byte over the cap (4 MiB of content plus its newline), a line the
/// logger refuses, is reported once and never served.
#[test]
fn p3_a_line_one_byte_over_the_cap_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let mut big = json!({"tool": "tool_1", "pad": ""});
    let base = big.to_string().len();
    big["pad"] = "x".repeat(4 * 1024 * 1024 - base).into();
    assert_eq!(
        big.to_string().len(),
        4 * 1024 * 1024,
        "one byte over the cap"
    );
    write_lines(&path, &[entry("0", None), big, entry("2", None)]);
    let page = read_page(&path, None, None, ALL, is_call).unwrap();
    assert_eq!(
        page.lines.iter().filter_map(call_index).collect::<Vec<_>>(),
        vec![2, 0]
    );
    assert_eq!(page.unreadable.len(), 1, "{:?}", page.unreadable);
}

#[test]
fn p3_an_over_cap_line_is_reported_once_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let mut body = entry("0", None).to_string() + "\n";
    body.push_str(&"y".repeat(6 * 1024 * 1024));
    body.push('\n');
    body.push_str(&(entry("2", None).to_string() + "\n"));
    // An unterminated tail: an append still in flight, never served.
    body.push_str(r#"{"tool":"tool_3""#);
    std::fs::write(&path, body).unwrap();
    let limits = Limits {
        matches: 50,
        bytes: 32 << 20,
    };
    let page = read_page(&path, None, None, limits, is_call).unwrap();
    assert_eq!(
        page.lines.iter().filter_map(call_index).collect::<Vec<_>>(),
        vec![2, 0]
    );
    assert_eq!(page.unreadable.len(), 1, "{:?}", page.unreadable);
    assert!(
        page.bytes_examined <= 16 << 20,
        "read {}",
        page.bytes_examined
    );
}

#[test]
fn p5_a_cursor_into_an_expired_segment_restarts_newest() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let l = logger(&path, 2);
    for i in 0..40 {
        call(&l, i);
    }
    let limits = Limits {
        matches: 5,
        bytes: 8 << 20,
    };
    let page = read_page(&path, None, None, limits, is_call).unwrap();
    let old = page.next.unwrap();
    // Rotate until the segment that cursor names is expired.
    let named = old.inv.unwrap().segment;
    let mut i = 40;
    while list_segments(&path)
        .unwrap()
        .first()
        .is_some_and(|s| s.seq <= named)
    {
        call(&l, i);
        i += 1;
        assert!(i < 2_000);
    }
    let reset = read_page(&path, None, Some(&old), limits, is_call).unwrap();
    assert!(reset.cursor_reset);
    assert_eq!(reset.lines.first().and_then(call_index), Some(i - 1));
}

/// Ids read from `inv` and `gov` page by page, at each page size, and the
/// log each came from.
fn merged(inv: &Path, gov: &Path, matches: usize) -> Vec<(Which, String)> {
    let id = |line: &Line| {
        line.entry["tool"]
            .as_str()
            .and_then(|t| t.strip_prefix("tool_"))
            .unwrap()
            .to_string()
    };
    let mut got = Vec::new();
    let mut cursor = None;
    loop {
        let limits = Limits {
            matches,
            bytes: 8 << 20,
        };
        let page = read_page(inv, Some(gov), cursor.as_ref(), limits, |_| true).unwrap();
        got.extend(page.lines.iter().map(|l| (l.log, id(l))));
        match page.next {
            Some(n) => cursor = Some(n),
            None => return got,
        }
    }
}

/// Invocation lines and governance lines, oldest first, as `(id, time)`,
/// and the expected merged order.
type Scenario<'a> = (
    &'a [(&'a str, Option<String>)],
    &'a [(&'a str, Option<String>)],
    &'a [&'a str],
);

#[test]
fn p6_merge_is_the_full_expected_sequence_across_page_boundaries() {
    let ts = |t: &str| format!("2026-10-26T{t}Z");
    // (invocation lines, governance lines, oldest first; expected order).
    // A: a missing time takes the invocation log first (i4 over g2); a tie
    // does too (i2 over g1); otherwise the later time first.
    // B: a backward clock step (i2) never reorders a log: i1 stays after i2
    // though its time is later.
    let scenarios: [Scenario<'_>; 2] = [
        (
            &[
                ("i1", Some(ts("10:00:00"))),
                ("i2", Some(ts("10:00:05"))),
                ("i3", Some(ts("10:00:20"))),
                ("i4", None),
            ],
            &[("g1", Some(ts("10:00:05"))), ("g2", Some(ts("10:00:30")))],
            &["i4", "g2", "i3", "i2", "g1", "i1"],
        ),
        (
            &[
                ("i1", Some(ts("10:00:00"))),
                ("i2", Some(ts("09:00:00"))),
                ("i3", Some(ts("10:00:20"))),
            ],
            &[("g1", Some(ts("10:00:10")))],
            &["i3", "g1", "i2", "i1"],
        ),
    ];
    for (n, (inv_lines, gov_lines, expected)) in scenarios.iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let inv = log_path(&dir, "inv.jsonl");
        let gov = log_path(&dir, "gov.jsonl");
        let lines = |l: &[(&str, Option<String>)]| -> Vec<Value> {
            l.iter().map(|(id, t)| entry(id, t.as_deref())).collect()
        };
        write_lines(&inv, &lines(inv_lines));
        write_lines(&gov, &lines(gov_lines));
        for matches in [1, 2, 3, 50] {
            let got = merged(&inv, &gov, matches);
            let ids: Vec<&str> = got.iter().map(|(_, i)| i.as_str()).collect();
            assert_eq!(ids, *expected, "scenario {n}, page size {matches}");
            assert!(
                got.iter()
                    .all(|(w, i)| (*w == Which::Governance) == i.starts_with('g'))
            );
        }
    }
}

#[test]
fn p7_a_sparse_filter_stops_at_the_budget_and_resumes_to_an_older_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let pad = "z".repeat(400);
    let mut lines = vec![json!({"tool": "tool_needle", "pad": pad})];
    for i in 0..25_000 {
        lines.push(json!({"tool": format!("hay_{i}"), "pad": pad}));
    }
    write_lines(&path, &lines);
    assert!(std::fs::metadata(&path).unwrap().len() > 9 << 20);
    let needle = |line: &Line| line.entry["tool"] == "tool_needle";
    let page = read_page(&path, None, None, ALL, needle).unwrap();
    assert!(page.lines.is_empty());
    assert!(page.scan_exhausted);
    assert!(
        page.bytes_examined <= (8 << 20) + super::WINDOW,
        "read {}",
        page.bytes_examined
    );
    let resumed = read_page(&path, None, page.next.as_ref(), ALL, needle).unwrap();
    assert_eq!(resumed.lines.len(), 1);
}

#[test]
fn p6_untimed_governance_records_sort_just_below_the_oldest_timed_one() {
    let ts = |t: &str| Some(format!("2026-10-26T{t}Z"));
    let dir = tempfile::tempdir().unwrap();
    let inv = log_path(&dir, "inv.jsonl");
    let gov = log_path(&dir, "gov.jsonl");
    // Governance: two records from before the upgrade (untimed), then two timed.
    write_lines(
        &gov,
        &[
            entry("u1", None),
            entry("u2", None),
            entry("s1", ts("10:00:10").as_deref()),
            entry("s2", ts("10:00:30").as_deref()),
        ],
    );
    write_lines(
        &inv,
        &[
            entry("i1", ts("10:00:00").as_deref()),
            entry("i2", ts("10:00:05").as_deref()),
            entry("i3", ts("10:00:20").as_deref()),
            entry("i4", ts("10:00:40").as_deref()),
        ],
    );
    // u1 and u2 are older than s1 (10:00:10) with no recorded time: they come
    // right below s1, before every call older than it, in file order.
    let expected = ["i4", "s2", "i3", "s1", "u2", "u1", "i2", "i1"];
    for matches in [1, 2, 3, 50] {
        let got = merged(&inv, &gov, matches);
        let ids: Vec<&str> = got.iter().map(|(_, i)| i.as_str()).collect();
        assert_eq!(ids, expected, "page size {matches}");
    }
}

#[test]
fn a_read_in_the_rotation_gap_finds_the_sealed_file() {
    // Rotation renames the active file to its sealed name, then creates the
    // next one; a read opening by name in between must not see an empty log.
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    write_lines(&path, &[entry("0", None), entry("1", None)]);
    let (from, to) = (path.clone(), sealed_path(&path, 0));
    BEFORE_OPEN.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || std::fs::rename(&from, &to).unwrap()));
    });
    let page = read_page(&path, None, None, ALL, |_| true).unwrap();
    assert_eq!(page.lines.len(), 2, "the sealed file was read");
}

#[test]
fn the_active_segment_is_numbered_by_its_open_record() {
    // Every sealed segment expired (retention or the disk-full path): only
    // the active file, opened as segment 7, is left.
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir, "inv.jsonl");
    let opened = |seq: u64| json!({"event": "audit_segment_opened", "segment_seq": seq});
    write_lines(&path, &[opened(7), entry("a", None), entry("b", None)]);
    let limits = Limits {
        matches: 1,
        bytes: 8 << 20,
    };
    let first = read_page(&path, None, None, limits, |l| {
        call_index(l).is_none() && l.entry.get("tool").is_some()
    })
    .unwrap();
    let token = first.next.expect("more to read");
    assert_eq!(token.inv.unwrap().segment, 7);
    // Resumed before any rotation, the token names the active segment.
    let still_active = read_page(&path, None, Some(&token), ALL, |l| {
        l.entry.get("tool").is_some()
    })
    .unwrap();
    assert!(!still_active.cursor_reset);
    // It is sealed as segment 7 and segment 8 opens: the token still reads on.
    std::fs::rename(&path, sealed_path(&path, 7)).unwrap();
    write_lines(&path, &[opened(8)]);
    let rest = read_page(&path, None, Some(&token), ALL, |l| {
        l.entry.get("tool").is_some()
    })
    .unwrap();
    assert!(!rest.cursor_reset);
    let tools: Vec<&str> = rest
        .lines
        .iter()
        .filter_map(|l| l.entry["tool"].as_str())
        .collect();
    assert_eq!(tools, ["tool_a"]);
}
