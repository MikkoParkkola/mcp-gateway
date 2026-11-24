// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The counting scan's stops: the window rule, one stamp out of time order,
//! two logs sharing a pass's bytes, a rotation during the read, the caller
//! stopping it, and the delivery record each call is handed.

use std::cell::RefCell;
use std::io;
use std::ops::{ControlFlow, RangeInclusive};
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Duration, FixedOffset};
use serde_json::{Value, json};

use super::access::Access;
use super::answer::{Delivery, Effect, Findings, Joined, Searched};
use super::answer_fixture::{Dl, Fixture};
use super::counts::{COUNT_SCAN_BYTES, Pass, ScanEnd, scan_window};
use super::decision_fixtures::{call, write_chained};
use super::rows::{Check, Kind};
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::segments::{list_segments, sealed_path};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

pub(super) const MIB: u64 = 1 << 20;
const KIB: u64 = 1 << 10;
/// The bytes one pass of the scan reads.
const PASS_BYTES: u64 = 2 * MIB;

/// The fixed now the stamped rows are read against.
pub(super) fn n() -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339("2026-11-24T12:00:00+00:00").expect("a time")
}

/// `hours` before `n()`.
pub(super) fn ago(hours: i64) -> DateTime<FixedOffset> {
    n() - Duration::hours(hours)
}

/// The 48 hours ending at `n()`.
fn two_days() -> RangeInclusive<DateTime<FixedOffset>> {
    ago(48)..=n()
}

/// The real clock now, for rows written through the logger.
pub(super) fn wall_now() -> DateTime<FixedOffset> {
    crate::clock::utc_now().expect("a clock").fixed_offset()
}

/// An hour either side of `t0`.
fn around(t0: DateTime<FixedOffset>) -> RangeInclusive<DateTime<FixedOffset>> {
    t0 - Duration::hours(1)..=t0 + Duration::hours(1)
}

/// A call on `tool` stamped `at`, padded to about a KiB.
pub(super) fn stamped(tool: &str, at: DateTime<FixedOffset>) -> Value {
    let mut e = call("srv", tool, None);
    e["timestamp"] = at.to_rfc3339().into();
    e["pad"] = "p".repeat(640).into();
    e
}

/// A line's length once chained, near enough to place rows by size.
pub(super) fn line_len(entry: &Value) -> u64 {
    let mut e = entry.clone();
    e["counter"] = 99_999.into();
    e["prev_entry_hash"] = format!("sha256:{}", "0".repeat(64)).into();
    e["entry_hash"] = e["prev_entry_hash"].clone();
    e.to_string().len() as u64 + 1
}

/// Write `newest_first` so that its first entry is the log's newest line.
pub(super) fn write_newest_first(path: &Path, mut newest_first: Vec<Value>) {
    newest_first.reverse();
    write_chained(path, &mut newest_first);
}

/// The bytes from the start of the first line `wanted` picks to the end of
/// the file: how far below the log's top a newest-first read meets it.
pub(super) fn depth(path: &Path, wanted: impl Fn(&str) -> bool) -> u64 {
    let text = std::fs::read_to_string(path).expect("the log");
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        if wanted(line) {
            return (text.len() - start) as u64;
        }
        start += line.len();
    }
    panic!("no such line in {}", path.display());
}

/// The bytes of every kept segment and the active file.
pub(super) fn kept_bytes(path: &Path) -> u64 {
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let sealed: u64 = list_segments(path)
        .expect("segments")
        .iter()
        .map(|s| size(&sealed_path(path, s.seq)))
        .sum();
    sealed + size(path)
}

/// A logger that seals 64 KiB segments and keeps 64, expiring the oldest.
pub(super) fn rotating_logger(path: &Path) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        rotation: RotationConfig {
            max_segment_bytes: 64 * KIB,
            max_segment_age_secs: 0,
            retain_segments: 64,
            on_disk_full: OnDiskFull::ExpireOldest,
        },
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("a logger"))
}

/// Call `write` with 0, 1, 2, ... until more than 3 MiB is kept, more than
/// one pass; the number of writes.
pub(super) fn fill_past_one_pass(path: &Path, mut write: impl FnMut(usize)) -> usize {
    let mut written = 0;
    while kept_bytes(path) <= 3 * MIB {
        for _ in 0..100 {
            write(written);
            written += 1;
        }
    }
    written
}

/// Call `write` until every segment sealed now has expired.
pub(super) fn rotate_past_sealed(path: &Path, mut write: impl FnMut(usize)) {
    let newest = list_segments(path)
        .expect("segments")
        .last()
        .map_or(0, |s| s.seq);
    let mut i = 0;
    while list_segments(path)
        .expect("segments")
        .first()
        .is_some_and(|s| s.seq <= newest)
    {
        write(i);
        i += 1;
    }
}

/// A plain call through the logger.
fn plain(log: &TransparencyLogger, i: usize) {
    log.log_invocation(
        "s",
        "c",
        "srv",
        &format!("tool_{i}"),
        "sha256:aa",
        "sha256:bb",
    )
    .expect("written");
}

/// What one scan did.
struct Run {
    end: io::Result<ScanEnd>,
    visits: Vec<(Kind, DateTime<FixedOffset>)>,
    passes: Vec<Pass>,
}

/// Scan with every row admitted; `hook` runs after each pass with that pass
/// and the visits so far, and decides whether the scan goes on.
fn scan(
    inv: &Path,
    gov: Option<&Path>,
    window: RangeInclusive<DateTime<FixedOffset>>,
    mut hook: impl FnMut(Pass, usize) -> ControlFlow<()>,
) -> Run {
    let visits = RefCell::new(Vec::new());
    let mut passes = Vec::new();
    let check = Check::new(None, inv, gov);
    let end = scan_window(
        window,
        inv,
        gov,
        &check,
        &Access::All,
        COUNT_SCAN_BYTES,
        |_, kind, _, at| visits.borrow_mut().push((kind, at)),
        |pass| {
            passes.push(pass);
            hook(pass, visits.borrow().len())
        },
    );
    Run {
        end,
        visits: visits.into_inner(),
        passes,
    }
}

fn go_on(_: Pass, _: usize) -> ControlFlow<()> {
    ControlFlow::Continue(())
}

fn total(passes: &[Pass]) -> u64 {
    passes.iter().map(|p| p.bytes).sum()
}

/// x-late's stamp: inside the window, and unlike any whole-hour stamp.
fn x_stamp() -> DateTime<FixedOffset> {
    n() - Duration::minutes(90)
}

/// y-late's stamp.
fn y_stamp() -> DateTime<FixedOffset> {
    n() - Duration::minutes(150)
}

/// s1's log, newest first: 20 calls inside the window, then 17 MiB stamped
/// three days back, holding `x-late` about 5 MiB down, in the middle of the
/// third pass, and `y-late` about 11 MiB down, in the middle of the sixth.
fn long_log(path: &Path) {
    let old = stamped("old", ago(72));
    let per = line_len(&old);
    let mut rows: Vec<Value> = (1..=20).map(|h| stamped("fresh", ago(h))).collect();
    let fresh: u64 = rows.iter().map(line_len).sum();
    let at_depth = |bytes: u64| usize::try_from((bytes - fresh) / per).expect("an index");
    let (x, y) = (at_depth(5 * MIB), at_depth(11 * MIB));
    for i in 0..usize::try_from(17 * MIB / per).expect("a count") {
        rows.push(if i == x {
            stamped("x-late", x_stamp())
        } else if i == y {
            stamped("y-late", y_stamp())
        } else {
            old.clone()
        });
    }
    write_newest_first(path, rows);
    // Premise: each late row sits in the middle of its pass.
    let x_at = depth(path, |l| l.contains("\"x-late\""));
    let y_at = depth(path, |l| l.contains("\"y-late\""));
    assert!(
        (4 * MIB + MIB / 2..5 * MIB + MIB / 2).contains(&x_at),
        "{x_at}"
    );
    assert!(
        (10 * MIB + MIB / 2..11 * MIB + MIB / 2).contains(&y_at),
        "{y_at}"
    );
    assert!(std::fs::metadata(path).expect("the log").len() > 16 * MIB);
}

#[test]
fn s1_a_narrow_window_on_a_long_log_stops_at_the_window() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    long_log(&path);
    let run = scan(&path, None, two_days(), go_on);
    assert_eq!(run.end.expect("read"), ScanEnd::WindowPassed);
    // The 20 newest and x-late; y-late lies below the stop.
    assert_eq!(run.visits.len(), 21, "{:?}", run.visits);
    assert!(run.visits.iter().any(|(_, at)| *at == x_stamp()));
    assert!(run.visits.iter().all(|(_, at)| *at != y_stamp()));
    assert_eq!(run.passes.len(), 5, "{:?}", run.passes);
    let bytes = total(&run.passes);
    assert!((10 * MIB..12 * MIB).contains(&bytes), "{bytes}");
}

#[test]
fn s2_one_old_stamp_above_newer_records_does_not_stop_the_read() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    let mut rows = vec![stamped("stray", ago(72))];
    rows.extend((1..=10).map(|h| stamped("fresh", ago(h))));
    write_newest_first(&path, rows);
    let run = scan(&path, None, two_days(), go_on);
    assert_eq!(run.end.expect("read"), ScanEnd::End);
    assert_eq!(run.visits.len(), 10);
}

/// A governance record stamped `at`, padded to about a KiB.
fn governance_row(at: DateTime<FixedOffset>) -> Value {
    json!({
        "kind": "control_plane_audit", "action": "grant", "actor_id": "a",
        "target_id": "t", "timestamp": at.to_rfc3339(), "pad": "g".repeat(640),
    })
}

/// `count` rows from `row`, newest first, stamped evenly from 1 h to 47 h
/// before `n()`.
fn spread(count: usize, row: impl Fn(DateTime<FixedOffset>) -> Value) -> Vec<Value> {
    let span = Duration::hours(46).num_seconds();
    let count_i = i64::try_from(count).expect("a count");
    (0..count_i)
        .map(|i| row(ago(1) - Duration::seconds(i * span / count_i)))
        .collect()
}

#[test]
fn s3_a_governance_log_does_not_eat_the_cap() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (inv, gov) = (dir.path().join("inv.jsonl"), dir.path().join("gov.jsonl"));
    let per_inv = line_len(&stamped("t", n()));
    let per_gov = line_len(&governance_row(n()));
    let inv_rows = usize::try_from(10 * MIB / per_inv).expect("a count");
    let gov_rows = usize::try_from(6 * MIB / per_gov).expect("a count");
    write_newest_first(&inv, spread(inv_rows, |at| stamped("t", at)));
    write_newest_first(&gov, spread(gov_rows, governance_row));
    // Premise: 16 MiB between the two logs.
    let size = |p: &Path| std::fs::metadata(p).expect("a log").len();
    assert!(size(&inv) + size(&gov) >= 16 * MIB - 64 * KIB);
    let run = scan(&inv, Some(&gov), two_days(), go_on);
    assert_eq!(run.end.expect("read"), ScanEnd::End);
    assert_eq!(run.visits.len(), inv_rows + gov_rows);
    assert!(
        run.passes.iter().all(|p| p.bytes <= 3 * MIB),
        "{:?}",
        run.passes
    );
    assert!(total(&run.passes) >= 16 * MIB - 64 * KIB);
    let passes = run.passes.len();
    eprintln!("s3 passes: {passes}");
    assert!(passes <= 10, "s3 passes: {passes}");
}

#[test]
fn s4_a_log_that_rotates_during_the_read_is_not_read_twice() {
    for rotate in [true, false] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = dir.path().join("inv.jsonl");
        let log = rotating_logger(&path);
        let t0 = wall_now();
        let written = fill_past_one_pass(&path, |i| plain(&log, i));
        let mut hooks = 0;
        let run = scan(&path, None, around(t0), |_, _| {
            if rotate && hooks == 0 {
                rotate_past_sealed(&path, |i| plain(&log, 1_000_000 + i));
            }
            hooks += 1;
            ControlFlow::Continue(())
        });
        if rotate {
            // Premise: the hook ran once, after the first pass.
            assert_eq!(hooks, 1);
            let error = run.end.expect_err("the read stops");
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        } else {
            // Only the rotation differs: the same read, whole.
            assert_eq!(run.end.expect("read"), ScanEnd::End);
            assert_eq!(run.visits.len(), written);
        }
    }
    // A reset on the first pass cannot arise: a read with no cursor opens
    // the newest lines and has nothing to reset (reader.rs `open_tails`).
}

#[test]
fn s5_between_can_stop_the_scan() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    long_log(&path);
    let mut seen = Vec::new();
    let run = scan(&path, None, two_days(), |pass, visits| {
        seen.push((visits, pass.bytes));
        ControlFlow::Break(())
    });
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, 20, "pass 1's records were read before the hook");
    assert!(seen[0].1 > 0);
    let error = run.end.expect_err("the caller stopped it");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!((run.passes.len(), run.visits.len()), (1, 20));
    let whole = scan(&path, None, two_days(), go_on);
    assert_eq!(whole.end.expect("read"), ScanEnd::WindowPassed);
    assert_eq!((whole.passes.len(), whole.visits.len()), (5, 21));
}

/// Calls tagged `tag` until the log has grown by `bytes`.
fn grow(fx: &Fixture, tag: &str, bytes: u64) {
    let size = || std::fs::metadata(&fx.path).map_or(0, |m| m.len());
    let until = size() + bytes;
    let mut i = 0;
    while size() < until {
        fx.call(&format!("{tag}-{i}"));
        i += 1;
    }
}

#[test]
fn s6_visit_gets_each_call_s_joined_delivery_record() {
    let fx = Fixture::rotating(None, 64 * MIB);
    let t0 = wall_now();
    fx.call("c-call");
    fx.call("a-call");
    fx.delivery("a-call", &Dl::effect("annotated"));
    fx.call("b-call");
    grow(&fx, "gap", 200 * KIB);
    fx.delivery("b-call", &Dl::effect("rewritten"));
    grow(&fx, "top", 1900 * KIB);
    // Premise: B's delivery is read in pass 1 and its call in pass 2, within
    // the join's 256 KiB.
    let delivery = depth(&fx.path, |l| {
        l.contains("\"b-call\"") && l.contains("response_delivery_attempt")
    });
    let b_call = depth(&fx.path, |l| {
        l.contains("\"b-call\"") && !l.contains("response_delivery_attempt")
    });
    assert!(delivery <= PASS_BYTES - 8 * KIB, "{delivery}");
    assert!(b_call >= PASS_BYTES + 8 * KIB, "{b_call}");
    assert!(b_call - delivery < 256 * KIB, "{b_call} {delivery}");
    let joined = RefCell::new(Vec::new());
    let check = Check::new(None, &fx.path, None);
    let end = scan_window(
        around(t0),
        &fx.path,
        None,
        &check,
        &Access::All,
        COUNT_SCAN_BYTES,
        |line, _, j, _| {
            let trace = line.entry["trace_id"].as_str().unwrap_or_default();
            if ["a-call", "b-call", "c-call"].contains(&trace) {
                joined.borrow_mut().push((trace.to_owned(), j.clone()));
            }
        },
        |_| ControlFlow::Continue(()),
    );
    assert_eq!(end.expect("read"), ScanEnd::End);
    let found = |effect| {
        Joined::Found(Delivery {
            effect,
            findings: Findings::Scanned {
                list: Vec::new(),
                total: None,
            },
            unverifiable: true,
        })
    };
    let mut joined = joined.into_inner();
    joined.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        joined,
        [
            ("a-call".to_owned(), found(Effect::Annotated)),
            ("b-call".to_owned(), found(Effect::Rewritten)),
            ("c-call".to_owned(), Joined::NoRecord(Searched::Finished)),
        ]
    );
}
