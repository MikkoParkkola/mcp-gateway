// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resolving a cursor and opening its segment, each shape and race.

use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::{end_in, older_segment, open_segment, position, sealed_path};

/// An open record naming segment `seq`, then `records` lines.
fn segment(seq: u64, records: usize) -> String {
    let opened = serde_json::json!({"event": "audit_segment_opened", "segment_seq": seq});
    let mut text = format!("{opened}\n");
    for i in 0..records {
        text.push_str(&format!("{{\"n\":{i}}}\n"));
    }
    text
}

/// A log whose sealed segments are `sealed` and whose active file, if any,
/// is segment `active`.
fn log_with(sealed: &[u64], active: Option<u64>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    for &seq in sealed {
        std::fs::write(sealed_path(&log, seq), segment(seq, 2)).unwrap();
    }
    if let Some(seq) = active {
        std::fs::write(&log, segment(seq, 2)).unwrap();
    }
    (dir, log)
}

fn len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// Every sealed segment expired (retention or the disk-full path): the
/// active file is numbered by its open record, not by counting siblings.
#[test]
fn the_active_segment_is_numbered_by_its_open_record() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    let opened = serde_json::json!({"event": "audit_segment_opened", "segment_seq": 7});
    std::fs::write(&log, format!("{opened}\n")).unwrap();
    assert_eq!(position(&log, None).unwrap().segment, 7);
    // A cursor into that segment resolves to the active file.
    let at = position(&log, Some((3, Some(7)))).unwrap();
    assert!(!at.reset);
}

/// Retention deletes a sealed segment after `position` resolved a cursor
/// into it. Opening that segment then finds it under neither name, and
/// must not hand back the active file, which is a different segment.
#[test]
fn a_segment_removed_after_resolving_is_not_replaced_by_the_active_file() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    let sealed = sealed_path(&log, 3);
    let opened =
        |seq: u64| serde_json::json!({"event": "audit_segment_opened", "segment_seq": seq});
    std::fs::write(&sealed, format!("{}\n{{\"a\":1}}\n", opened(3))).unwrap();
    std::fs::write(&log, format!("{}\n", opened(4))).unwrap();
    let at = position(&log, Some((10, Some(3)))).unwrap();
    assert_eq!(at.segment, 3);
    assert!(!at.reset);
    // Retention, between resolving the cursor and opening its file.
    std::fs::remove_file(&sealed).unwrap();
    let file = open_segment(&log, 3, || {}).unwrap();
    assert!(
        file.is_none(),
        "segment 3 is gone; the active file is segment 4"
    );
}

/// The identity check reads the active file's first line through the handle
/// it returns; a caller reading on from the handle must start at byte 0.
#[test]
fn an_opened_active_segment_is_positioned_at_its_first_byte() {
    let (_dir, log) = log_with(&[], Some(0));
    let mut file = open_segment(&log, 0, || {}).unwrap().expect("segment 0");
    assert_eq!(file.stream_position().unwrap(), 0);
    assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), len(&log));
}

/// Retention removes a sealed segment just before it is opened by its
/// sealed name: gone, not an error.
#[test]
fn a_sealed_segment_removed_before_its_open_is_none() {
    let (_dir, log) = log_with(&[3], Some(4));
    let sealed = sealed_path(&log, 3);
    let opened = open_segment(&log, 3, || std::fs::remove_file(&sealed).unwrap()).unwrap();
    assert!(opened.is_none());
}

/// The page's end comes from the file opened: the bound when inside it,
/// the file's end otherwise.
#[test]
fn the_end_is_clamped_to_the_opened_file() {
    let (_dir, log) = log_with(&[], Some(0));
    let file = std::fs::File::open(&log).unwrap();
    assert_eq!(end_in(Some(5), &file).unwrap(), 5);
    assert_eq!(end_in(Some(u64::MAX), &file).unwrap(), len(&log));
    assert_eq!(end_in(None, &file).unwrap(), len(&log));
}

/// A cursor into a segment below the oldest kept, or above the newest,
/// restarts at the newest record.
#[test]
fn a_cursor_outside_the_kept_segments_restarts_newest() {
    let (_dir, log) = log_with(&[3, 4], Some(5));
    for seq in [2, 6] {
        let at = position(&log, Some((10, Some(seq)))).unwrap();
        assert!(at.reset, "segment {seq}");
        assert_eq!(at.segment, 5);
        assert_eq!(at.bound, None);
    }
    let kept = position(&log, Some((10, Some(3)))).unwrap();
    assert!(!kept.reset);
    assert_eq!((kept.segment, kept.bound), (3, Some(10)));
}

/// An offset-only cursor names a place in segment 0: it holds while the
/// log is still in segment 0, and restarts once the active segment is
/// later, even with every sealed segment expired.
#[test]
fn an_offset_only_cursor_holds_only_in_segment_zero() {
    let (_dir, log) = log_with(&[], Some(0));
    let at = position(&log, Some((7, None))).unwrap();
    assert!(!at.reset);
    assert_eq!((at.segment, at.bound), (0, Some(7)));

    let (_dir, log) = log_with(&[], Some(4));
    assert!(position(&log, Some((7, None))).unwrap().reset);
}

/// A log never written: the newest page is empty, and a cursor still naming
/// bytes restarts rather than reading as the end of the log.
#[test]
fn a_log_never_written_reads_empty_and_resets_a_live_cursor() {
    let (_dir, log) = log_with(&[], None);
    let newest = position(&log, None).unwrap();
    assert!(!newest.reset);
    assert!(!newest.lost_if_unopened());
    assert!(open_segment(&log, newest.segment, || {}).unwrap().is_none());

    assert!(position(&log, Some((9, Some(0)))).unwrap().reset);
    let at_zero = position(&log, Some((0, Some(0)))).unwrap();
    assert!(!at_zero.reset);
    assert!(!at_zero.lost_if_unopened());
}

/// A log whose only file goes between resolving and opening is not a log
/// never written: the page names bytes that went unread.
#[test]
fn a_single_segment_log_removed_after_resolving_is_lost() {
    let (_dir, log) = log_with(&[], Some(0));
    let at = position(&log, None).unwrap();
    std::fs::remove_file(&log).unwrap();
    assert!(open_segment(&log, at.segment, || {}).unwrap().is_none());
    assert!(at.lost_if_unopened());
}

/// With no active file, the newest page is the next segment's number at
/// offset 0: empty, nothing lost, and it steps to the newest sealed one.
#[test]
fn a_sealed_only_log_steps_from_an_empty_newest_page() {
    let (_dir, log) = log_with(&[3, 4], None);
    let at = position(&log, None).unwrap();
    assert_eq!((at.segment, at.bound), (5, Some(0)));
    assert!(!at.lost_if_unopened());
    let older = older_segment(&log, Some(at.segment)).unwrap();
    assert_eq!(older, Some((len(&sealed_path(&log, 4)), 4)));
}

/// A kept segment below a missing one is a hole: an error, never a step
/// over it. With nothing older kept, the log simply ends.
#[test]
fn a_missing_segment_between_kept_ones_is_an_error() {
    let (_dir, log) = log_with(&[2, 4], Some(5));
    assert!(older_segment(&log, Some(5)).unwrap().is_some());
    let hole = older_segment(&log, Some(4)).unwrap_err();
    assert_eq!(hole.kind(), std::io::ErrorKind::NotFound);
    assert!(hole.to_string().contains("segment 3"), "{hole}");
    assert_eq!(older_segment(&log, Some(2)).unwrap(), None);
}

/// What marks a production file as touching the log's segments: the pager,
/// the segment listing, or the whole-file read helpers, by any path.
const READER_TOKENS: &[&str] = &[
    "pager::",
    "segments::",
    "sealed_path",
    "list_segments",
    "super::pager",
    "super::segments",
    "bounded_read_to_string",
    "log_files(",
];

/// Ways to open or measure a file by name.
const BY_NAME: &[&str] = &[
    "File::open",
    "OpenOptions",
    "fs::metadata",
    "fs::read",
    "read_to_string",
    "try_exists",
    ".exists()",
];

/// Files that touch the segments and open nothing by name: they read
/// through [`open_segment`].
const READERS: &[(&str, &str)] = &[
    ("src/control_plane/export_segments.rs", "the export"),
    (
        "src/control_plane/store/file.rs",
        "the governance audit pages",
    ),
    (
        "src/gateway/ui/overview.rs",
        "the Overview's recent actions",
    ),
    (
        "src/gateway/ui/activity/seek.rs",
        "Activity's seek by counter",
    ),
    ("src/gateway/ui/activity/reader.rs", "Activity's pages"),
    (
        "src/security/transparency_log_lease.rs",
        "names segments for the lease, opens none",
    ),
];

/// Files allowed to open or measure log files by name, each for one reason.
const OPENERS: &[(&str, &str)] = &[
    (
        "src/security/transparency_log_pager.rs",
        "the one segment opener readers use",
    ),
    (
        "src/security/transparency_log_segments.rs",
        "the listing and open-record reads",
    ),
    (
        "src/security/transparency_log_append.rs",
        "writer: appends under the log's lock",
    ),
    (
        "src/security/transparency_log_rotation.rs",
        "writer: seals and starts segments under the lock",
    ),
    (
        "src/security/transparency_log_hwm_scan.rs",
        "writer: the high-water scan at open",
    ),
    (
        "src/security/transparency_log_anchor.rs",
        "writer: the anchor file, not a segment",
    ),
    (
        "src/security/transparency_log.rs",
        "writer: the tail read when the logger opens",
    ),
    (
        "src/security/transparency_log_verify.rs",
        "whole-log reader: verify, relists after each pass and retries",
    ),
    (
        "src/security/transparency_log_session.rs",
        "whole-log reader: one session, relists after each pass and retries",
    ),
    (
        "src/control_plane/store/file_io.rs",
        "uses the pager's line splitter; its open is a directory fsync",
    ),
];

fn production_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                production_files(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// One segment opener (SEG.2): every production file that touches the log's
/// segments is listed above with its reason, and only the listed openers
/// open or measure a file by name. A new reader fails here until it is
/// listed, so each one is reviewed.
#[test]
fn only_the_listed_files_open_log_segments_by_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    production_files(&root.join("src"), &mut files);
    let mut touching = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        if !READER_TOKENS.iter().any(|t| text.contains(t)) {
            continue;
        }
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let opens: Vec<&str> = BY_NAME
            .iter()
            .copied()
            .filter(|t| text.contains(t))
            .collect();
        if READERS.iter().any(|(f, _)| *f == rel) {
            assert!(
                opens.is_empty(),
                "{rel} opens by name ({opens:?}); use open_segment"
            );
        }
        touching.push(rel);
    }
    touching.sort();
    let mut listed: Vec<String> = READERS
        .iter()
        .chain(OPENERS)
        .map(|(f, _)| (*f).to_string())
        .collect();
    listed.sort();
    assert_eq!(
        touching, listed,
        "a file touching the log's segments is not listed"
    );
}
