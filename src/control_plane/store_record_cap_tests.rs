// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance records up to the logger's record cap read back through
//! `read_audit`, not only those that fit one scan window.

use super::*;

/// Page the whole governance log, newest first, returning each event's id and
/// the length of its reason. Every page must read.
fn page_all(store: &FileControlPlaneStore) -> Vec<(String, String)> {
    let mut seen = Vec::new();
    let mut cursor = None;
    for _ in 0..100 {
        let filter = match cursor {
            Some(at) => AuditFilter::new(10).resume(at),
            None => AuditFilter::new(10),
        };
        let page = store.read_audit(&filter).expect("every page reads");
        seen.extend(
            page.events
                .iter()
                .map(|event| (event.event_id.clone(), event.reason.clone())),
        );
        match page.next_cursor {
            Some(at) => cursor = Some(at),
            None => return seen,
        }
    }
    panic!("paging the log did not terminate");
}

/// READ.1: a 3 MiB record, longer than the 1 MiB scan window but under the
/// logger's 4 MiB cap, reads back whole, and the records on either side of it
/// read normally.
#[test]
fn a_record_between_the_scan_window_and_the_cap_reads_back_with_its_neighbours() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    let three_mib = 3 * 1024 * 1024;
    let mut large = audit_event("large", "alice", ControlPlaneAction::MutatePolicy);
    // A payload that varies along its length, so a shifted or truncated read
    // cannot match it.
    let payload: String = (0..three_mib)
        .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap()))
        .collect();
    large.reason.clone_from(&payload);
    for event in [
        audit_event("before", "alice", ControlPlaneAction::MutateGrant),
        large,
        audit_event("after", "alice", ControlPlaneAction::MutateGrant),
    ] {
        store.append_audit(&event).unwrap();
    }

    let small = audit_event("x", "alice", ControlPlaneAction::MutateGrant).reason;
    assert_eq!(
        page_all(&store),
        [
            ("after".to_string(), small.clone()),
            ("large".to_string(), payload),
            ("before".to_string(), small),
        ]
    );
}

/// The logger's record cap, newline included: one less than the assembly
/// window, which also holds the newline ending the line before.
fn cap() -> usize {
    usize::try_from(crate::security::transparency_log::pager::ASSEMBLY_WINDOW).unwrap() - 1
}

/// A log holding one real record, and that record's line as a template for
/// raw lines: only parsing and paging are under test, not the hash chain.
fn store_with_template() -> (
    tempfile::TempDir,
    FileControlPlaneStore,
    std::path::PathBuf,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    store
        .append_audit(&audit_event(
            "seed",
            "alice",
            ControlPlaneAction::MutateGrant,
        ))
        .unwrap();
    let path = logger.path();
    let template = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .next_back()
        .unwrap()
        .to_string();
    (dir, store, path, template)
}

/// A record line for `id`, from `template`.
fn record(template: &str, id: &str) -> String {
    template.replace("\"seed\"", &format!("\"{id}\""))
}

/// Append raw `lines` to the log, each with its newline; returns the offset
/// each line starts at.
fn append_raw(path: &std::path::Path, lines: &[String]) -> Vec<u64> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    let mut at = file.metadata().unwrap().len();
    let mut starts = Vec::new();
    for line in lines {
        starts.push(at);
        writeln!(file, "{line}").unwrap();
        at += u64::try_from(line.len()).unwrap() + 1;
    }
    starts
}

/// Page the whole log, newest first: the event ids read and every
/// `unreadable` position reported, in the order met.
fn page_reports(store: &FileControlPlaneStore) -> (Vec<String>, Vec<AuditCursor>) {
    let (mut ids, mut holes) = (Vec::new(), Vec::new());
    let mut cursor = None;
    for _ in 0..1000 {
        let filter = match cursor {
            Some(at) => AuditFilter::new(10).resume(at),
            None => AuditFilter::new(10),
        };
        let page = store.read_audit(&filter).expect("every page reads");
        ids.extend(page.events.iter().map(|e| e.event_id.clone()));
        holes.extend(page.unreadable);
        match page.next_cursor {
            Some(at) => cursor = Some(at),
            None => return (ids, holes),
        }
    }
    panic!("paging the log did not terminate");
}

/// READ.2: a 9 MiB line, over the cap and longer than two assembly windows,
/// is reported once, inside its own bytes, and the records on either side
/// still read.
#[test]
fn an_over_cap_line_is_reported_once_and_later_pages_still_read() {
    let (_dir, store, path, template) = store_with_template();
    let starts = append_raw(
        &path,
        &["y".repeat(9 * 1024 * 1024), record(&template, "after")],
    );
    let (ids, holes) = page_reports(&store);
    assert_eq!(ids, ["after", "seed"]);
    assert_eq!(holes.len(), 1, "reported once: {holes:?}");
    assert!(
        (starts[0]..starts[1]).contains(&holes[0].offset),
        "the report sits inside the over-cap line: {holes:?}, line {starts:?}"
    );
}

/// READ.2: two over-cap lines in a row are two reports, and nothing between
/// or around them is lost.
#[test]
fn two_adjacent_over_cap_lines_are_reported_once_each() {
    let (_dir, store, path, template) = store_with_template();
    let big = "z".repeat(5 * 1024 * 1024);
    let starts = append_raw(&path, &[big.clone(), big, record(&template, "after")]);
    let (ids, holes) = page_reports(&store);
    assert_eq!(ids, ["after", "seed"]);
    let offsets: Vec<u64> = holes.iter().map(|h| h.offset).collect();
    assert_eq!(offsets.len(), 2, "{holes:?}");
    // Newest first: the second line's report, then the first's, each inside
    // its own line.
    assert!(
        (starts[1]..starts[2]).contains(&offsets[0]),
        "{offsets:?} {starts:?}"
    );
    assert!(
        (starts[0]..starts[1]).contains(&offsets[1]),
        "{offsets:?} {starts:?}"
    );
}

/// The cap counts the newline: a line of `cap - 1` bytes is a record and
/// reads; one of `cap` bytes is over it and is reported.
#[test]
fn the_cap_counts_the_newline() {
    let (_dir, store, path, template) = store_with_template();
    // The fixture's reason, padded so the record has an exact length.
    let reason = audit_event("x", "alice", ControlPlaneAction::MutateGrant).reason;
    let padded = |id: &str, len: usize| {
        let line = record(&template, id);
        let pad = len - line.len();
        line.replacen(
            &format!("\"{reason}\""),
            &format!("\"{reason}{}\"", "p".repeat(pad)),
            1,
        )
    };
    let at_cap = padded("at-cap", cap() - 1);
    assert_eq!(at_cap.len() + 1, cap(), "a record exactly at the cap");
    append_raw(
        &path,
        &[at_cap, "o".repeat(cap()), record(&template, "after")],
    );
    let (ids, holes) = page_reports(&store);
    assert_eq!(ids, ["after", "at-cap", "seed"]);
    assert_eq!(holes.len(), 1, "the over-by-one line: {holes:?}");
}

/// A line over the cap at byte 0 of the file, where no newline precedes it,
/// is still reported, at offset 0, and paging ends below it.
#[test]
fn an_over_cap_first_line_is_reported_at_offset_zero() {
    let (_dir, _store, path, template) = store_with_template();
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    std::fs::write(
        logger.path(),
        format!("{}\n{}\n", "o".repeat(cap()), record(&template, "after")),
    )
    .unwrap();
    drop(path);
    let (ids, holes) = page_reports(&store);
    assert_eq!(ids, ["after"]);
    assert_eq!(holes.iter().map(|h| h.offset).collect::<Vec<_>>(), [0]);
}

/// A line starting exactly one assembly window below the page's end: the next
/// page ends on a true line boundary, so nothing below is dropped.
#[test]
fn an_over_cap_line_starting_exactly_one_window_down_drops_nothing() {
    let (_dir, store, path, template) = store_with_template();
    // `cap` content bytes plus the newline span exactly the assembly window.
    let starts = append_raw(&path, &["o".repeat(cap()), record(&template, "after")]);
    let (ids, holes) = page_reports(&store);
    assert_eq!(ids, ["after", "seed"]);
    assert_eq!(
        holes.iter().map(|h| h.offset).collect::<Vec<_>>(),
        [starts[0]]
    );
}

/// READ.3: one line assembler. Both readers call the shared pager's
/// `tail_window_assembled`, and it is defined once.
#[test]
fn the_governance_and_activity_readers_share_one_line_assembler() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
    // Built here, so this file's own text does not count as a definition.
    let needle = format!("fn {}(", "tail_window_assembled");
    let mut definitions = 0;
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                definitions += std::fs::read_to_string(&path)
                    .unwrap()
                    .matches(needle.as_str())
                    .count();
            }
        }
    }
    assert_eq!(definitions, 1, "one line assembler");
    assert!(read("src/control_plane/store/file.rs").contains("pager::tail_window_assembled("));
    assert!(read("src/gateway/ui/activity/reader.rs").contains("tail_window_assembled("));
}
