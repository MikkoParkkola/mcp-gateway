// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 2.5: `read_audit` pages across the governance log's rotation.

use super::*;
use crate::security::TransparencyLogConfig;

fn audit_event(event_id: &str) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
        grant_change: None,
        event_id: event_id.to_string(),
        actor_id: "alice".to_string(),
        action: ControlPlaneAction::MutateGrant,
        target_id: "target-1".to_string(),
        reason: "ticket MIK-1".to_string(),
        rollback: ControlPlaneRollbackPlan {
            summary: "revert".to_string(),
            step: "helm rollback".to_string(),
        },
    }
}

// ── D6 2.5: `read_audit` pages across the governance log's rotation ──────────

fn rotating_store(dir: &Path) -> FileControlPlaneStore {
    let rotation = crate::security::transparency_log::RotationConfig {
        max_segment_bytes: 4096,
        ..crate::security::transparency_log::RotationConfig::default()
    };
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().to_string(),
        key_id: "gov".to_string(),
        rotation,
        ..TransparencyLogConfig::default()
    });
    let log = Arc::new(TransparencyLogger::open(cfg).expect("open governance log"));
    FileControlPlaneStore::open(dir.join("store"), log).expect("open store")
}

fn sealed_count(dir: &Path) -> usize {
    crate::security::transparency_log::segments::list_segments(&dir.join("audit.jsonl"))
        .unwrap()
        .len()
}

/// Append audit events until the governance log has rotated `n` times.
fn fill_until_rotated(store: &FileControlPlaneStore, dir: &Path, n: usize) -> usize {
    let mut i = 0;
    while sealed_count(dir) < n {
        store.append_audit(&audit_event(&format!("e{i}"))).unwrap();
        i += 1;
        assert!(i < 1_000, "no rotation happened");
    }
    i
}

#[test]
fn read_audit_pages_across_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    let written = fill_until_rotated(&store, dir.path(), 2);
    let mut seen = Vec::new();
    let mut filter = AuditFilter::new(3);
    loop {
        let page = store.read_audit(&filter).unwrap();
        assert!(!page.cursor_reset);
        seen.extend(page.events.into_iter().map(|e| e.event_id));
        match page.next_cursor {
            Some(c) => filter = filter.resume(c),
            None => break,
        }
    }
    let want: Vec<String> = (0..written).rev().map(|i| format!("e{i}")).collect();
    assert_eq!(seen, want, "every entry once, newest first");
}

/// Every `e{i}` event read by paging from `filter` to the start of the log,
/// newest first. Other events are not counted.
fn drain_events(store: &FileControlPlaneStore, mut filter: AuditFilter) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let page = store.read_audit(&filter).unwrap();
        seen.extend(
            page.events
                .into_iter()
                .map(|e| e.event_id)
                .filter(|id| id.starts_with('e')),
        );
        match page.next_cursor {
            Some(c) => filter = filter.resume(c),
            None => return seen,
        }
        assert!(seen.len() < 10_000, "paging never ends");
    }
}

/// The log rotates after resolving a page has named the active segment and
/// before it reads anything of it. Writes go on until the rotation, so
/// `r{i}` events fill the segment past the `e{i}` events.
fn rotate_inside_resolve(store: &Arc<FileControlPlaneStore>, dir: &Path) {
    let writer = Arc::clone(store);
    let dir = dir.to_path_buf();
    let before = sealed_count(&dir);
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        let mut i = 0;
        while sealed_count(&dir) == before {
            writer.append_audit(&audit_event(&format!("r{i}"))).unwrap();
            i += 1;
            assert!(i < 1_000, "no rotation happened");
        }
    });
}

/// The newest page resolved while the log rotates reads its segment from that
/// segment's own end: no event is skipped and none repeated.
#[test]
fn a_rotation_while_resolving_the_newest_page_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(rotating_store(dir.path()));
    for i in 0..4 {
        store.append_audit(&audit_event(&format!("e{i}"))).unwrap();
    }
    rotate_inside_resolve(&store, dir.path());

    let seen = drain_events(&store, AuditFilter::new(3));

    let want: Vec<String> = (0..4).rev().map(|i| format!("e{i}")).collect();
    assert_eq!(seen, want, "every event once, newest first");
}

/// The same race for a cursor into the active segment: the page starts at
/// the cursor, not at the new active file's shorter length.
#[test]
fn a_rotation_while_resolving_an_active_cursor_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(rotating_store(dir.path()));
    for i in 0..4 {
        store.append_audit(&audit_event(&format!("e{i}"))).unwrap();
    }
    let first = store.read_audit(&AuditFilter::new(1)).unwrap();
    assert_eq!(first.events[0].event_id, "e3");
    let cursor = first.next_cursor.expect("older events remain");
    rotate_inside_resolve(&store, dir.path());

    let seen = drain_events(&store, AuditFilter::new(1).resume(cursor));

    let want: Vec<String> = (0..3).rev().map(|i| format!("e{i}")).collect();
    assert_eq!(seen, want, "every event below the cursor once");
}

/// An offset-only cursor from before any rotation, resolved while the log
/// rotates: the page starts at the cursor in segment 0, now sealed.
#[test]
fn a_rotation_while_resolving_an_offset_only_cursor_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(rotating_store(dir.path()));
    for i in 0..4 {
        store.append_audit(&audit_event(&format!("e{i}"))).unwrap();
    }
    assert_eq!(sealed_count(dir.path()), 0, "the fixture is one segment");
    let first = store.read_audit(&AuditFilter::new(1)).unwrap();
    let offset = first.next_cursor.expect("older events remain").offset;
    rotate_inside_resolve(&store, dir.path());

    let seen = drain_events(&store, AuditFilter::new(1).resume(AuditCursor::at(offset)));

    let want: Vec<String> = (0..3).rev().map(|i| format!("e{i}")).collect();
    assert_eq!(seen, want, "every event below the cursor once");
}

fn sealed_file(dir: &Path, seq: u64) -> std::path::PathBuf {
    crate::security::transparency_log::segments::sealed_path(&dir.join("audit.jsonl"), seq)
}

/// A cursor into a segment no longer kept restarts at the newest record,
/// flagged, rather than reading as the end of the log.
#[test]
fn a_cursor_into_a_removed_oldest_segment_restarts_newest() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    fill_until_rotated(&store, dir.path(), 2);
    std::fs::remove_file(sealed_file(dir.path(), 0)).unwrap();
    let cursor = AuditCursor {
        offset: 10,
        segment: Some(0),
    };

    let page = store
        .read_audit(&AuditFilter::new(3).resume(cursor))
        .unwrap();

    assert!(page.cursor_reset);
    assert!(!page.events.is_empty(), "the newest page");
}

/// A segment removed between kept ones is a hole the pages never step over.
#[test]
fn a_missing_segment_between_kept_ones_fails_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    fill_until_rotated(&store, dir.path(), 3);
    std::fs::remove_file(sealed_file(dir.path(), 1)).unwrap();
    let mut filter = AuditFilter::new(1_000);
    let err = loop {
        match store.read_audit(&filter) {
            Ok(page) => match page.next_cursor {
                Some(c) => filter = filter.resume(c),
                None => panic!("paged over the missing segment"),
            },
            Err(e) => break e,
        }
    };
    assert!(err.to_string().contains("segment 1"), "{err}");
}

/// The only file of a log goes after the newest page has resolved it: the
/// page fails, rather than read as a log never written.
#[test]
fn a_newest_segment_removed_while_resolving_fails_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    store.append_audit(&audit_event("e0")).unwrap();
    let log = dir.path().join("audit.jsonl");
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        std::fs::remove_file(&log).unwrap();
    });

    assert!(store.read_audit(&AuditFilter::new(3)).is_err());
}

/// Retention takes a cursor's segment between resolving and opening: the
/// request fails, and the same cursor retried restarts at the newest record,
/// flagged. Nothing passes silently as complete.
#[test]
fn a_cursor_expiring_while_resolving_fails_then_restarts_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    fill_until_rotated(&store, dir.path(), 2);
    let cursor = AuditCursor {
        offset: 10,
        segment: Some(0),
    };
    let doomed = sealed_file(dir.path(), 0);
    crate::security::transparency_log::pager::seam::after_active_seq(move || {
        std::fs::remove_file(&doomed).unwrap();
    });
    let filter = AuditFilter::new(3).resume(cursor);

    assert!(
        store.read_audit(&filter).is_err(),
        "the race fails the page"
    );
    let retried = store.read_audit(&filter).unwrap();
    assert!(retried.cursor_reset);
    assert!(!retried.events.is_empty(), "the newest page");
}

#[test]
fn legacy_read_audit_cursor_after_rotation_resets() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    store.append_audit(&audit_event("old")).unwrap();
    let len = std::fs::metadata(dir.path().join("audit.jsonl"))
        .unwrap()
        .len();
    fill_until_rotated(&store, dir.path(), 1);
    let filter = AuditFilter::new(10_000).resume(AuditCursor::at(len));
    let page = store.read_audit(&filter).unwrap();
    assert!(
        page.cursor_reset,
        "a pre-rotation offset no longer names a position"
    );
    assert!(!page.events.is_empty(), "restarts at the newest record");
}

/// One shared paging engine (activity feed): every page's cursor is the
/// byte offset of its event's line in that segment's file, found here by
/// reading the files directly, so a move of the paging code that shifts an
/// offset fails.
#[test]
fn read_audit_cursors_are_line_starts_in_their_segment() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    fill_until_rotated(&store, dir.path(), 2);
    let log = dir.path().join("audit.jsonl");
    let file_of = |segment: Option<u64>| {
        let sealed = crate::security::transparency_log::segments::list_segments(&log).unwrap();
        let active = sealed.last().map_or(0, |s| s.seq + 1);
        match segment {
            Some(seq) if seq != active => {
                crate::security::transparency_log::segments::sealed_path(&log, seq)
            }
            _ => log.clone(),
        }
    };
    let mut filter = AuditFilter::new(1);
    let (mut pages, mut checked) = (0, 0);
    while let Some(cursor) = {
        let page = store.read_audit(&filter).unwrap();
        // A window holding only a segment's seal record returns no event and
        // moves the cursor to the older segment; only event pages are checked.
        if let (Some(event), Some(next)) = (page.events.first(), page.next_cursor) {
            let bytes = std::fs::read(file_of(next.segment)).unwrap();
            let needle = format!("\"event_id\":\"{}\"", event.event_id);
            let at = bytes
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
                .map(|hit| {
                    bytes[..hit]
                        .iter()
                        .rposition(|b| *b == b'\n')
                        .map_or(0, |nl| nl + 1)
                });
            if let Some(line_start) = at {
                assert_eq!(
                    next.offset,
                    u64::try_from(line_start).unwrap(),
                    "{}",
                    event.event_id
                );
                checked += 1;
            }
        }
        pages += 1;
        page.next_cursor
    } {
        filter = filter.resume(cursor);
    }
    assert!(pages > 3, "the log spans several segments");
    assert!(checked > 3, "cursors were checked across segments");
}
