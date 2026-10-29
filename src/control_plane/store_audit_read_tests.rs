// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bounded audit-read rows of the control-plane store tests, moved from
//! `store_tests.rs` for the file-size ceiling.

use super::*;

// MIK-6710.AUDIT.1 — a bounded newest-first read: paging with a cursor over a
// log far larger than one page reproduces a full-scan oracle exactly, for
// filters that match everything, some events and nothing; every call examines
// at most the scan budget; and no filtered result is silently dropped.
//
// Both backends run this one suite, so the file and in-memory paths cannot
// drift apart on order, filter semantics or cursor behaviour.
fn bounded_audit_conformance(store: &dyn ControlPlaneStore) {
    // The oracle: what a full scan in chain order would have contained.
    let oracle: Vec<ControlPlaneAuditEvent> = (0..200)
        .map(|i| {
            let actor = match i {
                137 => "rare",
                _ if i % 2 == 0 => "alice",
                _ => "bob",
            };
            let action = if i % 3 == 0 {
                ControlPlaneAction::MutatePolicy
            } else {
                ControlPlaneAction::MutateGrant
            };
            audit_event(&format!("a{i:04}"), actor, action)
        })
        .collect();
    for event in &oracle {
        store.append_audit(event).unwrap();
    }

    let cases: Vec<(Option<&str>, Option<ControlPlaneAction>)> = vec![
        (None, None),
        (Some("bob"), None),
        (None, Some(ControlPlaneAction::MutatePolicy)),
        (Some("bob"), Some(ControlPlaneAction::MutatePolicy)),
        (Some("rare"), None),
        (Some("nobody-did-this"), None),
    ];
    for (actor, action) in cases {
        let label = format!("actor={actor:?} action={action:?}");
        let base = AuditFilter {
            limit: 7,
            scan_budget: 13,
            cursor: None,
            actor_id: actor.map(str::to_string),
            action,
        };

        let mut seen: Vec<String> = Vec::new();
        let mut filter = base.clone();
        let mut calls = 0;
        loop {
            let page = store.read_audit(&filter).unwrap();
            calls += 1;
            assert!(calls < 1000, "{label}: pagination must terminate");
            assert!(
                page.records_examined <= base.scan_budget,
                "{label}: examined {} records, budget {}",
                page.records_examined,
                base.scan_budget
            );
            assert!(
                page.bytes_examined <= MAX_AUDIT_SCAN_BYTES,
                "{label}: read {} bytes, cap {MAX_AUDIT_SCAN_BYTES}",
                page.bytes_examined
            );
            assert!(
                page.events.len() <= base.limit,
                "{label}: page overran limit"
            );
            seen.extend(page.events.iter().map(|e| e.event_id.clone()));
            match page.next_cursor {
                // A bounded page that stops early MUST hand back a cursor, or
                // the missing events are silently truncated.
                Some(cursor) => filter = base.resume(cursor),
                None => break,
            }
        }

        let expected: Vec<String> = oracle
            .iter()
            .filter(|e| {
                actor.is_none_or(|a| a == e.actor_id) && action.is_none_or(|a| a == e.action)
            })
            .rev()
            .map(|e| e.event_id.clone())
            .collect();
        assert_eq!(seen, expected, "{label}: paged read must equal the oracle");
    }
}

// MIK-6710.AUDIT.1 — both backends satisfy the bounded-read contract.
#[test]
fn in_memory_audit_read_is_bounded_and_ordered() {
    bounded_audit_conformance(&InMemoryControlPlaneStore::new());
}

// MIK-6710.AUDIT.1 — both backends satisfy the bounded-read contract.
#[test]
fn file_audit_read_is_bounded_and_ordered() {
    let dir = tempfile::tempdir().unwrap();
    bounded_audit_conformance(&file_store(dir.path()));
}

// MIK-6710.AUDIT.1 — on a log larger than the scan window, one call reads a
// bounded tail rather than the whole file, and still returns the newest
// events. The positive control is the byte count: it must be below the file
// size, which is what the previous whole-file read could never satisfy.
#[test]
fn file_audit_read_caps_bytes_on_a_log_larger_than_the_window() {
    use std::io::Write;
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

    // Grow the log past MAX_AUDIT_SCAN_BYTES by replaying the seed line with
    // fresh ids. Only parsing and ordering are under test here, so the
    // replayed lines need not extend the hash chain.
    let seed = std::fs::read_to_string(logger.path()).unwrap();
    let template = seed.lines().next_back().unwrap().to_string();
    let mut blob = String::new();
    let mut written = 0u64;
    let mut i = 0;
    while written <= MAX_AUDIT_SCAN_BYTES + (64 * 1024) {
        let line = template.replace("\"seed\"", &format!("\"bulk-{i:06}\""));
        written += u64::try_from(line.len()).unwrap_or(u64::MAX) + 1;
        blob.push_str(&line);
        blob.push('\n');
        i += 1;
    }
    let newest = format!("bulk-{:06}", i - 1);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(logger.path())
        .unwrap();
    f.write_all(blob.as_bytes()).unwrap();
    drop(f);

    let file_len = std::fs::metadata(logger.path()).unwrap().len();
    assert!(
        file_len > MAX_AUDIT_SCAN_BYTES,
        "log must exceed the window"
    );
    let page = store.read_audit(&AuditFilter::new(5)).unwrap();
    assert_eq!(page.events.len(), 5);
    assert_eq!(page.events[0].event_id, newest, "newest event comes first");
    assert!(
        page.bytes_examined <= MAX_AUDIT_SCAN_BYTES && page.bytes_examined < file_len,
        "one call read {} of {file_len} bytes",
        page.bytes_examined
    );
    assert!(
        page.next_cursor.is_some(),
        "unread bytes remain, so the page must be continuable"
    );

    // Page the whole log. The second window ends where the first one began,
    // so the line straddling that boundary is the one an off-by-one in the
    // cursor handoff would drop or return twice.
    let mut ids: Vec<String> = Vec::new();
    let mut cursor = None;
    let mut calls = 0;
    loop {
        let filter = match cursor {
            Some(at) => AuditFilter::new(10_000).resume(at),
            None => AuditFilter::new(10_000),
        };
        let page = store.read_audit(&filter).unwrap();
        assert!(
            page.bytes_examined <= MAX_AUDIT_SCAN_BYTES,
            "page {calls} read {} bytes",
            page.bytes_examined
        );
        ids.extend(page.events.iter().map(|event| event.event_id.clone()));
        calls += 1;
        assert!(calls < 100, "paging the log did not terminate");
        match page.next_cursor {
            Some(at) => cursor = Some(at),
            None => break,
        }
    }
    assert!(calls > 1, "the log must span more than one window");
    let expected: Vec<String> = (0..i)
        .rev()
        .map(|n| format!("bulk-{n:06}"))
        .chain(std::iter::once("seed".to_string()))
        .collect();
    assert_eq!(
        ids.len(),
        expected.len(),
        "every line must be returned exactly once across pages"
    );
    if let Some(pos) = ids
        .iter()
        .zip(&expected)
        .position(|(got, want)| got != want)
    {
        panic!(
            "page handoff diverged at index {pos}: got {}, want {}",
            ids[pos], expected[pos]
        );
    }
}

// MIK-6710.AUDIT.1 — a single line longer than the whole scan window can
// never be read by any page, so it fails closed instead of returning a cursor
// that never advances.
// A line longer than the scan window but within the record cap is assembled
// whole now; one that is not a record (here, not JSON) still fails closed.
#[test]
fn file_audit_read_fails_closed_on_a_line_longer_than_the_window() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    store
        .append_audit(&audit_event("ok", "alice", ControlPlaneAction::MutateGrant))
        .unwrap();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(logger.path())
        .unwrap();
    let giant = "x".repeat(usize::try_from(MAX_AUDIT_SCAN_BYTES).unwrap() + 4096);
    writeln!(f, "{giant}").unwrap();
    drop(f);

    assert!(matches!(
        store.read_audit(&AuditFilter::new(10)),
        Err(StoreError::Corrupt(_))
    ));
}

// MIK-6710.AUDIT.1 — an oversized or zero scan budget is an invalid filter,
// so a caller cannot opt out of the work bound.
#[test]
fn invalid_scan_budget_errors() {
    let store = InMemoryControlPlaneStore::new();
    let bad = |budget| AuditFilter {
        scan_budget: budget,
        ..AuditFilter::new(10)
    };
    assert!(matches!(
        store.read_audit(&bad(0)),
        Err(StoreError::InvalidFilter(_))
    ));
    assert!(matches!(
        store.read_audit(&bad(MAX_AUDIT_SCAN_RECORDS + 1)),
        Err(StoreError::InvalidFilter(_))
    ));
}

// MIK-6685.STORE.6 — an invalid filter errors, never silently returns all.
#[test]
fn invalid_filter_errors() {
    let store = InMemoryControlPlaneStore::new();
    store
        .append_audit(&audit_event("a0", "alice", ControlPlaneAction::MutateGrant))
        .unwrap();
    assert!(matches!(
        store.read_audit(&AuditFilter::new(0)),
        Err(StoreError::InvalidFilter(_))
    ));
    assert!(matches!(
        store.read_audit(&AuditFilter::new(MAX_AUDIT_LIMIT + 1)),
        Err(StoreError::InvalidFilter(_))
    ));
}
