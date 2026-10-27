// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance records up to the logger's record cap read back through
//! `read_audit`, not only those that fit one scan window.

use super::*;

/// Page the whole governance log, newest first, returning each event's id and
/// the length of its reason. Every page must read.
fn page_all(store: &FileControlPlaneStore) -> Vec<(String, usize)> {
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
                .map(|event| (event.event_id.clone(), event.reason.len())),
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
    large.reason = "r".repeat(three_mib);
    for event in [
        audit_event("before", "alice", ControlPlaneAction::MutateGrant),
        large,
        audit_event("after", "alice", ControlPlaneAction::MutateGrant),
    ] {
        store.append_audit(&event).unwrap();
    }

    let small = audit_event("x", "alice", ControlPlaneAction::MutateGrant)
        .reason
        .len();
    assert_eq!(
        page_all(&store),
        [
            ("after".to_string(), small),
            ("large".to_string(), three_mib),
            ("before".to_string(), small),
        ]
    );
}
