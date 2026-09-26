// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the file control-plane store (moved out for the file-size ceiling).

use super::*;
use crate::control_plane::ControlPlaneGrantStatus;
use crate::security::TransparencyLogConfig;

fn grant(id: &str, status: ControlPlaneGrantStatus) -> ControlPlaneGrant {
    ControlPlaneGrant {
        grant_id: id.to_string(),
        subject_id: "user-1".to_string(),
        server_id: "srv-1".to_string(),
        tool_id: None,
        status,
    }
}

fn policy(id: &str, enforced: bool) -> ControlPlanePolicy {
    ControlPlanePolicy {
        policy_id: id.to_string(),
        name: format!("policy {id}"),
        enforced,
    }
}

fn audit_event(event_id: &str, actor: &str, action: ControlPlaneAction) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
        event_id: event_id.to_string(),
        actor_id: actor.to_string(),
        action,
        target_id: "target-1".to_string(),
        reason: "ticket MIK-1".to_string(),
        rollback: ControlPlaneRollbackPlan {
            summary: "revert".to_string(),
            step: "helm rollback".to_string(),
        },
    }
}

fn governance_logger(dir: &Path) -> Arc<TransparencyLogger> {
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().to_string(),
        key_id: "gov".to_string(),
        shared_secret: "governance-secret-at-least-32-bytes-long!".to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(TransparencyLogger::open(cfg).expect("open governance log"))
}

#[path = "store_lock_tests.rs"]
mod lock_tests;

fn file_store(dir: &Path) -> FileControlPlaneStore {
    FileControlPlaneStore::open(dir.join("store"), governance_logger(dir)).expect("open store")
}

// MIK-6685.STORE.1 — shared conformance suite over both impls.
fn conformance(store: &dyn ControlPlaneStore) {
    assert!(store.list_grants().unwrap().is_empty());
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
        .unwrap();
    store
        .put_grant(grant("g2", ControlPlaneGrantStatus::Approved))
        .unwrap();
    assert_eq!(store.list_grants().unwrap().len(), 2);
    assert_eq!(
        store.get_grant("g1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Requested
    );
    // Upsert replaces, does not duplicate.
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
        .unwrap();
    assert_eq!(store.list_grants().unwrap().len(), 2);
    assert_eq!(
        store.get_grant("g1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Approved
    );
    store.delete_grant("g1").unwrap();
    assert!(store.get_grant("g1").unwrap().is_none());
    store.delete_grant("does-not-exist").unwrap(); // no-op

    store.put_policy(policy("p1", false)).unwrap();
    store.put_policy(policy("p1", true)).unwrap();
    assert_eq!(store.list_policies().unwrap().len(), 1);
    assert!(store.get_policy("p1").unwrap().unwrap().enforced);
    store.delete_policy("p1").unwrap();
    assert!(store.list_policies().unwrap().is_empty());

    store
        .append_audit(&audit_event("a1", "alice", ControlPlaneAction::MutateGrant))
        .unwrap();
    store
        .append_audit(&audit_event("a2", "bob", ControlPlaneAction::MutatePolicy))
        .unwrap();
    let all = store.read_audit(&AuditFilter::new(10)).unwrap();
    assert_eq!(
        all.events
            .iter()
            .map(|e| e.event_id.as_str())
            .collect::<Vec<_>>(),
        ["a2", "a1"],
        "audit reads newest first"
    );
    assert!(
        all.next_cursor.is_none(),
        "a scan that reached the start of the log is final"
    );
}

#[test]
fn in_memory_passes_conformance() {
    conformance(&InMemoryControlPlaneStore::new());
}

#[test]
fn file_backend_passes_conformance() {
    let dir = tempfile::tempdir().unwrap();
    conformance(&file_store(dir.path()));
}

// MIK-6685.STORE.1 — durability across "restart" (reopen the same dir).
#[test]
fn file_backend_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = file_store(dir.path());
        s.put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
            .unwrap();
    }
    let s2 = file_store(dir.path());
    assert_eq!(
        s2.get_grant("g1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Approved
    );
}

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

// MIK-6685.STORE.4 — audit view fed by a governance TransparencyLogger that
// passes verify_log.
#[test]
fn audit_backed_by_verifiable_transparency_log() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    store
        .append_audit(&audit_event(
            "gov1",
            "alice",
            ControlPlaneAction::MutateGrant,
        ))
        .unwrap();
    store
        .append_audit(&audit_event(
            "gov2",
            "bob",
            ControlPlaneAction::ApproveServer,
        ))
        .unwrap();

    let view = store.read_audit(&AuditFilter::new(10)).unwrap().events;
    assert_eq!(view.len(), 2);
    assert_eq!(view[0].event_id, "gov2", "newest first");
    assert_eq!(view[1].action, ControlPlaneAction::MutateGrant);

    let result = crate::security::transparency_log::verify_log(&logger.path()).unwrap();
    assert!(
        result.ok,
        "governance chain must verify: {:?}",
        result.error_message
    );
    assert_eq!(result.entries_checked, 2);
}

// MIK-6685.STORE.6 — collection files are 0600.
#[cfg(unix)]
#[test]
fn collection_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path());
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
        .unwrap();
    let mode = std::fs::metadata(dir.path().join("store/grants.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "grants collection must be 0600");
}

// MIK-6685.STORE.5 — malformed collection JSON fails closed; a write never
// truncates good data.
#[test]
fn corrupt_collection_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path());
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
        .unwrap();

    let grants_path = dir.path().join("store/grants.json");
    let good = std::fs::read(&grants_path).unwrap();
    std::fs::write(&grants_path, b"{ this is not valid json").unwrap();

    assert!(matches!(store.list_grants(), Err(StoreError::Corrupt(_))));
    // A write also fails closed and does NOT overwrite the corrupt-but-present collection.
    assert!(
        store
            .put_grant(grant("g2", ControlPlaneGrantStatus::Requested))
            .is_err()
    );

    std::fs::write(&grants_path, &good).unwrap();
    assert_eq!(
        store.get_grant("g1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Approved
    );
}

// MIK-6685.STORE.3 — cross-process (two handles) stale writer is rejected;
// the optimistic put loop then does not lose updates.
#[test]
fn stale_generation_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store_dir = dir.path().join("store");
    let a = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger)).unwrap();
    let b = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger)).unwrap();
    let grants_path = a.grants_file();

    let gen_a = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
        .unwrap()
        .generation;
    let gen_b = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
        .unwrap()
        .generation;
    assert_eq!(gen_a, 0);
    assert_eq!(gen_b, 0);

    let items_a = vec![grant("ga", ControlPlaneGrantStatus::Approved)];
    assert_eq!(
        a.store_cas(&grants_path, &items_a, gen_a, FaultPoint::None)
            .unwrap(),
        1
    );

    let items_b = vec![grant("gb", ControlPlaneGrantStatus::Approved)];
    assert!(matches!(
        b.store_cas(&grants_path, &items_b, gen_b, FaultPoint::None),
        Err(StoreError::StaleGeneration {
            expected: 0,
            actual: 1
        })
    ));

    // The optimistic put loop re-reads and does not lose A's update.
    b.put_grant(grant("gb", ControlPlaneGrantStatus::Approved))
        .unwrap();
    let ids: Vec<_> = a
        .list_grants()
        .unwrap()
        .into_iter()
        .map(|g| g.grant_id)
        .collect();
    assert!(
        ids.contains(&"ga".to_string()) && ids.contains(&"gb".to_string()),
        "no lost update: {ids:?}"
    );
}

// MIK-6685.STORE.2 — phase-fault injection: a crash at any write phase leaves
// either the complete old collection or the complete new one, never a torn one.
#[test]
fn write_phase_faults_never_tear_the_collection() {
    for fault in [
        FaultPoint::AfterTempWrite,
        FaultPoint::AfterTempFsync,
        FaultPoint::AfterRename,
        FaultPoint::AfterDirFsync,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        let grants_path = store.grants_file();

        store
            .put_grant(grant("old", ControlPlaneGrantStatus::Approved))
            .unwrap();
        let old = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path).unwrap();
        assert_eq!(old.generation, 1);

        let new_items = vec![grant("new", ControlPlaneGrantStatus::Requested)];
        let _ = store.store_cas(&grants_path, &new_items, old.generation, fault);

        let recovered = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
            .unwrap_or_else(|e| panic!("torn collection after {fault:?}: {e}"));
        let ids: Vec<_> = recovered
            .items
            .iter()
            .map(|g| g.grant_id.as_str())
            .collect();
        assert!(
            ids == ["old"] || ids == ["new"],
            "after {fault:?}: expected complete old or new, got {ids:?}"
        );
    }
}

// MIK-6685.STORE.4 — cross-process audit append stays verifiable. Two
// loggers over the same log file (separate "processes") append via the
// synced path; the chain must not fork and must pass verify_log.
#[test]
fn cross_process_audit_append_stays_verifiable() {
    let dir = tempfile::tempdir().unwrap();
    let logger_a = governance_logger(dir.path());
    let logger_b = governance_logger(dir.path()); // second handle, same file
    let store_dir = dir.path().join("store");
    let a = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger_a)).unwrap();
    let b = FileControlPlaneStore::open(store_dir, Arc::clone(&logger_b)).unwrap();

    // Interleave appends across the two handles.
    a.append_audit(&audit_event("e1", "alice", ControlPlaneAction::MutateGrant))
        .unwrap();
    b.append_audit(&audit_event("e2", "bob", ControlPlaneAction::MutatePolicy))
        .unwrap();
    a.append_audit(&audit_event(
        "e3",
        "carol",
        ControlPlaneAction::ApproveServer,
    ))
    .unwrap();

    let view = a.read_audit(&AuditFilter::new(10)).unwrap();
    assert_eq!(
        view.events
            .iter()
            .map(|e| e.event_id.as_str())
            .collect::<Vec<_>>(),
        ["e3", "e2", "e1"]
    );
    let result = crate::security::transparency_log::verify_log(&logger_a.path()).unwrap();
    assert!(
        result.ok,
        "chain must not fork across processes: {:?}",
        result.error_message
    );
    assert_eq!(result.entries_checked, 3);
}

// MIK-6685.STORE.6 — a malformed control-plane audit line fails closed
// (errors) rather than silently vanishing from the view.
#[test]
fn malformed_audit_entry_fails_closed() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    store
        .append_audit(&audit_event(
            "ok1",
            "alice",
            ControlPlaneAction::MutateGrant,
        ))
        .unwrap();

    // Append a line tagged as a control-plane audit event but missing fields.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(logger.path())
        .unwrap();
    writeln!(f, r#"{{"kind":"control_plane_audit","event_id":"broken"}}"#).unwrap();
    drop(f);

    assert!(matches!(
        store.read_audit(&AuditFilter::new(10)),
        Err(StoreError::Corrupt(_))
    ));
}

// MIK-6686.CP.2 — the audited commit persists the grant AND appends a
// verifiable audit entry as one unit, under a single lock.
#[test]
fn audited_commit_persists_grant_and_appends_verifiable_audit() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();

    let g = grant("g1", ControlPlaneGrantStatus::Approved);
    let event = audit_event("e1", "alice", ControlPlaneAction::MutateGrant);
    store.commit_grant_audited(g, &event).unwrap();

    assert_eq!(store.list_grants().unwrap().len(), 1);
    let audit = store.read_audit(&AuditFilter::new(10)).unwrap();
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].event_id, "e1");
    let result = crate::security::transparency_log::verify_log(&logger.path()).unwrap();
    assert!(
        result.ok,
        "audit chain must verify: {:?}",
        result.error_message
    );
}

// MIK-6687.CP.3 — set_grant_status_audited flips ONLY the status and
// preserves other fields (no stale-clone lost update), audits the change,
// and returns false (no audit) for a missing target.
#[test]
fn set_grant_status_audited_is_field_only_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();

    // Seed g1, then a concurrent edit changes a NON-status field.
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
        .unwrap();
    let mut edited = grant("g1", ControlPlaneGrantStatus::Requested);
    edited.subject_id = "user-CHANGED".to_string();
    store.put_grant(edited).unwrap();

    // A decision flips status; the concurrent field edit must survive.
    let ev = audit_event("d1", "alice", ControlPlaneAction::MutateGrant);
    assert!(
        store
            .set_grant_status_audited("g1", ControlPlaneGrantStatus::Approved, &ev)
            .unwrap()
    );
    let g = store.get_grant("g1").unwrap().unwrap();
    assert_eq!(g.status, ControlPlaneGrantStatus::Approved);
    assert_eq!(
        g.subject_id, "user-CHANGED",
        "non-status field must be preserved"
    );
    assert_eq!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .len(),
        1
    );

    // Missing target -> false, and NO extra audit entry is written.
    assert!(
        !store
            .set_grant_status_audited("absent", ControlPlaneGrantStatus::Revoked, &ev)
            .unwrap()
    );
    assert_eq!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .len(),
        1
    );
}
