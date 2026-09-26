// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 2.5: `read_audit` pages across the governance log's rotation.

use super::*;
use crate::security::TransparencyLogConfig;

fn audit_event(event_id: &str) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
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

#[test]
fn legacy_read_audit_cursor_after_rotation_resets() {
    let dir = tempfile::tempdir().unwrap();
    let store = rotating_store(dir.path());
    store.append_audit(&audit_event("old")).unwrap();
    let len = std::fs::metadata(dir.path().join("audit.jsonl"))
        .unwrap()
        .len();
    fill_until_rotated(&store, dir.path(), 1);
    let filter = AuditFilter::new(10_000).resume(AuditCursor::legacy_for_test(len));
    let page = store.read_audit(&filter).unwrap();
    assert!(
        page.cursor_reset,
        "a pre-rotation offset no longer names a position"
    );
    assert!(!page.events.is_empty(), "restarts at the newest record");
}
