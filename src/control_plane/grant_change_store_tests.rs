// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T11: `grant_change` survives a durable write and read back, and an event
//! without it serialises as before (MIK-7570.AUDIT.4).

use std::sync::Arc;

use super::store::{AuditFilter, ControlPlaneStore, FileControlPlaneStore};
use super::{
    ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan, GrantChangeRecord,
    GrantChangeVerb,
};

fn event(id: &str, change: Option<GrantChangeRecord>) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
        event_id: id.to_string(),
        actor_id: "unknown".to_string(),
        action: ControlPlaneAction::MutateGrant,
        target_id: "g1".to_string(),
        reason: "grant file change".to_string(),
        rollback: ControlPlaneRollbackPlan {
            summary: "none".to_string(),
            step: "none".to_string(),
        },
        grant_change: change,
    }
}

fn store(dir: &std::path::Path) -> FileControlPlaneStore {
    let cfg = Arc::new(crate::security::TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().to_string(),
        key_id: "gov".to_string(),
        shared_secret: "governance-secret-at-least-32-bytes-long!".to_string(),
        ..crate::security::TransparencyLogConfig::default()
    });
    let log = Arc::new(crate::security::TransparencyLogger::open(cfg).expect("open log"));
    FileControlPlaneStore::open(dir.join("store"), log).expect("open store")
}

#[test]
fn t11_grant_change_round_trips_through_the_file_store() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let mut full = GrantChangeRecord::new(GrantChangeVerb::Revoke);
    full.digest = Some("sha256:ab".to_string());
    full.expires_at = Some("2030-01-01T00:00:00Z".parse().unwrap());
    full.occurred_at = Some("2026-09-28T00:00:00Z".parse().unwrap());
    full.os_account_hint = Some("alice".to_string());
    full.run_id = Some("run-1".to_string());
    full.count = Some(3);
    s.append_audit(&event("e1", Some(full.clone()))).unwrap();
    s.append_audit(&event("e2", None)).unwrap();

    let page = s.read_audit(&AuditFilter::new(10)).unwrap();
    let by_id = |id: &str| page.events.iter().find(|e| e.event_id == id).unwrap().clone();
    assert_eq!(by_id("e1").grant_change, Some(full));
    assert_eq!(by_id("e2").grant_change, None);

    let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let e2 = log.lines().find(|l| l.contains("\"e2\"")).unwrap();
    assert!(!e2.contains("grant_change"), "{e2}");
}
