// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance records carry a time, so Activity can merge them with calls.

use super::*;

/// Governance records are timed now; a log holding records from before
/// (untimed) and after still verifies, and reads back whole.
#[test]
fn governance_records_are_timed_and_a_mixed_log_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let logger = governance_logger(dir.path());
    let store = FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
    // A record as written before the stamp: the same fields, no time.
    let old = audit_event("gov-old", "alice", ControlPlaneAction::MutateGrant);
    logger
        .append_event_synced(
            audit::audit_fields(&old),
            &crate::security::audit::AuditEnvelope::governance(&old.actor_id),
        )
        .unwrap();
    store
        .append_audit(&audit_event(
            "gov-new",
            "bob",
            ControlPlaneAction::ApproveServer,
        ))
        .unwrap();

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(logger.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|v: &serde_json::Value| v["kind"] == "control_plane_audit")
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].get("timestamp").is_none(), "{}", lines[0]);
    let stamped = lines[1]["timestamp"].as_str().expect("new record is timed");
    assert!(
        chrono::DateTime::parse_from_rfc3339(stamped).is_ok(),
        "{stamped}"
    );

    let result = crate::security::transparency_log::verify_log(&logger.path()).unwrap();
    assert!(
        result.ok,
        "mixed log must verify: {:?}",
        result.error_message
    );
    let view = store.read_audit(&AuditFilter::new(10)).unwrap().events;
    let ids: Vec<&str> = view.iter().map(|e| e.event_id.as_str()).collect();
    assert_eq!(ids, ["gov-new", "gov-old"]);
}
