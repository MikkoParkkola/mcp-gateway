// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::merge_store_into_snapshot;
use crate::control_plane::{
    AuditFilter, AuditPage, ControlPlaneAction, ControlPlaneActor, ControlPlaneAuditEvent,
    ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlanePolicy, ControlPlaneRole,
    ControlPlaneRollbackPlan, ControlPlaneSnapshot, ControlPlaneStore, InMemoryControlPlaneStore,
    StoreError, StoreResult,
};

fn auditor() -> ControlPlaneActor {
    ControlPlaneActor {
        actor_id: "auditor".to_string(),
        display_name: "auditor".to_string(),
        role: ControlPlaneRole::Auditor,
        group_ids: vec![],
    }
}

/// A store whose every read fails — used to prove the degraded flag.
struct FailingStore;
impl ControlPlaneStore for FailingStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn get_grant(&self, _id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn put_grant(&self, _grant: ControlPlaneGrant) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn delete_grant(&self, _id: &str) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn get_policy(&self, _id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn put_policy(&self, _policy: ControlPlanePolicy) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn delete_policy(&self, _id: &str) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn append_audit(&self, _event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn read_audit(&self, _filter: &AuditFilter) -> StoreResult<AuditPage> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
}

// MIK-6701.CP.READ.1/2, narrowed by E2-min — audit_events come from the
// store; its grant and policy rows are not merged, so the local projection
// of g1 is kept as it was and p1 does not appear.
#[test]
fn store_audit_reflected_and_store_rows_not_merged() {
    let store = InMemoryControlPlaneStore::new();
    store
        .put_grant(ControlPlaneGrant {
            grant_id: "g1".to_string(),
            subject_id: "store-user".to_string(),
            server_id: "srv".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Approved,
        })
        .unwrap();
    store
        .put_policy(ControlPlanePolicy {
            policy_id: "p1".to_string(),
            name: "p".to_string(),
            enforced: true,
        })
        .unwrap();
    store
        .append_audit(&ControlPlaneAuditEvent {
            grant_change: None,
            event_id: "e1".to_string(),
            actor_id: "alice".to_string(),
            action: ControlPlaneAction::MutateGrant,
            target_id: "g1".to_string(),
            reason: "MIK-1".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "revert".to_string(),
                step: "restore".to_string(),
            },
        })
        .unwrap();

    // A snapshot that already has a LOCAL projection of g1 (different status).
    let mut snapshot = ControlPlaneSnapshot::default();
    snapshot.grants.push(ControlPlaneGrant {
        grant_id: "g1".to_string(),
        subject_id: "local-projection".to_string(),
        server_id: "srv".to_string(),
        tool_id: None,
        status: ControlPlaneGrantStatus::Requested,
    });

    let degraded = merge_store_into_snapshot(&store, &mut snapshot);
    assert!(!degraded, "a healthy store read must not report degraded");

    assert_eq!(snapshot.grants.len(), 1);
    assert_eq!(
        snapshot.grants[0].status,
        ControlPlaneGrantStatus::Requested
    );
    assert_eq!(snapshot.grants[0].subject_id, "local-projection");
    assert!(snapshot.policies.is_empty());
    assert_eq!(snapshot.audit_events.len(), 1);
    assert_eq!(snapshot.audit_events[0].event_id, "e1");
    // AuditFilter is exercised via read_audit inside the merge.
    assert!(store.read_audit(&AuditFilter::new(10)).is_ok());
}

// A grant present only locally (not in the store) is preserved.
#[test]
fn local_only_grant_is_kept() {
    let store: &dyn ControlPlaneStore = &InMemoryControlPlaneStore::new();
    let mut snapshot = ControlPlaneSnapshot::default();
    snapshot.grants.push(ControlPlaneGrant {
        grant_id: "local-1".to_string(),
        subject_id: "u".to_string(),
        server_id: "s".to_string(),
        tool_id: None,
        status: ControlPlaneGrantStatus::Approved,
    });
    let degraded = merge_store_into_snapshot(store, &mut snapshot);
    assert!(!degraded);
    assert!(snapshot.grants.iter().any(|g| g.grant_id == "local-1"));
}

// MIK-6701.CP.READ.1, inverted by E2-min — the view keeps its grants and
// policies row arrays, but a store-only grant or policy is not a row in
// them: nothing enforces it, so showing it would present it as live.
#[test]
fn read_only_view_omits_store_only_grants_and_policies() {
    let store = InMemoryControlPlaneStore::new();
    store
        .put_grant(ControlPlaneGrant {
            grant_id: "g-approved".to_string(),
            subject_id: "u".to_string(),
            server_id: "srv".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Approved,
        })
        .unwrap();
    store
        .put_policy(ControlPlanePolicy {
            policy_id: "p-enforced".to_string(),
            name: "p".to_string(),
            enforced: true,
        })
        .unwrap();

    let mut snapshot = ControlPlaneSnapshot::default();
    let degraded = merge_store_into_snapshot(&store, &mut snapshot);
    assert!(!degraded);

    let view = snapshot
        .read_only_view(&auditor())
        .expect("auditor can read inventory + evidence");
    assert!(view.grants.is_empty(), "{:?}", view.grants);
    assert!(view.policies.is_empty(), "{:?}", view.policies);

    // The serialized JSON still carries the row arrays.
    let json = serde_json::to_value(&view).unwrap();
    assert!(json["grants"].is_array());
    assert!(json["policies"].is_array());
}

// MIK-6701.CP.READ.2 (failure mode) — a store read failure sets the degraded
// flag so an empty/stale view is not mistaken for an authoritative empty
// result.
#[test]
fn store_read_failure_marks_degraded() {
    let mut snapshot = ControlPlaneSnapshot::default();
    let degraded = merge_store_into_snapshot(&FailingStore, &mut snapshot);
    assert!(degraded, "a failing store read must report degraded");
}

// MIK-6701.CP.READ.3 — feature entitlements report GovernanceMutation as
// available exactly when the mutation endpoint is active, instead of always
// reporting only LocalStatus.
#[test]
fn governance_mutation_entitlement_tracks_mutation_route() {
    use super::feature_entitlements;
    use crate::control_plane::ControlPlaneFeature;

    let read_only = feature_entitlements(false, false);
    let gov = read_only
        .iter()
        .find(|e| e.feature == ControlPlaneFeature::GovernanceMutation)
        .expect("GovernanceMutation entitlement present");
    assert!(
        !gov.available_in_this_route,
        "GovernanceMutation must be unavailable on a read-only route"
    );

    let mutating = feature_entitlements(true, false);
    let gov = mutating
        .iter()
        .find(|e| e.feature == ControlPlaneFeature::GovernanceMutation)
        .expect("GovernanceMutation entitlement present");
    assert!(
        gov.available_in_this_route,
        "GovernanceMutation must be available when the mutation endpoint is active"
    );
    // LocalStatus stays available on both routes.
    assert!(
        mutating
            .iter()
            .any(|e| e.feature == ControlPlaneFeature::LocalStatus && e.available_in_this_route)
    );
}

// MIK-6703 SIEM.RUN.2 — EvidenceExport entitlement is available exactly when
// export is configured, and unavailable otherwise.
#[test]
fn evidence_export_entitlement_tracks_export_configured() {
    use super::feature_entitlements;
    use crate::control_plane::ControlPlaneFeature;

    let off = feature_entitlements(false, false);
    assert!(
        !off.iter()
            .find(|e| e.feature == ControlPlaneFeature::EvidenceExport)
            .unwrap()
            .available_in_this_route,
        "EvidenceExport must be unavailable when export is not configured"
    );

    let on = feature_entitlements(false, true);
    assert!(
        on.iter()
            .find(|e| e.feature == ControlPlaneFeature::EvidenceExport)
            .unwrap()
            .available_in_this_route,
        "EvidenceExport must be available when export is configured"
    );
}
