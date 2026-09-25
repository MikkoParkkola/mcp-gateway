// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance mutation and decision tests for `ui::control_plane`.

use super::{GRANT_WRITES_REFUSED, apply_mutation};
use crate::control_plane::{
    AuditFilter, ControlPlaneAction, ControlPlaneActor, ControlPlaneDecisionTargetKind,
    ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlaneRole, ControlPlaneRollbackPlan,
    ControlPlaneStore, InMemoryControlPlaneStore,
};
use axum::http::StatusCode;
use std::sync::Arc;

fn actor(role: ControlPlaneRole) -> ControlPlaneActor {
    ControlPlaneActor {
        actor_id: "gateway-client:tester".to_string(),
        display_name: "tester".to_string(),
        role,
        group_ids: vec!["g".to_string()],
    }
}

fn grant() -> ControlPlaneGrant {
    ControlPlaneGrant {
        grant_id: "grant-1".to_string(),
        subject_id: "user-1".to_string(),
        server_id: "srv-1".to_string(),
        tool_id: None,
        status: ControlPlaneGrantStatus::Approved,
    }
}

fn rollback() -> ControlPlaneRollbackPlan {
    ControlPlaneRollbackPlan {
        summary: "revert".to_string(),
        step: "restore prior grant".to_string(),
    }
}

// MIK-6686.CP.2, inverted by E2-min — an admin mutation passes RBAC and is
// then refused with 409: nothing is persisted or audited, because dispatch
// never reads the store.
#[test]
fn admin_grant_mutation_is_refused_after_rbac() {
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let g = grant();
    let resp = apply_mutation(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        ControlPlaneAction::MutateGrant,
        g.grant_id.clone(),
        "upsert".to_string(),
        "MIK-1".to_string(),
        rollback(),
        &GRANT_WRITES_REFUSED,
    );
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(store.list_grants().unwrap().is_empty());
    assert!(audit_is_empty(&store));
}

fn audit_is_empty(store: &Arc<dyn ControlPlaneStore>) -> bool {
    store
        .read_audit(&AuditFilter::new(10))
        .unwrap()
        .events
        .is_empty()
}

// MIK-6686.CP.2 — a non-admin is denied; nothing is persisted or audited.
#[test]
fn auditor_grant_mutation_is_denied_with_no_side_effects() {
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let g = grant();
    let resp = apply_mutation(
        Ok(&store),
        &actor(ControlPlaneRole::Auditor),
        ControlPlaneAction::MutateGrant,
        g.grant_id.clone(),
        "upsert".to_string(),
        "MIK-1".to_string(),
        rollback(),
        &GRANT_WRITES_REFUSED,
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(store.list_grants().unwrap().is_empty());
    assert!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .is_empty()
    );
}

// MIK-6686.CP.2 — with no store configured the route reports 503.
#[test]
fn mutation_without_store_returns_503() {
    let resp = apply_mutation(
        Err("store unavailable".to_string()),
        &actor(ControlPlaneRole::Admin),
        ControlPlaneAction::MutateGrant,
        "grant-1".to_string(),
        "upsert".to_string(),
        "MIK-1".to_string(),
        rollback(),
        &GRANT_WRITES_REFUSED,
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

fn decide(
    store: &Arc<dyn ControlPlaneStore>,
    role: ControlPlaneRole,
    target_kind: ControlPlaneDecisionTargetKind,
    target_id: &str,
    decision: super::Decision,
) -> StatusCode {
    super::resolve_decision_core(
        Ok(store),
        &actor(role),
        super::DecisionRequest {
            target_kind,
            target_id: target_id.to_string(),
            decision,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    )
    .status()
}

// MIK-6687.CP.3, inverted by E2-min — an admin decision on a queued grant is
// refused with 409 either way; the store row and the audit log are untouched.
#[test]
fn decision_on_a_grant_is_refused_without_side_effects() {
    use super::Decision;
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let mut g = grant();
    g.status = ControlPlaneGrantStatus::Requested;
    store.put_grant(g).unwrap();

    for decision in [Decision::Approve, Decision::Deny] {
        let status = decide(
            &store,
            ControlPlaneRole::Admin,
            ControlPlaneDecisionTargetKind::Grant,
            "grant-1",
            decision,
        );
        assert_eq!(status, StatusCode::CONFLICT, "{decision:?}");
    }
    assert_eq!(
        store.get_grant("grant-1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Requested
    );
    assert!(audit_is_empty(&store));
}

// MIK-6687.CP.3, inverted by E2-min — a policy decision is refused with 409.
#[test]
fn decision_on_a_policy_is_refused_without_side_effects() {
    use super::Decision;
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    store
        .put_policy(crate::control_plane::ControlPlanePolicy {
            policy_id: "pol-1".to_string(),
            name: "p".to_string(),
            enforced: false,
        })
        .unwrap();

    let status = decide(
        &store,
        ControlPlaneRole::Admin,
        ControlPlaneDecisionTargetKind::Policy,
        "pol-1",
        Decision::Approve,
    );
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!store.get_policy("pol-1").unwrap().unwrap().enforced);
    assert!(audit_is_empty(&store));
}

// MIK-6687.CP.3 — decision guards: a non-admin is denied by RBAC (no state
// change), an admin's decision on a target the store lacks gets the same 409
// as one it holds (E2-min; the store is never read), and an unsupported kind
// returns 422.
#[test]
fn decision_guards_rbac_missing_and_unsupported() {
    use super::Decision;
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let mut g = grant();
    g.status = ControlPlaneGrantStatus::Requested;
    store.put_grant(g).unwrap();

    let status = decide(
        &store,
        ControlPlaneRole::Auditor,
        ControlPlaneDecisionTargetKind::Grant,
        "grant-1",
        Decision::Approve,
    );
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        store.get_grant("grant-1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Requested
    );
    assert!(audit_is_empty(&store));

    let status = decide(
        &store,
        ControlPlaneRole::Admin,
        ControlPlaneDecisionTargetKind::Policy,
        "absent",
        Decision::Approve,
    );
    assert_eq!(status, StatusCode::CONFLICT);

    let status = decide(
        &store,
        ControlPlaneRole::Admin,
        ControlPlaneDecisionTargetKind::RuntimeHealth,
        "srv-1",
        Decision::Approve,
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
