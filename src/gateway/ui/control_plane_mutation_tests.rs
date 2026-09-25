// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance mutation and decision tests for `ui::control_plane`.

use super::apply_mutation;
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

// MIK-6686.CP.2 — an admin mutation is authorized, persisted, and audited.
#[test]
fn admin_grant_mutation_persists_and_audits() {
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
        |s, event| s.commit_grant_audited(g.clone(), event),
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(store.list_grants().unwrap().len(), 1);
    let audit = store.read_audit(&AuditFilter::new(10)).unwrap().events;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, ControlPlaneAction::MutateGrant);
    assert_eq!(audit[0].actor_id, "gateway-client:tester");
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
        |s, event| s.commit_grant_audited(g.clone(), event),
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
        |_s, _event| Ok(()),
    );
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// MIK-6687.CP.3 — an admin decision on a queued grant flips its status
// through the audited-commit path (approve -> Approved, deny -> Revoked).
#[test]
fn decision_resolves_grant_through_audited_path() {
    use super::{Decision, DecisionRequest, resolve_decision_core};
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let mut g = grant();
    g.status = ControlPlaneGrantStatus::Requested;
    store.put_grant(g).unwrap();

    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Grant,
            target_id: "grant-1".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        store.get_grant("grant-1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Approved
    );
    assert_eq!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .len(),
        1
    );

    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Grant,
            target_id: "grant-1".to_string(),
            decision: Decision::Deny,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        store.get_grant("grant-1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Revoked
    );
    // Deny is also audited: two decisions -> two audit entries.
    assert_eq!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .len(),
        2
    );
}

// MIK-6687.CP.3 — a policy decision flips `enforced` through the audited path.
#[test]
fn decision_resolves_policy_through_audited_path() {
    use super::{Decision, DecisionRequest, resolve_decision_core};
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    store
        .put_policy(crate::control_plane::ControlPlanePolicy {
            policy_id: "pol-1".to_string(),
            name: "p".to_string(),
            enforced: false,
        })
        .unwrap();

    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Policy,
            target_id: "pol-1".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(store.get_policy("pol-1").unwrap().unwrap().enforced);
    assert_eq!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .len(),
        1
    );
}

// MIK-6687.CP.3 — decision guards: non-admin denied (no state change), a
// missing target returns 404, an unsupported kind returns 422.
#[test]
fn decision_guards_rbac_missing_and_unsupported() {
    use super::{Decision, DecisionRequest, resolve_decision_core};
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    let mut g = grant();
    g.status = ControlPlaneGrantStatus::Requested;
    store.put_grant(g).unwrap();

    // Auditor is denied; grant stays Requested; no audit entry.
    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Auditor),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Grant,
            target_id: "grant-1".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        store.get_grant("grant-1").unwrap().unwrap().status,
        ControlPlaneGrantStatus::Requested
    );
    assert!(
        store
            .read_audit(&AuditFilter::new(10))
            .unwrap()
            .events
            .is_empty()
    );

    // Missing target -> 404.
    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::Policy,
            target_id: "absent".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unsupported kind -> 422.
    let resp = resolve_decision_core(
        Ok(&store),
        &actor(ControlPlaneRole::Admin),
        DecisionRequest {
            target_kind: ControlPlaneDecisionTargetKind::RuntimeHealth,
            target_id: "srv-1".to_string(),
            decision: Decision::Approve,
            reason: "MIK-1".to_string(),
            rollback: rollback(),
        },
    );
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
