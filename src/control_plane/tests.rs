// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn actor(role: ControlPlaneRole) -> ControlPlaneActor {
    ControlPlaneActor {
        actor_id: format!("{role:?}"),
        display_name: format!("{role:?}"),
        role,
        group_ids: vec!["security".to_string()],
    }
}

fn rollback() -> ControlPlaneRollbackPlan {
    ControlPlaneRollbackPlan {
        summary: "Restore previous policy".to_string(),
        step: "Reconcile the previous gateway policy document".to_string(),
    }
}

fn audit_event(
    actor: &ControlPlaneActor,
    action: ControlPlaneAction,
) -> ControlPlaneAuditEvent {
    ControlPlaneAuditEvent {
        grant_change: None,
        event_id: "audit-1".to_string(),
        actor_id: actor.actor_id.clone(),
        action,
        target_id: "policy-1".to_string(),
        reason: "MIK-6558 test".to_string(),
        rollback: rollback(),
    }
}

fn complete_snapshot() -> ControlPlaneSnapshot {
    let admin = ControlPlaneUser {
        user_id: "user-1".to_string(),
        display_name: "Admin".to_string(),
        role: ControlPlaneRole::Admin,
    };
    let admin_actor = actor(ControlPlaneRole::Admin);
    ControlPlaneSnapshot {
        servers: vec![ControlPlaneServer {
            server_id: "server-1".to_string(),
            name: "docs".to_string(),
            owner_group_id: "security".to_string(),
            status: ControlPlaneServerStatus::PendingApproval,
        }],
        tools: vec![ControlPlaneTool {
            tool_id: "tool-1".to_string(),
            server_id: "server-1".to_string(),
            name: "search_docs".to_string(),
            high_impact: false,
        }],
        trust_cards: vec![ControlPlaneTrustCard {
            server_id: "server-1".to_string(),
            trust_card_digest_sha256: "abc".to_string(),
            schema_version: "trust_card.v1".to_string(),
        }],
        trust_evaluations: vec![ControlPlaneTrustEvaluation {
            server_id: "server-1".to_string(),
            evaluation_id: "trustlab:abc".to_string(),
            score: 91,
            policy_verdict: "allow".to_string(),
        }],
        grants: vec![ControlPlaneGrant {
            grant_id: "grant-1".to_string(),
            subject_id: "group-1".to_string(),
            server_id: "server-1".to_string(),
            tool_id: Some("tool-1".to_string()),
            status: ControlPlaneGrantStatus::Requested,
        }],
        policies: vec![ControlPlanePolicy {
            policy_id: "policy-1".to_string(),
            name: "baseline".to_string(),
            enforced: true,
        }],
        users: vec![admin],
        groups: vec![ControlPlaneGroup {
            group_id: "group-1".to_string(),
            display_name: "Security".to_string(),
            member_user_ids: vec!["user-1".to_string()],
        }],
        runtime_health: vec![ControlPlaneRuntimeHealth {
            server_id: "server-1".to_string(),
            provider: "static_advisory".to_string(),
            health: ControlPlaneHealth::Unknown,
        }],
        audit_events: vec![audit_event(&admin_actor, ControlPlaneAction::MutatePolicy)],
    }
}

#[test]
fn domain_model_covers_all_control_plane_areas() {
    let coverage = complete_snapshot().domain_coverage();

    assert!(coverage.is_complete());
}

#[test]
fn auditor_gets_read_only_inventory_and_evidence_view() {
    let snapshot = complete_snapshot();
    let auditor = actor(ControlPlaneRole::Auditor);
    let view = snapshot.read_only_view(&auditor).unwrap();
    let mutation = ControlPlaneRbac::authorize(&auditor, ControlPlaneAction::MutatePolicy);

    assert_eq!(view.servers.len(), 1);
    assert_eq!(view.trust_evaluations.len(), 1);
    assert!(!mutation.allowed);
    assert_eq!(mutation.reason_code, "CONTROL_RBAC_MUTATION_DENIED");
}

#[test]
fn decision_queue_summarizes_human_gates_for_admins() {
    let mut snapshot = complete_snapshot();
    snapshot.trust_evaluations[0].score = 61;
    snapshot.trust_evaluations[0].policy_verdict = "quarantine".to_string();
    snapshot.policies[0].enforced = false;
    let admin = actor(ControlPlaneRole::Admin);

    let queue = snapshot.decision_queue(&admin).unwrap();

    assert_eq!(queue.actor_id, admin.actor_id);
    assert_eq!(queue.items.len(), 5);
    assert!(queue.items.iter().all(|item| item.human_gate));
    assert!(queue.items.iter().all(|item| item.can_act));
    assert!(queue.items.iter().any(|item| {
        item.reason_code == "CONTROL_DECISION_SERVER_APPROVAL"
            && item.license_tier == ControlPlaneLicenseTier::Enterprise
            && item.required_action == ControlPlaneAction::ApproveServer
    }));
    assert!(queue.items.iter().any(|item| {
        item.reason_code == "CONTROL_DECISION_RUNTIME_HEALTH_REVIEW"
            && item.license_tier == ControlPlaneLicenseTier::FreeCore
            && item.required_action == ControlPlaneAction::ReviewEvidence
    }));
}

#[test]
fn reviewer_queue_can_review_evidence_but_not_mutate_grants() {
    let snapshot = complete_snapshot();
    let reviewer = actor(ControlPlaneRole::SecurityReviewer);

    let queue = snapshot.decision_queue(&reviewer).unwrap();
    let grant = queue
        .items
        .iter()
        .find(|item| item.reason_code == "CONTROL_DECISION_GRANT_REQUESTED")
        .unwrap();
    let runtime = queue
        .items
        .iter()
        .find(|item| item.reason_code == "CONTROL_DECISION_RUNTIME_HEALTH_REVIEW")
        .unwrap();

    assert_eq!(grant.required_role, ControlPlaneRole::Admin);
    assert!(!grant.can_act);
    assert_eq!(runtime.required_role, ControlPlaneRole::SecurityReviewer);
    assert!(runtime.can_act);
    assert!(runtime.next_step.contains("Inspect runtime evidence"));
}

#[test]
fn non_admin_mutation_is_denied() {
    let reviewer = actor(ControlPlaneRole::SecurityReviewer);

    let decision = ControlPlaneRbac::authorize(&reviewer, ControlPlaneAction::MutateGrant);

    assert!(!decision.allowed);
    assert!(decision.audit_required);
    assert!(decision.rollback_required);
}

#[test]
fn admin_mutation_requires_audit_event_and_rollback() {
    let admin = actor(ControlPlaneRole::Admin);
    let mutation = ControlPlaneMutation {
        action: ControlPlaneAction::MutatePolicy,
        target_id: "policy-1".to_string(),
        summary: "Tighten baseline policy".to_string(),
        audit_event: None,
    };

    let missing_audit = mutation.validate_for_actor(&admin);
    assert!(!missing_audit.allowed);
    assert_eq!(missing_audit.reason_code, "CONTROL_AUDIT_REQUIRED");

    let with_audit = ControlPlaneMutation {
        audit_event: Some(audit_event(&admin, ControlPlaneAction::MutatePolicy)),
        ..mutation
    };
    let allowed = with_audit.validate_for_actor(&admin);
    assert!(allowed.allowed);
}

#[test]
fn enterprise_license_boundary_is_explicit() {
    assert_eq!(
        ControlPlaneFeature::LocalStatus.license_tier(),
        ControlPlaneLicenseTier::FreeCore
    );
    assert_eq!(
        ControlPlaneFeature::GovernanceMutation.license_tier(),
        ControlPlaneLicenseTier::Enterprise
    );
    assert_eq!(
        ControlPlaneFeature::EvidenceExport.license_tier(),
        ControlPlaneLicenseTier::Enterprise
    );
}
