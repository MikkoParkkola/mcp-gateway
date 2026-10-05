// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    ControlPlaneAction, ControlPlaneActor, ControlPlaneDecisionQueue,
    ControlPlaneDecisionQueueItem, ControlPlaneDecisionQueueSeed, ControlPlaneDecisionTargetKind,
    ControlPlaneDomainCoverage, ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlaneHealth,
    ControlPlaneLicenseTier, ControlPlanePolicy, ControlPlaneRbac, ControlPlaneReadOnlyView,
    ControlPlaneRole, ControlPlaneRuntimeHealth, ControlPlaneServer, ControlPlaneServerStatus,
    ControlPlaneSnapshot, ControlPlaneTrustEvaluation,
};

impl ControlPlaneSnapshot {
    /// Return coverage of expected control-plane domains.
    #[must_use]
    pub fn domain_coverage(&self) -> ControlPlaneDomainCoverage {
        ControlPlaneDomainCoverage {
            servers: !self.servers.is_empty(),
            tools: !self.tools.is_empty(),
            trust_cards: !self.trust_cards.is_empty(),
            trust_evaluations: !self.trust_evaluations.is_empty(),
            grants: !self.grants.is_empty(),
            policies: !self.policies.is_empty(),
            users: !self.users.is_empty(),
            groups: !self.groups.is_empty(),
            runtime_health: !self.runtime_health.is_empty(),
            audit_events: !self.audit_events.is_empty(),
        }
    }

    /// Return a read-only projection for a permitted actor.
    #[must_use]
    pub fn read_only_view(&self, actor: &ControlPlaneActor) -> Option<ControlPlaneReadOnlyView> {
        let can_read_inventory =
            ControlPlaneRbac::authorize(actor, ControlPlaneAction::ReadInventory).allowed;
        let can_read_evidence =
            ControlPlaneRbac::authorize(actor, ControlPlaneAction::ReadEvidence).allowed;

        if !(can_read_inventory && can_read_evidence) {
            return None;
        }

        Some(ControlPlaneReadOnlyView {
            servers: self.servers.clone(),
            tools: self.tools.clone(),
            trust_cards: self.trust_cards.clone(),
            trust_evaluations: self.trust_evaluations.clone(),
            grants: self.grants.clone(),
            policies: self.policies.clone(),
            runtime_health: self.runtime_health.clone(),
            audit_events: self.audit_events.clone(),
        })
    }

    /// Return a role-aware queue of human decisions needed for this snapshot.
    #[must_use]
    pub fn decision_queue(&self, actor: &ControlPlaneActor) -> Option<ControlPlaneDecisionQueue> {
        let _readable = self.read_only_view(actor)?;
        let mut items = Vec::new();

        append_server_decisions(actor, &self.servers, &mut items);
        append_grant_decisions(actor, &self.grants, &mut items);
        append_policy_decisions(actor, &self.policies, &mut items);
        append_trust_evaluation_decisions(actor, &self.trust_evaluations, &mut items);
        append_runtime_health_decisions(actor, &self.runtime_health, &mut items);

        items.sort_by(|left, right| left.item_id.cmp(&right.item_id));

        Some(ControlPlaneDecisionQueue {
            actor_id: actor.actor_id.clone(),
            items,
        })
    }
}

fn append_server_decisions(
    actor: &ControlPlaneActor,
    servers: &[ControlPlaneServer],
    items: &mut Vec<ControlPlaneDecisionQueueItem>,
) {
    for server in servers {
        match server.status {
            ControlPlaneServerStatus::PendingApproval => items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("server:{}:approval", server.server_id),
                    target_kind: ControlPlaneDecisionTargetKind::Server,
                    target_id: server.server_id.clone(),
                    summary: format!("Server '{}' is waiting for enablement approval", server.name),
                    next_step:
                        "Review TrustCard, TrustLab evidence, owner group, and runtime policy before approval",
                    required_action: ControlPlaneAction::ApproveServer,
                    required_role: ControlPlaneRole::Admin,
                    license_tier: ControlPlaneLicenseTier::Enterprise,
                    reason_code: "CONTROL_DECISION_SERVER_APPROVAL",
                },
            )),
            ControlPlaneServerStatus::Blocked => items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("server:{}:blocked", server.server_id),
                    target_kind: ControlPlaneDecisionTargetKind::Server,
                    target_id: server.server_id.clone(),
                    summary: format!("Server '{}' is blocked by policy", server.name),
                    next_step:
                        "Review blocking evidence and decide whether remediation or exception approval is appropriate",
                    required_action: ControlPlaneAction::ReviewEvidence,
                    required_role: ControlPlaneRole::SecurityReviewer,
                    license_tier: ControlPlaneLicenseTier::Enterprise,
                    reason_code: "CONTROL_DECISION_SERVER_BLOCKED",
                },
            )),
            ControlPlaneServerStatus::Discovered | ControlPlaneServerStatus::Enabled => {}
        }
    }
}

fn append_grant_decisions(
    actor: &ControlPlaneActor,
    grants: &[ControlPlaneGrant],
    items: &mut Vec<ControlPlaneDecisionQueueItem>,
) {
    for grant in grants {
        if grant.status == ControlPlaneGrantStatus::Requested {
            items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("grant:{}:requested", grant.grant_id),
                    target_kind: ControlPlaneDecisionTargetKind::Grant,
                    target_id: grant.grant_id.clone(),
                    summary: format!(
                        "Grant '{}' for subject '{}' is waiting for approval",
                        grant.grant_id, grant.subject_id
                    ),
                    next_step:
                        "Confirm subject, tool scope, data class, expiry, and rollback before approving",
                    required_action: ControlPlaneAction::MutateGrant,
                    required_role: ControlPlaneRole::Admin,
                    license_tier: ControlPlaneLicenseTier::Enterprise,
                    reason_code: "CONTROL_DECISION_GRANT_REQUESTED",
                },
            ));
        }
    }
}

fn append_policy_decisions(
    actor: &ControlPlaneActor,
    policies: &[ControlPlanePolicy],
    items: &mut Vec<ControlPlaneDecisionQueueItem>,
) {
    for policy in policies {
        if !policy.enforced {
            items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("policy:{}:not_enforced", policy.policy_id),
                    target_kind: ControlPlaneDecisionTargetKind::Policy,
                    target_id: policy.policy_id.clone(),
                    summary: format!("Policy '{}' is not enforced", policy.name),
                    next_step:
                        "Decide whether to enforce, archive, or replace the policy with rollback evidence",
                    required_action: ControlPlaneAction::MutatePolicy,
                    required_role: ControlPlaneRole::Admin,
                    license_tier: ControlPlaneLicenseTier::Enterprise,
                    reason_code: "CONTROL_DECISION_POLICY_NOT_ENFORCED",
                },
            ));
        }
    }
}

fn append_trust_evaluation_decisions(
    actor: &ControlPlaneActor,
    evaluations: &[ControlPlaneTrustEvaluation],
    items: &mut Vec<ControlPlaneDecisionQueueItem>,
) {
    for evaluation in evaluations {
        if evaluation.score < 80 || !evaluation.policy_verdict.eq_ignore_ascii_case("allow") {
            items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("trust_eval:{}:review", evaluation.evaluation_id),
                    target_kind: ControlPlaneDecisionTargetKind::TrustEvaluation,
                    target_id: evaluation.evaluation_id.clone(),
                    summary: format!(
                        "Trust evaluation '{}' needs review: verdict '{}' with score {}",
                        evaluation.evaluation_id, evaluation.policy_verdict, evaluation.score
                    ),
                    next_step:
                        "Review failing evidence and choose remediation, quarantine, or exception handling",
                    required_action: ControlPlaneAction::ReviewEvidence,
                    required_role: ControlPlaneRole::SecurityReviewer,
                    license_tier: ControlPlaneLicenseTier::Enterprise,
                    reason_code: "CONTROL_DECISION_TRUST_EVALUATION_REVIEW",
                },
            ));
        }
    }
}

fn append_runtime_health_decisions(
    actor: &ControlPlaneActor,
    runtimes: &[ControlPlaneRuntimeHealth],
    items: &mut Vec<ControlPlaneDecisionQueueItem>,
) {
    for runtime in runtimes {
        if runtime.health != ControlPlaneHealth::Healthy {
            items.push(decision_queue_item(
                actor,
                ControlPlaneDecisionQueueSeed {
                    item_id: format!("runtime:{}:{}:health", runtime.server_id, runtime.provider),
                    target_kind: ControlPlaneDecisionTargetKind::RuntimeHealth,
                    target_id: runtime.server_id.clone(),
                    summary: format!(
                        "Runtime provider '{}' for server '{}' is {:?}",
                        runtime.provider, runtime.server_id, runtime.health
                    ),
                    next_step: "Inspect runtime evidence before enabling or expanding the server",
                    required_action: ControlPlaneAction::ReviewEvidence,
                    required_role: ControlPlaneRole::SecurityReviewer,
                    license_tier: ControlPlaneLicenseTier::FreeCore,
                    reason_code: "CONTROL_DECISION_RUNTIME_HEALTH_REVIEW",
                },
            ));
        }
    }
}

fn decision_queue_item(
    actor: &ControlPlaneActor,
    seed: ControlPlaneDecisionQueueSeed<'_>,
) -> ControlPlaneDecisionQueueItem {
    ControlPlaneDecisionQueueItem {
        item_id: seed.item_id,
        target_kind: seed.target_kind,
        target_id: seed.target_id,
        summary: seed.summary,
        next_step: seed.next_step.to_string(),
        required_action: seed.required_action,
        required_role: seed.required_role,
        license_tier: seed.license_tier,
        human_gate: true,
        can_act: ControlPlaneRbac::authorize(actor, seed.required_action).allowed,
        reason_code: seed.reason_code.to_string(),
    }
}
