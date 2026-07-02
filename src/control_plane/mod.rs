//! Enterprise control-plane domain model.
//!
//! This module is the backend contract for future governance UI/API work. It
//! models inventory, trust evidence, grants, policies, users, groups, runtime
//! health, and audited mutations without serving a UI or persisting state yet.

use serde::{Deserialize, Serialize};

pub mod export;
pub mod role_mapping;
pub mod store;

pub use export::{
    CollectingSink, ExportConfig, ExportCursor, ExportEntry, ExportError, ExportSink, ExportSource,
    ExportStatus, FileExportSink, LogExporter, PollOutcome, SourceExportStatus,
    default_cursor_path,
};
pub use role_mapping::{ControlPlaneConfig, ControlPlaneRoleMappingConfig, ControlPlaneRoleRule};
pub use store::{
    AuditFilter, ControlPlaneStore, FileControlPlaneStore, InMemoryControlPlaneStore, StoreError,
    StoreResult,
};

/// License tier for control-plane capabilities.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneLicenseTier {
    /// Free/core read-only local status.
    FreeCore,
    /// Enterprise governance and mutation workflows.
    Enterprise,
}

/// Control-plane feature families.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneFeature {
    /// Read-only local inventory/status.
    LocalStatus,
    /// Enterprise fleet catalog and evidence.
    FleetInventory,
    /// Enterprise grant and policy mutation workflows.
    GovernanceMutation,
    /// Enterprise evidence export.
    EvidenceExport,
}

impl ControlPlaneFeature {
    /// Return the license tier required for the feature.
    #[must_use]
    pub const fn license_tier(self) -> ControlPlaneLicenseTier {
        match self {
            Self::LocalStatus => ControlPlaneLicenseTier::FreeCore,
            Self::FleetInventory | Self::GovernanceMutation | Self::EvidenceExport => {
                ControlPlaneLicenseTier::Enterprise
            }
        }
    }
}

/// Actor role in the control plane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneRole {
    /// Full administration role.
    Admin,
    /// Reviews trust evidence but does not mutate grants or policies.
    SecurityReviewer,
    /// Developer role with read access to inventory/evidence.
    Developer,
    /// Read-only audit role.
    Auditor,
}

/// One authenticated actor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneActor {
    /// Stable actor id.
    pub actor_id: String,
    /// Display name.
    pub display_name: String,
    /// Role.
    pub role: ControlPlaneRole,
    /// Group ids.
    #[serde(default)]
    pub group_ids: Vec<String>,
}

/// Action checked by control-plane RBAC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneAction {
    /// Read server/tool/runtime inventory.
    ReadInventory,
    /// Read trust, evaluation, and audit evidence.
    ReadEvidence,
    /// Review evidence and record a recommendation.
    ReviewEvidence,
    /// Mutate grant records.
    MutateGrant,
    /// Mutate policy records.
    MutatePolicy,
    /// Approve or reject server enablement.
    ApproveServer,
}

impl ControlPlaneAction {
    /// Return true when this action changes durable state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::MutateGrant | Self::MutatePolicy | Self::ApproveServer
        )
    }
}

/// RBAC authorization decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneAuthorization {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Stable reason code.
    pub reason_code: String,
    /// Human-readable reason.
    pub reason: String,
    /// Whether an audit event is required.
    pub audit_required: bool,
    /// Whether a rollback plan is required.
    pub rollback_required: bool,
}

impl ControlPlaneAuthorization {
    fn allow(reason_code: &str, reason: &str, action: ControlPlaneAction) -> Self {
        Self {
            allowed: true,
            reason_code: reason_code.to_string(),
            reason: reason.to_string(),
            audit_required: action.is_mutation(),
            rollback_required: action.is_mutation(),
        }
    }

    fn deny(reason_code: &str, reason: &str, action: ControlPlaneAction) -> Self {
        Self {
            allowed: false,
            reason_code: reason_code.to_string(),
            reason: reason.to_string(),
            audit_required: action.is_mutation(),
            rollback_required: action.is_mutation(),
        }
    }
}

/// RBAC engine for the control-plane domain.
pub struct ControlPlaneRbac;

impl ControlPlaneRbac {
    /// Authorize an actor for an action.
    #[must_use]
    pub fn authorize(
        actor: &ControlPlaneActor,
        action: ControlPlaneAction,
    ) -> ControlPlaneAuthorization {
        match (actor.role, action) {
            (
                ControlPlaneRole::Admin,
                ControlPlaneAction::ReadInventory
                | ControlPlaneAction::ReadEvidence
                | ControlPlaneAction::ReviewEvidence
                | ControlPlaneAction::MutateGrant
                | ControlPlaneAction::MutatePolicy
                | ControlPlaneAction::ApproveServer,
            ) => {
                ControlPlaneAuthorization::allow("CONTROL_RBAC_ADMIN", "Admin role allowed", action)
            }
            (
                ControlPlaneRole::SecurityReviewer,
                ControlPlaneAction::ReadInventory
                | ControlPlaneAction::ReadEvidence
                | ControlPlaneAction::ReviewEvidence,
            ) => ControlPlaneAuthorization::allow(
                "CONTROL_RBAC_REVIEWER",
                "Security reviewer role allowed",
                action,
            ),
            (
                ControlPlaneRole::Developer,
                ControlPlaneAction::ReadInventory | ControlPlaneAction::ReadEvidence,
            ) => ControlPlaneAuthorization::allow(
                "CONTROL_RBAC_DEVELOPER_READ",
                "Developer read access allowed",
                action,
            ),
            (
                ControlPlaneRole::Auditor,
                ControlPlaneAction::ReadInventory | ControlPlaneAction::ReadEvidence,
            ) => ControlPlaneAuthorization::allow(
                "CONTROL_RBAC_AUDITOR_READ",
                "Auditor read-only access allowed",
                action,
            ),
            _ if action.is_mutation() => ControlPlaneAuthorization::deny(
                "CONTROL_RBAC_MUTATION_DENIED",
                "Only admins may mutate grants, policies, or approvals",
                action,
            ),
            _ => ControlPlaneAuthorization::deny(
                "CONTROL_RBAC_ACTION_DENIED",
                "Role is not allowed for this action",
                action,
            ),
        }
    }
}

/// Server inventory row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneServer {
    /// Stable server id.
    pub server_id: String,
    /// Display name.
    pub name: String,
    /// Owner group id.
    pub owner_group_id: String,
    /// Current enablement status.
    pub status: ControlPlaneServerStatus,
}

/// Server enablement status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneServerStatus {
    /// Discovered but not enabled.
    Discovered,
    /// Awaiting approval.
    PendingApproval,
    /// Enabled.
    Enabled,
    /// Blocked by policy.
    Blocked,
}

/// Tool inventory row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneTool {
    /// Stable tool id.
    pub tool_id: String,
    /// Owning server id.
    pub server_id: String,
    /// Tool name.
    pub name: String,
    /// Whether the tool is considered high impact.
    pub high_impact: bool,
}

/// `TrustCard` reference stored in inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneTrustCard {
    /// Owning server id.
    pub server_id: String,
    /// `TrustCard` digest.
    pub trust_card_digest_sha256: String,
    /// `TrustCard` schema version.
    pub schema_version: String,
}

/// `TrustLab` evaluation reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneTrustEvaluation {
    /// Owning server id.
    pub server_id: String,
    /// Evaluation id or digest.
    pub evaluation_id: String,
    /// Score from 0 to 100.
    pub score: u8,
    /// Policy verdict label.
    pub policy_verdict: String,
}

/// Capability grant row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneGrant {
    /// Stable grant id.
    pub grant_id: String,
    /// Subject actor or group id.
    pub subject_id: String,
    /// Server id.
    pub server_id: String,
    /// Optional tool id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    /// Grant status.
    pub status: ControlPlaneGrantStatus,
}

/// Grant status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneGrantStatus {
    /// Requested but not approved.
    Requested,
    /// Approved.
    Approved,
    /// Revoked.
    Revoked,
}

/// Policy row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlanePolicy {
    /// Stable policy id.
    pub policy_id: String,
    /// Policy name.
    pub name: String,
    /// Whether the policy is currently enforced.
    pub enforced: bool,
}

/// User row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneUser {
    /// Stable user id.
    pub user_id: String,
    /// Display name.
    pub display_name: String,
    /// Role.
    pub role: ControlPlaneRole,
}

/// Group row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneGroup {
    /// Stable group id.
    pub group_id: String,
    /// Display name.
    pub display_name: String,
    /// Member user ids.
    #[serde(default)]
    pub member_user_ids: Vec<String>,
}

/// Runtime health row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneRuntimeHealth {
    /// Server id.
    pub server_id: String,
    /// Provider name.
    pub provider: String,
    /// Current health.
    pub health: ControlPlaneHealth,
}

/// Health state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneHealth {
    /// Healthy.
    Healthy,
    /// Degraded.
    Degraded,
    /// Down.
    Down,
    /// Unknown.
    Unknown,
}

/// Control-plane decision target kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneDecisionTargetKind {
    /// Server enablement or block review.
    Server,
    /// Grant approval, denial, or revocation review.
    Grant,
    /// Policy enforcement review.
    Policy,
    /// Trust evaluation review.
    TrustEvaluation,
    /// Runtime health review.
    RuntimeHealth,
}

/// One human-gated decision surfaced for a control-plane UI or API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneDecisionQueueItem {
    /// Stable queue item id.
    pub item_id: String,
    /// Target kind.
    pub target_kind: ControlPlaneDecisionTargetKind,
    /// Target id.
    pub target_id: String,
    /// Human-readable summary.
    pub summary: String,
    /// Suggested next step.
    pub next_step: String,
    /// Action required to resolve the item.
    pub required_action: ControlPlaneAction,
    /// Role expected to resolve the item.
    pub required_role: ControlPlaneRole,
    /// License tier that owns the workflow.
    pub license_tier: ControlPlaneLicenseTier,
    /// Whether this item requires a human decision.
    pub human_gate: bool,
    /// Whether the requesting actor can perform the required action.
    pub can_act: bool,
    /// Stable reason code.
    pub reason_code: String,
}

struct ControlPlaneDecisionQueueSeed<'a> {
    item_id: String,
    target_kind: ControlPlaneDecisionTargetKind,
    target_id: String,
    summary: String,
    next_step: &'a str,
    required_action: ControlPlaneAction,
    required_role: ControlPlaneRole,
    license_tier: ControlPlaneLicenseTier,
    reason_code: &'a str,
}

/// Role-aware decision queue for control-plane review surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneDecisionQueue {
    /// Actor id used for RBAC projection.
    pub actor_id: String,
    /// Pending human-gated decisions.
    pub items: Vec<ControlPlaneDecisionQueueItem>,
}

/// Rollback plan required for mutations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneRollbackPlan {
    /// Human-readable rollback summary.
    pub summary: String,
    /// Operator command or reconciliation step.
    pub step: String,
}

/// Audit event for a control-plane mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneAuditEvent {
    /// Stable event id.
    pub event_id: String,
    /// Actor id.
    pub actor_id: String,
    /// Action.
    pub action: ControlPlaneAction,
    /// Target id.
    pub target_id: String,
    /// Reason or ticket id.
    pub reason: String,
    /// Rollback plan.
    pub rollback: ControlPlaneRollbackPlan,
}

/// Mutation request guarded by RBAC plus audit evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneMutation {
    /// Requested action.
    pub action: ControlPlaneAction,
    /// Target id.
    pub target_id: String,
    /// Summary of the requested change.
    pub summary: String,
    /// Optional audit event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event: Option<ControlPlaneAuditEvent>,
}

/// Validation report for a mutation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneMutationReport {
    /// Whether the mutation may proceed.
    pub allowed: bool,
    /// Stable reason code.
    pub reason_code: String,
    /// Human-readable reason.
    pub reason: String,
}

impl ControlPlaneMutation {
    /// Validate a mutation with RBAC and mandatory audit evidence.
    #[must_use]
    pub fn validate_for_actor(&self, actor: &ControlPlaneActor) -> ControlPlaneMutationReport {
        let authorization = ControlPlaneRbac::authorize(actor, self.action);
        if !authorization.allowed {
            return ControlPlaneMutationReport {
                allowed: false,
                reason_code: authorization.reason_code,
                reason: authorization.reason,
            };
        }

        if !self.action.is_mutation() {
            return ControlPlaneMutationReport {
                allowed: false,
                reason_code: "CONTROL_MUTATION_ACTION_REQUIRED".to_string(),
                reason: "Mutation validation requires a mutating action".to_string(),
            };
        }

        let Some(audit_event) = self.audit_event.as_ref() else {
            return ControlPlaneMutationReport {
                allowed: false,
                reason_code: "CONTROL_AUDIT_REQUIRED".to_string(),
                reason: "Mutation requires an audit event and rollback plan".to_string(),
            };
        };

        if audit_event.actor_id != actor.actor_id {
            return ControlPlaneMutationReport {
                allowed: false,
                reason_code: "CONTROL_AUDIT_ACTOR_MISMATCH".to_string(),
                reason: "Audit event actor must match the requesting actor".to_string(),
            };
        }

        if audit_event.target_id != self.target_id || audit_event.action != self.action {
            return ControlPlaneMutationReport {
                allowed: false,
                reason_code: "CONTROL_AUDIT_TARGET_MISMATCH".to_string(),
                reason: "Audit event target and action must match the mutation".to_string(),
            };
        }

        ControlPlaneMutationReport {
            allowed: true,
            reason_code: "CONTROL_MUTATION_ALLOWED".to_string(),
            reason: "Mutation is authorized and carries audit rollback evidence".to_string(),
        }
    }
}

/// Complete read model for the control plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneSnapshot {
    /// Server inventory.
    #[serde(default)]
    pub servers: Vec<ControlPlaneServer>,
    /// Tool inventory.
    #[serde(default)]
    pub tools: Vec<ControlPlaneTool>,
    /// `TrustCard` references.
    #[serde(default)]
    pub trust_cards: Vec<ControlPlaneTrustCard>,
    /// `TrustLab` evaluations.
    #[serde(default)]
    pub trust_evaluations: Vec<ControlPlaneTrustEvaluation>,
    /// Grants.
    #[serde(default)]
    pub grants: Vec<ControlPlaneGrant>,
    /// Policies.
    #[serde(default)]
    pub policies: Vec<ControlPlanePolicy>,
    /// Users.
    #[serde(default)]
    pub users: Vec<ControlPlaneUser>,
    /// Groups.
    #[serde(default)]
    pub groups: Vec<ControlPlaneGroup>,
    /// Runtime health.
    #[serde(default)]
    pub runtime_health: Vec<ControlPlaneRuntimeHealth>,
    /// Audit evidence.
    #[serde(default)]
    pub audit_events: Vec<ControlPlaneAuditEvent>,
}

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

/// Coverage flags for expected control-plane domains.
#[allow(clippy::struct_excessive_bools)] // Coverage is intentionally a flat domain checklist.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneDomainCoverage {
    /// Servers are present.
    pub servers: bool,
    /// Tools are present.
    pub tools: bool,
    /// `TrustCard`s are present.
    pub trust_cards: bool,
    /// Trust evaluations are present.
    pub trust_evaluations: bool,
    /// Grants are present.
    pub grants: bool,
    /// Policies are present.
    pub policies: bool,
    /// Users are present.
    pub users: bool,
    /// Groups are present.
    pub groups: bool,
    /// Runtime health is present.
    pub runtime_health: bool,
    /// Audit events are present.
    pub audit_events: bool,
}

impl ControlPlaneDomainCoverage {
    /// Return true when every domain expected by MIK-6558 is represented.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.servers
            && self.tools
            && self.trust_cards
            && self.trust_evaluations
            && self.grants
            && self.policies
            && self.users
            && self.groups
            && self.runtime_health
            && self.audit_events
    }
}

/// Read-only projection for inventory and evidence views.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneReadOnlyView {
    /// Server inventory.
    pub servers: Vec<ControlPlaneServer>,
    /// Tool inventory.
    pub tools: Vec<ControlPlaneTool>,
    /// `TrustCard` references.
    pub trust_cards: Vec<ControlPlaneTrustCard>,
    /// `TrustLab` evaluations.
    pub trust_evaluations: Vec<ControlPlaneTrustEvaluation>,
    /// Capability grants (all statuses — requested, approved, revoked).
    ///
    /// Exposed as rows (not just a count) so a persisted grant from the durable
    /// store is visible on GET, including approved grants that never enter the
    /// decision queue (MIK-6701).
    pub grants: Vec<ControlPlaneGrant>,
    /// Governance policies (enforced and not-yet-enforced).
    ///
    /// Exposed as rows for the same reason as `grants`: an enforced policy has
    /// no decision-queue entry, so a count alone would hide it (MIK-6701).
    pub policies: Vec<ControlPlanePolicy>,
    /// Runtime health.
    pub runtime_health: Vec<ControlPlaneRuntimeHealth>,
    /// Audit evidence.
    pub audit_events: Vec<ControlPlaneAuditEvent>,
}

#[cfg(test)]
mod tests {
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
}
