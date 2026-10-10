// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Enterprise control-plane domain model.
//!
//! This module is the backend contract for future governance UI/API work. It
//! models inventory, trust evidence, grants, policies, users, groups, runtime
//! health, and audited mutations without serving a UI or persisting state yet.

use serde::{Deserialize, Serialize};

pub mod export;
pub mod grant_change;
pub mod role_mapping;
mod snapshot;
pub mod store;

pub use export::{
    CollectingSink, ExportConfig, ExportCursor, ExportEntry, ExportError, ExportSink, ExportSource,
    ExportStatus, FileExportSink, LogExporter, PollOutcome, SourceExportStatus,
    default_cursor_path,
};
pub use grant_change::{GrantChangeRecord, GrantChangeVerb};
pub use role_mapping::{ControlPlaneConfig, ControlPlaneRoleMappingConfig, ControlPlaneRoleRule};
pub use store::{
    AuditCursor, AuditFilter, AuditPage, ControlPlaneStore, FileControlPlaneStore,
    InMemoryControlPlaneStore, StoreError, StoreResult,
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
    /// Grant-change detail, on records for a grant-file change (MIK-7570.AUDIT.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_change: Option<GrantChangeRecord>,
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
mod grant_change_store_tests;
#[cfg(test)]
mod tests;
