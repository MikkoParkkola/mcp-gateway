// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture reports, evidence, verdicts, certification and remediation types.

use crate::hashing::canonical_json_sha256;
use crate::trust::{TrustCard, TrustFinding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    TRUST_LAB_SCHEMA_VERSION, TrustLabInput, TrustLabLicenseTier, TrustLabPolicy, TrustLabProfile,
    TrustLabRuntimeEvidence, TrustLabScannerEvidence,
};

/// Candidate fixture call for active evaluation planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabFixtureCall {
    /// Tool name.
    pub tool_name: String,
    /// JSON arguments.
    pub arguments: serde_json::Value,
    /// Whether the fixture was explicitly reviewed as safe.
    pub declared_safe: bool,
}

/// Fixture execution result returned by an active-eval runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabFixtureExecution {
    /// Whether the fixture passed.
    pub passed: bool,
    /// Optional output captured from the fixture call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Optional failure detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TrustLabFixtureExecution {
    /// Build a passing fixture execution.
    #[must_use]
    pub fn passed(output: serde_json::Value) -> Self {
        Self {
            passed: true,
            output: Some(output),
            error: None,
        }
    }

    /// Build a failing fixture execution.
    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            passed: false,
            output: None,
            error: Some(error.into()),
        }
    }
}

/// Active fixture-call status.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabFixtureCallStatus {
    /// Safe fixture was planned but not executed by this report.
    Planned,
    /// Safe fixture executed and passed.
    Passed,
    /// Safe fixture was validated in a dry run but not invoked.
    DryRun,
    /// Safe fixture executed and failed.
    Failed,
    /// Fixture was skipped.
    #[default]
    Skipped,
}

/// Planned or executed fixture-call outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabFixtureCallReport {
    /// Tool name.
    pub tool_name: String,
    /// Digest of fixture arguments.
    pub arguments_digest_sha256: String,
    /// Whether the fixture was explicitly reviewed as safe.
    pub declared_safe: bool,
    /// Whether the lab may invoke it.
    pub invoked: bool,
    /// Planned or executed status.
    #[serde(default)]
    pub status: TrustLabFixtureCallStatus,
    /// Digest of the fixture output when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest_sha256: Option<String>,
    /// Failure detail when execution failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Skip reason when not invoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
}

/// Evidence item for audit/export consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabEvidence {
    /// Evidence code.
    pub code: String,
    /// Evidence field.
    pub field: String,
    /// Digest of the finding that produced this evidence.
    pub digest_sha256: String,
}

/// Policy verdict for enablement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabPolicyVerdict {
    /// Candidate is allowed by policy.
    Allow,
    /// Candidate is allowed with warnings.
    Warn,
    /// Candidate is blocked.
    Block,
    /// Candidate would block, but this policy is advisory-only.
    Advisory,
}

/// Certification status derived from score and policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabCertificationStatus {
    /// Certified by the configured policy.
    Certified,
    /// Advisory or warning result.
    Provisional,
    /// Rejected by the configured policy.
    Rejected,
}

/// Certification record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabCertification {
    /// Deterministic certification id.
    pub certification_id: String,
    /// Certification status.
    pub status: TrustLabCertificationStatus,
    /// License tier that owns this feature mode.
    pub license_tier: TrustLabLicenseTier,
    /// Timestamp when this record was issued.
    pub issued_at: DateTime<Utc>,
    /// Optional expiry timestamp for continuous enterprise evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Recommended enablement outcome after remediation planning.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabRemediationOutcome {
    /// Enable without additional work.
    Enable,
    /// Apply safe metadata or configuration fixes before enabling.
    Fix,
    /// Block enablement until the issue is resolved.
    Block,
    /// Quarantine the candidate from routing and catalog promotion.
    Quarantine,
}

/// Normalized remediation category for `TrustLab` findings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabRemediationCategory {
    /// Add or correct `TrustCard` or protocol metadata.
    AddMetadata,
    /// Regenerate `TrustCard` or CBOM evidence from source descriptors.
    RegenerateEvidence,
    /// Restrict runtime permissions, network, filesystem, or execution access.
    RestrictRuntime,
    /// Require explicit human approval or risk acceptance.
    RequireApproval,
    /// Review and approve a baseline update.
    UpdateBaseline,
    /// Quarantine the candidate because the descriptor appears hostile.
    Quarantine,
    /// Keep the candidate disabled until findings are resolved.
    BlockEnablement,
    /// Rerun or inspect scanner output.
    ReviewScanner,
}

/// One machine-readable remediation action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabRemediationAction {
    /// Finding code that produced this action.
    pub finding_code: String,
    /// Remediation category.
    pub category: TrustLabRemediationCategory,
    /// Field or target affected by this action.
    pub target: String,
    /// Operator-facing action title.
    pub title: String,
    /// Detailed next action.
    pub detail: String,
    /// Whether a safe reviewable metadata/config diff can be proposed.
    pub reviewable_diff_available: bool,
    /// Whether a human approval gate is required.
    pub human_approval_required: bool,
    /// Verification command or check to run after applying the action.
    pub verification: String,
    /// Rollback or undo guidance for the action.
    pub rollback: String,
}

/// Machine-readable remediation plan derived from findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabRemediationPlan {
    /// Recommended enablement outcome.
    pub outcome: TrustLabRemediationOutcome,
    /// Short summary.
    pub summary: String,
    /// Whether any action can be proposed as a safe reviewable diff.
    pub reviewable_diff_available: bool,
    /// Whether any action requires human approval.
    pub human_approval_required: bool,
    /// Ordered actions.
    #[serde(default)]
    pub actions: Vec<TrustLabRemediationAction>,
}

impl Default for TrustLabRemediationPlan {
    fn default() -> Self {
        Self {
            outcome: TrustLabRemediationOutcome::Enable,
            summary: "No remediation plan recorded.".to_string(),
            reviewable_diff_available: false,
            human_approval_required: false,
            actions: Vec::new(),
        }
    }
}

impl TrustLabCertification {
    pub(super) fn new(
        card: &TrustCard,
        policy: &TrustLabPolicy,
        score: u8,
        policy_verdict: TrustLabPolicyVerdict,
        issued_at: DateTime<Utc>,
    ) -> Self {
        let status = if matches!(policy_verdict, TrustLabPolicyVerdict::Block) {
            TrustLabCertificationStatus::Rejected
        } else if score >= policy.certification_score
            && matches!(policy_verdict, TrustLabPolicyVerdict::Allow)
        {
            TrustLabCertificationStatus::Certified
        } else {
            TrustLabCertificationStatus::Provisional
        };

        let digest = canonical_json_sha256(&serde_json::json!({
            "schema": TRUST_LAB_SCHEMA_VERSION,
            "card": card,
            "minimum_score": policy.minimum_score,
            "certification_score": policy.certification_score,
        }));

        Self {
            certification_id: format!("trustlab:{}", &digest[..16]),
            status,
            license_tier: policy.license_tier(),
            issued_at,
            expires_at: match policy.profile {
                TrustLabProfile::LocalOneShot => None,
                TrustLabProfile::EnterpriseContinuous => {
                    Some(issued_at + crate::duration_bound::delta!(days, 30))
                }
            },
        }
    }
}

/// Full `TrustLab` evaluation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabEvaluation {
    /// Schema version.
    pub schema_version: String,
    /// Evaluation timestamp.
    pub evaluated_at: DateTime<Utc>,
    /// Inputs evaluated.
    pub input: TrustLabInput,
    /// Runtime evidence.
    pub runtime: TrustLabRuntimeEvidence,
    /// Scanner evidence.
    #[serde(default)]
    pub scanners: Vec<TrustLabScannerEvidence>,
    /// Audit evidence items.
    #[serde(default)]
    pub evidence: Vec<TrustLabEvidence>,
    /// Findings.
    #[serde(default)]
    pub findings: Vec<TrustFinding>,
    /// Score from 0 to 100.
    pub score: u8,
    /// Policy verdict.
    pub policy_verdict: TrustLabPolicyVerdict,
    /// Machine-readable remediation plan.
    #[serde(default)]
    pub remediation_plan: TrustLabRemediationPlan,
    /// Certification record.
    pub certification: TrustLabCertification,
}
