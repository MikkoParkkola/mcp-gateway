//! `CatalogTrustLab` evaluation and certification schema.
//!
//! The lab is an advisory evaluator for candidate MCP servers. It combines
//! TrustCard/CBOM validation, existing MCP tool-poisoning checks, schema-drift
//! comparison, policy thresholds, and safe active-eval planning into one
//! versioned evidence record.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    hashing::canonical_json_sha256,
    protocol::Tool,
    trust::{CbomComponentKind, TrustCard, TrustEvidenceKind, TrustFinding, TrustFindingSeverity},
    validator::{Rule, ToolPoisoningRule},
};

mod analysis;

use analysis::{
    annotation_findings, canonical_struct_sha256, evidence_from_findings,
    findings_from_tool_poisoning_result, lab_finding, remediation_plan_from_findings,
    risk_findings, scanner_status_from_severity, schema_drift_findings, score_findings,
};

/// Stable `TrustLab` evaluation schema version.
pub const TRUST_LAB_SCHEMA_VERSION: &str = "trust_lab.v1";

/// Existing scanner adapter id for AX-010 tool-poisoning checks.
pub const TRUST_LAB_TOOL_POISONING_SCANNER: &str = "mcp-gateway.ax010.tool_poisoning";

/// `CatalogTrustLab` evaluator with a policy threshold.
#[derive(Debug, Clone)]
pub struct CatalogTrustLab {
    policy: TrustLabPolicy,
}

impl CatalogTrustLab {
    /// Create a lab from a policy.
    #[must_use]
    pub const fn new(policy: TrustLabPolicy) -> Self {
        Self { policy }
    }

    /// Return the policy used by this lab.
    #[must_use]
    pub const fn policy(&self) -> &TrustLabPolicy {
        &self.policy
    }

    /// Evaluate a `TrustCard` with the current clock and no baseline.
    #[must_use]
    pub fn evaluate_card(&self, card: &TrustCard) -> TrustLabEvaluation {
        self.evaluate_card_with_baseline_at(card, None, Utc::now())
    }

    /// Evaluate a `TrustCard` at a specific time and optional baseline.
    #[must_use]
    pub fn evaluate_card_with_baseline_at(
        &self,
        card: &TrustCard,
        baseline: Option<&TrustLabBaseline>,
        evaluated_at: DateTime<Utc>,
    ) -> TrustLabEvaluation {
        let validated_card = card.clone().with_validation();
        let mut findings = validated_card.findings.clone();
        let mut scanners = vec![TrustLabScannerEvidence::from_findings(
            "mcp-gateway.trust_card_validator",
            "TrustCard validator",
            "1",
            &validated_card.findings,
        )];

        findings.extend(risk_findings(&validated_card));

        if let Some(baseline) = baseline {
            let drift_findings = schema_drift_findings(&validated_card, baseline);
            scanners.push(TrustLabScannerEvidence::from_findings(
                "mcp-gateway.schema_drift",
                "Schema drift detector",
                "1",
                &drift_findings,
            ));
            findings.extend(drift_findings);
        }

        let runtime = TrustLabRuntimeEvidence::static_advisory();
        let score = score_findings(&findings);
        let policy_verdict = self.policy.verdict(score, &findings);
        let remediation_plan = remediation_plan_from_findings(&findings, policy_verdict);
        let certification = TrustLabCertification::new(
            &validated_card,
            &self.policy,
            score,
            policy_verdict,
            evaluated_at,
        );

        TrustLabEvaluation {
            schema_version: TRUST_LAB_SCHEMA_VERSION.to_string(),
            evaluated_at,
            input: TrustLabInput::from_card(&validated_card, baseline),
            runtime,
            scanners,
            evidence: evidence_from_findings(&findings),
            findings,
            score,
            policy_verdict,
            remediation_plan,
            certification,
        }
    }

    /// Evaluate one protocol tool through `TrustCard` plus scanner adapters.
    #[must_use]
    pub fn evaluate_tool_at(
        &self,
        server_name: impl Into<String>,
        tool: &Tool,
        baseline: Option<&TrustLabBaseline>,
        evaluated_at: DateTime<Utc>,
    ) -> TrustLabEvaluation {
        let card = TrustCard::from_tool(server_name, tool);
        let mut evaluation = self.evaluate_card_with_baseline_at(&card, baseline, evaluated_at);

        let mut tool_findings = annotation_findings(tool);
        let scanner_result = ToolPoisoningRule.check(tool);
        match scanner_result {
            Ok(result) => {
                tool_findings.extend(findings_from_tool_poisoning_result(&result));
                evaluation.scanners.push(TrustLabScannerEvidence {
                    scanner_id: TRUST_LAB_TOOL_POISONING_SCANNER.to_string(),
                    name: "AX-010 Tool Poisoning Detection".to_string(),
                    version: "1".to_string(),
                    status: scanner_status_from_severity(result.severity),
                    score: scanner_score_percent(result.score),
                    findings_count: result.issues.len(),
                });
            }
            Err(err) => {
                tool_findings.push(lab_finding(
                    "TRUSTLAB_SCANNER_ERROR",
                    TrustFindingSeverity::Warn,
                    "scanner.ax010",
                    format!("Tool-poisoning scanner did not complete: {err}"),
                    "Rerun the evaluation and inspect the tool descriptor manually.",
                    TrustEvidenceKind::Observed,
                ));
                evaluation.scanners.push(TrustLabScannerEvidence {
                    scanner_id: TRUST_LAB_TOOL_POISONING_SCANNER.to_string(),
                    name: "AX-010 Tool Poisoning Detection".to_string(),
                    version: "1".to_string(),
                    status: TrustLabScannerStatus::Warn,
                    score: 60,
                    findings_count: 1,
                });
            }
        }

        evaluation
            .evidence
            .extend(evidence_from_findings(&tool_findings));
        evaluation.findings.extend(tool_findings);
        evaluation.score = score_findings(&evaluation.findings);
        evaluation.policy_verdict = self.policy.verdict(evaluation.score, &evaluation.findings);
        evaluation.remediation_plan =
            remediation_plan_from_findings(&evaluation.findings, evaluation.policy_verdict);
        evaluation.certification = TrustLabCertification::new(
            &card.with_validation(),
            &self.policy,
            evaluation.score,
            evaluation.policy_verdict,
            evaluated_at,
        );
        evaluation
    }

    /// Produce an active-eval plan that can only invoke declared-safe fixtures.
    #[must_use]
    pub fn plan_active_fixture_calls(
        fixtures: &[TrustLabFixtureCall],
    ) -> Vec<TrustLabFixtureCallReport> {
        fixtures
            .iter()
            .map(|fixture| {
                let arguments_digest_sha256 = canonical_json_sha256(&fixture.arguments);
                TrustLabFixtureCallReport {
                    tool_name: fixture.tool_name.clone(),
                    arguments_digest_sha256,
                    declared_safe: fixture.declared_safe,
                    invoked: fixture.declared_safe,
                    skipped_reason: if fixture.declared_safe {
                        None
                    } else {
                        Some("fixture was not explicitly declared safe".to_string())
                    },
                }
            })
            .collect()
    }
}

fn scanner_score_percent(score: f64) -> u8 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (score.clamp(0.0, 1.0) * 100.0).round() as u8
    }
}

impl Default for CatalogTrustLab {
    fn default() -> Self {
        Self::new(TrustLabPolicy::default())
    }
}

/// Policy profile for the evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabProfile {
    /// Free/core one-shot local evaluation.
    LocalOneShot,
    /// Enterprise continuous evaluation and evidence export.
    EnterpriseContinuous,
}

/// License tier associated with the evaluation feature surface.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabLicenseTier {
    /// Free/core local evaluation.
    FreeCore,
    /// Enterprise continuous governance.
    Enterprise,
}

/// Policy for converting score and findings into an enablement verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabPolicy {
    /// Local or enterprise evaluation profile.
    pub profile: TrustLabProfile,
    /// Minimum score for policy allow.
    pub minimum_score: u8,
    /// Minimum score for certification.
    pub certification_score: u8,
    /// Block when any failing finding exists.
    pub fail_on_blocking_findings: bool,
    /// Advisory mode records would-block evidence without blocking.
    pub advisory_only: bool,
}

impl TrustLabPolicy {
    /// Return the license tier for this policy profile.
    #[must_use]
    pub const fn license_tier(&self) -> TrustLabLicenseTier {
        match self.profile {
            TrustLabProfile::LocalOneShot => TrustLabLicenseTier::FreeCore,
            TrustLabProfile::EnterpriseContinuous => TrustLabLicenseTier::Enterprise,
        }
    }

    fn verdict(&self, score: u8, findings: &[TrustFinding]) -> TrustLabPolicyVerdict {
        let has_blocking = findings
            .iter()
            .any(|finding| finding.severity == TrustFindingSeverity::Fail);
        let would_block =
            score < self.minimum_score || (self.fail_on_blocking_findings && has_blocking);

        if self.advisory_only && would_block {
            TrustLabPolicyVerdict::Advisory
        } else if would_block {
            TrustLabPolicyVerdict::Block
        } else if findings
            .iter()
            .any(|finding| finding.severity == TrustFindingSeverity::Warn)
        {
            TrustLabPolicyVerdict::Warn
        } else {
            TrustLabPolicyVerdict::Allow
        }
    }
}

impl Default for TrustLabPolicy {
    fn default() -> Self {
        Self {
            profile: TrustLabProfile::LocalOneShot,
            minimum_score: 75,
            certification_score: 90,
            fail_on_blocking_findings: true,
            advisory_only: true,
        }
    }
}

/// Baseline schema digests used for drift detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabBaseline {
    /// Stable baseline identifier.
    pub baseline_id: String,
    /// Expected tool schema digest by CBOM component name.
    #[serde(default)]
    pub tool_schema_digests: BTreeMap<String, String>,
}

impl TrustLabBaseline {
    /// Build a baseline from a `TrustCard`'s current tool digests.
    #[must_use]
    pub fn from_card(baseline_id: impl Into<String>, card: &TrustCard) -> Self {
        let tool_schema_digests = card
            .cbom
            .components
            .iter()
            .filter(|component| component.kind == CbomComponentKind::Tool)
            .filter_map(|component| {
                component
                    .digest_sha256
                    .as_ref()
                    .map(|digest| (component.name.clone(), digest.clone()))
            })
            .collect();

        Self {
            baseline_id: baseline_id.into(),
            tool_schema_digests,
        }
    }
}

/// Inputs recorded in every `TrustLab` evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabInput {
    /// `TrustCard` schema version.
    pub trust_card_schema_version: String,
    /// Digest of the validated `TrustCard`.
    pub trust_card_digest_sha256: String,
    /// Digest of the CBOM section.
    pub cbom_digest_sha256: String,
    /// Candidate server name.
    pub server_name: String,
    /// Number of tool components evaluated.
    pub tool_count: usize,
    /// Optional baseline id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_id: Option<String>,
    /// Optional baseline digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_digest_sha256: Option<String>,
}

impl TrustLabInput {
    fn from_card(card: &TrustCard, baseline: Option<&TrustLabBaseline>) -> Self {
        Self {
            trust_card_schema_version: card.schema_version.clone(),
            trust_card_digest_sha256: canonical_struct_sha256(card),
            cbom_digest_sha256: canonical_struct_sha256(&card.cbom),
            server_name: card.server.name.clone(),
            tool_count: card
                .cbom
                .components
                .iter()
                .filter(|component| component.kind == CbomComponentKind::Tool)
                .count(),
            baseline_id: baseline.map(|baseline| baseline.baseline_id.clone()),
            baseline_digest_sha256: baseline.map(canonical_struct_sha256),
        }
    }
}

/// Scanner status inside the `TrustLab` evidence record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabScannerStatus {
    /// Scanner passed.
    Pass,
    /// Scanner produced warnings.
    Warn,
    /// Scanner produced failing findings.
    Fail,
    /// Scanner was skipped.
    Skipped,
}

/// Evidence for one scanner run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabScannerEvidence {
    /// Stable scanner identifier.
    pub scanner_id: String,
    /// Human-readable scanner name.
    pub name: String,
    /// Scanner adapter version.
    pub version: String,
    /// Scanner status.
    pub status: TrustLabScannerStatus,
    /// Scanner score from 0 to 100.
    pub score: u8,
    /// Number of findings emitted.
    pub findings_count: usize,
}

impl TrustLabScannerEvidence {
    fn from_findings(
        scanner_id: &str,
        name: &str,
        version: &str,
        findings: &[TrustFinding],
    ) -> Self {
        let status = if findings
            .iter()
            .any(|finding| finding.severity == TrustFindingSeverity::Fail)
        {
            TrustLabScannerStatus::Fail
        } else if findings
            .iter()
            .any(|finding| finding.severity == TrustFindingSeverity::Warn)
        {
            TrustLabScannerStatus::Warn
        } else {
            TrustLabScannerStatus::Pass
        };

        Self {
            scanner_id: scanner_id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            status,
            score: score_findings(findings),
            findings_count: findings.len(),
        }
    }
}

/// Runtime evidence captured for the evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabRuntimeEvidence {
    /// Runtime provider identifier.
    pub provider: String,
    /// Whether runtime isolation was used or the run was static-only.
    pub isolated: bool,
    /// Whether active fixture calls were enabled.
    pub active_eval: bool,
    /// Whether every planned call was explicitly safe.
    pub safe_fixture_only: bool,
    /// Planned or invoked fixture calls.
    #[serde(default)]
    pub fixture_calls: Vec<TrustLabFixtureCallReport>,
}

impl TrustLabRuntimeEvidence {
    fn static_advisory() -> Self {
        Self {
            provider: "static_advisory".to_string(),
            isolated: true,
            active_eval: false,
            safe_fixture_only: true,
            fixture_calls: Vec::new(),
        }
    }
}

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

/// Planned fixture-call outcome.
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
    fn new(
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
                TrustLabProfile::EnterpriseContinuous => Some(issued_at + Duration::days(30)),
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

#[cfg(test)]
mod tests;
