use serde::Serialize;
use serde_json::Value;

use crate::{
    hashing::canonical_json_sha256,
    protocol::Tool,
    trust::{
        CbomComponentKind, TrustCard, TrustEvidenceKind, TrustFinding, TrustFindingSeverity,
        TrustPermission, TrustRiskClass, TrustTransport,
    },
    validator::Severity,
};

use super::{
    TrustLabBaseline, TrustLabEvidence, TrustLabPolicyVerdict, TrustLabRemediationAction,
    TrustLabRemediationCategory, TrustLabRemediationOutcome, TrustLabRemediationPlan,
    TrustLabScannerStatus,
};

pub(super) fn risk_findings(card: &TrustCard) -> Vec<TrustFinding> {
    let mut findings = Vec::new();

    if matches!(
        card.server.risk_class,
        TrustRiskClass::High | TrustRiskClass::Critical
    ) {
        findings.push(lab_finding(
            "TRUSTLAB_HIGH_RISK_CLASS",
            if card.server.risk_class == TrustRiskClass::Critical {
                TrustFindingSeverity::Fail
            } else {
                TrustFindingSeverity::Warn
            },
            "server.risk_class",
            "Server risk class requires explicit review",
            "Require owner approval or a narrower capability definition before enablement.",
            card.server.evidence,
        ));
    }

    if card.server.permissions.iter().any(|permission| {
        matches!(
            permission,
            TrustPermission::Execute | TrustPermission::Filesystem
        )
    }) {
        findings.push(lab_finding(
            "TRUSTLAB_OVERBROAD_PERMISSION",
            TrustFindingSeverity::Warn,
            "server.permissions",
            "Server declares broad host-impacting permissions",
            "Run in an isolated RuntimeProvider and require review before enablement.",
            card.server.evidence,
        ));
    }

    if card.server.transport == TrustTransport::Unknown {
        findings.push(lab_finding(
            "TRUSTLAB_RUNTIME_UNKNOWN",
            TrustFindingSeverity::Warn,
            "server.transport",
            "Runtime or transport is unknown",
            "Attach runtime metadata or run the server through RuntimeProvider.",
            TrustEvidenceKind::Missing,
        ));
    }

    findings
}

pub(super) fn schema_drift_findings(
    card: &TrustCard,
    baseline: &TrustLabBaseline,
) -> Vec<TrustFinding> {
    let mut findings = Vec::new();
    for component in &card.cbom.components {
        if component.kind != CbomComponentKind::Tool {
            continue;
        }
        let Some(current_digest) = component.digest_sha256.as_deref() else {
            continue;
        };
        if let Some(expected_digest) = baseline.tool_schema_digests.get(&component.name)
            && expected_digest != current_digest
        {
            findings.push(lab_finding(
                "TRUSTLAB_SCHEMA_DRIFT",
                TrustFindingSeverity::Fail,
                format!("cbom.components[{}].digest_sha256", component.name),
                "Tool schema digest changed from the stored baseline",
                "Review the schema change and update the baseline only after approval.",
                component.evidence,
            ));
        }
    }
    findings
}

pub(super) fn annotation_findings(tool: &Tool) -> Vec<TrustFinding> {
    let mut findings = Vec::new();
    let Some(annotations) = tool.annotations.as_ref() else {
        findings.push(lab_finding(
            "TRUSTLAB_ANNOTATIONS_MISSING",
            TrustFindingSeverity::Warn,
            format!("tools[{}].annotations", tool.name),
            "MCP behavior annotations are missing",
            "Add read-only, destructive, and open-world annotations before approval.",
            TrustEvidenceKind::Missing,
        ));
        return findings;
    };

    for (field, value) in [
        ("readOnlyHint", annotations.read_only_hint),
        ("destructiveHint", annotations.destructive_hint),
        ("openWorldHint", annotations.open_world_hint),
    ] {
        if value.is_none() {
            findings.push(lab_finding(
                "TRUSTLAB_ANNOTATION_FIELD_MISSING",
                TrustFindingSeverity::Warn,
                format!("tools[{}].annotations.{field}", tool.name),
                "MCP behavior annotation field is missing",
                "Declare the behavior hint so clients can apply safety policy.",
                TrustEvidenceKind::Missing,
            ));
        }
    }

    findings
}

pub(super) fn findings_from_tool_poisoning_result(
    result: &crate::validator::ValidationResult,
) -> Vec<TrustFinding> {
    result
        .issues
        .iter()
        .map(|issue| {
            lab_finding(
                "TRUSTLAB_TOOL_POISONING",
                trust_severity_from_validator(result.severity),
                format!("tools[{}]", result.tool_name),
                issue.clone(),
                if result.suggestions.is_empty() {
                    "Review and rewrite the tool description.".to_string()
                } else {
                    result.suggestions.join(" ")
                },
                TrustEvidenceKind::Observed,
            )
        })
        .collect()
}

fn trust_severity_from_validator(severity: Severity) -> TrustFindingSeverity {
    match severity {
        Severity::Fail => TrustFindingSeverity::Fail,
        Severity::Warn => TrustFindingSeverity::Warn,
        Severity::Info | Severity::Pass => TrustFindingSeverity::Info,
    }
}

pub(super) fn scanner_status_from_severity(severity: Severity) -> TrustLabScannerStatus {
    match severity {
        Severity::Fail => TrustLabScannerStatus::Fail,
        Severity::Warn | Severity::Info => TrustLabScannerStatus::Warn,
        Severity::Pass => TrustLabScannerStatus::Pass,
    }
}

pub(super) fn score_findings(findings: &[TrustFinding]) -> u8 {
    let penalty = findings.iter().fold(0u16, |score, finding| {
        score
            + match finding.severity {
                TrustFindingSeverity::Fail => 40,
                TrustFindingSeverity::Warn => 10,
                TrustFindingSeverity::Info => 2,
            }
    });
    100u16.saturating_sub(penalty).min(100) as u8
}

pub(super) fn evidence_from_findings(findings: &[TrustFinding]) -> Vec<TrustLabEvidence> {
    findings
        .iter()
        .map(|finding| TrustLabEvidence {
            code: finding.code.clone(),
            field: finding.field.clone(),
            digest_sha256: canonical_struct_sha256(finding),
        })
        .collect()
}

pub(super) fn remediation_plan_from_findings(
    findings: &[TrustFinding],
    policy_verdict: TrustLabPolicyVerdict,
) -> TrustLabRemediationPlan {
    let actions: Vec<_> = findings
        .iter()
        .map(remediation_action_from_finding)
        .collect();
    let reviewable_diff_available = actions
        .iter()
        .any(|action| action.reviewable_diff_available);
    let human_approval_required = actions.iter().any(|action| action.human_approval_required);
    let outcome = remediation_outcome(findings, policy_verdict);
    let summary = remediation_summary(outcome, actions.len());

    TrustLabRemediationPlan {
        outcome,
        summary,
        reviewable_diff_available,
        human_approval_required,
        actions,
    }
}

fn remediation_outcome(
    findings: &[TrustFinding],
    policy_verdict: TrustLabPolicyVerdict,
) -> TrustLabRemediationOutcome {
    if findings
        .iter()
        .any(|finding| finding.code == "TRUSTLAB_TOOL_POISONING")
    {
        return TrustLabRemediationOutcome::Quarantine;
    }
    if matches!(policy_verdict, TrustLabPolicyVerdict::Block)
        || findings
            .iter()
            .any(|finding| finding.severity == TrustFindingSeverity::Fail)
    {
        return TrustLabRemediationOutcome::Block;
    }
    if findings.is_empty() {
        TrustLabRemediationOutcome::Enable
    } else {
        TrustLabRemediationOutcome::Fix
    }
}

fn remediation_summary(outcome: TrustLabRemediationOutcome, action_count: usize) -> String {
    match outcome {
        TrustLabRemediationOutcome::Enable => "No remediation required.".to_string(),
        TrustLabRemediationOutcome::Fix => {
            format!("Apply {action_count} remediation action(s) before approval.")
        }
        TrustLabRemediationOutcome::Block => {
            format!("Resolve {action_count} blocking remediation action(s) before enablement.")
        }
        TrustLabRemediationOutcome::Quarantine => {
            format!("Quarantine candidate and resolve {action_count} security action(s).")
        }
    }
}

fn remediation_action_from_finding(finding: &TrustFinding) -> TrustLabRemediationAction {
    let (category, title, reviewable_diff_available, human_approval_required) =
        match finding.code.as_str() {
            "TRUST_PUBLISHER_MISSING"
            | "TRUST_LICENSE_MISSING"
            | "TRUST_SOURCE_MISSING"
            | "TRUST_TRANSPORT_UNKNOWN"
            | "TRUST_RISK_UNKNOWN"
            | "TRUSTLAB_ANNOTATIONS_MISSING"
            | "TRUSTLAB_ANNOTATION_FIELD_MISSING" => (
                TrustLabRemediationCategory::AddMetadata,
                "Add missing trust metadata",
                true,
                false,
            ),
            "TRUST_SCHEMA_VERSION" | "TRUST_SERVER_NAME" | "TRUST_TOOL_DIGEST_MISSING" => (
                TrustLabRemediationCategory::RegenerateEvidence,
                "Regenerate trust evidence",
                true,
                false,
            ),
            "TRUSTLAB_SCHEMA_DRIFT" => (
                TrustLabRemediationCategory::UpdateBaseline,
                "Review schema drift before baseline update",
                true,
                true,
            ),
            "TRUSTLAB_HIGH_RISK_CLASS" => (
                TrustLabRemediationCategory::RequireApproval,
                "Require risk approval",
                false,
                true,
            ),
            "TRUSTLAB_OVERBROAD_PERMISSION" | "TRUSTLAB_RUNTIME_UNKNOWN" => (
                TrustLabRemediationCategory::RestrictRuntime,
                "Restrict runtime before enablement",
                true,
                true,
            ),
            "TRUSTLAB_TOOL_POISONING" => (
                TrustLabRemediationCategory::Quarantine,
                "Quarantine suspicious tool descriptor",
                false,
                true,
            ),
            "TRUSTLAB_SCANNER_ERROR" => (
                TrustLabRemediationCategory::ReviewScanner,
                "Rerun scanner or inspect adapter output",
                false,
                false,
            ),
            _ => (
                TrustLabRemediationCategory::BlockEnablement,
                "Review TrustLab finding",
                false,
                finding.severity != TrustFindingSeverity::Info,
            ),
        };

    TrustLabRemediationAction {
        finding_code: finding.code.clone(),
        category,
        target: finding.field.clone(),
        title: title.to_string(),
        detail: finding.remediation.clone(),
        reviewable_diff_available,
        human_approval_required,
        verification: verification_for_category(category),
        rollback: rollback_for_category(category),
    }
}

fn verification_for_category(category: TrustLabRemediationCategory) -> String {
    match category {
        TrustLabRemediationCategory::AddMetadata
        | TrustLabRemediationCategory::RegenerateEvidence => {
            "Rerun mcp-gateway trust lab evaluate for the affected capability.".to_string()
        }
        TrustLabRemediationCategory::RestrictRuntime
        | TrustLabRemediationCategory::RequireApproval => {
            "Rerun TrustLab with the intended policy profile and inspect the policy verdict."
                .to_string()
        }
        TrustLabRemediationCategory::UpdateBaseline => {
            "Rerun TrustLab with --baseline after approving the schema change.".to_string()
        }
        TrustLabRemediationCategory::Quarantine => {
            "Rerun TrustLab and the tool-poisoning scanner before removing quarantine.".to_string()
        }
        TrustLabRemediationCategory::BlockEnablement => {
            "Rerun TrustLab and confirm the blocking finding is absent.".to_string()
        }
        TrustLabRemediationCategory::ReviewScanner => {
            "Rerun the scanner and inspect adapter logs.".to_string()
        }
    }
}

fn rollback_for_category(category: TrustLabRemediationCategory) -> String {
    match category {
        TrustLabRemediationCategory::AddMetadata
        | TrustLabRemediationCategory::RegenerateEvidence
        | TrustLabRemediationCategory::UpdateBaseline => {
            "Revert the generated metadata or baseline change.".to_string()
        }
        TrustLabRemediationCategory::RestrictRuntime
        | TrustLabRemediationCategory::RequireApproval
        | TrustLabRemediationCategory::Quarantine
        | TrustLabRemediationCategory::BlockEnablement => {
            "Keep the candidate disabled and revert any enablement policy change.".to_string()
        }
        TrustLabRemediationCategory::ReviewScanner => {
            "Keep the prior TrustLab verdict until scanner evidence is reproducible.".to_string()
        }
    }
}

pub(super) fn lab_finding(
    code: &str,
    severity: TrustFindingSeverity,
    field: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
    evidence: TrustEvidenceKind,
) -> TrustFinding {
    TrustFinding {
        code: code.to_string(),
        severity,
        field: field.into(),
        message: message.into(),
        remediation: remediation.into(),
        evidence,
    }
}

pub(super) fn canonical_struct_sha256(value: &impl Serialize) -> String {
    let json_value = serde_json::to_value(value).unwrap_or(Value::Null);
    canonical_json_sha256(&json_value)
}
