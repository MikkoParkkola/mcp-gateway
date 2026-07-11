// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    TRUST_CARD_ASSISTANT_SCHEMA_VERSION, TrustCard, TrustCardValidator, TrustFinding,
    TrustFindingSeverity,
};

/// Automation-first plan for turning `TrustCard` findings into operator decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustCardAssistantPlan {
    /// Schema version.
    pub schema_version: String,
    /// Server this plan applies to.
    pub server_name: String,
    /// Number of validator findings considered.
    pub finding_count: usize,
    /// Automated actions to try before asking a human.
    #[serde(default)]
    pub automation_actions: Vec<TrustAssistantAutomationAction>,
    /// Grouped human decisions that remain after automation.
    #[serde(default)]
    pub human_decisions: Vec<TrustAssistantPrompt>,
    /// Human decisions that block trust approval.
    pub blocking_decision_count: usize,
}

/// Automated `TrustCard` assistant action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustAssistantAutomationAction {
    /// Stable action id.
    pub action_id: String,
    /// Human title.
    pub title: String,
    /// Current action status.
    pub status: TrustAssistantAutomationStatus,
    /// Fields the action can improve.
    #[serde(default)]
    pub fields: Vec<String>,
    /// Finding codes addressed by the action.
    #[serde(default)]
    pub finding_codes: Vec<String>,
    /// Short operator-facing description.
    pub description: String,
}

/// Automation action status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustAssistantAutomationStatus {
    /// The action can run from currently available local metadata.
    Available,
    /// The action needs missing inputs before it can run.
    Blocked,
    /// The action does not apply to this card.
    NotApplicable,
}

/// Grouped human prompt for `TrustCard` metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustAssistantPrompt {
    /// Stable prompt id.
    pub prompt_id: String,
    /// Decision kind.
    pub kind: TrustAssistantPromptKind,
    /// Human title.
    pub title: String,
    /// The question to ask a person.
    pub question: String,
    /// Why automation cannot safely decide this alone.
    pub why_needed: String,
    /// Fields covered by this prompt.
    #[serde(default)]
    pub fields: Vec<String>,
    /// Finding codes covered by this prompt.
    #[serde(default)]
    pub finding_codes: Vec<String>,
    /// Highest severity represented by this prompt.
    pub severity: TrustFindingSeverity,
    /// Suggested default when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_default: Option<String>,
    /// Whether trust approval must wait for this decision.
    pub blocks_approval: bool,
}

/// `TrustCard` assistant decision kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustAssistantPromptKind {
    /// Publisher, owner, and canonical source.
    SourceOwnership,
    /// License or usage rights.
    LicenseReview,
    /// Runtime, transport, or deployment context.
    RuntimeTransport,
    /// Risk, data class, and permission acceptance.
    RiskAcceptance,
    /// Broken or stale machine metadata that must be regenerated or corrected.
    MetadataRepair,
}

/// `TrustCard` assistant.
pub struct TrustCardAssistant;

impl TrustCardAssistant {
    /// Build an automation-first plan for `TrustCard` follow-up work.
    #[must_use]
    pub fn plan(card: &TrustCard) -> TrustCardAssistantPlan {
        let report = TrustCardValidator::validate(card);
        let automation_actions = assistant_automation_actions(&report.findings);
        let human_decisions = assistant_human_decisions(card, &report.findings);
        let blocking_decision_count = human_decisions
            .iter()
            .filter(|decision| decision.blocks_approval)
            .count();

        TrustCardAssistantPlan {
            schema_version: TRUST_CARD_ASSISTANT_SCHEMA_VERSION.to_string(),
            server_name: card.server.name.clone(),
            finding_count: report.findings.len(),
            automation_actions,
            human_decisions,
            blocking_decision_count,
        }
    }
}

fn assistant_automation_actions(findings: &[TrustFinding]) -> Vec<TrustAssistantAutomationAction> {
    let mut actions = Vec::new();

    if has_any(
        findings,
        &[
            "TRUST_PUBLISHER_MISSING",
            "TRUST_LICENSE_MISSING",
            "TRUST_SOURCE_MISSING",
        ],
    ) {
        let matches = matching_findings(
            findings,
            &[
                "TRUST_PUBLISHER_MISSING",
                "TRUST_LICENSE_MISSING",
                "TRUST_SOURCE_MISSING",
            ],
        );
        actions.push(TrustAssistantAutomationAction {
            action_id: "scan-package-metadata".to_string(),
            title: "Scan package metadata".to_string(),
            status: TrustAssistantAutomationStatus::Available,
            fields: unique_fields(&matches),
            finding_codes: unique_codes(&matches),
            description: "Check local config, package manifests, import sources, and registry metadata before asking for owner or license input.".to_string(),
        });
    }

    if has_any(
        findings,
        &[
            "TRUST_SCHEMA_VERSION",
            "TRUST_TRANSPORT_UNKNOWN",
            "TRUST_RISK_UNKNOWN",
            "TRUST_TOOL_DIGEST_MISSING",
        ],
    ) {
        let matches = matching_findings(
            findings,
            &[
                "TRUST_SCHEMA_VERSION",
                "TRUST_TRANSPORT_UNKNOWN",
                "TRUST_RISK_UNKNOWN",
                "TRUST_TOOL_DIGEST_MISSING",
            ],
        );
        actions.push(TrustAssistantAutomationAction {
            action_id: "regenerate-from-descriptors".to_string(),
            title: "Regenerate from descriptors".to_string(),
            status: TrustAssistantAutomationStatus::Available,
            fields: unique_fields(&matches),
            finding_codes: unique_codes(&matches),
            description: "Regenerate TrustCard and CBOM evidence from current MCP descriptors, schemas, annotations, and runtime config.".to_string(),
        });
    }

    actions
}

fn assistant_human_decisions(
    card: &TrustCard,
    findings: &[TrustFinding],
) -> Vec<TrustAssistantPrompt> {
    let mut prompts = Vec::new();

    push_prompt(
        &mut prompts,
        findings,
        &["TRUST_PUBLISHER_MISSING", "TRUST_SOURCE_MISSING"],
        TrustAssistantPromptKind::SourceOwnership,
        "Confirm source ownership",
        "Who is accountable for this server, and what canonical source should users inspect?",
        "Ownership and source authority can affect legal and operational trust; automation can suggest candidates but cannot accept accountability.",
        card.server.source_uri.clone(),
        true,
    );
    push_prompt(
        &mut prompts,
        findings,
        &["TRUST_LICENSE_MISSING"],
        TrustAssistantPromptKind::LicenseReview,
        "Confirm license",
        "Which SPDX license or usage-rights statement applies to this server?",
        "Ambiguous licensing is a product and compliance decision; automation can discover candidates but cannot approve usage rights.",
        card.server.license.clone(),
        true,
    );
    push_prompt(
        &mut prompts,
        findings,
        &["TRUST_TRANSPORT_UNKNOWN"],
        TrustAssistantPromptKind::RuntimeTransport,
        "Confirm runtime transport",
        "Which transport and runtime profile should this card declare?",
        "Transport affects blast radius and policy routing; if config inference fails, a person must choose the deployment context.",
        card.server.runtime_profile.clone(),
        false,
    );
    push_prompt(
        &mut prompts,
        findings,
        &["TRUST_RISK_UNKNOWN"],
        TrustAssistantPromptKind::RiskAcceptance,
        "Review risk classification",
        "What risk class and data handling posture should this server use?",
        "Unknown risk must not be treated as safe; humans own data classification and acceptance when inference is inconclusive.",
        None,
        true,
    );
    push_prompt(
        &mut prompts,
        findings,
        &[
            "TRUST_SCHEMA_VERSION",
            "TRUST_SERVER_NAME",
            "TRUST_TOOL_DIGEST_MISSING",
        ],
        TrustAssistantPromptKind::MetadataRepair,
        "Repair machine metadata",
        "Should this TrustCard be regenerated or corrected before approval?",
        "Broken schema, missing identity, or missing tool digests are mechanical integrity failures that must be repaired before trust decisions.",
        None,
        true,
    );

    prompts
}

#[allow(clippy::too_many_arguments)]
fn push_prompt(
    prompts: &mut Vec<TrustAssistantPrompt>,
    findings: &[TrustFinding],
    codes: &[&str],
    kind: TrustAssistantPromptKind,
    title: &str,
    question: &str,
    why_needed: &str,
    suggested_default: Option<String>,
    blocks_approval: bool,
) {
    let matches = matching_findings(findings, codes);
    if matches.is_empty() {
        return;
    }

    prompts.push(TrustAssistantPrompt {
        prompt_id: prompt_id(kind).to_string(),
        kind,
        title: title.to_string(),
        question: question.to_string(),
        why_needed: why_needed.to_string(),
        fields: unique_fields(&matches),
        finding_codes: unique_codes(&matches),
        severity: highest_severity(&matches),
        suggested_default: suggested_default.filter(|value| !value.trim().is_empty()),
        blocks_approval,
    });
}

fn prompt_id(kind: TrustAssistantPromptKind) -> &'static str {
    match kind {
        TrustAssistantPromptKind::SourceOwnership => "source-ownership",
        TrustAssistantPromptKind::LicenseReview => "license-review",
        TrustAssistantPromptKind::RuntimeTransport => "runtime-transport",
        TrustAssistantPromptKind::RiskAcceptance => "risk-acceptance",
        TrustAssistantPromptKind::MetadataRepair => "metadata-repair",
    }
}

fn matching_findings(findings: &[TrustFinding], codes: &[&str]) -> Vec<TrustFinding> {
    findings
        .iter()
        .filter(|finding| codes.contains(&finding.code.as_str()))
        .cloned()
        .collect()
}

fn has_any(findings: &[TrustFinding], codes: &[&str]) -> bool {
    findings
        .iter()
        .any(|finding| codes.contains(&finding.code.as_str()))
}

fn unique_fields(findings: &[TrustFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.field.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_codes(findings: &[TrustFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn highest_severity(findings: &[TrustFinding]) -> TrustFindingSeverity {
    if findings
        .iter()
        .any(|finding| finding.severity == TrustFindingSeverity::Fail)
    {
        TrustFindingSeverity::Fail
    } else if findings
        .iter()
        .any(|finding| finding.severity == TrustFindingSeverity::Warn)
    {
        TrustFindingSeverity::Warn
    } else {
        TrustFindingSeverity::Info
    }
}
