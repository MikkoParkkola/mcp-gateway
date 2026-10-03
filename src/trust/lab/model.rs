// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Policy, baseline, input and scanner-evidence types of the `TrustLab` schema.

use super::analysis::{canonical_struct_sha256, score_findings};
use crate::trust::{CbomComponentKind, TrustFindingSeverity};
use crate::trust::{TrustCard, TrustFinding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::TrustLabPolicyVerdict;

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

    pub(super) fn verdict(&self, score: u8, findings: &[TrustFinding]) -> TrustLabPolicyVerdict {
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
    pub(super) fn from_card(card: &TrustCard, baseline: Option<&TrustLabBaseline>) -> Self {
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
    pub(super) fn from_findings(
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
