// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    CbomComponentKind, TRUST_CARD_SCHEMA_VERSION, TrustCard, TrustCardValidator,
    TrustEvaluationStatus, TrustEvidenceKind, TrustFinding, TrustFindingSeverity, TrustRiskClass,
    TrustTransport, TrustValidationReport,
};

impl TrustCardValidator {
    /// Validate required `TrustCard` fields and conservative trust defaults.
    #[must_use]
    pub fn validate(card: &TrustCard) -> TrustValidationReport {
        let mut findings = Vec::new();

        if card.schema_version != TRUST_CARD_SCHEMA_VERSION {
            findings.push(finding(
                "TRUST_SCHEMA_VERSION",
                TrustFindingSeverity::Fail,
                "schema_version",
                "TrustCard schema version is unsupported",
                "Regenerate the TrustCard with the current schema version.",
                TrustEvidenceKind::Declared,
            ));
        }

        validate_server_metadata(card, &mut findings);
        validate_cbom_components(card, &mut findings);

        TrustValidationReport {
            status: trust_validation_status(&findings),
            findings,
        }
    }
}

fn validate_server_metadata(card: &TrustCard, findings: &mut Vec<TrustFinding>) {
    if card.server.name.trim().is_empty() {
        findings.push(finding(
            "TRUST_SERVER_NAME",
            TrustFindingSeverity::Fail,
            "server.name",
            "Server name is required",
            "Set a stable server name.",
            TrustEvidenceKind::Missing,
        ));
    }

    if card
        .server
        .publisher
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        findings.push(finding(
            "TRUST_PUBLISHER_MISSING",
            TrustFindingSeverity::Warn,
            "server.publisher",
            "Publisher or maintainer is missing",
            "Declare the publisher or maintainer before approval.",
            TrustEvidenceKind::Missing,
        ));
    }

    if card
        .server
        .license
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        findings.push(finding(
            "TRUST_LICENSE_MISSING",
            TrustFindingSeverity::Warn,
            "server.license",
            "License is missing",
            "Declare an SPDX-style license or document why it is unknown.",
            TrustEvidenceKind::Missing,
        ));
    }

    if card
        .server
        .source_uri
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        findings.push(finding(
            "TRUST_SOURCE_MISSING",
            TrustFindingSeverity::Warn,
            "server.source_uri",
            "Source URI is missing",
            "Attach a homepage, package, repository, or internal source URI.",
            TrustEvidenceKind::Missing,
        ));
    }

    if card.server.transport == TrustTransport::Unknown {
        findings.push(finding(
            "TRUST_TRANSPORT_UNKNOWN",
            TrustFindingSeverity::Warn,
            "server.transport",
            "Transport is unknown",
            "Infer or declare the server transport.",
            TrustEvidenceKind::Missing,
        ));
    }

    if card.server.risk_class == TrustRiskClass::Unknown {
        findings.push(finding(
            "TRUST_RISK_UNKNOWN",
            TrustFindingSeverity::Warn,
            "server.risk_class",
            "Risk class is unknown",
            "Run TrustCard generation or review risk manually.",
            TrustEvidenceKind::Missing,
        ));
    }
}

fn validate_cbom_components(card: &TrustCard, findings: &mut Vec<TrustFinding>) {
    for component in &card.cbom.components {
        if component.kind == CbomComponentKind::Tool && component.digest_sha256.is_none() {
            findings.push(finding(
                "TRUST_TOOL_DIGEST_MISSING",
                TrustFindingSeverity::Fail,
                "cbom.components[].digest_sha256",
                "Tool schema digest is missing",
                "Regenerate the CBOM from protocol tool metadata.",
                component.evidence,
            ));
        }
    }
}

fn trust_validation_status(findings: &[TrustFinding]) -> TrustEvaluationStatus {
    if findings
        .iter()
        .any(|finding| finding.severity == TrustFindingSeverity::Fail)
    {
        TrustEvaluationStatus::Failed
    } else if findings
        .iter()
        .any(|finding| finding.severity == TrustFindingSeverity::Warn)
    {
        TrustEvaluationStatus::Warning
    } else {
        TrustEvaluationStatus::Passed
    }
}

fn finding(
    code: &str,
    severity: TrustFindingSeverity,
    field: &str,
    message: &str,
    remediation: &str,
    evidence: TrustEvidenceKind,
) -> TrustFinding {
    TrustFinding {
        code: code.to_string(),
        severity,
        field: field.to_string(),
        message: message.to_string(),
        remediation: remediation.to_string(),
        evidence,
    }
}
