//! TrustCard validation.
//!
//! Emits stable findings with Info, Warn, and Fail severities.
//! Conservative behavior for unknown metadata: missing or unknown fields
//! produce Warn findings rather than silently passing.

use crate::trust::{TrustCard, TrustFinding, TrustFindingSeverity};

/// Validate a TrustCard and return deterministic findings.
///
/// Findings are sorted by code for stable output across runs.
pub fn validate_trust_card(card: &TrustCard) -> Vec<TrustFinding> {
    let mut findings = Vec::new();

    // TC001: Info — schema version present
    findings.push(TrustFinding {
        severity: TrustFindingSeverity::Info,
        code: "TC001".to_string(),
        message: format!(
            "TrustCard schema version: {}",
            card.schema_version
        ),
    });

    // TC002: Warn — missing publisher
    if card.server.publisher.is_none() {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Warn,
            code: "TC002".to_string(),
            message: "Server publisher/owner is unknown".to_string(),
        });
    }

    // TC003: Warn — missing license
    if card.server.license.is_none() {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Warn,
            code: "TC003".to_string(),
            message: "Server license is unknown".to_string(),
        });
    }

    // TC004: Warn — no signature evidence
    if card.server.signature_evidence.is_empty() {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Warn,
            code: "TC004".to_string(),
            message: "No signature or provenance evidence available".to_string(),
        });
    }

    // TC005: Warn — unknown evidence quality
    if card.server.evidence_quality == "unknown" {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Warn,
            code: "TC005".to_string(),
            message: "Evidence quality is unknown — metadata may be unreliable".to_string(),
        });
    }

    // TC006: Fail — critical risk class
    if card.server.risk_class == crate::trust::TrustRiskClass::Critical {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Fail,
            code: "TC006".to_string(),
            message: "Server has critical risk classification".to_string(),
        });
    }

    // TC007: Info — transport type
    findings.push(TrustFinding {
        severity: TrustFindingSeverity::Info,
        code: "TC007".to_string(),
        message: format!("Transport: {}", card.server.transport),
    });

    // TC008: Warn — no auth with network transport
    if card.server.auth_mode == "none"
        && (card.server.transport == "http" || card.server.transport == "sse")
    {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Warn,
            code: "TC008".to_string(),
            message: "Network transport with no authentication".to_string(),
        });
    }

    // TC009: Info — missing source_uri
    if card.server.source_uri.is_none() {
        findings.push(TrustFinding {
            severity: TrustFindingSeverity::Info,
            code: "TC009".to_string(),
            message: "Source URI is not specified".to_string(),
        });
    }

    // Sort by code for deterministic output
    findings.sort_by(|a, b| a.code.cmp(&b.code));

    findings
}
