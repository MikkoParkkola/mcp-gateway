use super::schema::*;

pub fn validate_trust_card(card: &TrustCard) -> Vec<TrustFinding> {
    let mut findings = Vec::new();

    if card.subject.name.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Critical,
            code: "TRUST-001".to_string(),
            message: "Subject name is empty".to_string(),
        });
    }

    if card.subject.description.is_none() || card.subject.description.as_deref() == Some("") {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "TRUST-002".to_string(),
            message: "Subject description is missing".to_string(),
        });
    }

    if card.owner.name.is_none() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "TRUST-003".to_string(),
            message: "Owner name is missing".to_string(),
        });
    }

    if card.license.spdx.is_none() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "TRUST-004".to_string(),
            message: "License SPDX identifier is missing".to_string(),
        });
    }

    if card.transport.protocol.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Critical,
            code: "TRUST-005".to_string(),
            message: "Transport protocol is empty".to_string(),
        });
    }

    if card.credential_needs.iter().any(|c| c.required && c.name.is_empty()) {
        findings.push(TrustFinding {
            severity: FindingSeverity::Error,
            code: "TRUST-006".to_string(),
            message: "Required credential has empty name".to_string(),
        });
    }

    if card.source.origin.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Error,
            code: "TRUST-007".to_string(),
            message: "Source origin is empty".to_string(),
        });
    }

    if card.source.manual_override && card.source.registry.is_none() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "TRUST-008".to_string(),
            message: "Manual override without registry reference".to_string(),
        });
    }

    if card.signature.is_some() && card.provenance.is_none() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "TRUST-009".to_string(),
            message: "Signature present but provenance is missing".to_string(),
        });
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
    });

    findings
}

pub fn validate_cbom(cbom: &Cbom) -> Vec<TrustFinding> {
    let mut findings = Vec::new();

    if cbom.subject.name.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Critical,
            code: "CBOM-001".to_string(),
            message: "CBOM subject name is empty".to_string(),
        });
    }

    if cbom.tools.is_empty() && cbom.prompts.is_empty() && cbom.resources.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Warn,
            code: "CBOM-002".to_string(),
            message: "CBOM has no tools, prompts, or resources".to_string(),
        });
    }

    for tool in &cbom.tools {
        if tool.name.is_empty() {
            findings.push(TrustFinding {
                severity: FindingSeverity::Error,
                code: "CBOM-003".to_string(),
                message: "CBOM tool has empty name".to_string(),
            });
        }
        if tool.description.is_none() || tool.description.as_deref() == Some("") {
            findings.push(TrustFinding {
                severity: FindingSeverity::Warn,
                code: "CBOM-004".to_string(),
                message: format!("CBOM tool '{}' has no description", tool.name),
            });
        }
    }

    if cbom.schema_version.is_empty() {
        findings.push(TrustFinding {
            severity: FindingSeverity::Critical,
            code: "CBOM-005".to_string(),
            message: "CBOM schema version is empty".to_string(),
        });
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
    });

    findings
}
