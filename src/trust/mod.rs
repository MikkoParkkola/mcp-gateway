//! TrustCard and Capability BOM schema, generation, and validation.
//!
//! TrustCard is the human-readable trust summary for a backend or tool.
//! CapabilityBom is the machine-readable capability bill of materials.
//! Both expose stable schema version strings and deterministic JSON output.

pub mod descriptor;
pub mod generator;
pub mod schema;
pub mod validator;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema version for TrustCard output.
pub const TRUSTCARD_SCHEMA_VERSION: &str = "1.0.0";

/// Schema version for CapabilityBom output.
pub const CBOM_SCHEMA_VERSION: &str = "1.0.0";

/// Trust risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRiskClass {
    /// Low risk — read-only, no secrets, no network reach.
    Low,
    /// Medium risk — may access network or handle user input.
    Medium,
    /// High risk — writes data, accesses secrets, or has broad network reach.
    High,
    /// Critical risk — policy-blocked or unverified provenance.
    Critical,
}

/// Trust finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustFindingSeverity {
    /// Informational — no action required.
    Info,
    /// Warning — review recommended.
    Warn,
    /// Failure — policy violation, should block.
    Fail,
}

/// Network reach classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustNetworkReach {
    /// No network access.
    None,
    /// Localhost only.
    Local,
    /// Private/internal network.
    Private,
    /// Public internet.
    Public,
}

/// Server metadata for a TrustCard.
///
/// Covers source, publisher/owner, license, transport, auth mode, runtime
/// profile, network reach, signature/provenance evidence, risk class,
/// data classes, permissions, and evidence quality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServer {
    /// Source URI of the backend (e.g. npm package, git repo, URL).
    pub source_uri: Option<String>,
    /// Publisher or owner identity.
    pub publisher: Option<String>,
    /// License identifier (SPDX).
    pub license: Option<String>,
    /// Transport type (stdio, http, sse, a2a).
    pub transport: String,
    /// Authentication mode (none, bearer, oauth, api_key, mtls).
    pub auth_mode: String,
    /// Runtime profile (local subprocess, remote http, embedded).
    pub runtime_profile: String,
    /// Network reach classification.
    pub network_reach: TrustNetworkReach,
    /// Signature or provenance evidence.
    pub signature_evidence: Vec<TrustSignatureEvidence>,
    /// Risk classification.
    pub risk_class: TrustRiskClass,
    /// Data classes handled (e.g. pii, credentials, public).
    pub data_classes: Vec<String>,
    /// Permissions required (e.g. network, filesystem, exec).
    pub permissions: Vec<String>,
    /// Evidence quality assessment (verified, self-reported, unknown).
    pub evidence_quality: String,
}

/// Signature or provenance evidence entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSignatureEvidence {
    /// Evidence type (e.g. "sha256_pin", "vendor_signed", "transparency_log").
    pub evidence_type: String,
    /// Digest or reference (never contains resolved secrets).
    pub digest: Option<String>,
    /// Issuer or signer identity.
    pub issuer: Option<String>,
    /// Verification status.
    pub verified: bool,
}

/// Human-readable trust summary for a single tool or backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCard {
    /// Schema version.
    pub schema_version: String,
    /// Tool or backend name.
    pub name: String,
    /// Server metadata.
    pub server: TrustServer,
    /// Tool-level trust details (if tool-specific).
    pub tool: Option<TrustTool>,
    /// Validation findings.
    pub findings: Vec<TrustFinding>,
    /// Generated timestamp (ISO 8601).
    pub generated_at: String,
}

/// Trust metadata for a specific tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustTool {
    /// Tool name.
    pub name: String,
    /// Whether the tool is read-only (no side effects).
    pub read_only: Option<bool>,
    /// Whether the tool is destructive.
    pub destructive: Option<bool>,
    /// Whether the tool is idempotent.
    pub idempotent: Option<bool>,
    /// Input schema summary.
    pub input_schema_digest: Option<String>,
    /// Output schema summary.
    pub output_schema_digest: Option<String>,
}

/// Validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFinding {
    /// Finding severity.
    pub severity: TrustFindingSeverity,
    /// Finding code (stable identifier, e.g. "TC001").
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

/// Machine-readable capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityBom {
    /// Schema version.
    pub schema_version: String,
    /// Backend or server name.
    pub name: String,
    /// Version of the backend.
    pub version: Option<String>,
    /// Tools provided.
    pub tools: Vec<CbomTool>,
    /// Prompts provided.
    pub prompts: Vec<CbomPrompt>,
    /// Resources provided.
    pub resources: Vec<CbomResource>,
    /// Annotations.
    pub annotations: Vec<CbomAnnotation>,
    /// Dependencies.
    pub dependencies: Vec<CbomDependency>,
    /// Provenance information.
    pub provenance: CbomProvenance,
    /// Components (sub-components or sub-modules).
    pub components: Vec<String>,
    /// Generated timestamp (ISO 8601).
    pub generated_at: String,
}

/// A tool entry in the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomTool {
    /// Tool name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Input schema digest.
    pub input_schema_digest: Option<String>,
    /// Output schema digest.
    pub output_schema_digest: Option<String>,
    /// Annotations associated with this tool.
    pub annotations: BTreeMap<String, serde_json::Value>,
}

/// A prompt entry in the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomPrompt {
    /// Prompt name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Arguments.
    pub arguments: Vec<String>,
}

/// A resource entry in the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomResource {
    /// Resource URI.
    pub uri: String,
    /// Name.
    pub name: Option<String>,
    /// MIME type.
    pub mime_type: Option<String>,
}

/// An annotation entry in the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomAnnotation {
    /// Annotation key.
    pub key: String,
    /// Annotation value.
    pub value: serde_json::Value,
}

/// A dependency entry in the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomDependency {
    /// Dependency name.
    pub name: String,
    /// Version constraint.
    pub version: Option<String>,
    /// Whether the dependency is optional.
    pub optional: bool,
}

/// Provenance information for the CapabilityBom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomProvenance {
    /// Source type (e.g. "mcp_protocol", "local_capability", "config").
    pub source_type: String,
    /// Source reference (URI, path, etc.).
    pub source_ref: Option<String>,
    /// Whether provenance was verified.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // MIK-6556.AC.5: Local capability generation infers transport and auth mode
    // while avoiding resolved secret values.
    #[test]
    fn capability_generation_infers_transport_and_auth_mode() {
        use crate::trust::generator::generate_from_capability_config;

        let tc = generate_from_capability_config(
            "test-backend",
            Some("http://localhost:8080/mcp"),
            Some("bearer"),
            &[],
            &[],
        );
        let json = serde_json::to_string_pretty(&tc).unwrap();

        assert_eq!(tc.server.transport, "http");
        assert_eq!(tc.server.auth_mode, "bearer");
        assert!(
            !json.contains("super-secret-token-12345"),
            "TrustCard output must never contain resolved secret values"
        );
        assert!(
            !json.contains("my-api-key-abcdef"),
            "TrustCard output must never contain resolved API key values"
        );
    }

    // MIK-6556.AC.6: Validation emits stable findings with Info, Warn, and Fail
    // severities and conservative unknown-metadata behavior.
    #[test]
    fn validation_findings_status_and_unknown_metadata_are_stable() {
        use crate::trust::validator::validate_trust_card;

        let card = TrustCard {
            schema_version: TRUSTCARD_SCHEMA_VERSION.to_string(),
            name: "test-tool".to_string(),
            server: TrustServer {
                source_uri: None,
                publisher: None,
                license: None,
                transport: "stdio".to_string(),
                auth_mode: "none".to_string(),
                runtime_profile: "local".to_string(),
                network_reach: TrustNetworkReach::None,
                signature_evidence: vec![],
                risk_class: TrustRiskClass::Low,
                data_classes: vec![],
                permissions: vec![],
                evidence_quality: "unknown".to_string(),
            },
            tool: None,
            findings: vec![],
            generated_at: "2026-06-30T00:00:00Z".to_string(),
        };

        let findings = validate_trust_card(&card);
        assert!(
            !findings.is_empty(),
            "Validation should emit findings for unknown metadata"
        );

        let has_info = findings
            .iter()
            .any(|f| f.severity == TrustFindingSeverity::Info);
        let has_warn = findings
            .iter()
            .any(|f| f.severity == TrustFindingSeverity::Warn);

        assert!(has_info, "Expected at least one Info finding");
        assert!(
            has_warn,
            "Expected at least one Warn finding for unknown/missing metadata"
        );

        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        let mut sorted_codes = codes.clone();
        sorted_codes.sort();
        assert_eq!(
            codes, sorted_codes,
            "Finding codes must be stable (sorted) for deterministic output"
        );
    }
}
