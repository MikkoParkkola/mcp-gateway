// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustCard` and CBOM metadata for MCP servers and tools.
//!
//! `TrustCard` is the human-facing summary. CBOM is the machine-readable
//! capability bill of materials used by validators, rankers, and control
//! planes. This module is advisory metadata only; enforcement consumers must
//! opt in explicitly.

pub mod generator;
pub mod lab;
pub mod schema;

use serde::{Deserialize, Serialize};

use crate::{
    capability::CapabilityDefinition,
    hashing::canonical_json_sha256,
    protocol::{Tool, ToolAnnotations},
};

mod assistant;
pub mod claim_capture;
mod descriptor;
mod inference;
mod kinds;
pub mod provenance_eval;
pub mod result_extractor;
mod result_provenance;
mod schema_bounds;
mod validator;
pub use assistant::{
    TrustAssistantAutomationAction, TrustAssistantAutomationStatus, TrustAssistantPrompt,
    TrustAssistantPromptKind, TrustCardAssistant, TrustCardAssistantPlan,
};
pub use claim_capture::{ClaimCaptureSink, ClientClaim, derive_claim};
pub use descriptor::{
    TOOL_DESCRIPTOR_TRUST_CARD_KEY, ToolDescriptorTrustCard, cbom_digest_sha256,
    project_tool_descriptor_trust_card, project_tool_descriptors_trust_cards,
    tools_list_result_with_trust_cards, trust_card_digest_sha256,
};
#[cfg(test)]
pub(crate) use descriptor::memo_counters;
pub use kinds::{CbomComponentKind, CbomSubjectKind, TrustEvidenceKind};
pub use result_extractor::extract_row_count;
pub use result_provenance::{CacheOutcome, RuntimeProvenanceReceipt, SignedResultProvenance};
pub(crate) use schema_bounds::closed_keys;
pub use schema_bounds::{SchemaBounds, unresolved_refs};

use inference::{
    infer_data_classes, infer_permissions, infer_risk_class, source_uri_from_capability,
    transport_from_capability,
};

/// Stable `TrustCard` schema version.
pub const TRUST_CARD_SCHEMA_VERSION: &str = "trust_card.v1";

/// Stable CBOM schema version.
pub const CBOM_SCHEMA_VERSION: &str = "cbom.v1";

/// Stable `TrustCard` assistant schema version.
pub const TRUST_CARD_ASSISTANT_SCHEMA_VERSION: &str = "trust_card_assistant.v1";

/// Human-facing trust summary plus machine CBOM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustCard {
    /// Schema version.
    pub schema_version: String,
    /// Server-level trust metadata.
    pub server: TrustServer,
    /// Capability bill of materials.
    pub cbom: CapabilityBom,
    /// Current evaluation status.
    pub evaluation_status: TrustEvaluationStatus,
    /// Validation findings.
    #[serde(default)]
    pub findings: Vec<TrustFinding>,
}

impl TrustCard {
    /// Build a minimal card from a protocol tool.
    #[must_use]
    pub fn from_tool(server_name: impl Into<String>, tool: &Tool) -> Self {
        let server_name = server_name.into();
        let trust_tool = TrustTool::from_tool(tool);
        let cbom_tool = CbomTool::from_trust_tool(&trust_tool);
        let cbom_annotation = CbomAnnotation::from_trust_tool(&trust_tool);
        let provenance = CbomProvenance::observed(
            CbomSubjectKind::Tool,
            trust_tool.name.clone(),
            "protocol.tools/list",
        );
        Self {
            schema_version: TRUST_CARD_SCHEMA_VERSION.to_string(),
            server: TrustServer {
                name: server_name.clone(),
                publisher: None,
                version: None,
                license: None,
                source_uri: None,
                transport: TrustTransport::Unknown,
                auth_mode: TrustAuthMode::Unknown,
                runtime_profile: None,
                network_reach: Vec::new(),
                signature_evidence: Vec::new(),
                risk_class: trust_tool.risk_class,
                data_classes: trust_tool.data_classes.clone(),
                permissions: trust_tool.permissions.clone(),
                evidence: TrustEvidenceKind::Observed,
            },
            cbom: CapabilityBom {
                schema_version: CBOM_SCHEMA_VERSION.to_string(),
                tools: vec![cbom_tool],
                prompts: Vec::new(),
                resources: Vec::new(),
                annotations: vec![cbom_annotation],
                dependencies: Vec::new(),
                provenance: vec![provenance],
                components: vec![trust_tool.into_component(&server_name)],
            },
            evaluation_status: TrustEvaluationStatus::NotEvaluated,
            findings: Vec::new(),
        }
    }

    /// Build a card from a local capability definition.
    #[must_use]
    pub fn from_capability(capability: &CapabilityDefinition) -> Self {
        let tool = capability.to_mcp_tool();
        let mut card = Self::from_tool(capability.name.clone(), &tool);
        card.server.version = Some(capability.fulcrum.clone());
        card.server.transport = transport_from_capability(capability);
        card.server.auth_mode = TrustAuthMode::from_capability(capability);
        card.server.source_uri = source_uri_from_capability(capability);
        card.server.evidence = TrustEvidenceKind::Inferred;
        if let Some(source_uri) = card.server.source_uri.clone() {
            for tool in &mut card.cbom.tools {
                tool.source_uri = Some(source_uri.clone());
            }
            for component in &mut card.cbom.components {
                component.source_uri = Some(source_uri.clone());
            }
            card.cbom.provenance.push(CbomProvenance::inferred(
                CbomSubjectKind::Server,
                capability.name.clone(),
                source_uri,
            ));
        }
        card.cbom.dependencies.push(CbomDependency {
            name: capability.name.clone(),
            version: Some(capability.fulcrum.clone()),
            source_uri: card.server.source_uri.clone(),
            digest_sha256: None,
            license: None,
            evidence: TrustEvidenceKind::Inferred,
        });
        card
    }

    /// Return a copy with findings and evaluation status populated.
    #[must_use]
    pub fn with_validation(mut self) -> Self {
        let report = TrustCardValidator::validate(&self);
        self.evaluation_status = report.status;
        self.findings = report.findings;
        self
    }
}

/// Server-level `TrustCard` metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustServer {
    /// Server name.
    pub name: String,
    /// Publisher or maintainer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SPDX-style license expression when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Source, package, or homepage URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Transport mode.
    pub transport: TrustTransport,
    /// Authentication mode.
    pub auth_mode: TrustAuthMode,
    /// Runtime profile identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_profile: Option<String>,
    /// Network targets the server may contact.
    #[serde(default)]
    pub network_reach: Vec<TrustNetworkReach>,
    /// Signature or provenance verification evidence.
    #[serde(default)]
    pub signature_evidence: Vec<TrustSignatureEvidence>,
    /// Coarse risk classification.
    pub risk_class: TrustRiskClass,
    /// Data classes the server may touch.
    #[serde(default)]
    pub data_classes: Vec<TrustDataClass>,
    /// Permissions inferred or declared for the server.
    #[serde(default)]
    pub permissions: Vec<TrustPermission>,
    /// Evidence quality for this metadata.
    pub evidence: TrustEvidenceKind,
}

/// One surfaced tool in a `TrustCard`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustTool {
    /// Tool name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 of canonical input schema JSON.
    pub input_schema_sha256: String,
    /// SHA-256 of canonical output schema JSON, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_sha256: Option<String>,
    /// MCP behavior annotations projected into `TrustCard` form.
    pub annotations: TrustToolAnnotations,
    /// Inferred permissions.
    #[serde(default)]
    pub permissions: Vec<TrustPermission>,
    /// Inferred data classes.
    #[serde(default)]
    pub data_classes: Vec<TrustDataClass>,
    /// Coarse risk classification.
    pub risk_class: TrustRiskClass,
    /// Evidence quality for this metadata.
    pub evidence: TrustEvidenceKind,
}

impl TrustTool {
    /// Build `TrustTool` metadata from a protocol tool.
    #[must_use]
    pub fn from_tool(tool: &Tool) -> Self {
        let annotations = TrustToolAnnotations::from(tool.annotations.as_ref());
        let permissions = infer_permissions(tool, &annotations);
        let data_classes = infer_data_classes(tool);
        let risk_class = infer_risk_class(&permissions, &data_classes, &annotations);

        Self {
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema_sha256: canonical_json_sha256(&tool.input_schema),
            output_schema_sha256: tool.output_schema.as_ref().map(canonical_json_sha256),
            annotations,
            permissions,
            data_classes,
            risk_class,
            evidence: TrustEvidenceKind::Observed,
        }
    }

    pub(super) fn into_component(self, server_name: &str) -> CbomComponent {
        CbomComponent {
            name: format!("{server_name}:{}", self.name),
            kind: CbomComponentKind::Tool,
            version: None,
            source_uri: None,
            digest_sha256: Some(self.input_schema_sha256),
            license: None,
            permissions: self.permissions,
            data_classes: self.data_classes,
            evidence: self.evidence,
        }
    }
}

/// MCP behavior annotations captured for `TrustCard`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustToolAnnotations {
    /// Read-only hint.
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Destructive-action hint.
    #[serde(default)]
    pub destructive: Option<bool>,
    /// Open-world hint.
    #[serde(default)]
    pub open_world: Option<bool>,
}

impl From<Option<&ToolAnnotations>> for TrustToolAnnotations {
    fn from(value: Option<&ToolAnnotations>) -> Self {
        value.map_or_else(Self::default, |annotations| Self {
            read_only: annotations.read_only_hint,
            destructive: annotations.destructive_hint,
            open_world: annotations.open_world_hint,
        })
    }
}

/// Capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityBom {
    /// Schema version.
    pub schema_version: String,
    /// Tool entries with schema digests and inferred policy surfaces.
    #[serde(default)]
    pub tools: Vec<CbomTool>,
    /// Prompt entries with schema or content digests when known.
    #[serde(default)]
    pub prompts: Vec<CbomPrompt>,
    /// Resource entries with URI and digest metadata when known.
    #[serde(default)]
    pub resources: Vec<CbomResource>,
    /// Annotation records captured from protocol descriptors.
    #[serde(default)]
    pub annotations: Vec<CbomAnnotation>,
    /// Package, runtime, or source dependencies.
    #[serde(default)]
    pub dependencies: Vec<CbomDependency>,
    /// Provenance records for how CBOM fields were declared, observed, or inferred.
    #[serde(default)]
    pub provenance: Vec<CbomProvenance>,
    /// Components in the bill of materials.
    #[serde(default)]
    pub components: Vec<CbomComponent>,
}

/// One tool entry in a capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomTool {
    /// Tool name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional source URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Optional SPDX-style license expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// SHA-256 digest of the canonical input schema JSON.
    pub input_schema_sha256: String,
    /// SHA-256 digest of the canonical output schema JSON, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_sha256: Option<String>,
    /// Inferred permissions.
    #[serde(default)]
    pub permissions: Vec<TrustPermission>,
    /// Inferred data classes.
    #[serde(default)]
    pub data_classes: Vec<TrustDataClass>,
    /// Coarse risk classification.
    pub risk_class: TrustRiskClass,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

impl CbomTool {
    pub(super) fn from_trust_tool(tool: &TrustTool) -> Self {
        Self {
            name: tool.name.clone(),
            description: tool.description.clone(),
            source_uri: None,
            license: None,
            input_schema_sha256: tool.input_schema_sha256.clone(),
            output_schema_sha256: tool.output_schema_sha256.clone(),
            permissions: tool.permissions.clone(),
            data_classes: tool.data_classes.clone(),
            risk_class: tool.risk_class,
            evidence: tool.evidence,
        }
    }
}

/// One prompt entry in a capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomPrompt {
    /// Prompt name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional digest for the prompt definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// One resource entry in a capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomResource {
    /// Resource URI or URI template.
    pub uri: String,
    /// Optional name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional digest for the resource descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// Protocol annotation evidence attached to a CBOM subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomAnnotation {
    /// Subject kind.
    pub subject_kind: CbomSubjectKind,
    /// Subject name.
    pub subject_name: String,
    /// Captured tool annotations.
    pub annotations: TrustToolAnnotations,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

impl CbomAnnotation {
    pub(super) fn from_trust_tool(tool: &TrustTool) -> Self {
        Self {
            subject_kind: CbomSubjectKind::Tool,
            subject_name: tool.name.clone(),
            annotations: tool.annotations.clone(),
            evidence: tool.evidence,
        }
    }
}

/// Dependency evidence attached to a capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomDependency {
    /// Dependency name.
    pub name: String,
    /// Optional version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional source URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Optional digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    /// Optional SPDX-style license expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// Provenance evidence attached to a capability bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomProvenance {
    /// Subject kind.
    pub subject_kind: CbomSubjectKind,
    /// Subject name.
    pub subject_name: String,
    /// Source URI or source label.
    pub source_uri: String,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

impl CbomProvenance {
    pub(super) fn observed(
        subject_kind: CbomSubjectKind,
        subject_name: impl Into<String>,
        source_uri: impl Into<String>,
    ) -> Self {
        Self {
            subject_kind,
            subject_name: subject_name.into(),
            source_uri: source_uri.into(),
            evidence: TrustEvidenceKind::Observed,
        }
    }

    pub(super) fn inferred(
        subject_kind: CbomSubjectKind,
        subject_name: impl Into<String>,
        source_uri: impl Into<String>,
    ) -> Self {
        Self {
            subject_kind,
            subject_name: subject_name.into(),
            source_uri: source_uri.into(),
            evidence: TrustEvidenceKind::Inferred,
        }
    }
}

/// One CBOM component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomComponent {
    /// Component name.
    pub name: String,
    /// Component kind.
    pub kind: CbomComponentKind,
    /// Optional version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional source URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Optional SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    /// Optional license.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Permissions.
    #[serde(default)]
    pub permissions: Vec<TrustPermission>,
    /// Data classes.
    #[serde(default)]
    pub data_classes: Vec<TrustDataClass>,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// Network target evidence for a server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustNetworkReach {
    /// Target URL, host, or service label.
    pub target: String,
    /// Optional protocol or transport hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// Signature verification status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustSignatureStatus {
    /// Signature or provenance was verified.
    Verified,
    /// Signature or provenance is missing.
    Missing,
    /// Signature or provenance verification failed.
    Failed,
    /// Signature status is unknown.
    Unknown,
}

/// Signature or provenance evidence attached to a server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustSignatureEvidence {
    /// Evidence subject.
    pub subject: String,
    /// Evidence kind, such as `capability_sha256`.
    pub kind: String,
    /// Verification status.
    pub status: TrustSignatureStatus,
    /// Evidence quality.
    pub evidence: TrustEvidenceKind,
}

/// Coarse risk class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustRiskClass {
    /// Risk is unknown.
    Unknown,
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

/// Data class touched by a server or tool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustDataClass {
    /// Public data.
    Public,
    /// Internal workspace data.
    Internal,
    /// Personal data.
    Personal,
    /// Financial data.
    Financial,
    /// Health data.
    Health,
    /// Source code or development metadata.
    SourceCode,
    /// Host or system access.
    SystemAccess,
    /// Unknown data class.
    Unknown,
}

/// Permission class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustPermission {
    /// Read operation.
    Read,
    /// Write operation.
    Write,
    /// Execute operation.
    Execute,
    /// Network operation.
    Network,
    /// Filesystem operation.
    Filesystem,
    /// Browser operation.
    Browser,
    /// Database operation.
    Database,
    /// Messaging operation.
    Messaging,
    /// Payment operation.
    Payment,
    /// Unknown permission.
    Unknown,
}

/// Transport mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTransport {
    /// Stdio transport.
    Stdio,
    /// HTTP transport.
    Http,
    /// Server-sent events.
    Sse,
    /// WebSocket transport.
    WebSocket,
    /// Agent-to-agent transport.
    A2a,
    /// Unknown transport.
    Unknown,
}

/// Authentication mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustAuthMode {
    /// No authentication.
    None,
    /// Key-based access.
    Key,
    /// OAuth access.
    OAuth,
    /// Bearer-style access.
    Bearer,
    /// Basic access.
    Basic,
    /// Header-based access.
    Header,
    /// Unknown authentication mode.
    Unknown,
}

impl TrustAuthMode {
    fn from_capability(capability: &CapabilityDefinition) -> Self {
        if !capability.auth.required {
            return Self::None;
        }
        match capability.auth.auth_type.as_str() {
            "oauth" => Self::OAuth,
            "api_key" => Self::Key,
            "bearer" => Self::Bearer,
            "basic" => Self::Basic,
            "header" => Self::Header,
            "" | "none" => Self::None,
            _ => Self::Unknown,
        }
    }
}

/// Evaluation status after validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvaluationStatus {
    /// Not evaluated yet.
    NotEvaluated,
    /// No findings.
    Passed,
    /// Warning findings exist.
    Warning,
    /// Failing findings exist.
    Failed,
}

/// Trust validation severity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustFindingSeverity {
    /// Blocking finding.
    Fail,
    /// Non-blocking warning.
    Warn,
    /// Informational finding.
    Info,
}

/// One `TrustCard` validation finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustFinding {
    /// Stable finding code.
    pub code: String,
    /// Finding severity.
    pub severity: TrustFindingSeverity,
    /// Field path.
    pub field: String,
    /// Human-readable message.
    pub message: String,
    /// Suggested remediation.
    pub remediation: String,
    /// Evidence kind.
    pub evidence: TrustEvidenceKind,
}

/// Trust validation report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustValidationReport {
    /// Evaluation status.
    pub status: TrustEvaluationStatus,
    /// Findings.
    pub findings: Vec<TrustFinding>,
}

/// `TrustCard` validator.
pub struct TrustCardValidator;

#[cfg(test)]
mod tests;
