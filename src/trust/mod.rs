//! `TrustCard` and CBOM metadata for MCP servers and tools.
//!
//! `TrustCard` is the human-facing summary. CBOM is the machine-readable
//! capability bill of materials used by validators, rankers, and control
//! planes. This module is advisory metadata only; enforcement consumers must
//! opt in explicitly.

pub mod lab;

use serde::{Deserialize, Serialize};

use crate::{
    capability::CapabilityDefinition,
    hashing::canonical_json_sha256,
    protocol::{Tool, ToolAnnotations},
};

mod assistant;
mod descriptor;
mod inference;

pub use assistant::{
    TrustAssistantAutomationAction, TrustAssistantAutomationStatus, TrustAssistantPrompt,
    TrustAssistantPromptKind, TrustCardAssistant, TrustCardAssistantPlan,
};
pub use descriptor::{
    TOOL_DESCRIPTOR_TRUST_CARD_KEY, ToolDescriptorTrustCard, cbom_digest_sha256,
    project_tool_descriptor_trust_card, project_tool_descriptors_trust_cards,
    tools_list_result_with_trust_cards, trust_card_digest_sha256,
};

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
                risk_class: trust_tool.risk_class,
                data_classes: trust_tool.data_classes.clone(),
                permissions: trust_tool.permissions.clone(),
                evidence: TrustEvidenceKind::Observed,
            },
            cbom: CapabilityBom {
                schema_version: CBOM_SCHEMA_VERSION.to_string(),
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

    fn into_component(self, server_name: &str) -> CbomComponent {
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
    /// Components in the bill of materials.
    #[serde(default)]
    pub components: Vec<CbomComponent>,
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

/// CBOM component kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CbomComponentKind {
    /// Server component.
    Server,
    /// Tool component.
    Tool,
    /// Prompt component.
    Prompt,
    /// Resource component.
    Resource,
    /// Runtime component.
    Runtime,
    /// Dependency component.
    Dependency,
}

/// Evidence quality for a `TrustCard` field.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvidenceKind {
    /// Declared by a trusted source.
    Declared,
    /// Inferred from local metadata.
    Inferred,
    /// Observed from a live protocol response.
    Observed,
    /// Missing or unknown.
    Missing,
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

#[cfg(test)]
mod tests;
