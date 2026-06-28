//! Safe protocol import planning for external API and MCP package sources.
//!
//! This module does not activate imported tools. It produces deterministic,
//! disabled capability drafts with TrustCard-oriented provenance, policy
//! defaults, and human review gates for the decisions automation cannot infer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod helpers;
mod planner;

pub use planner::ProtocolImportPlanner;

use helpers::empty_object_schema;

/// External source format handled by the protocol import planner.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportSourceKind {
    /// `OpenAPI` 3.x or Swagger 2.0 API description.
    OpenApi,
    /// GraphQL operation or introspection-derived description.
    Graphql,
    /// Postman collection.
    Postman,
    /// OCI-distributed MCP package.
    OciMcpPackage,
}

/// Source metadata captured for the import plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportSource {
    /// Human-readable source name.
    pub name: String,
    /// Source kind.
    pub kind: ImportSourceKind,
    /// Optional source URI or package reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Optional SPDX-style license string when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Optional provenance pointer such as a build attestation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

/// Top-level import plan returned by every planner entry point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportPlan {
    /// Source metadata.
    pub source: ImportSource,
    /// SHA-256 over the normalized import input.
    pub source_digest_sha256: String,
    /// SHA-256 over the deterministic plan projection.
    pub plan_digest_sha256: String,
    /// Disabled drafts generated from the source.
    pub drafts: Vec<CapabilityDraft>,
    /// Review gates aggregated across all drafts.
    pub review_gates: Vec<ImportReviewGate>,
    /// Safe import defaults applied to every draft.
    pub safe_defaults: ImportSafeDefaults,
    /// Whether the plan can be discarded before active routing changes.
    pub reversible: bool,
}

/// Safe defaults applied to all import plans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportSafeDefaults {
    /// Imported tools start inactive.
    pub drafts_enabled: bool,
    /// Default behavior for mutating or destructive operations.
    pub destructive_action: ReviewAction,
    /// Default behavior when auth semantics cannot be inferred safely.
    pub ambiguous_auth: ReviewAction,
    /// Default behavior for broad external network access.
    pub broad_network_egress: ReviewAction,
    /// Whether rollback metadata is required before activation.
    pub rollback_required: bool,
}

impl Default for ImportSafeDefaults {
    fn default() -> Self {
        Self {
            drafts_enabled: false,
            destructive_action: ReviewAction::Confirm,
            ambiguous_auth: ReviewAction::ManualReview,
            broad_network_egress: ReviewAction::ManualReview,
            rollback_required: true,
        }
    }
}

/// Review action used by safe import policy defaults.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    /// Allow automatically.
    Allow,
    /// Require explicit confirmation before execution.
    Confirm,
    /// Require a human review decision before activation.
    ManualReview,
    /// Deny activation.
    Deny,
}

/// One disabled capability draft generated from an imported source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityDraft {
    /// Stable draft identifier.
    pub id: String,
    /// Generated capability name.
    pub name: String,
    /// Source kind that produced this draft.
    pub source_kind: ImportSourceKind,
    /// Short title shown in preview and review UIs.
    pub title: String,
    /// Longer generated description.
    pub description: String,
    /// Safe default: generated drafts are inactive until applied and reviewed.
    pub enabled: bool,
    /// Route metadata inferred from the protocol source.
    pub route: DraftRoute,
    /// Input schema projected for the generated tool.
    pub input_schema: Value,
    /// Output schema projected for the generated tool.
    pub output_schema: Value,
    /// TrustCard-oriented provenance stub.
    pub trust_card: TrustCardDraft,
    /// Risk annotations surfaced to the user.
    pub risks: Vec<ImportRisk>,
    /// Gates that must be satisfied before activation.
    pub review_gates: Vec<ImportReviewGate>,
    /// Policy defaults attached to the draft.
    pub policy_defaults: DraftPolicyDefaults,
    /// Reversible generated YAML, when this draft originated from capability YAML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_yaml: Option<String>,
}

/// Protocol route metadata for a generated draft.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DraftRoute {
    /// Protocol adapter name such as `rest`, `graphql`, or `oci_mcp`.
    pub protocol: String,
    /// HTTP method or package invocation method when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Endpoint or package reference when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Path, GraphQL operation type, or tool reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// Minimal `TrustCard` stub generated during import preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustCardDraft {
    /// Source name.
    pub source_name: String,
    /// Source kind.
    pub source_kind: ImportSourceKind,
    /// Source digest copied from the import plan.
    pub source_digest_sha256: String,
    /// Draft-specific digest.
    pub draft_digest_sha256: String,
    /// Optional source URI or package reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Optional license metadata preserved from the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Optional provenance pointer preserved from the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Evidence quality for generated metadata.
    pub evidence: TrustEvidenceLevel,
}

/// Evidence level for generated `TrustCard` metadata.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvidenceLevel {
    /// Generated from source metadata and needs review.
    Generated,
    /// Verified by policy or package metadata.
    Verified,
}

/// Risk level for generated import annotations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportRiskLevel {
    /// Informational or low-severity risk.
    Low,
    /// Needs review but is not inherently blocking.
    Medium,
    /// Must be addressed before activation.
    High,
    /// Blocks activation until remediated.
    Critical,
}

/// Risk category attached to a generated draft.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportRiskKind {
    /// Operation can mutate or delete remote state.
    DestructiveOperation,
    /// The source did not make auth requirements unambiguous.
    AuthAmbiguity,
    /// Operation appears broad, bulk, or admin-scoped.
    BroadScope,
    /// Draft reaches an external endpoint or package source.
    ExternalNetwork,
    /// Input or output schema appears to include regulated or sensitive data.
    SensitiveDataSurface,
    /// Package provenance is missing or unverified.
    SupplyChainProvenance,
    /// License metadata is missing.
    LicenseUnknown,
    /// Query shape lacks obvious pagination or complexity bounds.
    UnboundedQuery,
}

/// One risk annotation attached to a generated draft.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportRisk {
    /// Risk kind.
    pub kind: ImportRiskKind,
    /// Risk level.
    pub level: ImportRiskLevel,
    /// Human-readable reason.
    pub reason: String,
    /// Optional field or operation that triggered the risk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Review gate category for generated drafts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportReviewGateKind {
    /// Mutating or destructive operation review.
    DestructiveAction,
    /// Auth semantics require a human decision.
    AuthDecision,
    /// Network scope requires a human decision.
    NetworkScope,
    /// License needs review.
    LicenseReview,
    /// Package provenance needs verification.
    ProvenanceVerification,
    /// Query needs bounds before activation.
    QueryBoundaries,
}

/// Review gate that blocks or constrains activation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportReviewGate {
    /// Gate kind.
    pub kind: ImportReviewGateKind,
    /// Gate severity.
    pub level: ImportRiskLevel,
    /// Human-readable reason.
    pub reason: String,
    /// True when the decision cannot be inferred from source metadata.
    pub non_inferable: bool,
    /// True when an automated resolver can close the gate.
    pub can_auto_resolve: bool,
}

/// Policy defaults attached to one capability draft.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DraftPolicyDefaults {
    /// Activation action required for this draft.
    pub activation: ReviewAction,
    /// Auth decision required for this draft.
    pub auth: ReviewAction,
    /// Network decision required for this draft.
    pub network_egress: ReviewAction,
    /// Context integrity profile applied before active routing.
    pub context_integrity_profile: String,
    /// Whether audit logging is required.
    pub audit_required: bool,
    /// Whether rollback metadata is required.
    pub rollback_required: bool,
}

/// GraphQL import specification used by the planner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphqlImportSpec {
    /// GraphQL endpoint URI.
    pub endpoint: String,
    /// Operations selected or inferred for import.
    pub operations: Vec<GraphqlOperationImport>,
}

/// One GraphQL operation selected for import.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphqlOperationImport {
    /// Operation name.
    pub name: String,
    /// Operation type.
    pub operation_type: GraphqlOperationType,
    /// Query or mutation template.
    pub query: String,
    /// Variables schema.
    #[serde(default = "empty_object_schema")]
    pub variables_schema: Value,
    /// Response schema.
    #[serde(default = "empty_object_schema")]
    pub response_schema: Value,
}

/// GraphQL operation type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphqlOperationType {
    /// Read-only query.
    Query,
    /// Mutating operation.
    Mutation,
    /// Subscription stream.
    Subscription,
}

/// OCI MCP package import metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OciMcpPackageImport {
    /// Package name.
    pub name: String,
    /// OCI image or package reference.
    pub image_ref: String,
    /// Optional package digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    /// Optional package license.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Optional provenance reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Tools exposed by the package metadata.
    pub tools: Vec<OciToolImport>,
}

/// One tool described by an OCI MCP package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OciToolImport {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Input schema.
    #[serde(default = "empty_object_schema")]
    pub input_schema: Value,
    /// Output schema.
    #[serde(default = "empty_object_schema")]
    pub output_schema: Value,
}

#[cfg(test)]
mod tests;
