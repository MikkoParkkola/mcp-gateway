//! `CapabilityDraft` — intermediate model for protocol import
//!
//! Normalizes source kind, source identity, protocol, operation name, auth
//! requirements, input/output JSON Schema, examples, safety classification,
//! review state, and TrustCard metadata for OpenAPI, GraphQL, Postman, and
//! OCI inputs before YAML generation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source kind for an imported draft capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSourceKind {
    /// Generated from an OpenAPI 3.x / Swagger 2.0 specification.
    OpenApi,
    /// Generated from a GraphQL SDL or introspection JSON schema.
    GraphQl,
    /// Generated from a Postman collection.
    Postman,
    /// Generated from an OCI MCP package manifest (`server.json`).
    OciMcpPackage,
}

impl ImportSourceKind {
    /// Human-readable label for the source kind.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ImportSourceKind::OpenApi => "openapi",
            ImportSourceKind::GraphQl => "graphql",
            ImportSourceKind::Postman => "postman",
            ImportSourceKind::OciMcpPackage => "oci-mcp-package",
        }
    }
}

/// Review state for an imported draft capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewState {
    /// Not yet reviewed — destructive / open-world tools are disabled.
    Pending,
    /// Reviewed and approved — the capability is enabled.
    Approved,
    /// Reviewed and explicitly rejected.
    Rejected,
}

impl ReviewState {
    /// Returns `true` if the draft requires review before activation.
    #[must_use]
    pub fn requires_review(&self) -> bool {
        matches!(self, ReviewState::Pending)
    }

    /// Returns `true` if the draft is approved and should be enabled.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, ReviewState::Approved)
    }
}

/// Safety classification for a draft capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyClassification {
    /// Read-only, safe to enable automatically.
    ReadOnly,
    /// Mutation — modifies data, requires review.
    Mutation,
    /// Destructive — deletes or irreversibly modifies, requires review.
    Destructive,
    /// Open-world — interacts with external services in broad ways.
    OpenWorld,
}

impl SafetyClassification {
    /// Returns `true` if this classification requires human review.
    #[must_use]
    pub fn requires_review(&self) -> bool {
        !matches!(self, SafetyClassification::ReadOnly)
    }

    /// Derive from an HTTP method and operation semantics.
    #[must_use]
    pub fn from_http_method(method: &str) -> Self {
        match method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => SafetyClassification::ReadOnly,
            "POST" | "PUT" | "PATCH" => SafetyClassification::Mutation,
            "DELETE" => SafetyClassification::Destructive,
            _ => SafetyClassification::Mutation,
        }
    }

    /// Derive from GraphQL operation type.
    #[must_use]
    pub fn from_graphql_op(op_type: &str) -> Self {
        match op_type.to_lowercase().as_str() {
            "query" => SafetyClassification::ReadOnly,
            "mutation" => SafetyClassification::Mutation,
            "subscription" => SafetyClassification::ReadOnly,
            _ => SafetyClassification::Mutation,
        }
    }
}

/// TrustCard metadata stub generated during import.
///
/// Contains the minimum information needed for a human reviewer to
/// understand and approve the imported capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCardStub {
    /// Who is responsible for reviewing this capability.
    #[serde(default)]
    pub reviewer: Option<String>,
    /// Review notes or rationale.
    #[serde(default)]
    pub notes: String,
    /// Date when the draft was generated.
    #[serde(default)]
    pub generated_at: String,
    /// Link to the source specification (URL or file path).
    #[serde(default)]
    pub source_url: String,
    /// SHA-256 hash of the source content at import time.
    #[serde(default)]
    pub source_hash: String,
    /// Risk annotations surfaced to the reviewer.
    #[serde(default)]
    pub risk_annotations: Vec<String>,
}

/// Example input/output pair for a capability draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftExample {
    /// Brief description of what this example demonstrates.
    #[serde(default)]
    pub description: String,
    /// Example input parameters.
    #[serde(default)]
    pub input: serde_json::Value,
    /// Expected output shape.
    #[serde(default)]
    pub output: serde_json::Value,
}

/// An intermediate capability draft produced by protocol importers.
///
/// Normalizes source kind, source identity, protocol, operation name, auth
/// requirements, input/output JSON Schema, examples, safety classification,
/// review state, and TrustCard metadata before YAML generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDraft {
    /// Source kind that produced this draft.
    pub source_kind: ImportSourceKind,
    /// Source identity — URL, file path, or package identifier.
    pub source_id: String,
    /// Protocol (rest, graphql, jsonrpc).
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Unique operation / capability name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Authentication requirements.
    pub auth: DraftAuth,
    /// Input JSON Schema.
    pub input_schema: serde_json::Value,
    /// Output JSON Schema.
    pub output_schema: serde_json::Value,
    /// Input/output examples.
    #[serde(default)]
    pub examples: Vec<DraftExample>,
    /// Safety classification.
    pub safety: SafetyClassification,
    /// Review state.
    #[serde(default)]
    pub review_state: ReviewState,
    /// Whether the capability is enabled (always false for destructive before review).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// TrustCard stub metadata.
    #[serde(default)]
    pub trust_card: Option<TrustCardStub>,
    /// HTTP method (for REST capabilities).
    #[serde(default)]
    pub http_method: String,
    /// Base URL for the API.
    #[serde(default)]
    pub base_url: String,
    /// URL path template.
    #[serde(default)]
    pub path: String,
    /// Request body template (for POST/PUT/PATCH).
    #[serde(default)]
    pub request_body: Option<serde_json::Value>,
    /// Additional headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Query parameters.
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    /// Whether authentication is required.
    #[serde(default)]
    pub auth_required: bool,
    /// Maximum depth (for GraphQL queries).
    #[serde(default)]
    pub max_depth: Option<u32>,
    /// Maximum complexity (for GraphQL queries).
    #[serde(default)]
    pub max_complexity: Option<u32>,
    /// OCI package arguments (for OCI MCP packages).
    #[serde(default)]
    pub oci_package_args: Vec<String>,
    /// OCI transport type (for OCI MCP packages).
    #[serde(default)]
    pub oci_transport: Option<String>,
    /// Original source tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_protocol() -> String {
    "rest".to_string()
}

fn default_enabled() -> bool {
    // Drafts are disabled by default; they become enabled after review.
    false
}

/// Authentication requirements for a draft capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftAuth {
    /// Auth type: bearer, api_key, oauth, basic, none.
    #[serde(default)]
    pub auth_type: String,
    /// Credential key reference (e.g. `env:MYAPI_TOKEN`).
    #[serde(default)]
    pub key: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// HTTP header name for the credential.
    #[serde(default)]
    pub header: Option<String>,
    /// Query parameter name for the credential.
    #[serde(default)]
    pub query_param: Option<String>,
    /// Header prefix (e.g. Bearer).
    #[serde(default)]
    pub prefix: Option<String>,
}

impl Default for DraftAuth {
    fn default() -> Self {
        Self {
            auth_type: "none".to_string(),
            key: String::new(),
            description: String::new(),
            header: None,
            query_param: None,
            prefix: None,
        }
    }
}

impl CapabilityDraft {
    /// Returns `true` if this draft requires human review before activation.
    #[must_use]
    pub fn review_required(&self) -> bool {
        self.review_state.requires_review() || self.safety.requires_review()
    }

    /// Returns `true` if this draft should be visible in `tools/list`.
    #[must_use]
    pub fn is_visible(&self) -> bool {
        self.enabled && !self.review_required()
    }

    /// Derive the file name for this draft's YAML output.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.yaml", self.name)
    }

    /// Derive the TrustCard file name for this draft.
    #[must_use]
    pub fn trust_card_file_name(&self) -> String {
        format!("{}.trustcard.md", self.name)
    }

    /// Derive the example file name for this draft.
    #[must_use]
    pub fn example_file_name(&self) -> String {
        format!("{}.examples.json", self.name)
    }

    /// Derive the test file name for this draft.
    #[must_use]
    pub fn test_file_name(&self) -> String {
        format!("{}_test.rs", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_source_kind_variants() {
        // AC.1: ImportSourceKind has all four variants
        assert_eq!(ImportSourceKind::OpenApi.as_str(), "openapi");
        assert_eq!(ImportSourceKind::GraphQl.as_str(), "graphql");
        assert_eq!(ImportSourceKind::Postman.as_str(), "postman");
        assert_eq!(ImportSourceKind::OciMcpPackage.as_str(), "oci-mcp-package");
    }

    #[test]
    fn safety_classification_from_http_method() {
        assert_eq!(
            SafetyClassification::from_http_method("GET"),
            SafetyClassification::ReadOnly
        );
        assert_eq!(
            SafetyClassification::from_http_method("POST"),
            SafetyClassification::Mutation
        );
        assert_eq!(
            SafetyClassification::from_http_method("PUT"),
            SafetyClassification::Mutation
        );
        assert_eq!(
            SafetyClassification::from_http_method("DELETE"),
            SafetyClassification::Destructive
        );
    }

    #[test]
    fn safety_requires_review() {
        assert!(!SafetyClassification::ReadOnly.requires_review());
        assert!(SafetyClassification::Mutation.requires_review());
        assert!(SafetyClassification::Destructive.requires_review());
        assert!(SafetyClassification::OpenWorld.requires_review());
    }

    #[test]
    fn draft_review_required() {
        let draft = CapabilityDraft {
            source_kind: ImportSourceKind::OpenApi,
            source_id: "test".into(),
            name: "test".into(),
            description: "test".into(),
            safety: SafetyClassification::Destructive,
            review_state: ReviewState::Pending,
            enabled: false,
            ..Default::default()
        };
        assert!(draft.review_required());
        assert!(!draft.is_visible());
    }

    #[test]
    fn draft_approved_read_only_is_visible() {
        let draft = CapabilityDraft {
            source_kind: ImportSourceKind::OpenApi,
            source_id: "test".into(),
            name: "test".into(),
            description: "test".into(),
            safety: SafetyClassification::ReadOnly,
            review_state: ReviewState::Approved,
            enabled: true,
            ..Default::default()
        };
        assert!(!draft.review_required());
        assert!(draft.is_visible());
    }

    #[test]
    fn draft_file_names_are_deterministic() {
        let draft = CapabilityDraft {
            source_kind: ImportSourceKind::Postman,
            source_id: "test".into(),
            name: "my_capability".into(),
            description: "test".into(),
            ..Default::default()
        };
        assert_eq!(draft.file_name(), "my_capability.yaml");
        assert_eq!(draft.trust_card_file_name(), "my_capability.trustcard.md");
        assert_eq!(draft.example_file_name(), "my_capability.examples.json");
        assert_eq!(draft.test_file_name(), "my_capability_test.rs");
    }
}

impl Default for CapabilityDraft {
    fn default() -> Self {
        Self {
            source_kind: ImportSourceKind::OpenApi,
            source_id: String::new(),
            protocol: default_protocol(),
            name: String::new(),
            description: String::new(),
            auth: DraftAuth::default(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            examples: Vec::new(),
            safety: SafetyClassification::ReadOnly,
            review_state: ReviewState::Pending,
            enabled: false,
            trust_card: None,
            http_method: String::new(),
            base_url: String::new(),
            path: String::new(),
            request_body: None,
            headers: HashMap::new(),
            query_params: HashMap::new(),
            auth_required: false,
            max_depth: None,
            max_complexity: None,
            oci_package_args: Vec::new(),
            oci_transport: None,
            tags: Vec::new(),
        }
    }
}
