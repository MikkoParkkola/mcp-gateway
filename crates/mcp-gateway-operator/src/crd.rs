// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Custom Resource Definitions for the mcp-gateway operator.
//!
//! Defines the Rust types for Gateway, MCPServer, Policy, TrustCardReference,
//! and RuntimeProfile CRDs.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Condition type constants for status conditions.
pub mod condition_type {
    pub const READY: &str = "Ready";
    pub const DRIFT_DETECTED: &str = "DriftDetected";
    pub const POLICY_ACCEPTED: &str = "PolicyAccepted";
    pub const POLICY_VIOLATION: &str = "PolicyViolation";
}

/// Status condition for a custom resource.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Condition {
    /// Type of condition (Ready, DriftDetected, PolicyAccepted, PolicyViolation).
    #[serde(rename = "type")]
    pub condition_type: String,
    /// Status of the condition: True, False, or Unknown.
    pub status: String,
    /// Machine-readable reason for the condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Last time the condition transitioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<DateTime<Utc>>,
}

/// Common status shared by all CRDs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CommonStatus {
    /// List of status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// The generation observed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Gateway custom resource — the top-level gateway deployment.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcp-gateway.io",
    version = "v1",
    kind = "Gateway",
    namespaced,
    status = "CommonStatus",
    shortname = "gw"
)]
pub struct GatewaySpec {
    /// Container image for the gateway.
    pub image: String,
    /// Number of replicas (default 1).
    #[serde(default = "default_replicas")]
    pub replicas: i32,
    /// Gateway configuration (YAML).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Resource requests and limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// Pod security context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    /// Service account name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    /// Network policy configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicySpec>,
    /// Health probes configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<ProbesSpec>,
    /// ServiceMonitor configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_monitor: Option<ServiceMonitorSpec>,
    /// PodDisruptionBudget configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_disruption_budget: Option<PodDisruptionBudgetSpec>,
    /// Rolling update strategy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateSpec>,
}

fn default_replicas() -> i32 {
    1
}

/// MCPServer custom resource — an MCP backend server.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcp-gateway.io",
    version = "v1",
    kind = "MCPServer",
    namespaced,
    status = "CommonStatus",
    shortname = "mcps"
)]
pub struct MCPServerSpec {
    /// Transport type: stdio, sse, or streamable-http.
    pub transport: String,
    /// Command for stdio transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Arguments for stdio transport.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// URL for HTTP-based transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// HTTP headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// Connection timeout.
    #[serde(default = "default_timeout")]
    pub timeout: String,
    /// Reference to the owning Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ref: Option<ObjectReference>,
}

fn default_timeout() -> String {
    "30s".into()
}

/// Policy custom resource — access control policy.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcp-gateway.io",
    version = "v1",
    kind = "Policy",
    namespaced,
    status = "CommonStatus",
    shortname = "pol"
)]
pub struct PolicySpec {
    /// Policy rules.
    pub rules: Vec<PolicyRule>,
    /// Reference to the owning Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ref: Option<ObjectReference>,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyRule {
    /// Rule name.
    pub name: String,
    /// Rule description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Action: allow, deny, or audit.
    pub action: String,
    /// Match criteria.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<PolicyMatch>,
    /// Additional conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<serde_json::Value>,
}

/// Match criteria for a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

/// TrustCardReference custom resource — trust domain reference.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcp-gateway.io",
    version = "v1",
    kind = "TrustCardReference",
    namespaced,
    status = "CommonStatus",
    shortname = "tcr"
)]
pub struct TrustCardReferenceSpec {
    /// Trust domain identifier.
    pub trust_domain: String,
    /// Trust card content.
    pub trust_card: String,
    /// Cryptographic signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Reference to the owning Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ref: Option<ObjectReference>,
}

/// RuntimeProfile custom resource — runtime configuration.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcp-gateway.io",
    version = "v1",
    kind = "RuntimeProfile",
    namespaced,
    status = "CommonStatus",
    shortname = "rp"
)]
pub struct RuntimeProfileSpec {
    /// Runtime type: docker, kubernetes, or wasm.
    pub runtime: String,
    /// Container image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Resource requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// Environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Security context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    /// Reference to the owning Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ref: Option<ObjectReference>,
}

/// Environment variable definition with optional secret reference.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EnvVar {
    /// Variable name.
    pub name: String,
    /// Literal value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Value from a source (e.g. secretKeyRef).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from: Option<EnvVarSource>,
}

/// Source for an environment variable value.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EnvVarSource {
    /// Reference to a key in a Kubernetes Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key_ref: Option<SecretKeyRef>,
}

/// Reference to a key in a Kubernetes Secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretKeyRef {
    /// Name of the Secret.
    pub name: String,
    /// Key within the Secret.
    pub key: String,
}

/// Resource requirements.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResourceRequirements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<serde_json::Value>,
}

/// Network policy specification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NetworkPolicySpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress_rules: Vec<serde_json::Value>,
}

/// Health probes specification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbesSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<serde_json::Value>,
}

/// ServiceMonitor specification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceMonitorSpec {
    #[serde(default)]
    pub enabled: bool,
}

/// PodDisruptionBudget specification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PodDisruptionBudgetSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<i32>,
}

/// Rolling update specification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RollingUpdateSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<i32>,
}

/// Reference to another Kubernetes object.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ObjectReference {
    /// Name of the referenced object.
    pub name: String,
    /// Namespace of the referenced object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}
