use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TRUST_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustCard {
    pub schema_version: String,
    pub subject: TrustSubject,
    pub source: SourceInfo,
    pub owner: OwnerInfo,
    pub license: LicenseInfo,
    pub transport: TransportInfo,
    pub runtime: RuntimeInfo,
    pub permissions: Vec<CapabilityPermission>,
    pub data_classes: Vec<DataClass>,
    pub credential_needs: Vec<CredentialNeed>,
    pub network_reach: NetworkReach,
    pub signature: Option<SignatureEvidence>,
    pub provenance: Option<ProvenanceEvidence>,
    pub risk_verdict: RiskVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustSubject {
    pub name: String,
    pub kind: String,
    pub version: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInfo {
    pub origin: String,
    pub registry: Option<String>,
    pub config_path: Option<String>,
    pub manual_override: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerInfo {
    pub name: Option<String>,
    pub contact: Option<String>,
    pub homepage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseInfo {
    pub spdx: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportInfo {
    pub protocol: String,
    pub url: Option<String>,
    pub command: Option<String>,
    pub env_var_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub language: Option<String>,
    pub runtime: Option<String>,
    pub container_image: Option<String>,
    pub package_manager: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityPermission {
    pub name: String,
    pub description: Option<String>,
    pub read_only: Option<bool>,
    pub destructive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataClass {
    pub name: String,
    pub description: Option<String>,
    pub sensitivity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialNeed {
    pub name: String,
    pub required: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkReach {
    pub domains: Vec<String>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEvidence {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceEvidence {
    pub issuer: Option<String>,
    pub issued_at: Option<String>,
    pub subject: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskVerdict {
    pub level: String,
    pub findings: Vec<TrustFinding>,
    pub policy_allows: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustPolicy {
    pub schema_version: String,
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cbom {
    pub schema_version: String,
    pub subject: TrustSubject,
    pub tools: Vec<CbomTool>,
    pub prompts: Vec<CbomPrompt>,
    pub resources: Vec<CbomResource>,
    pub annotations: BTreeMap<String, Value>,
    pub dependencies: Vec<CbomDependency>,
    pub permissions: Vec<CapabilityPermission>,
    pub provenance: Option<ProvenanceEvidence>,
    pub signature: Option<SignatureEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomTool {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub annotations: Option<Value>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomPrompt {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub arguments: Vec<CbomPromptArgument>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomPromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomResource {
    pub uri: String,
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbomDependency {
    pub name: String,
    pub version: Option<String>,
    pub kind: String,
    pub url: Option<String>,
}
