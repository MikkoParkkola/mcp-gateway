// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — mcp-gateway Kubernetes Operator
//
// Reconcile controller for Gateway, MCPServer, Policy, TrustCardReference,
// and RuntimeProfile custom resources.

pub mod gateway;
pub mod mcpserver;
pub mod policy;
pub mod trustcardreference;
pub mod runtimeprofile;
pub mod status;

use std::collections::BTreeMap;

/// Condition types reported in status.conditions for all CRDs.
pub const CONDITION_READY: &str = "Ready";
pub const CONDITION_DRIFT_DETECTED: &str = "DriftDetected";
pub const CONDITION_POLICY_ACCEPTED: &str = "PolicyAccepted";
pub const CONDITION_POLICY_VIOLATION: &str = "PolicyViolation";

/// Resource kinds watched by the operator.
pub const KIND_GATEWAY: &str = "Gateway";
pub const KIND_MCPSERVER: &str = "MCPServer";
pub const KIND_POLICY: &str = "Policy";
pub const KIND_TRUSTCARDREFERENCE: &str = "TrustCardReference";
pub const KIND_RUNTIMEPROFILE: &str = "RuntimeProfile";

/// Represents an owner reference injected into every child resource
/// (Deployment, Service, ConfigMap, NetworkPolicy, ServiceAccount, RBAC)
/// so that Kubernetes garbage-collects them when the parent CR is deleted.
#[derive(Debug, Clone)]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

impl OwnerReference {
    /// Build ownerReferences block for a child resource owned by the given CR.
    pub fn for_resource(api_version: &str, kind: &str, name: &str, uid: &str) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
            controller: true,
        }
    }

    /// Serialize to the Kubernetes ownerReferences format.
    pub fn to_map(&self) -> BTreeMap<String, serde_json::Value> {
        let mut m = BTreeMap::new();
        m.insert("apiVersion".into(), serde_json::Value::String(self.api_version.clone()));
        m.insert("kind".into(), serde_json::Value::String(self.kind.clone()));
        m.insert("name".into(), serde_json::Value::String(self.name.clone()));
        m.insert("uid".into(), serde_json::Value::String(self.uid.clone()));
        m.insert("controller".into(), serde_json::Value::Bool(self.controller));
        m.insert("blockOwnerDeletion".into(), serde_json::Value::Bool(true));
        m
    }
}

/// ReconcileAction describes what the controller intends to do for a given CR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    CreateDeployment { name: String, replicas: u32 },
    UpdateDeployment { name: String, replicas: u32 },
    CreateService { name: String, port: u16 },
    UpdateService { name: String, port: u16 },
    CreateConfigMap { name: String },
    UpdateConfigMap { name: String },
    CreateNetworkPolicy { name: String },
    UpdateNetworkPolicy { name: String },
    CreateServiceAccount { name: String },
    CreateRoleBinding { name: String },
    UpdateStatusCondition {
        cr_name: String,
        condition_type: String,
        status: String,
        reason: String,
    },
    NoOp { reason: String },
}

/// ReconcileResult is returned after a single reconciliation pass.
#[derive(Debug, Clone)]
pub struct ReconcileResult {
    pub actions: Vec<ReconcileAction>,
    pub observed_generation: i64,
    pub conditions: Vec<StatusCondition>,
}

/// A status condition entry for a CR's status.conditions array.
#[derive(Debug, Clone)]
pub struct StatusCondition {
    pub condition_type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
}

impl StatusCondition {
    pub fn ready(reason: &str, message: &str) -> Self {
        Self {
            condition_type: CONDITION_READY.into(),
            status: "True".into(),
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn not_ready(reason: &str, message: &str) -> Self {
        Self {
            condition_type: CONDITION_READY.into(),
            status: "False".into(),
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn drift_detected(reason: &str, message: &str) -> Self {
        Self {
            condition_type: CONDITION_DRIFT_DETECTED.into(),
            status: "True".into(),
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn policy_accepted(reason: &str, message: &str) -> Self {
        Self {
            condition_type: CONDITION_POLICY_ACCEPTED.into(),
            status: "True".into(),
            reason: reason.into(),
            message: message.into(),
        }
    }

    pub fn policy_violation(reason: &str, message: &str) -> Self {
        Self {
            condition_type: CONDITION_POLICY_VIOLATION.into(),
            status: "True".into(),
            reason: reason.into(),
            message: message.into(),
        }
    }
}

/// ReconcileContext holds cluster state observed during a single reconcile pass.
/// Secrets are referenced by name only — never copied into this struct.
#[derive(Debug, Clone)]
pub struct ReconcileContext {
    pub namespace: String,
    pub cr_name: String,
    pub cr_uid: String,
    pub cr_generation: i64,
    pub secret_refs: Vec<SecretRef>,
    pub desired_replicas: u32,
    pub config_hash: String,
}

/// A reference to a Kubernetes Secret. The operator never reads the secret
/// value — it only records the name/key so that the Deployment can mount it
/// via secretKeyRef at runtime.
#[derive(Debug, Clone)]
pub struct SecretRef {
    pub name: String,
    pub key: String,
    pub env_var: String,
}
