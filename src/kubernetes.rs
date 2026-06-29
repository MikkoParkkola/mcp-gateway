//! Kubernetes enterprise reconciliation planning.
//!
//! This module is the typed planning contract for the enterprise Kubernetes
//! package. It does not run a controller manager; it turns reviewed custom
//! resources into deterministic reconcile actions, status conditions,
//! server-side dry-run commands, and rollback handles that a controller or
//! operator workflow can execute.

use std::collections::{BTreeMap, BTreeSet};

pub mod evidence;

pub use evidence::{
    KUBERNETES_EVIDENCE_EXPORT_SCHEMA, KubernetesEvidenceDelivery, KubernetesEvidenceExport,
    KubernetesEvidencePayload, KubernetesEvidenceRedaction, KubernetesEvidenceSink,
    KubernetesEvidenceTransport, plan_evidence_exports,
};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

/// Schema version emitted by Kubernetes reconcile plans.
pub const KUBERNETES_RECONCILE_PLAN_SCHEMA: &str = "kubernetes.reconcile_plan.v1";

/// Build a reconcile plan from a Kubernetes YAML document stream.
///
/// # Errors
///
/// Returns an error when the input is not valid YAML or when a document is
/// missing `kind` or `metadata.name`.
pub fn plan_reconciliation(
    namespace: &str,
    source: &str,
    manifest: &str,
) -> Result<KubernetesReconcilePlan, KubernetesPlanError> {
    KubernetesReconcilePlanner.plan(namespace, source, manifest)
}

/// Planner for Kubernetes enterprise custom resources.
#[derive(Debug, Default, Clone, Copy)]
pub struct KubernetesReconcilePlanner;

impl KubernetesReconcilePlanner {
    /// Build a reconcile plan from a Kubernetes YAML document stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not valid YAML or when a document is
    /// missing `kind` or `metadata.name`.
    pub fn plan(
        &self,
        namespace: &str,
        source: &str,
        manifest: &str,
    ) -> Result<KubernetesReconcilePlan, KubernetesPlanError> {
        let resources = parse_resources(manifest)?;
        let index = ResourceIndex::from_resources(&resources);
        let mut conditions = Vec::new();
        let mut actions = Vec::new();
        let mut human_gates = BTreeSet::new();

        push_required_resource_conditions(&index, &mut conditions);
        push_gateway_actions(
            namespace,
            source,
            &index,
            &mut actions,
            &mut conditions,
            &mut human_gates,
        );
        push_server_actions(&index, &mut actions, &mut conditions);
        push_status_actions(&index, &mut actions);
        push_shared_actions(source, namespace, &mut actions, &mut conditions);

        let status = if conditions
            .iter()
            .any(|condition| condition.status == KubernetesConditionStatus::False)
        {
            KubernetesPlanStatus::Blocked
        } else {
            KubernetesPlanStatus::Ready
        };

        let mut plan = KubernetesReconcilePlan {
            schema_version: KUBERNETES_RECONCILE_PLAN_SCHEMA.to_string(),
            namespace: namespace.to_string(),
            source: source.to_string(),
            status,
            resource_count: resources.len(),
            required_human_gates: human_gates.into_iter().collect(),
            server_side_dry_run: KubernetesDryRun {
                command: vec![
                    "kubectl".to_string(),
                    "apply".to_string(),
                    "--server-side".to_string(),
                    "--dry-run=server".to_string(),
                    "-n".to_string(),
                    namespace.to_string(),
                    "-f".to_string(),
                    source.to_string(),
                ],
                modifies_cluster: false,
                purpose:
                    "Validate rendered enterprise resources against the API server before apply"
                        .to_string(),
            },
            rollback: KubernetesRollbackPlan {
                command: vec![
                    "kubectl".to_string(),
                    "rollout".to_string(),
                    "undo".to_string(),
                    "deployment/mcp-gateway".to_string(),
                    "-n".to_string(),
                    namespace.to_string(),
                ],
                requires_human_confirmation: true,
                evidence: "Previous deployment revision or previous custom-resource generation"
                    .to_string(),
            },
            actions,
            conditions,
            evidence_exports: Vec::new(),
        };
        plan.evidence_exports = plan_evidence_exports(&plan);
        Ok(plan)
    }
}

/// Reconcile plan status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesPlanStatus {
    /// All required references are resolvable and the plan can be dry-run.
    Ready,
    /// One or more required references or resources are missing.
    Blocked,
}

/// A deterministic Kubernetes reconcile plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesReconcilePlan {
    /// Plan schema version.
    pub schema_version: String,
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Overall plan status.
    pub status: KubernetesPlanStatus,
    /// Number of parsed resources.
    pub resource_count: usize,
    /// Human decisions required before apply.
    pub required_human_gates: Vec<String>,
    /// Server-side dry-run command.
    pub server_side_dry_run: KubernetesDryRun,
    /// Rollback command and evidence.
    pub rollback: KubernetesRollbackPlan,
    /// Reconcile actions in execution order.
    pub actions: Vec<KubernetesReconcileAction>,
    /// Status conditions the controller would publish.
    pub conditions: Vec<KubernetesStatusCondition>,
    /// Sensitive-data-free evidence export payloads for status, event, `OTel`,
    /// and SIEM consumers.
    pub evidence_exports: Vec<KubernetesEvidenceExport>,
}

/// Server-side dry-run command metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesDryRun {
    /// Command vector.
    pub command: Vec<String>,
    /// Whether this command mutates cluster state.
    pub modifies_cluster: bool,
    /// Why the dry-run exists.
    pub purpose: String,
}

/// Rollback command metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesRollbackPlan {
    /// Command vector.
    pub command: Vec<String>,
    /// Whether a human must confirm rollback.
    pub requires_human_confirmation: bool,
    /// Evidence required before rollback.
    pub evidence: String,
}

/// One reconcile action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesReconcileAction {
    /// Action kind.
    pub action: KubernetesReconcileActionKind,
    /// Target resource kind.
    pub resource_kind: String,
    /// Target resource name.
    pub resource_name: String,
    /// Stable reason code.
    pub reason_code: String,
    /// Human-readable reason.
    pub reason: String,
    /// Whether the action requires explicit human approval.
    pub human_approval_required: bool,
    /// Verification evidence expected after the action.
    pub verification: String,
}

/// Reconcile action kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesReconcileActionKind {
    /// Validate manifests using server-side dry-run.
    ServerSideDryRun,
    /// Ensure gateway deployment resources.
    EnsureGatewayWorkload,
    /// Ensure service resource.
    EnsureService,
    /// Ensure policy resources.
    EnsurePolicy,
    /// Reconcile an MCP server custom resource.
    ReconcileMcpServer,
    /// Publish status conditions.
    PublishStatus,
    /// Prepare rollback evidence.
    PrepareRollback,
}

/// Kubernetes-style status condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesStatusCondition {
    /// Condition type.
    #[serde(rename = "type")]
    pub condition_type: String,
    /// Condition status.
    pub status: KubernetesConditionStatus,
    /// Stable reason code.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
}

/// Kubernetes condition status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KubernetesConditionStatus {
    /// Condition is true.
    True,
    /// Condition is false.
    False,
    /// Condition is unknown.
    Unknown,
}

/// Reconcile plan error.
#[derive(Debug, thiserror::Error)]
pub enum KubernetesPlanError {
    /// YAML parsing failed.
    #[error("failed to parse Kubernetes YAML: {0}")]
    Parse(String),
    /// A required document field is missing.
    #[error("Kubernetes document {document} is missing {field}")]
    MissingField {
        /// Zero-based document index.
        document: usize,
        /// Field path.
        field: &'static str,
    },
}

#[derive(Debug, Clone)]
struct KubernetesResource {
    kind: String,
    name: String,
    spec: Value,
}

#[derive(Default)]
struct ResourceIndex {
    by_kind: BTreeMap<String, BTreeSet<String>>,
    resources: Vec<KubernetesResource>,
}

impl ResourceIndex {
    fn from_resources(resources: &[KubernetesResource]) -> Self {
        let mut index = Self::default();
        for resource in resources {
            index
                .by_kind
                .entry(resource.kind.clone())
                .or_default()
                .insert(resource.name.clone());
            index.resources.push(resource.clone());
        }
        index
    }

    fn has_kind(&self, kind: &str) -> bool {
        self.by_kind
            .get(kind)
            .is_some_and(|names| !names.is_empty())
    }

    fn has_name(&self, kind: &str, name: &str) -> bool {
        self.by_kind
            .get(kind)
            .is_some_and(|names| names.contains(name))
    }

    fn resources_of_kind(&self, kind: &str) -> impl Iterator<Item = &KubernetesResource> {
        self.resources
            .iter()
            .filter(move |resource| resource.kind == kind)
    }
}

fn parse_resources(input: &str) -> Result<Vec<KubernetesResource>, KubernetesPlanError> {
    let mut resources = Vec::new();
    for (index, document) in serde_yaml::Deserializer::from_str(input).enumerate() {
        let value = Value::deserialize(document)
            .map_err(|err| KubernetesPlanError::Parse(err.to_string()))?;
        if value.is_null() {
            continue;
        }
        let kind =
            value
                .get("kind")
                .and_then(Value::as_str)
                .ok_or(KubernetesPlanError::MissingField {
                    document: index,
                    field: "kind",
                })?;
        let name = value
            .get("metadata")
            .and_then(|metadata| metadata.get("name"))
            .and_then(Value::as_str)
            .ok_or(KubernetesPlanError::MissingField {
                document: index,
                field: "metadata.name",
            })?;
        resources.push(KubernetesResource {
            kind: kind.to_string(),
            name: name.to_string(),
            spec: value.get("spec").cloned().unwrap_or(Value::Null),
        });
    }
    Ok(resources)
}

fn push_required_resource_conditions(
    index: &ResourceIndex,
    conditions: &mut Vec<KubernetesStatusCondition>,
) {
    for kind in ["Gateway", "RuntimeProfile", "Policy"] {
        conditions.push(if index.has_kind(kind) {
            condition_true(
                &format!("{kind}Present"),
                "K8S_REQUIRED_RESOURCE_PRESENT",
                format!("{kind} resource is present"),
            )
        } else {
            condition_false(
                &format!("{kind}Present"),
                "K8S_REQUIRED_RESOURCE_MISSING",
                format!("{kind} resource is required before reconciliation"),
            )
        });
    }
}

fn push_gateway_actions(
    namespace: &str,
    source: &str,
    index: &ResourceIndex,
    actions: &mut Vec<KubernetesReconcileAction>,
    conditions: &mut Vec<KubernetesStatusCondition>,
    human_gates: &mut BTreeSet<String>,
) {
    for gateway in index.resources_of_kind("Gateway") {
        human_gates.insert("namespace".to_string());
        human_gates.insert("protected_value_provider".to_string());
        let runtime_ref = str_spec(gateway, "runtimeProfileRef");
        let policy_ref = str_spec(gateway, "policyRef");
        let runtime_ok = runtime_ref
            .as_deref()
            .is_some_and(|name| index.has_name("RuntimeProfile", name));
        let policy_ok = policy_ref
            .as_deref()
            .is_some_and(|name| index.has_name("Policy", name));
        conditions.push(reference_condition(
            "RuntimeProfileResolved",
            runtime_ok,
            "RuntimeProfile",
            runtime_ref.as_deref(),
        ));
        conditions.push(reference_condition(
            "PolicyResolved",
            policy_ok,
            "Policy",
            policy_ref.as_deref(),
        ));

        actions.push(action(
            KubernetesReconcileActionKind::EnsureGatewayWorkload,
            "Gateway",
            &gateway.name,
            "K8S_GATEWAY_WORKLOAD",
            format!("Render Deployment and probes for Gateway in namespace {namespace}"),
            false,
            "Deployment has available replicas and startup/readiness/liveness probes pass",
        ));
        actions.push(action(
            KubernetesReconcileActionKind::EnsureService,
            "Gateway",
            &gateway.name,
            "K8S_GATEWAY_SERVICE",
            "Render the gateway Service from spec.service.port",
            false,
            "Service endpoint resolves and routes to ready gateway pods",
        ));
        actions.push(action(
            KubernetesReconcileActionKind::ServerSideDryRun,
            "Gateway",
            &gateway.name,
            "K8S_SERVER_DRY_RUN",
            format!("Run kubectl apply --server-side --dry-run=server -f {source}"),
            false,
            "API server accepts rendered resources without mutation",
        ));
    }
}

fn push_server_actions(
    index: &ResourceIndex,
    actions: &mut Vec<KubernetesReconcileAction>,
    conditions: &mut Vec<KubernetesStatusCondition>,
) {
    for server in index.resources_of_kind("MCPServer") {
        let runtime_ref = str_spec(server, "runtimeProfileRef");
        let policy_ref = str_spec(server, "policyRef");
        let trust_ref = str_spec(server, "trustCardRef");
        conditions.push(reference_condition(
            "MCPServerRuntimeResolved",
            runtime_ref
                .as_deref()
                .is_some_and(|name| index.has_name("RuntimeProfile", name)),
            "RuntimeProfile",
            runtime_ref.as_deref(),
        ));
        conditions.push(reference_condition(
            "MCPServerPolicyResolved",
            policy_ref
                .as_deref()
                .is_some_and(|name| index.has_name("Policy", name)),
            "Policy",
            policy_ref.as_deref(),
        ));
        conditions.push(reference_condition(
            "MCPServerTrustCardResolved",
            trust_ref
                .as_deref()
                .is_some_and(|name| index.has_name("TrustCardReference", name)),
            "TrustCardReference",
            trust_ref.as_deref(),
        ));
        actions.push(action(
            KubernetesReconcileActionKind::ReconcileMcpServer,
            "MCPServer",
            &server.name,
            "K8S_MCP_SERVER_RECONCILE",
            "Resolve runtime profile, policy, TrustCard reference, and endpoint wiring",
            false,
            "MCPServer status has Ready or Blocked condition with referenced evidence",
        ));
    }
}

fn push_status_actions(index: &ResourceIndex, actions: &mut Vec<KubernetesReconcileAction>) {
    for resource in &index.resources {
        actions.push(action(
            KubernetesReconcileActionKind::PublishStatus,
            &resource.kind,
            &resource.name,
            "K8S_STATUS_CONDITIONS",
            "Publish observedGeneration and condition evidence",
            false,
            "Status subresource contains latest observedGeneration and reason-coded conditions",
        ));
    }
}

fn push_shared_actions(
    source: &str,
    namespace: &str,
    actions: &mut Vec<KubernetesReconcileAction>,
    conditions: &mut Vec<KubernetesStatusCondition>,
) {
    actions.push(action(
        KubernetesReconcileActionKind::ServerSideDryRun,
        "Manifest",
        source,
        "K8S_SERVER_SIDE_DRY_RUN_READY",
        format!("Preview all rendered resources in namespace {namespace} before apply"),
        false,
        "Dry-run exits 0 and records API-server validation output",
    ));
    actions.push(action(
        KubernetesReconcileActionKind::PrepareRollback,
        "Deployment",
        "mcp-gateway",
        "K8S_ROLLBACK_READY",
        "Capture previous rollout revision before apply",
        true,
        "Rollback handle references previous deployment revision or CR generation",
    ));
    conditions.push(condition_true(
        "ServerSideDryRunPlanned",
        "K8S_SERVER_SIDE_DRY_RUN_READY",
        "Plan includes non-mutating API-server validation command",
    ));
    conditions.push(condition_true(
        "RollbackReady",
        "K8S_ROLLBACK_READY",
        "Plan includes rollback command and required evidence",
    ));
}

fn str_spec(resource: &KubernetesResource, key: &str) -> Option<String> {
    resource
        .spec
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn reference_condition(
    condition_type: &str,
    ok: bool,
    ref_kind: &str,
    ref_name: Option<&str>,
) -> KubernetesStatusCondition {
    let name = ref_name.unwrap_or("<missing>");
    if ok {
        condition_true(
            condition_type,
            "K8S_REFERENCE_RESOLVED",
            format!("{ref_kind} reference '{name}' is present"),
        )
    } else {
        condition_false(
            condition_type,
            "K8S_REFERENCE_MISSING",
            format!("{ref_kind} reference '{name}' is missing"),
        )
    }
}

fn condition_true(
    condition_type: &str,
    reason: &str,
    message: impl Into<String>,
) -> KubernetesStatusCondition {
    condition(
        condition_type,
        KubernetesConditionStatus::True,
        reason,
        message,
    )
}

fn condition_false(
    condition_type: &str,
    reason: &str,
    message: impl Into<String>,
) -> KubernetesStatusCondition {
    condition(
        condition_type,
        KubernetesConditionStatus::False,
        reason,
        message,
    )
}

fn condition(
    condition_type: &str,
    status: KubernetesConditionStatus,
    reason: &str,
    message: impl Into<String>,
) -> KubernetesStatusCondition {
    KubernetesStatusCondition {
        condition_type: condition_type.to_string(),
        status,
        reason: reason.to_string(),
        message: message.into(),
    }
}

fn action(
    action: KubernetesReconcileActionKind,
    resource_kind: &str,
    resource_name: &str,
    reason_code: &str,
    reason: impl Into<String>,
    human_approval_required: bool,
    verification: &str,
) -> KubernetesReconcileAction {
    KubernetesReconcileAction {
        action,
        resource_kind: resource_kind.to_string(),
        resource_name: resource_name.to_string(),
        reason_code: reason_code.to_string(),
        reason: reason.into(),
        human_approval_required,
        verification: verification.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        include_str!("../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml");

    #[test]
    fn reconcile_plan_resolves_example_custom_resources() {
        let plan = plan_reconciliation("mcp-gateway", "example-gateway.yaml", EXAMPLE).unwrap();

        assert_eq!(plan.status, KubernetesPlanStatus::Ready);
        assert_eq!(plan.resource_count, 5);
        assert!(
            plan.server_side_dry_run
                .command
                .contains(&"--dry-run=server".to_string())
        );
        assert!(!plan.server_side_dry_run.modifies_cluster);
        assert!(
            plan.actions
                .iter()
                .any(|action| action.action == KubernetesReconcileActionKind::ReconcileMcpServer)
        );
        assert!(
            plan.conditions
                .iter()
                .any(|condition| condition.reason == "K8S_REFERENCE_RESOLVED")
        );
        assert!(
            plan.evidence_exports
                .iter()
                .any(|export| export.sink == KubernetesEvidenceSink::OpenTelemetry)
        );
        assert!(
            plan.evidence_exports
                .iter()
                .all(|export| !export.contains_sensitive_material)
        );
    }

    #[test]
    fn reconcile_plan_blocks_missing_policy_reference() {
        let broken = EXAMPLE.replace("policyRef: default-policy", "policyRef: missing-policy");
        let plan = plan_reconciliation("mcp-gateway", "broken.yaml", &broken).unwrap();

        assert_eq!(plan.status, KubernetesPlanStatus::Blocked);
        assert!(
            plan.conditions
                .iter()
                .any(|condition| condition.reason == "K8S_REFERENCE_MISSING")
        );
    }
}
