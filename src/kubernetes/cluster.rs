//! Live-cluster Kubernetes apply adapter plan.
//!
//! This module turns a deterministic reconcile plan into an operator-facing
//! command plan for preflight, server-side dry-run, gated apply, verification,
//! evidence export, and rollback. It does not run `kubectl`; command execution
//! remains an explicit operator action or a future runner integration.

use serde::{Deserialize, Serialize};

use super::{
    KubernetesEvidenceTransport, KubernetesPlanError, KubernetesPlanStatus,
    KubernetesReconcilePlan, plan_reconciliation,
};

/// Schema version emitted by Kubernetes cluster apply plans.
pub const KUBERNETES_CLUSTER_APPLY_PLAN_SCHEMA: &str = "kubernetes.cluster_apply_plan.v1";

/// Operator intent represented by a cluster apply plan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesClusterApplyIntent {
    /// Preview and verify only; mutating commands are disabled.
    DryRun,
    /// Mutating commands may be executed by an external runner.
    ApplyApproved,
}

/// One stage in the cluster apply workflow.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesClusterStepKind {
    /// Read-only cluster capability and permission checks.
    Preflight,
    /// API-server validation without mutation.
    ServerSideDryRun,
    /// Server-side apply for the supplied resources.
    Apply,
    /// Post-apply status and rollout checks.
    Verify,
    /// Sensitive-data-free evidence export.
    EvidenceExport,
    /// Reversal handle to use if verification fails after apply.
    Rollback,
}

/// One command in the cluster apply workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterCommandStep {
    /// Step kind.
    pub step: KubernetesClusterStepKind,
    /// Stable reason code.
    pub reason_code: String,
    /// Command vector suitable for an external runner.
    pub command: Vec<String>,
    /// Whether the command mutates cluster state if executed.
    pub modifies_cluster: bool,
    /// Whether this step is enabled in the current plan.
    pub enabled: bool,
    /// Whether a human must approve this command before execution.
    pub requires_human_confirmation: bool,
    /// Human-readable description.
    pub description: String,
}

/// Options for a cluster apply plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterApplyOptions {
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Whether mutating apply/evidence steps are enabled.
    pub apply_approved: bool,
    /// Include evidence export command steps.
    pub include_evidence_exports: bool,
}

impl KubernetesClusterApplyOptions {
    /// Build dry-run cluster apply options.
    pub fn dry_run(namespace: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            source: source.into(),
            apply_approved: false,
            include_evidence_exports: true,
        }
    }

    /// Build approved cluster apply options.
    pub fn approved(namespace: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            source: source.into(),
            apply_approved: true,
            include_evidence_exports: true,
        }
    }
}

/// Cluster apply workflow plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterApplyPlan {
    /// Plan schema version.
    pub schema_version: String,
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Operator intent.
    pub intent: KubernetesClusterApplyIntent,
    /// Reconcile plan status.
    pub status: KubernetesPlanStatus,
    /// Whether mutating steps are enabled.
    pub mutation_allowed: bool,
    /// Human gates inherited from the reconcile plan.
    pub required_human_gates: Vec<String>,
    /// Stable blocked reasons. Empty for ready plans.
    pub blocked_reasons: Vec<String>,
    /// Workflow commands in execution order.
    pub steps: Vec<KubernetesClusterCommandStep>,
    /// Reconcile plan used to build this apply workflow.
    pub reconcile_plan: KubernetesReconcilePlan,
}

/// Build a cluster apply command plan from a manifest stream.
///
/// # Errors
///
/// Returns an error when the supplied manifest cannot be parsed into a
/// reconcile plan.
pub fn plan_cluster_apply(
    options: KubernetesClusterApplyOptions,
    manifest: &str,
) -> Result<KubernetesClusterApplyPlan, KubernetesPlanError> {
    let reconcile_plan = plan_reconciliation(&options.namespace, &options.source, manifest)?;
    let ready = reconcile_plan.status == KubernetesPlanStatus::Ready;
    let mutation_allowed = ready && options.apply_approved;
    let mut steps = vec![
        preflight_step(&options.namespace),
        dry_run_step(&options.namespace, &options.source),
        apply_step(&options.namespace, &options.source, mutation_allowed),
        verify_step(&options.namespace, mutation_allowed),
    ];

    if options.include_evidence_exports {
        steps.extend(evidence_steps(&reconcile_plan, mutation_allowed));
    }
    steps.push(rollback_step(&reconcile_plan, mutation_allowed));

    Ok(KubernetesClusterApplyPlan {
        schema_version: KUBERNETES_CLUSTER_APPLY_PLAN_SCHEMA.to_string(),
        namespace: options.namespace,
        source: options.source,
        intent: if options.apply_approved {
            KubernetesClusterApplyIntent::ApplyApproved
        } else {
            KubernetesClusterApplyIntent::DryRun
        },
        status: reconcile_plan.status,
        mutation_allowed,
        required_human_gates: reconcile_plan.required_human_gates.clone(),
        blocked_reasons: blocked_reasons(&reconcile_plan),
        steps,
        reconcile_plan,
    })
}

fn preflight_step(namespace: &str) -> KubernetesClusterCommandStep {
    step(
        KubernetesClusterStepKind::Preflight,
        "K8S_CLUSTER_PREFLIGHT",
        vec![
            "deploy/kubernetes/enterprise-alpha/scripts/preflight.sh".to_string(),
            namespace.to_string(),
        ],
        false,
        true,
        false,
        "Verify cluster permissions and capabilities before dry-run or apply",
    )
}

fn dry_run_step(namespace: &str, source: &str) -> KubernetesClusterCommandStep {
    step(
        KubernetesClusterStepKind::ServerSideDryRun,
        "K8S_CLUSTER_SERVER_DRY_RUN",
        vec![
            "kubectl".to_string(),
            "apply".to_string(),
            "--server-side".to_string(),
            "--dry-run=server".to_string(),
            "-n".to_string(),
            namespace.to_string(),
            "-f".to_string(),
            source.to_string(),
        ],
        false,
        true,
        false,
        "Ask the API server to validate the supplied resources without mutation",
    )
}

fn apply_step(namespace: &str, source: &str, enabled: bool) -> KubernetesClusterCommandStep {
    step(
        KubernetesClusterStepKind::Apply,
        "K8S_CLUSTER_APPLY_APPROVED",
        vec![
            "kubectl".to_string(),
            "apply".to_string(),
            "--server-side".to_string(),
            "-n".to_string(),
            namespace.to_string(),
            "-f".to_string(),
            source.to_string(),
        ],
        true,
        enabled,
        true,
        "Apply the reviewed resources after explicit operator approval",
    )
}

fn verify_step(namespace: &str, enabled: bool) -> KubernetesClusterCommandStep {
    step(
        KubernetesClusterStepKind::Verify,
        "K8S_CLUSTER_VERIFY_STATUS",
        vec![
            "kubectl".to_string(),
            "get".to_string(),
            "gateways.mcpgateway.io,mcpservers.mcpgateway.io,policies.mcpgateway.io,runtimeprofiles.mcpgateway.io,trustcardreferences.mcpgateway.io".to_string(),
            "-n".to_string(),
            namespace.to_string(),
            "-o".to_string(),
            "wide".to_string(),
        ],
        false,
        enabled,
        false,
        "Read custom-resource status after apply without exposing protected values",
    )
}

fn evidence_steps(
    plan: &KubernetesReconcilePlan,
    enabled: bool,
) -> impl Iterator<Item = KubernetesClusterCommandStep> + '_ {
    plan.evidence_exports
        .iter()
        .filter(|export| !export.delivery.command.is_empty())
        .map(move |export| {
            let modifies_cluster = matches!(
                export.delivery.transport,
                KubernetesEvidenceTransport::KubernetesStatusPatch
                    | KubernetesEvidenceTransport::KubernetesEvent
            );
            step(
                KubernetesClusterStepKind::EvidenceExport,
                "K8S_CLUSTER_EVIDENCE_EXPORT",
                export.delivery.command.clone(),
                modifies_cluster,
                enabled && modifies_cluster,
                modifies_cluster,
                &export.delivery.description,
            )
        })
}

fn rollback_step(plan: &KubernetesReconcilePlan, enabled: bool) -> KubernetesClusterCommandStep {
    step(
        KubernetesClusterStepKind::Rollback,
        "K8S_CLUSTER_ROLLBACK_HANDLE",
        plan.rollback.command.clone(),
        true,
        enabled,
        true,
        "Rollback handle to use when post-apply verification fails",
    )
}

fn step(
    step: KubernetesClusterStepKind,
    reason_code: &str,
    command: Vec<String>,
    modifies_cluster: bool,
    enabled: bool,
    requires_human_confirmation: bool,
    description: &str,
) -> KubernetesClusterCommandStep {
    KubernetesClusterCommandStep {
        step,
        reason_code: reason_code.to_string(),
        command,
        modifies_cluster,
        enabled,
        requires_human_confirmation,
        description: description.to_string(),
    }
}

fn blocked_reasons(plan: &KubernetesReconcilePlan) -> Vec<String> {
    plan.conditions
        .iter()
        .filter(|condition| matches!(condition.status, super::KubernetesConditionStatus::False))
        .map(|condition| format!("{}:{}", condition.condition_type, condition.reason))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        include_str!("../../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml");

    #[test]
    fn cluster_apply_plan_keeps_mutating_steps_disabled_without_approval() {
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::dry_run("mcp-gateway", "example-gateway.yaml"),
            EXAMPLE,
        )
        .unwrap();

        assert_eq!(plan.schema_version, KUBERNETES_CLUSTER_APPLY_PLAN_SCHEMA);
        assert_eq!(plan.intent, KubernetesClusterApplyIntent::DryRun);
        assert_eq!(plan.status, KubernetesPlanStatus::Ready);
        assert!(!plan.mutation_allowed);
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::ServerSideDryRun
                && step.enabled
                && !step.modifies_cluster
        }));
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Apply
                && !step.enabled
                && step.modifies_cluster
                && step.requires_human_confirmation
        }));
    }

    #[test]
    fn cluster_apply_plan_enables_mutating_steps_after_approval() {
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::approved("mcp-gateway", "example-gateway.yaml"),
            EXAMPLE,
        )
        .unwrap();

        assert_eq!(plan.intent, KubernetesClusterApplyIntent::ApplyApproved);
        assert!(plan.mutation_allowed);
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Apply && step.enabled && step.modifies_cluster
        }));
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::EvidenceExport
                && step.enabled
                && step.modifies_cluster
        }));
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Rollback
                && step.enabled
                && step.requires_human_confirmation
        }));
    }

    #[test]
    fn cluster_apply_plan_blocks_mutation_for_invalid_references() {
        let broken = EXAMPLE.replace("policyRef: default-policy", "policyRef: missing-policy");
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::approved("mcp-gateway", "broken.yaml"),
            &broken,
        )
        .unwrap();

        assert_eq!(plan.status, KubernetesPlanStatus::Blocked);
        assert!(!plan.mutation_allowed);
        assert!(!plan.blocked_reasons.is_empty());
        assert!(plan.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Apply && !step.enabled && step.modifies_cluster
        }));
    }
}
