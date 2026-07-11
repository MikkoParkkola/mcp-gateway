// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Live-cluster Kubernetes apply adapter plan.
//!
//! This module turns a deterministic reconcile plan into an operator-facing
//! command plan for preflight, server-side dry-run, gated apply, verification,
//! evidence export, and rollback. Command execution is opt-in and consumes the
//! same gated plan so default CLI behavior stays non-mutating.

use serde::{Deserialize, Serialize};

use super::{
    KubernetesEvidenceTransport, KubernetesPlanError, KubernetesPlanStatus,
    KubernetesReconcilePlan, plan_reconciliation,
};

/// Schema version emitted by Kubernetes cluster apply plans.
pub const KUBERNETES_CLUSTER_APPLY_PLAN_SCHEMA: &str = "kubernetes.cluster_apply_plan.v1";

/// Schema version emitted by Kubernetes cluster execution reports.
pub const KUBERNETES_CLUSTER_EXECUTION_REPORT_SCHEMA: &str =
    "kubernetes.cluster_execution_report.v1";

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

/// Overall status for a cluster command execution report.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesClusterExecutionStatus {
    /// Every runnable enabled step succeeded.
    Succeeded,
    /// The reconcile/apply plan was blocked before execution.
    Blocked,
    /// A runnable enabled step failed.
    Failed,
}

/// Execution status for one planned command step.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesClusterStepRunStatus {
    /// The command was invoked and exited successfully.
    Executed,
    /// The step was disabled by the apply plan gates.
    SkippedDisabled,
    /// Rollback is emitted as an operator handle and is not run automatically.
    SkippedRollbackHandle,
    /// The command was invoked and failed.
    Failed,
}

/// Minimal command outcome returned by the concrete runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterCommandOutcome {
    /// Whether the command exited successfully.
    pub success: bool,
    /// Process exit code when available.
    pub exit_code: Option<i32>,
    /// Short diagnostic message. Raw command output is intentionally omitted.
    pub message: Option<String>,
}

impl KubernetesClusterCommandOutcome {
    /// Build a successful command outcome.
    pub fn success(exit_code: i32) -> Self {
        Self {
            success: true,
            exit_code: Some(exit_code),
            message: None,
        }
    }

    /// Build a failed command outcome.
    pub fn failed(exit_code: Option<i32>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            exit_code,
            message: Some(message.into()),
        }
    }
}

/// Execution result for one planned command step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterStepExecution {
    /// Step kind.
    pub step: KubernetesClusterStepKind,
    /// Stable reason code from the plan.
    pub reason_code: String,
    /// Command vector that was run or skipped.
    pub command: Vec<String>,
    /// Whether running the command can mutate cluster state.
    pub modifies_cluster: bool,
    /// Execution status for this step.
    pub status: KubernetesClusterStepRunStatus,
    /// Exit code for executed commands when available.
    pub exit_code: Option<i32>,
    /// Short diagnostic message. Raw command output is intentionally omitted.
    pub message: Option<String>,
}

/// Report emitted by an opt-in cluster apply command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesClusterExecutionReport {
    /// Report schema version.
    pub schema_version: String,
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Reconcile plan status used before execution.
    pub plan_status: KubernetesPlanStatus,
    /// Overall execution status.
    pub status: KubernetesClusterExecutionStatus,
    /// Whether mutating steps were allowed by the reviewed plan.
    pub mutation_allowed: bool,
    /// Number of commands executed successfully.
    pub executed_steps: usize,
    /// Number of commands skipped by gates or rollback-handle policy.
    pub skipped_steps: usize,
    /// Failed step kind when execution failed.
    pub failed_step: Option<KubernetesClusterStepKind>,
    /// Short failure reason when status is blocked or failed.
    pub failure_reason: Option<String>,
    /// Per-step execution details.
    pub steps: Vec<KubernetesClusterStepExecution>,
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

/// Execute enabled cluster apply plan steps with a caller-provided runner.
///
/// Disabled steps are skipped, rollback remains an operator handle, and blocked
/// plans fail closed without invoking the runner.
pub fn execute_cluster_apply_plan<F>(
    plan: &KubernetesClusterApplyPlan,
    mut runner: F,
) -> KubernetesClusterExecutionReport
where
    F: FnMut(&KubernetesClusterCommandStep) -> KubernetesClusterCommandOutcome,
{
    if plan.status == KubernetesPlanStatus::Blocked {
        let steps: Vec<_> = plan
            .steps
            .iter()
            .map(|step| {
                step_execution(
                    step,
                    KubernetesClusterStepRunStatus::SkippedDisabled,
                    None,
                    Some("plan blocked before command execution".to_string()),
                )
            })
            .collect();
        return execution_report(
            plan,
            KubernetesClusterExecutionStatus::Blocked,
            None,
            Some(blocked_execution_reason(plan)),
            steps,
        );
    }

    let mut status = KubernetesClusterExecutionStatus::Succeeded;
    let mut failed_step = None;
    let mut failure_reason = None;
    let mut steps = Vec::new();

    for step in &plan.steps {
        if !step.enabled || (step.modifies_cluster && !plan.mutation_allowed) {
            steps.push(step_execution(
                step,
                KubernetesClusterStepRunStatus::SkippedDisabled,
                None,
                None,
            ));
            continue;
        }

        if step.step == KubernetesClusterStepKind::Rollback {
            steps.push(step_execution(
                step,
                KubernetesClusterStepRunStatus::SkippedRollbackHandle,
                None,
                Some("rollback is a recovery handle and is not run automatically".to_string()),
            ));
            continue;
        }

        let outcome = runner(step);
        if outcome.success {
            steps.push(step_execution(
                step,
                KubernetesClusterStepRunStatus::Executed,
                outcome.exit_code,
                outcome.message,
            ));
            continue;
        }

        status = KubernetesClusterExecutionStatus::Failed;
        failed_step = Some(step.step);
        failure_reason = outcome
            .message
            .clone()
            .or_else(|| Some(format!("{:?} command failed", step.step)));
        steps.push(step_execution(
            step,
            KubernetesClusterStepRunStatus::Failed,
            outcome.exit_code,
            outcome.message,
        ));
        break;
    }

    execution_report(plan, status, failed_step, failure_reason, steps)
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

fn step_execution(
    step: &KubernetesClusterCommandStep,
    status: KubernetesClusterStepRunStatus,
    exit_code: Option<i32>,
    message: Option<String>,
) -> KubernetesClusterStepExecution {
    KubernetesClusterStepExecution {
        step: step.step,
        reason_code: step.reason_code.clone(),
        command: step.command.clone(),
        modifies_cluster: step.modifies_cluster,
        status,
        exit_code,
        message,
    }
}

fn execution_report(
    plan: &KubernetesClusterApplyPlan,
    status: KubernetesClusterExecutionStatus,
    failed_step: Option<KubernetesClusterStepKind>,
    failure_reason: Option<String>,
    steps: Vec<KubernetesClusterStepExecution>,
) -> KubernetesClusterExecutionReport {
    let executed_steps = steps
        .iter()
        .filter(|step| step.status == KubernetesClusterStepRunStatus::Executed)
        .count();
    let skipped_steps = steps
        .iter()
        .filter(|step| {
            matches!(
                step.status,
                KubernetesClusterStepRunStatus::SkippedDisabled
                    | KubernetesClusterStepRunStatus::SkippedRollbackHandle
            )
        })
        .count();

    KubernetesClusterExecutionReport {
        schema_version: KUBERNETES_CLUSTER_EXECUTION_REPORT_SCHEMA.to_string(),
        namespace: plan.namespace.clone(),
        source: plan.source.clone(),
        plan_status: plan.status,
        status,
        mutation_allowed: plan.mutation_allowed,
        executed_steps,
        skipped_steps,
        failed_step,
        failure_reason,
        steps,
    }
}

fn blocked_reasons(plan: &KubernetesReconcilePlan) -> Vec<String> {
    plan.conditions
        .iter()
        .filter(|condition| matches!(condition.status, super::KubernetesConditionStatus::False))
        .map(|condition| format!("{}:{}", condition.condition_type, condition.reason))
        .collect()
}

fn blocked_execution_reason(plan: &KubernetesClusterApplyPlan) -> String {
    if plan.blocked_reasons.is_empty() {
        "plan blocked before command execution".to_string()
    } else {
        format!(
            "plan blocked before command execution: {}",
            plan.blocked_reasons.join(",")
        )
    }
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

    #[test]
    fn cluster_apply_execution_runs_only_enabled_dry_run_steps_without_approval() {
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::dry_run("mcp-gateway", "example-gateway.yaml"),
            EXAMPLE,
        )
        .unwrap();
        let mut ran = Vec::new();

        let report = execute_cluster_apply_plan(&plan, |step| {
            ran.push(step.step);
            KubernetesClusterCommandOutcome::success(0)
        });

        assert_eq!(
            report.schema_version,
            KUBERNETES_CLUSTER_EXECUTION_REPORT_SCHEMA
        );
        assert_eq!(report.status, KubernetesClusterExecutionStatus::Succeeded);
        assert_eq!(
            ran,
            vec![
                KubernetesClusterStepKind::Preflight,
                KubernetesClusterStepKind::ServerSideDryRun,
            ]
        );
        assert_eq!(report.executed_steps, 2);
        assert!(report.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Apply
                && step.status == KubernetesClusterStepRunStatus::SkippedDisabled
        }));
    }

    #[test]
    fn cluster_apply_execution_runs_approved_steps_without_auto_rollback() {
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::approved("mcp-gateway", "example-gateway.yaml"),
            EXAMPLE,
        )
        .unwrap();
        let mut ran = Vec::new();

        let report = execute_cluster_apply_plan(&plan, |step| {
            ran.push(step.step);
            KubernetesClusterCommandOutcome::success(0)
        });

        assert_eq!(report.status, KubernetesClusterExecutionStatus::Succeeded);
        assert!(ran.contains(&KubernetesClusterStepKind::Apply));
        assert!(ran.contains(&KubernetesClusterStepKind::Verify));
        assert!(ran.contains(&KubernetesClusterStepKind::EvidenceExport));
        assert!(!ran.contains(&KubernetesClusterStepKind::Rollback));
        assert!(report.steps.iter().any(|step| {
            step.step == KubernetesClusterStepKind::Rollback
                && step.status == KubernetesClusterStepRunStatus::SkippedRollbackHandle
        }));
    }

    #[test]
    fn cluster_apply_execution_blocks_before_runner_for_blocked_plan() {
        let broken = EXAMPLE.replace("policyRef: default-policy", "policyRef: missing-policy");
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::approved("mcp-gateway", "broken.yaml"),
            &broken,
        )
        .unwrap();

        let report = execute_cluster_apply_plan(&plan, |_| {
            panic!("blocked plans must not invoke the command runner")
        });

        assert_eq!(report.status, KubernetesClusterExecutionStatus::Blocked);
        assert_eq!(report.executed_steps, 0);
        assert_eq!(report.skipped_steps, report.steps.len());
        assert!(report.failure_reason.is_some());
    }

    #[test]
    fn cluster_apply_execution_stops_on_first_failed_step() {
        let plan = plan_cluster_apply(
            KubernetesClusterApplyOptions::approved("mcp-gateway", "example-gateway.yaml"),
            EXAMPLE,
        )
        .unwrap();
        let mut ran = Vec::new();

        let report = execute_cluster_apply_plan(&plan, |step| {
            ran.push(step.step);
            if step.step == KubernetesClusterStepKind::Apply {
                KubernetesClusterCommandOutcome::failed(Some(1), "apply failed")
            } else {
                KubernetesClusterCommandOutcome::success(0)
            }
        });

        assert_eq!(report.status, KubernetesClusterExecutionStatus::Failed);
        assert_eq!(report.failed_step, Some(KubernetesClusterStepKind::Apply));
        assert_eq!(report.failure_reason.as_deref(), Some("apply failed"));
        assert_eq!(
            ran,
            vec![
                KubernetesClusterStepKind::Preflight,
                KubernetesClusterStepKind::ServerSideDryRun,
                KubernetesClusterStepKind::Apply,
            ]
        );
    }
}
