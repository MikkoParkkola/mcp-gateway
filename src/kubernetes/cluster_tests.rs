// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
