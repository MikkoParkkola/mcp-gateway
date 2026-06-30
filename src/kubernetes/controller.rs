//! Deterministic Kubernetes controller-manager contract.
//!
//! The controller manager runs the same reconciliation planner used by the
//! dry-run command and summarizes each reconcile cycle without requiring a
//! live cluster client. Cluster watch/apply adapters can layer on this contract
//! without changing the evidence payload shape.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    KubernetesPlanError, KubernetesPlanStatus, KubernetesReconcilePlan, plan_reconciliation,
};

/// Schema version emitted by Kubernetes controller-manager reports.
pub const KUBERNETES_CONTROLLER_REPORT_SCHEMA: &str = "kubernetes.controller_report.v1";

/// Controller-manager execution mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesControllerMode {
    /// Execute one reconcile cycle and exit.
    Once,
    /// Execute a bounded number of cycles and exit.
    Bounded,
    /// Execute repeated cycles until the process is stopped.
    Continuous,
}

/// Reason the controller-manager report stopped.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesControllerShutdownReason {
    /// The requested finite cycle count completed.
    CycleLimitReached,
    /// A blocked plan stopped the reconcile loop before more mutations could
    /// be attempted by a future cluster adapter.
    PlanBlocked,
    /// Continuous mode emitted a cycle report and kept the loop open.
    ContinuousPreview,
}

/// Controller-manager options that affect deterministic planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesControllerOptions {
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Seconds between reconcile cycles.
    pub interval_seconds: u64,
    /// Requested finite cycle count. Continuous mode uses this as one report
    /// batch size before the caller sleeps and repeats.
    pub requested_cycles: usize,
    /// Controller-manager execution mode.
    pub mode: KubernetesControllerMode,
}

impl KubernetesControllerOptions {
    /// Build one-shot controller-manager options.
    pub fn once(
        namespace: impl Into<String>,
        source: impl Into<String>,
        interval_seconds: u64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            source: source.into(),
            interval_seconds,
            requested_cycles: 1,
            mode: KubernetesControllerMode::Once,
        }
    }

    /// Build bounded controller-manager options.
    pub fn bounded(
        namespace: impl Into<String>,
        source: impl Into<String>,
        interval_seconds: u64,
        requested_cycles: usize,
    ) -> Self {
        let requested_cycles = requested_cycles.max(1);
        Self {
            namespace: namespace.into(),
            source: source.into(),
            interval_seconds,
            requested_cycles,
            mode: if requested_cycles == 1 {
                KubernetesControllerMode::Once
            } else {
                KubernetesControllerMode::Bounded
            },
        }
    }

    /// Build continuous controller-manager options.
    pub fn continuous(
        namespace: impl Into<String>,
        source: impl Into<String>,
        interval_seconds: u64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            source: source.into(),
            interval_seconds,
            requested_cycles: 1,
            mode: KubernetesControllerMode::Continuous,
        }
    }
}

/// Summary emitted by one reconcile cycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesControllerCycle {
    /// One-based reconcile cycle number.
    pub cycle: usize,
    /// Plan status observed for this cycle.
    pub status: KubernetesPlanStatus,
    /// Parsed resource count.
    pub resource_count: usize,
    /// Planned action count.
    pub action_count: usize,
    /// Planned status condition count.
    pub condition_count: usize,
    /// Evidence exports emitted by the plan.
    pub evidence_export_count: usize,
    /// Required human gates still attached to the plan.
    pub required_human_gates: Vec<String>,
    /// Stable reason codes observed across actions and status conditions.
    pub reason_codes: Vec<String>,
    /// Seconds until the next reconcile cycle.
    pub next_reconcile_after_seconds: Option<u64>,
}

impl KubernetesControllerCycle {
    fn from_plan(cycle: usize, plan: &KubernetesReconcilePlan, interval_seconds: u64) -> Self {
        let reason_codes = plan
            .actions
            .iter()
            .map(|action| action.reason_code.clone())
            .chain(
                plan.conditions
                    .iter()
                    .map(|condition| condition.reason.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        Self {
            cycle,
            status: plan.status,
            resource_count: plan.resource_count,
            action_count: plan.actions.len(),
            condition_count: plan.conditions.len(),
            evidence_export_count: plan.evidence_exports.len(),
            required_human_gates: plan.required_human_gates.clone(),
            reason_codes,
            next_reconcile_after_seconds: (plan.status == KubernetesPlanStatus::Ready)
                .then_some(interval_seconds),
        }
    }
}

/// Deterministic controller-manager report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesControllerReport {
    /// Report schema version.
    pub schema_version: String,
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Controller-manager execution mode.
    pub mode: KubernetesControllerMode,
    /// Seconds between reconcile cycles.
    pub interval_seconds: u64,
    /// Requested finite cycle count.
    pub requested_cycles: usize,
    /// Completed cycle count.
    pub completed_cycles: usize,
    /// Final observed status.
    pub status: KubernetesPlanStatus,
    /// Why this finite report stopped.
    pub shutdown_reason: KubernetesControllerShutdownReason,
    /// Per-cycle summaries.
    pub cycles: Vec<KubernetesControllerCycle>,
    /// Last reconcile plan emitted by the loop.
    pub last_plan: KubernetesReconcilePlan,
}

/// Run deterministic controller-manager cycles from a manifest stream.
///
/// # Errors
///
/// Returns an error when the supplied manifest cannot be parsed into a
/// reconcile plan.
pub fn plan_controller_report(
    options: KubernetesControllerOptions,
    manifest: &str,
) -> Result<KubernetesControllerReport, KubernetesPlanError> {
    let mut cycles = Vec::with_capacity(options.requested_cycles);
    let mut last_plan = None;

    for cycle in 1..=options.requested_cycles {
        let plan = plan_reconciliation(&options.namespace, &options.source, manifest)?;
        cycles.push(KubernetesControllerCycle::from_plan(
            cycle,
            &plan,
            options.interval_seconds,
        ));
        let blocked = plan.status == KubernetesPlanStatus::Blocked;
        last_plan = Some(plan);
        if blocked {
            break;
        }
    }

    let last_plan = last_plan.expect("requested_cycles is clamped to at least one");
    let shutdown_reason = match (options.mode, last_plan.status) {
        (_, KubernetesPlanStatus::Blocked) => KubernetesControllerShutdownReason::PlanBlocked,
        (KubernetesControllerMode::Continuous, KubernetesPlanStatus::Ready) => {
            KubernetesControllerShutdownReason::ContinuousPreview
        }
        (_, KubernetesPlanStatus::Ready) => KubernetesControllerShutdownReason::CycleLimitReached,
    };

    Ok(KubernetesControllerReport {
        schema_version: KUBERNETES_CONTROLLER_REPORT_SCHEMA.to_string(),
        namespace: options.namespace,
        source: options.source,
        mode: options.mode,
        interval_seconds: options.interval_seconds,
        requested_cycles: options.requested_cycles,
        completed_cycles: cycles.len(),
        status: last_plan.status,
        shutdown_reason,
        cycles,
        last_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str =
        include_str!("../../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml");

    #[test]
    fn controller_report_summarizes_bounded_reconcile_cycles() {
        let report = plan_controller_report(
            KubernetesControllerOptions::bounded("mcp-gateway", "example-gateway.yaml", 30, 2),
            EXAMPLE,
        )
        .unwrap();

        assert_eq!(report.schema_version, KUBERNETES_CONTROLLER_REPORT_SCHEMA);
        assert_eq!(report.mode, KubernetesControllerMode::Bounded);
        assert_eq!(report.completed_cycles, 2);
        assert_eq!(report.status, KubernetesPlanStatus::Ready);
        assert_eq!(
            report.shutdown_reason,
            KubernetesControllerShutdownReason::CycleLimitReached
        );
        assert!(
            report
                .cycles
                .iter()
                .all(|cycle| cycle.evidence_export_count == 4)
        );
        assert!(
            report.cycles[0]
                .reason_codes
                .contains(&"K8S_SERVER_SIDE_DRY_RUN_READY".to_string())
        );
    }

    #[test]
    fn controller_report_stops_when_plan_is_blocked() {
        let broken = EXAMPLE.replace("policyRef: default-policy", "policyRef: missing-policy");
        let report = plan_controller_report(
            KubernetesControllerOptions::bounded("mcp-gateway", "broken.yaml", 30, 3),
            &broken,
        )
        .unwrap();

        assert_eq!(report.completed_cycles, 1);
        assert_eq!(report.status, KubernetesPlanStatus::Blocked);
        assert_eq!(
            report.shutdown_reason,
            KubernetesControllerShutdownReason::PlanBlocked
        );
        assert_eq!(report.cycles[0].next_reconcile_after_seconds, None);
    }
}
