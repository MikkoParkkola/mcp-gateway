// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime and runtime-provider evidence, and the findings derived from it.

use super::analysis::lab_finding;
use crate::runtime::RuntimeDenyReason;
use crate::runtime::{
    RuntimeLicenseTier, RuntimePlan, RuntimeProviderKind, RuntimeProviderSelection,
};
use crate::trust::TrustFindingSeverity;
use crate::trust::{TrustEvidenceKind, TrustFinding};
use serde::{Deserialize, Serialize};

use super::{TrustLabFixtureCallReport, TrustLabFixtureCallStatus};

/// Runtime evidence captured for the evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabRuntimeEvidence {
    /// Runtime provider identifier.
    pub provider: String,
    /// Whether runtime isolation was used or the run was static-only.
    pub isolated: bool,
    /// Whether active fixture calls were enabled.
    pub active_eval: bool,
    /// Whether every planned call was explicitly safe.
    pub safe_fixture_only: bool,
    /// Planned or invoked fixture calls.
    #[serde(default)]
    pub fixture_calls: Vec<TrustLabFixtureCallReport>,
    /// Optional `RuntimeProvider` plan evidence for active fixture execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_provider_plan: Option<TrustLabRuntimeProviderPlanEvidence>,
}

impl TrustLabRuntimeEvidence {
    pub(super) fn static_advisory() -> Self {
        Self {
            provider: "static_advisory".to_string(),
            isolated: true,
            active_eval: false,
            safe_fixture_only: true,
            fixture_calls: Vec::new(),
            runtime_provider_plan: None,
        }
    }

    /// Attach a `RuntimeProvider` plan summary without mutating fixture-call
    /// execution evidence.
    #[must_use]
    pub fn with_runtime_provider_plan(mut self, plan: TrustLabRuntimeProviderPlanEvidence) -> Self {
        self.runtime_provider_plan = Some(plan);
        self
    }
}

pub(super) fn runtime_findings(runtime: &TrustLabRuntimeEvidence) -> Vec<TrustFinding> {
    let mut findings = Vec::new();

    if let Some(plan) = &runtime.runtime_provider_plan {
        if !plan.denied_reasons.is_empty() {
            findings.push(lab_finding(
                "TRUSTLAB_RUNTIME_PROVIDER_PLAN_DENIED",
                TrustFindingSeverity::Fail,
                "runtime.runtime_provider_plan.denied_reasons",
                "RuntimeProvider plan denied active fixture execution",
                "Resolve the denied RuntimeProvider preflight before treating active fixture evidence as certifying.",
                TrustEvidenceKind::Observed,
            ));
        }
        if !plan.confirmation_ids.is_empty() {
            findings.push(lab_finding(
                "TRUSTLAB_RUNTIME_PROVIDER_CONFIRMATION_REQUIRED",
                TrustFindingSeverity::Fail,
                "runtime.runtime_provider_plan.confirmation_ids",
                "RuntimeProvider plan requires human approval before active execution",
                "Approve the required runtime confirmations or choose a lower-risk provider policy before certification.",
                TrustEvidenceKind::Observed,
            ));
        }
    }

    if !runtime.fixture_calls.is_empty() && !runtime.isolated {
        findings.push(lab_finding(
            "TRUSTLAB_ACTIVE_RUNTIME_NOT_ISOLATED",
            TrustFindingSeverity::Fail,
            "runtime.isolated",
            "Active fixture evaluation requires an isolated runtime",
            "Run active evaluation through RuntimeProvider isolation before trusting runtime evidence.",
            TrustEvidenceKind::Observed,
        ));
    }

    for fixture in &runtime.fixture_calls {
        if !fixture.declared_safe {
            findings.push(lab_finding(
                "TRUSTLAB_UNSAFE_FIXTURE_SKIPPED",
                TrustFindingSeverity::Warn,
                format!("runtime.fixture_calls[{}]", fixture.tool_name),
                "Fixture was skipped because it was not explicitly declared safe",
                "Review the fixture and mark it safe only when it cannot mutate state or exfiltrate data.",
                TrustEvidenceKind::Observed,
            ));
        } else if fixture.status == TrustLabFixtureCallStatus::Skipped {
            findings.push(lab_finding(
                "TRUSTLAB_ACTIVE_FIXTURE_SKIPPED",
                TrustFindingSeverity::Warn,
                format!("runtime.fixture_calls[{}]", fixture.tool_name),
                "Declared-safe fixture was not invoked",
                "Rerun active evaluation after resolving the runtime skip reason.",
                TrustEvidenceKind::Observed,
            ));
        } else if fixture.status == TrustLabFixtureCallStatus::DryRun {
            findings.push(lab_finding(
                "TRUSTLAB_ACTIVE_FIXTURE_DRY_RUN",
                TrustFindingSeverity::Warn,
                format!("runtime.fixture_calls[{}]", fixture.tool_name),
                "Declared-safe fixture was dry-run only and was not invoked",
                "Run the fixture through an isolated RuntimeProvider-backed runner before certification.",
                TrustEvidenceKind::Observed,
            ));
        } else if fixture.status == TrustLabFixtureCallStatus::Failed {
            findings.push(lab_finding(
                "TRUSTLAB_ACTIVE_FIXTURE_FAILED",
                TrustFindingSeverity::Fail,
                format!("runtime.fixture_calls[{}]", fixture.tool_name),
                fixture
                    .error
                    .as_deref()
                    .unwrap_or("Active fixture call failed"),
                "Keep the candidate disabled until the safe fixture passes in isolation.",
                TrustEvidenceKind::Observed,
            ));
        }
    }

    findings
}

/// `RuntimeProvider` plan summary attached to active fixture evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustLabRuntimeProviderPlanEvidence {
    /// Planned provider kind.
    pub provider_kind: String,
    /// License tier for the planned provider.
    pub license_tier: String,
    /// Runtime policy id.
    pub policy_id: String,
    /// How the provider was selected.
    pub selected_by: String,
    /// Required preflight checks.
    #[serde(default)]
    pub preflight_checks: Vec<String>,
    /// Confirmation ids required before apply.
    #[serde(default)]
    pub confirmation_ids: Vec<String>,
    /// Denied reason codes.
    #[serde(default)]
    pub denied_reasons: Vec<String>,
    /// Structured launch program, if the provider can emit one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_program: Option<String>,
    /// Digest of structured launch args, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_args_digest_sha256: Option<String>,
    /// Provider health check instruction.
    pub health_check: String,
    /// Rollback instruction.
    pub rollback_step: String,
}

impl TrustLabRuntimeProviderPlanEvidence {
    /// Convert a `RuntimeProvider` plan into value-free `TrustLab` evidence.
    #[must_use]
    pub fn from_runtime_plan(plan: &RuntimePlan) -> Self {
        Self {
            provider_kind: runtime_provider_kind_name(plan.provider).to_string(),
            license_tier: runtime_license_tier_name(plan.audit.license_tier).to_string(),
            policy_id: plan.policy.id.clone(),
            selected_by: runtime_selection_name(plan.recommendation.selected_by).to_string(),
            preflight_checks: plan
                .preflight_checks
                .iter()
                .map(|check| check.check.clone())
                .collect(),
            confirmation_ids: plan
                .confirmations
                .iter()
                .map(|confirmation| confirmation.id.clone())
                .collect(),
            denied_reasons: plan
                .denied
                .iter()
                .map(|denial| runtime_deny_reason_name(denial.reason).to_string())
                .collect(),
            launch_program: plan
                .launch_command
                .as_ref()
                .map(|command| command.program.clone()),
            launch_args_digest_sha256: plan
                .launch_command
                .as_ref()
                .map(crate::runtime::RuntimeLaunchCommand::args_digest_sha256),
            health_check: plan.lifecycle.health_check.clone(),
            rollback_step: plan.rollback_step.clone(),
        }
    }
}

pub(super) fn runtime_provider_kind_name(kind: RuntimeProviderKind) -> &'static str {
    match kind {
        RuntimeProviderKind::LocalProcess => "local_process",
        RuntimeProviderKind::Docker => "docker",
        RuntimeProviderKind::Podman => "podman",
        RuntimeProviderKind::Systemd => "systemd",
        RuntimeProviderKind::Launchd => "launchd",
        RuntimeProviderKind::Kubernetes => "kubernetes",
    }
}

pub(super) fn runtime_license_tier_name(tier: RuntimeLicenseTier) -> &'static str {
    match tier {
        RuntimeLicenseTier::FreeCore => "free_core",
        RuntimeLicenseTier::Enterprise => "enterprise",
    }
}

pub(super) fn runtime_selection_name(selection: RuntimeProviderSelection) -> &'static str {
    match selection {
        RuntimeProviderSelection::OperatorPreference => "operator_preference",
        RuntimeProviderSelection::IsolationPreferred => "isolation_preferred",
        RuntimeProviderSelection::CompatibilityFallback => "compatibility_fallback",
    }
}

pub(super) fn runtime_deny_reason_name(reason: RuntimeDenyReason) -> &'static str {
    match reason {
        RuntimeDenyReason::RuntimeUnavailable => "runtime_unavailable",
        RuntimeDenyReason::MissingContainerImage => "missing_container_image",
        RuntimeDenyReason::InvalidResourcePolicy => "invalid_resource_policy",
        RuntimeDenyReason::ForbiddenMount => "forbidden_mount",
    }
}
