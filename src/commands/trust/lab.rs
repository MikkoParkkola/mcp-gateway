// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustLab` evaluation: baseline selection, active fixtures and runtime-provider evidence.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use mcp_gateway::{
    capability::CapabilityExecutionContext,
    cli::{
        RuntimeProviderArg,
        invoke::{ToolCatalogue, execute_tool_with_context},
    },
    runtime::{
        RuntimeAvailability, RuntimeDataClass, RuntimeIntent, RuntimeNetworkEgress, RuntimePlan,
        RuntimePlanner, RuntimeProviderKind,
    },
    trust::{
        TrustCard,
        lab::{
            CatalogTrustLab, TrustLabBaseline, TrustLabEvaluation, TrustLabFixtureCall,
            TrustLabFixtureExecution, TrustLabPolicy, TrustLabPolicyVerdict,
            TrustLabRuntimeEvidence, TrustLabRuntimeProviderPlanEvidence,
        },
    },
};
use serde::{Deserialize, Serialize};

use super::{
    baseline::{
        lab_baseline_from_cards, read_lab_baseline, read_lab_registry_baseline, write_lab_baseline,
        write_lab_registry_baseline,
    },
    select_cards,
};

#[cfg(test)]
pub(super) async fn evaluate_lab_from_capabilities(
    capabilities: &Path,
    name: Option<&str>,
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
) -> Result<Vec<TrustLabEvaluation>, String> {
    let cards = select_cards(capabilities, name).await?;
    evaluate_lab_cards(capabilities, &cards, policy, baseline, None).await
}

#[derive(Debug)]
pub(super) struct LabEvaluationRun {
    pub(super) evaluations: Vec<TrustLabEvaluation>,
    pub(super) written_baseline: Option<PathBuf>,
    pub(super) written_registry_baseline: Option<PathBuf>,
}

pub(super) struct LabEvaluationOptions<'a> {
    pub(super) policy: TrustLabPolicy,
    pub(super) baseline_path: Option<&'a Path>,
    pub(super) write_baseline_path: Option<&'a Path>,
    pub(super) baseline_registry_path: Option<&'a Path>,
    pub(super) update_baseline_registry: bool,
    pub(super) active_fixtures_path: Option<&'a Path>,
    pub(super) active_fixture_mode: TrustLabActiveFixtureMode,
    pub(super) runtime_provider: Option<TrustLabRuntimeProviderOptions>,
    pub(super) baseline_id: &'a str,
}

#[derive(Debug, Clone)]
pub(super) struct TrustLabRuntimeProviderOptions {
    pub(super) provider: RuntimeProviderKind,
    pub(super) image: Option<String>,
    pub(super) availability: RuntimeAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrustLabActiveFixtureMode {
    DryRun,
    ExecuteLocal,
}

pub(super) async fn run_lab_evaluation(
    capabilities: &Path,
    name: Option<&str>,
    options: LabEvaluationOptions<'_>,
) -> Result<LabEvaluationRun, String> {
    let LabEvaluationOptions {
        policy,
        baseline_path,
        write_baseline_path,
        baseline_registry_path,
        update_baseline_registry,
        active_fixtures_path,
        active_fixture_mode,
        runtime_provider,
        baseline_id,
    } = options;
    if active_fixture_mode == TrustLabActiveFixtureMode::ExecuteLocal
        && active_fixtures_path.is_none()
    {
        return Err("--execute-active-fixtures requires --active-fixtures".to_string());
    }
    let cards = select_cards(capabilities, name).await?;
    let active_fixtures = match active_fixtures_path {
        Some(path) => Some(read_active_fixture_spec(path).await?),
        None => None,
    };
    let baseline = match baseline_path {
        Some(path) => Some(read_lab_baseline(path).await?),
        None => match baseline_registry_path {
            Some(path) => {
                let baseline = read_lab_registry_baseline(path, baseline_id).await?;
                if baseline.is_none() && !update_baseline_registry {
                    return Err(format!(
                        "no TrustLab baseline '{baseline_id}' found in registry {}; pass --update-baseline-registry to create it",
                        path.display()
                    ));
                }
                baseline
            }
            None => None,
        },
    };
    let evaluations = evaluate_lab_cards_with_mode(
        capabilities,
        &cards,
        policy,
        baseline.as_ref(),
        active_fixtures.as_ref(),
        active_fixture_mode,
        runtime_provider.as_ref(),
    )
    .await?;
    let written_baseline = match write_baseline_path {
        Some(path) => {
            let baseline = lab_baseline_from_cards(baseline_id, &cards);
            write_lab_baseline(&baseline, path).await?;
            Some(path.to_path_buf())
        }
        None => None,
    };
    let written_registry_baseline = match (baseline_registry_path, update_baseline_registry) {
        (Some(path), true) => Some(write_lab_registry_baseline(path, baseline_id, &cards).await?),
        (None, true) => {
            return Err("--update-baseline-registry requires --baseline-registry".to_string());
        }
        _ => None,
    };

    Ok(LabEvaluationRun {
        evaluations,
        written_baseline,
        written_registry_baseline,
    })
}

#[cfg(test)]
pub(super) async fn evaluate_lab_cards(
    capabilities: &Path,
    cards: &[TrustCard],
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
    active_fixtures: Option<&TrustLabActiveFixtureSpec>,
) -> Result<Vec<TrustLabEvaluation>, String> {
    evaluate_lab_cards_with_mode(
        capabilities,
        cards,
        policy,
        baseline,
        active_fixtures,
        TrustLabActiveFixtureMode::DryRun,
        None,
    )
    .await
}

pub(super) async fn evaluate_lab_cards_with_mode(
    capabilities: &Path,
    cards: &[TrustCard],
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
    active_fixtures: Option<&TrustLabActiveFixtureSpec>,
    active_fixture_mode: TrustLabActiveFixtureMode,
    runtime_provider: Option<&TrustLabRuntimeProviderOptions>,
) -> Result<Vec<TrustLabEvaluation>, String> {
    let lab = CatalogTrustLab::new(policy);
    let mut evaluations = Vec::with_capacity(cards.len());
    for card in cards {
        let evaluation = if let Some(spec) = active_fixtures {
            let fixtures = fixture_calls_for_card(card, &spec.fixtures);
            let provider_name = spec.provider_name(active_fixture_mode);
            let runtime = match active_fixture_mode {
                TrustLabActiveFixtureMode::DryRun => CatalogTrustLab::dry_run_active_fixture_calls(
                    provider_name,
                    spec.isolated,
                    &fixtures,
                ),
                TrustLabActiveFixtureMode::ExecuteLocal => {
                    run_local_active_fixture_calls(
                        capabilities,
                        provider_name,
                        spec.isolated,
                        &fixtures,
                    )
                    .await?
                }
            };
            let runtime = if let Some(runtime_provider) = runtime_provider {
                runtime.with_runtime_provider_plan(
                    TrustLabRuntimeProviderPlanEvidence::from_runtime_plan(
                        &compile_trustlab_runtime_plan(card, runtime_provider),
                    ),
                )
            } else {
                runtime
            };
            lab.evaluate_card_with_runtime_at(card, baseline, chrono::Utc::now(), runtime)
        } else {
            lab.evaluate_card_with_baseline_at(card, baseline, chrono::Utc::now())
        };
        evaluations.push(evaluation);
    }
    Ok(evaluations)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TrustLabActiveFixtureSpec {
    #[serde(default)]
    provider: Option<String>,
    isolated: bool,
    #[serde(default)]
    fixtures: Vec<TrustLabFixtureCall>,
}

impl TrustLabActiveFixtureSpec {
    fn provider_name(&self, mode: TrustLabActiveFixtureMode) -> &str {
        self.provider.as_deref().unwrap_or(match mode {
            TrustLabActiveFixtureMode::DryRun => "cli_active_fixture_dry_run",
            TrustLabActiveFixtureMode::ExecuteLocal => "cli_local_capability_executor",
        })
    }
}

pub(super) async fn run_local_active_fixture_calls(
    capabilities: &Path,
    provider: &str,
    isolated: bool,
    fixtures: &[TrustLabFixtureCall],
) -> Result<TrustLabRuntimeEvidence, String> {
    if !isolated || !fixtures.iter().any(|fixture| fixture.declared_safe) {
        return Ok(CatalogTrustLab::run_active_fixture_calls(
            provider,
            isolated,
            fixtures,
            |_| {
                TrustLabFixtureExecution::failed(
                    "internal error: fixture runner was invoked for an ineligible fixture",
                )
            },
        ));
    }

    let dir = capabilities.to_str().ok_or_else(|| {
        format!(
            "capability path is not valid UTF-8: {}",
            capabilities.display()
        )
    })?;
    let catalogue = ToolCatalogue::load(dir).await.map_err(|e| {
        format!(
            "failed to load capabilities for TrustLab active fixtures from {}: {e}",
            capabilities.display()
        )
    })?;
    let mut executions = VecDeque::new();
    for fixture in fixtures.iter().filter(|fixture| fixture.declared_safe) {
        let execution = match execute_tool_with_context(
            &catalogue,
            &fixture.tool_name,
            fixture.arguments.clone(),
            CapabilityExecutionContext::default().with_isolated_loopback_egress(),
        )
        .await
        {
            Ok(output) => TrustLabFixtureExecution::passed(output),
            Err(e) => TrustLabFixtureExecution::failed(format!("fixture execution failed: {e}")),
        };
        executions.push_back(execution);
    }

    Ok(CatalogTrustLab::run_active_fixture_calls(
        provider,
        isolated,
        fixtures,
        |_| {
            executions.pop_front().unwrap_or_else(|| {
                TrustLabFixtureExecution::failed("fixture execution result missing")
            })
        },
    ))
}

pub(super) fn compile_trustlab_runtime_plan(
    card: &TrustCard,
    options: &TrustLabRuntimeProviderOptions,
) -> RuntimePlan {
    let mut intent = RuntimeIntent::named(format!("trustlab-{}", card.server.name));
    intent.preferred_provider = Some(options.provider);
    intent.image.clone_from(&options.image);
    intent.data_class = RuntimeDataClass::Internal;
    intent.requested_egress = RuntimeNetworkEgress::None;

    let planner = RuntimePlanner::new(options.availability.clone());
    let policy = planner.compile_default_policy(&intent);
    planner.plan_with_policy(&intent, options.provider, policy)
}

pub(super) fn detect_runtime_availability() -> RuntimeAvailability {
    RuntimeAvailability {
        local_process: true,
        docker: command_succeeds("docker", &["info"]),
        podman: command_succeeds("podman", &["info"]),
        systemd: command_succeeds("systemctl", &["--user", "status"]),
        launchd: command_succeeds("launchctl", &["print", "gui/$UID"]),
        kubernetes: command_succeeds("kubectl", &["version", "--client"]),
    }
}

pub(super) fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub(super) fn runtime_provider_kind(provider: RuntimeProviderArg) -> RuntimeProviderKind {
    match provider {
        RuntimeProviderArg::LocalProcess => RuntimeProviderKind::LocalProcess,
        RuntimeProviderArg::Docker => RuntimeProviderKind::Docker,
        RuntimeProviderArg::Podman => RuntimeProviderKind::Podman,
        RuntimeProviderArg::Systemd => RuntimeProviderKind::Systemd,
        RuntimeProviderArg::Launchd => RuntimeProviderKind::Launchd,
        RuntimeProviderArg::Kubernetes => RuntimeProviderKind::Kubernetes,
    }
}

pub(super) async fn read_active_fixture_spec(
    path: &Path,
) -> Result<TrustLabActiveFixtureSpec, String> {
    let content = tokio::fs::read_to_string(path).await.map_err(|e| {
        format!(
            "failed to read TrustLab active fixtures {}: {e}",
            path.display()
        )
    })?;
    let spec = serde_json::from_str::<TrustLabActiveFixtureSpec>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustLabActiveFixtureSpec>(&content))
        .map_err(|e| {
            format!(
                "failed to parse TrustLab active fixtures {}: {e}",
                path.display()
            )
        })?;
    Ok(spec)
}

pub(super) fn fixture_calls_for_card(
    card: &TrustCard,
    fixtures: &[TrustLabFixtureCall],
) -> Vec<TrustLabFixtureCall> {
    let mut tool_names = std::collections::BTreeSet::from([card.server.name.clone()]);
    for component in card
        .cbom
        .components
        .iter()
        .filter(|component| component.kind == mcp_gateway::trust::CbomComponentKind::Tool)
    {
        tool_names.insert(component.name.clone());
        if let Some((_, local_name)) = component.name.rsplit_once(':') {
            tool_names.insert(local_name.to_string());
        }
    }

    fixtures
        .iter()
        .filter(|fixture| tool_names.contains(&fixture.tool_name))
        .cloned()
        .collect()
}

pub(super) fn lab_exit_code(evaluations: &[TrustLabEvaluation], enforce: bool) -> ExitCode {
    if enforce
        && evaluations
            .iter()
            .any(|evaluation| evaluation.policy_verdict == TrustLabPolicyVerdict::Block)
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
