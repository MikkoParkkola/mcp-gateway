//! `TrustCard` and CBOM command handlers.

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    process::ExitCode,
};

use chrono::Utc;
use mcp_gateway::{
    capability::CapabilityLoader,
    cli::{
        TrustCommand, TrustLabCommand,
        invoke::{ToolCatalogue, execute_tool},
        output::OutputFormat,
    },
    trust::{
        TrustAssistantPrompt, TrustCard, TrustCardAssistant, TrustCardValidator,
        TrustEvaluationStatus, TrustFindingSeverity,
        lab::{
            CatalogTrustLab, TrustLabBaseline, TrustLabEvaluation, TrustLabFixtureCall,
            TrustLabFixtureExecution, TrustLabPolicy, TrustLabPolicyVerdict, TrustLabProfile,
            TrustLabRuntimeEvidence,
        },
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TRUST_LAB_BASELINE_REGISTRY_VERSION: &str = "trust_lab.baseline_registry.v1";
const TRUST_LAB_BASELINE_REGISTRY_MANIFEST: &str = "manifest.json";
const TRUST_LAB_BASELINE_REGISTRY_DIR: &str = "baselines";

/// Run a `trust` subcommand.
pub async fn run_trust_command(cmd: TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::Generate {
            capabilities,
            format,
            output,
        } => match generate_cards_from_capabilities(&capabilities).await {
            Ok(cards) => {
                if let Some(output) = output {
                    if let Err(e) = write_cards_json(&cards, &output).await {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                    eprintln!("Wrote {}", output.display());
                }
                print_cards(&cards, format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TrustCommand::Inspect {
            name,
            capabilities,
            format,
        } => match generate_cards_from_capabilities(&capabilities).await {
            Ok(cards) => {
                if let Some(card) = cards.iter().find(|card| card.server.name == name) {
                    print_card(card, format);
                    ExitCode::SUCCESS
                } else {
                    eprintln!(
                        "Error: no capability named '{name}' found under {}",
                        capabilities.display()
                    );
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TrustCommand::Validate {
            file,
            capabilities,
            strict,
            format,
        } => {
            let cards = if let Some(file) = file {
                match read_card_file(&file).await {
                    Ok(card) => vec![card.with_validation()],
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                match generate_cards_from_capabilities(&capabilities).await {
                    Ok(cards) => cards,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            };

            print_validation_report(&cards, format);
            validation_exit_code(&cards, strict)
        }
        TrustCommand::Lab(command) => run_trust_lab_command(command).await,
    }
}

async fn run_trust_lab_command(command: TrustLabCommand) -> ExitCode {
    match command {
        TrustLabCommand::Evaluate {
            name,
            capabilities,
            enforce,
            baseline,
            write_baseline,
            baseline_registry,
            update_baseline_registry,
            active_fixtures,
            execute_active_fixtures,
            baseline_id,
            minimum_score,
            certification_score,
            format,
        } => {
            let policy = TrustLabPolicy {
                profile: TrustLabProfile::LocalOneShot,
                minimum_score,
                certification_score,
                fail_on_blocking_findings: true,
                advisory_only: !enforce,
            };
            match run_lab_evaluation(
                &capabilities,
                name.as_deref(),
                LabEvaluationOptions {
                    policy,
                    baseline_path: baseline.as_deref(),
                    write_baseline_path: write_baseline.as_deref(),
                    baseline_registry_path: baseline_registry.as_deref(),
                    update_baseline_registry,
                    active_fixtures_path: active_fixtures.as_deref(),
                    active_fixture_mode: if execute_active_fixtures {
                        TrustLabActiveFixtureMode::ExecuteLocal
                    } else {
                        TrustLabActiveFixtureMode::DryRun
                    },
                    baseline_id: &baseline_id,
                },
            )
            .await
            {
                Ok(report) => {
                    if let Some(path) = report.written_baseline.as_ref() {
                        eprintln!("Wrote TrustLab baseline {}", path.display());
                    }
                    if let Some(path) = report.written_registry_baseline.as_ref() {
                        eprintln!("Updated TrustLab baseline registry {}", path.display());
                    }
                    print_lab_evaluations(&report.evaluations, format);
                    lab_exit_code(&report.evaluations, enforce)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn generate_cards_from_capabilities(capabilities: &Path) -> Result<Vec<TrustCard>, String> {
    let path = capabilities.to_str().ok_or_else(|| {
        format!(
            "capability path is not valid UTF-8: {}",
            capabilities.display()
        )
    })?;
    let mut cards: Vec<_> = CapabilityLoader::load_directory(path)
        .await
        .map_err(|e| {
            format!(
                "failed to load capabilities from {}: {e}",
                capabilities.display()
            )
        })?
        .iter()
        .map(|capability| TrustCard::from_capability(capability).with_validation())
        .collect();

    cards.sort_by(|left, right| left.server.name.cmp(&right.server.name));
    Ok(cards)
}

async fn read_card_file(path: &Path) -> Result<TrustCard, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str::<TrustCard>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustCard>(&content))
        .map_err(|e| format!("failed to parse TrustCard {}: {e}", path.display()))
}

async fn write_cards_json(cards: &[TrustCard], output: &Path) -> Result<(), String> {
    let body = serde_json::to_string_pretty(cards)
        .map_err(|e| format!("failed to serialize TrustCards: {e}"))?;
    tokio::fs::write(output, format!("{body}\n"))
        .await
        .map_err(|e| format!("failed to write {}: {e}", output.display()))
}

fn print_cards(cards: &[TrustCard], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(cards),
        OutputFormat::Plain => {
            for card in cards {
                println!("{}", card.server.name);
            }
        }
        OutputFormat::Table => print_card_table(cards),
    }
}

fn print_card(card: &TrustCard, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(card),
        OutputFormat::Plain | OutputFormat::Table => {
            println!("Name: {}", card.server.name);
            println!("Status: {:?}", card.evaluation_status);
            println!("Risk: {:?}", card.server.risk_class);
            println!("Transport: {:?}", card.server.transport);
            println!("Auth: {:?}", card.server.auth_mode);
            println!("Components: {}", card.cbom.components.len());
            print_findings(&card.findings);
            print_decision_prompts(&TrustCardAssistant::plan(card).human_decisions);
        }
    }
}

fn print_validation_report(cards: &[TrustCard], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let rows: Vec<_> = cards.iter().map(ValidationRow::from_card).collect();
            print_json(&rows);
        }
        OutputFormat::Plain => {
            for card in cards {
                let plan = TrustCardAssistant::plan(card);
                println!(
                    "{} {:?} decisions={}",
                    card.server.name,
                    card.evaluation_status,
                    plan.human_decisions.len()
                );
            }
        }
        OutputFormat::Table => {
            print_card_table(cards);
            for card in cards {
                if !card.findings.is_empty() {
                    println!();
                    println!("Findings for {}:", card.server.name);
                    print_findings(&card.findings);
                }
                let plan = TrustCardAssistant::plan(card);
                if !plan.human_decisions.is_empty() {
                    println!();
                    println!("Human decisions for {}:", card.server.name);
                    print_decision_prompts(&plan.human_decisions);
                }
            }
        }
    }
}

fn validation_exit_code(cards: &[TrustCard], strict: bool) -> ExitCode {
    let has_failure = cards
        .iter()
        .any(|card| card.evaluation_status == TrustEvaluationStatus::Failed);
    let has_warning = cards
        .iter()
        .any(|card| card.evaluation_status == TrustEvaluationStatus::Warning);

    if has_failure || (strict && has_warning) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
async fn evaluate_lab_from_capabilities(
    capabilities: &Path,
    name: Option<&str>,
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
) -> Result<Vec<TrustLabEvaluation>, String> {
    let cards = select_cards(capabilities, name).await?;
    evaluate_lab_cards(capabilities, &cards, policy, baseline, None).await
}

#[derive(Debug)]
struct LabEvaluationRun {
    evaluations: Vec<TrustLabEvaluation>,
    written_baseline: Option<PathBuf>,
    written_registry_baseline: Option<PathBuf>,
}

struct LabEvaluationOptions<'a> {
    policy: TrustLabPolicy,
    baseline_path: Option<&'a Path>,
    write_baseline_path: Option<&'a Path>,
    baseline_registry_path: Option<&'a Path>,
    update_baseline_registry: bool,
    active_fixtures_path: Option<&'a Path>,
    active_fixture_mode: TrustLabActiveFixtureMode,
    baseline_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustLabActiveFixtureMode {
    DryRun,
    ExecuteLocal,
}

async fn run_lab_evaluation(
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

async fn select_cards(capabilities: &Path, name: Option<&str>) -> Result<Vec<TrustCard>, String> {
    let cards = generate_cards_from_capabilities(capabilities).await?;
    if let Some(name) = name {
        let card = cards
            .iter()
            .find(|card| card.server.name == name)
            .ok_or_else(|| {
                format!(
                    "no capability named '{name}' found under {}",
                    capabilities.display()
                )
            })?;
        Ok(vec![card.clone()])
    } else {
        Ok(cards)
    }
}

#[cfg(test)]
async fn evaluate_lab_cards(
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
    )
    .await
}

async fn evaluate_lab_cards_with_mode(
    capabilities: &Path,
    cards: &[TrustCard],
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
    active_fixtures: Option<&TrustLabActiveFixtureSpec>,
    active_fixture_mode: TrustLabActiveFixtureMode,
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
            lab.evaluate_card_with_runtime_at(card, baseline, chrono::Utc::now(), runtime)
        } else {
            lab.evaluate_card_with_baseline_at(card, baseline, chrono::Utc::now())
        };
        evaluations.push(evaluation);
    }
    Ok(evaluations)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustLabActiveFixtureSpec {
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

async fn run_local_active_fixture_calls(
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
        let execution =
            match execute_tool(&catalogue, &fixture.tool_name, fixture.arguments.clone()).await {
                Ok(output) => TrustLabFixtureExecution::passed(output),
                Err(e) => {
                    TrustLabFixtureExecution::failed(format!("fixture execution failed: {e}"))
                }
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

async fn read_active_fixture_spec(path: &Path) -> Result<TrustLabActiveFixtureSpec, String> {
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

fn fixture_calls_for_card(
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

async fn read_lab_baseline(path: &Path) -> Result<TrustLabBaseline, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read TrustLab baseline {}: {e}", path.display()))?;
    serde_json::from_str::<TrustLabBaseline>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustLabBaseline>(&content))
        .map_err(|e| format!("failed to parse TrustLab baseline {}: {e}", path.display()))
}

async fn write_lab_baseline(baseline: &TrustLabBaseline, output: &Path) -> Result<(), String> {
    let body = serde_json::to_string_pretty(baseline)
        .map_err(|e| format!("failed to serialize TrustLab baseline: {e}"))?;
    tokio::fs::write(output, format!("{body}\n"))
        .await
        .map_err(|e| {
            format!(
                "failed to write TrustLab baseline {}: {e}",
                output.display()
            )
        })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct TrustLabBaselineRegistryManifest {
    schema_version: String,
    #[serde(default)]
    entries: BTreeMap<String, TrustLabBaselineRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustLabBaselineRegistryEntry {
    baseline_id: String,
    file: String,
    digest_sha256: String,
    tool_schema_count: usize,
    server_names: Vec<String>,
    updated_at: String,
}

async fn read_lab_registry_baseline(
    registry: &Path,
    baseline_id: &str,
) -> Result<Option<TrustLabBaseline>, String> {
    let baseline_path = lab_registry_baseline_path(registry, baseline_id)?;
    if !baseline_path.exists() {
        return Ok(None);
    }
    read_lab_baseline(&baseline_path).await.map(Some)
}

async fn write_lab_registry_baseline(
    registry: &Path,
    baseline_id: &str,
    cards: &[TrustCard],
) -> Result<PathBuf, String> {
    let baseline = lab_baseline_from_cards(baseline_id, cards);
    let baseline_path = lab_registry_baseline_path(registry, baseline_id)?;
    let Some(parent) = baseline_path.parent() else {
        return Err(format!(
            "failed to resolve TrustLab registry baseline parent for {}",
            baseline_path.display()
        ));
    };
    tokio::fs::create_dir_all(parent).await.map_err(|e| {
        format!(
            "failed to create TrustLab baseline registry {}: {e}",
            parent.display()
        )
    })?;
    write_lab_baseline(&baseline, &baseline_path).await?;

    let mut manifest = read_lab_registry_manifest(registry).await?;
    manifest.schema_version = TRUST_LAB_BASELINE_REGISTRY_VERSION.to_string();
    manifest.entries.insert(
        baseline.baseline_id.clone(),
        TrustLabBaselineRegistryEntry {
            baseline_id: baseline.baseline_id.clone(),
            file: lab_registry_baseline_relative_path(&baseline.baseline_id)?,
            digest_sha256: lab_baseline_digest(&baseline)?,
            tool_schema_count: baseline.tool_schema_digests.len(),
            server_names: cards.iter().map(|card| card.server.name.clone()).collect(),
            updated_at: Utc::now().to_rfc3339(),
        },
    );
    write_lab_registry_manifest(registry, &manifest).await?;

    Ok(baseline_path)
}

async fn read_lab_registry_manifest(
    registry: &Path,
) -> Result<TrustLabBaselineRegistryManifest, String> {
    let manifest_path = registry.join(TRUST_LAB_BASELINE_REGISTRY_MANIFEST);
    if !manifest_path.exists() {
        return Ok(TrustLabBaselineRegistryManifest {
            schema_version: TRUST_LAB_BASELINE_REGISTRY_VERSION.to_string(),
            entries: BTreeMap::default(),
        });
    }
    let content = tokio::fs::read_to_string(&manifest_path)
        .await
        .map_err(|e| {
            format!(
                "failed to read TrustLab baseline registry manifest {}: {e}",
                manifest_path.display()
            )
        })?;
    serde_json::from_str::<TrustLabBaselineRegistryManifest>(&content).map_err(|e| {
        format!(
            "failed to parse TrustLab baseline registry manifest {}: {e}",
            manifest_path.display()
        )
    })
}

async fn write_lab_registry_manifest(
    registry: &Path,
    manifest: &TrustLabBaselineRegistryManifest,
) -> Result<(), String> {
    tokio::fs::create_dir_all(registry).await.map_err(|e| {
        format!(
            "failed to create TrustLab baseline registry {}: {e}",
            registry.display()
        )
    })?;
    let manifest_path = registry.join(TRUST_LAB_BASELINE_REGISTRY_MANIFEST);
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("failed to serialize TrustLab baseline registry manifest: {e}"))?;
    tokio::fs::write(&manifest_path, format!("{body}\n"))
        .await
        .map_err(|e| {
            format!(
                "failed to write TrustLab baseline registry manifest {}: {e}",
                manifest_path.display()
            )
        })
}

fn lab_registry_baseline_path(registry: &Path, baseline_id: &str) -> Result<PathBuf, String> {
    Ok(registry.join(lab_registry_baseline_relative_path(baseline_id)?))
}

fn lab_registry_baseline_relative_path(baseline_id: &str) -> Result<String, String> {
    let file_name = lab_registry_baseline_file_name(baseline_id)?;
    Ok(format!("{TRUST_LAB_BASELINE_REGISTRY_DIR}/{file_name}"))
}

fn lab_registry_baseline_file_name(baseline_id: &str) -> Result<String, String> {
    if baseline_id.is_empty() || baseline_id == "." || baseline_id == ".." {
        return Err("TrustLab baseline id must be non-empty and cannot be '.' or '..'".to_string());
    }
    if baseline_id.starts_with('.') {
        return Err("TrustLab baseline id cannot start with '.'".to_string());
    }
    if !baseline_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "TrustLab baseline id '{baseline_id}' is not registry-safe; use only ASCII letters, numbers, '.', '-', or '_'"
        ));
    }
    Ok(format!("{baseline_id}.json"))
}

fn lab_baseline_digest(baseline: &TrustLabBaseline) -> Result<String, String> {
    let value = serde_json::to_value(baseline)
        .map_err(|e| format!("failed to serialize TrustLab baseline for digest: {e}"))?;
    let canonical = serde_json::to_string(&value)
        .map_err(|e| format!("failed to canonicalize TrustLab baseline for digest: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn lab_baseline_from_cards(baseline_id: &str, cards: &[TrustCard]) -> TrustLabBaseline {
    let mut baseline = TrustLabBaseline {
        baseline_id: baseline_id.to_string(),
        tool_schema_digests: std::collections::BTreeMap::default(),
    };
    for card in cards {
        let card_baseline = TrustLabBaseline::from_card(baseline_id, card);
        baseline
            .tool_schema_digests
            .extend(card_baseline.tool_schema_digests);
    }
    baseline
}

fn print_lab_evaluations(evaluations: &[TrustLabEvaluation], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(evaluations),
        OutputFormat::Plain => {
            for evaluation in evaluations {
                println!(
                    "{} {} {:?}",
                    evaluation.input.server_name, evaluation.score, evaluation.policy_verdict
                );
            }
        }
        OutputFormat::Table => print_lab_table(evaluations),
    }
}

fn print_lab_table(evaluations: &[TrustLabEvaluation]) {
    if evaluations.is_empty() {
        println!("No TrustLab evaluations generated.");
        return;
    }

    println!(
        "{:<28}  {:<5}  {:<10}  {:<12}  FINDINGS",
        "NAME", "SCORE", "VERDICT", "CERT"
    );
    println!("{}", "-".repeat(76));
    for evaluation in evaluations {
        println!(
            "{:<28}  {:<5}  {:<10}  {:<12}  {}",
            truncate(&evaluation.input.server_name, 28),
            evaluation.score,
            format!("{:?}", evaluation.policy_verdict),
            format!("{:?}", evaluation.certification.status),
            evaluation.findings.len()
        );
    }
}

fn lab_exit_code(evaluations: &[TrustLabEvaluation], enforce: bool) -> ExitCode {
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

fn print_card_table(cards: &[TrustCard]) {
    if cards.is_empty() {
        println!("No TrustCards generated.");
        return;
    }

    println!(
        "{:<28}  {:<12}  {:<8}  {:<10}  {:<8}  {:<8}  DECISIONS",
        "NAME", "STATUS", "RISK", "TRANSPORT", "AUTH", "FINDINGS"
    );
    println!("{}", "-".repeat(104));
    for card in cards {
        let plan = TrustCardAssistant::plan(card);
        println!(
            "{:<28}  {:<12}  {:<8}  {:<10}  {:<8}  {:<8}  {}",
            truncate(&card.server.name, 28),
            format!("{:?}", card.evaluation_status),
            format!("{:?}", card.server.risk_class),
            format!("{:?}", card.server.transport),
            format!("{:?}", card.server.auth_mode),
            card.findings.len(),
            plan.human_decisions.len()
        );
    }
}

fn print_findings(findings: &[mcp_gateway::trust::TrustFinding]) {
    if findings.is_empty() {
        println!("Findings: none");
        return;
    }

    println!("Findings:");
    for finding in findings {
        println!(
            "- {:?} {} {}: {}",
            finding.severity, finding.code, finding.field, finding.message
        );
    }
}

fn print_decision_prompts(prompts: &[TrustAssistantPrompt]) {
    if prompts.is_empty() {
        println!("Human decisions: none");
        return;
    }

    println!("Human decisions:");
    for prompt in prompts {
        println!(
            "- {:?} {}: {}",
            prompt.severity, prompt.prompt_id, prompt.question
        );
    }
}

fn print_json<T: Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error: failed to serialize JSON: {e}"),
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len.saturating_sub(3)])
    }
}

#[derive(Serialize)]
struct ValidationRow {
    name: String,
    status: TrustEvaluationStatus,
    risk_class: mcp_gateway::trust::TrustRiskClass,
    failure_count: usize,
    warning_count: usize,
    human_decision_count: usize,
    finding_codes: Vec<String>,
    human_decisions: Vec<TrustAssistantPrompt>,
}

impl ValidationRow {
    fn from_card(card: &TrustCard) -> Self {
        let report = TrustCardValidator::validate(card);
        let plan = TrustCardAssistant::plan(card);
        Self {
            name: card.server.name.clone(),
            status: report.status,
            risk_class: card.server.risk_class,
            failure_count: report
                .findings
                .iter()
                .filter(|finding| finding.severity == TrustFindingSeverity::Fail)
                .count(),
            warning_count: report
                .findings
                .iter()
                .filter(|finding| finding.severity == TrustFindingSeverity::Warn)
                .count(),
            human_decision_count: plan.human_decisions.len(),
            finding_codes: report
                .findings
                .into_iter()
                .map(|finding| finding.code)
                .collect(),
            human_decisions: plan.human_decisions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::trust::{
        TrustAuthMode,
        lab::{TrustLabFixtureCallStatus, TrustLabScannerStatus},
    };
    use tempfile::TempDir;

    fn write_capability(dir: &Path, name: &str) {
        let yaml = format!(
            r"
name: {name}
description: Read weather forecasts
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
auth:
  required: true
  type: api_key
schema:
  input:
    type: object
    properties:
      city:
        type: string
"
        );
        std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
    }

    fn write_executable_capability_with_invalid_method(dir: &Path, name: &str) {
        let yaml = format!(
            r"
name: {name}
description: Active fixture test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /fixture
      method: INVALID METHOD
auth:
  required: false
  type: none
schema:
  input:
    type: object
    properties:
      city:
        type: string
"
        );
        std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
    }

    #[tokio::test]
    async fn generate_cards_from_capabilities_sorts_and_validates() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather_z");
        write_capability(temp.path(), "weather_a");

        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        assert_eq!(cards[0].server.name, "weather_a");
        assert_eq!(cards[1].server.name, "weather_z");
        assert_eq!(cards[0].server.auth_mode, TrustAuthMode::Key);
        assert_eq!(cards[0].evaluation_status, TrustEvaluationStatus::Warning);
    }

    #[tokio::test]
    async fn validation_row_includes_grouped_human_decisions() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        let row = ValidationRow::from_card(&cards[0]);

        assert_eq!(row.name, "weather");
        assert!(row.human_decision_count >= 2);
        assert!(
            row.human_decisions
                .iter()
                .any(|prompt| prompt.prompt_id == "source-ownership")
        );
        assert!(
            row.human_decisions
                .iter()
                .any(|prompt| prompt.prompt_id == "license-review")
        );
    }

    #[tokio::test]
    async fn read_card_file_accepts_json_and_revalidates_on_command_path() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let card = generate_cards_from_capabilities(temp.path())
            .await
            .unwrap()
            .remove(0);
        let card_path = temp.path().join("trustcard.json");
        std::fs::write(&card_path, serde_json::to_string_pretty(&card).unwrap()).unwrap();

        let loaded = read_card_file(&card_path).await.unwrap().with_validation();

        assert_eq!(loaded.server.name, "weather");
        assert_eq!(loaded.evaluation_status, TrustEvaluationStatus::Warning);
    }

    #[tokio::test]
    async fn trust_validate_returns_failure_only_for_failures_or_strict_warnings() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        assert_eq!(validation_exit_code(&cards, false), ExitCode::SUCCESS);
        assert_eq!(validation_exit_code(&cards, true), ExitCode::FAILURE);

        let mut failed = cards[0].clone();
        failed.server.name.clear();
        let failed = failed.with_validation();

        assert_eq!(validation_exit_code(&[failed], false), ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn lab_evaluation_reports_warning_verdict_by_default() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let policy = TrustLabPolicy::default();

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
                .await
                .unwrap();

        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].input.server_name, "weather");
        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Warn);
        assert_eq!(lab_exit_code(&evaluations, false), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn lab_evaluation_enforce_mode_fails_blocking_thresholds() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let policy = TrustLabPolicy {
            advisory_only: false,
            minimum_score: 101,
            ..TrustLabPolicy::default()
        };

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
                .await
                .unwrap();

        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Block);
        assert_eq!(lab_exit_code(&evaluations, true), ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn lab_baseline_write_and_read_round_trips() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let baseline_path = temp.path().join("trustlab-baseline.json");

        let report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy::default(),
                baseline_path: None,
                write_baseline_path: Some(&baseline_path),
                baseline_registry_path: None,
                update_baseline_registry: false,
                active_fixtures_path: None,
                active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.written_baseline.as_deref(),
            Some(baseline_path.as_path())
        );
        let baseline = read_lab_baseline(&baseline_path).await.unwrap();
        assert_eq!(baseline.baseline_id, "weather-baseline");
        assert_eq!(baseline.tool_schema_digests.len(), 1);
    }

    #[tokio::test]
    async fn lab_baseline_registry_updates_manifest_and_reads_named_baseline() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let registry = temp.path().join("trustlab-registry");

        let write_report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy::default(),
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: Some(&registry),
                update_baseline_registry: true,
                active_fixtures_path: None,
                active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();

        let baseline_path = registry
            .join(TRUST_LAB_BASELINE_REGISTRY_DIR)
            .join("weather-baseline.json");
        assert_eq!(
            write_report.written_registry_baseline.as_deref(),
            Some(baseline_path.as_path())
        );

        let manifest_path = registry.join(TRUST_LAB_BASELINE_REGISTRY_MANIFEST);
        let manifest: TrustLabBaselineRegistryManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let entry = manifest.entries.get("weather-baseline").unwrap();
        assert_eq!(manifest.schema_version, TRUST_LAB_BASELINE_REGISTRY_VERSION);
        assert_eq!(entry.file, "baselines/weather-baseline.json");
        assert_eq!(entry.tool_schema_count, 1);
        assert_eq!(entry.server_names, vec!["weather".to_string()]);
        assert_eq!(entry.digest_sha256.len(), 64);

        let read_report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy::default(),
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: Some(&registry),
                update_baseline_registry: false,
                active_fixtures_path: None,
                active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read_report.evaluations[0].input.baseline_id,
            Some("weather-baseline".to_string())
        );
        assert!(
            read_report.evaluations[0]
                .input
                .baseline_digest_sha256
                .is_some()
        );
    }

    #[tokio::test]
    async fn lab_baseline_registry_requires_update_for_missing_entry() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let registry = temp.path().join("trustlab-registry");

        let err = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy::default(),
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: Some(&registry),
                update_baseline_registry: false,
                active_fixtures_path: None,
                active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
                baseline_id: "missing-baseline",
            },
        )
        .await
        .unwrap_err();

        assert!(err.contains("no TrustLab baseline 'missing-baseline' found"));
    }

    #[tokio::test]
    async fn lab_active_fixture_file_attaches_dry_run_evidence_for_matching_tool() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let fixtures_path = temp.path().join("trustlab-fixtures.json");
        std::fs::write(
            &fixtures_path,
            serde_json::json!({
                "provider": "cli_fixture_plan",
                "isolated": true,
                "fixtures": [
                    {
                        "tool_name": "weather",
                        "arguments": {"city": "Helsinki"},
                        "declared_safe": true
                    },
                    {
                        "tool_name": "delete_doc",
                        "arguments": {"id": "demo"},
                        "declared_safe": false
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy::default(),
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: None,
                update_baseline_registry: false,
                active_fixtures_path: Some(&fixtures_path),
                active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();

        let evaluation = &report.evaluations[0];
        assert_eq!(evaluation.runtime.provider, "cli_fixture_plan");
        assert!(evaluation.runtime.isolated);
        assert!(!evaluation.runtime.active_eval);
        assert_eq!(evaluation.runtime.fixture_calls.len(), 1);
        assert_eq!(evaluation.runtime.fixture_calls[0].tool_name, "weather");
        assert_eq!(
            evaluation.runtime.fixture_calls[0].status,
            TrustLabFixtureCallStatus::DryRun
        );
        assert!(!evaluation.runtime.fixture_calls[0].invoked);
        assert!(evaluation.scanners.iter().any(|scanner| {
            scanner.scanner_id == mcp_gateway::trust::lab::TRUST_LAB_ACTIVE_FIXTURE_SCANNER
                && scanner.status == TrustLabScannerStatus::Warn
        }));
        assert!(
            evaluation
                .findings
                .iter()
                .any(|finding| finding.code == "TRUSTLAB_ACTIVE_FIXTURE_DRY_RUN")
        );
        assert_eq!(
            evaluation.certification.status,
            mcp_gateway::trust::lab::TrustLabCertificationStatus::Provisional
        );
    }

    #[tokio::test]
    async fn lab_execute_active_fixtures_requires_fixture_file() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");

        let err = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy {
                    advisory_only: false,
                    ..TrustLabPolicy::default()
                },
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: None,
                update_baseline_registry: false,
                active_fixtures_path: None,
                active_fixture_mode: TrustLabActiveFixtureMode::ExecuteLocal,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err, "--execute-active-fixtures requires --active-fixtures");
    }

    #[tokio::test]
    async fn lab_execute_active_fixtures_skips_non_isolated_runtime() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let fixtures_path = temp.path().join("trustlab-fixtures.json");
        std::fs::write(
            &fixtures_path,
            serde_json::json!({
                "isolated": false,
                "fixtures": [
                    {
                        "tool_name": "weather",
                        "arguments": {"city": "Helsinki"},
                        "declared_safe": true
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy {
                    advisory_only: false,
                    ..TrustLabPolicy::default()
                },
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: None,
                update_baseline_registry: false,
                active_fixtures_path: Some(&fixtures_path),
                active_fixture_mode: TrustLabActiveFixtureMode::ExecuteLocal,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();

        let evaluation = &report.evaluations[0];
        assert_eq!(evaluation.runtime.provider, "cli_local_capability_executor");
        assert!(!evaluation.runtime.isolated);
        assert!(!evaluation.runtime.active_eval);
        assert_eq!(
            evaluation.runtime.fixture_calls[0].status,
            TrustLabFixtureCallStatus::Skipped
        );
        assert!(!evaluation.runtime.fixture_calls[0].invoked);
        assert!(
            evaluation
                .findings
                .iter()
                .any(|finding| finding.code == "TRUSTLAB_ACTIVE_RUNTIME_NOT_ISOLATED")
        );
    }

    #[tokio::test]
    async fn lab_execute_active_fixtures_records_capability_execution_failure() {
        let temp = TempDir::new().unwrap();
        write_executable_capability_with_invalid_method(temp.path(), "weather");
        let fixtures_path = temp.path().join("trustlab-fixtures.json");
        std::fs::write(
            &fixtures_path,
            serde_json::json!({
                "isolated": true,
                "fixtures": [
                    {
                        "tool_name": "weather",
                        "arguments": {"city": "Helsinki"},
                        "declared_safe": true
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            LabEvaluationOptions {
                policy: TrustLabPolicy {
                    advisory_only: false,
                    ..TrustLabPolicy::default()
                },
                baseline_path: None,
                write_baseline_path: None,
                baseline_registry_path: None,
                update_baseline_registry: false,
                active_fixtures_path: Some(&fixtures_path),
                active_fixture_mode: TrustLabActiveFixtureMode::ExecuteLocal,
                baseline_id: "weather-baseline",
            },
        )
        .await
        .unwrap();

        let evaluation = &report.evaluations[0];
        assert!(evaluation.runtime.isolated);
        assert!(evaluation.runtime.active_eval);
        assert_eq!(
            evaluation.runtime.fixture_calls[0].status,
            TrustLabFixtureCallStatus::Failed
        );
        assert!(evaluation.runtime.fixture_calls[0].invoked);
        assert!(
            evaluation.runtime.fixture_calls[0]
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("fixture execution failed")
        );
        assert_eq!(evaluation.policy_verdict, TrustLabPolicyVerdict::Block);
        assert!(
            evaluation
                .findings
                .iter()
                .any(|finding| finding.code == "TRUSTLAB_ACTIVE_FIXTURE_FAILED")
        );
    }

    #[test]
    fn lab_baseline_registry_rejects_path_traversal_ids() {
        assert!(lab_registry_baseline_file_name("../weather").is_err());
        assert!(lab_registry_baseline_file_name("nested/weather").is_err());
        assert!(lab_registry_baseline_file_name(".hidden").is_err());
        assert_eq!(
            lab_registry_baseline_file_name("weather-prod_1.0").unwrap(),
            "weather-prod_1.0.json"
        );
    }

    #[tokio::test]
    async fn lab_baseline_detects_schema_drift_in_enforce_mode() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();
        let baseline = lab_baseline_from_cards("baseline-1", &cards);

        let changed = r"
name: weather
description: Read weather forecasts
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
auth:
  required: true
  type: api_key
schema:
  input:
    type: object
    properties:
      postal_code:
        type: string
";
        std::fs::write(temp.path().join("weather.yaml"), changed).unwrap();
        let policy = TrustLabPolicy {
            advisory_only: false,
            ..TrustLabPolicy::default()
        };

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, Some(&baseline))
                .await
                .unwrap();

        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Block);
        assert!(
            evaluations[0]
                .findings
                .iter()
                .any(|finding| finding.code == "TRUSTLAB_SCHEMA_DRIFT")
        );
    }
}
