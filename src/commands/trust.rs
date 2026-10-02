// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustCard` and CBOM command handlers.

use std::{path::Path, process::ExitCode};

use mcp_gateway::{
    capability::CapabilityLoader,
    cli::{TrustCommand, TrustLabCommand},
    trust::{
        TrustCard, TrustEvaluationStatus,
        lab::{TrustLabPolicy, TrustLabProfile},
    },
};

mod baseline;
mod lab;
mod output;

use lab::{
    LabEvaluationOptions, TrustLabActiveFixtureMode, TrustLabRuntimeProviderOptions,
    detect_runtime_availability, lab_exit_code, run_lab_evaluation, runtime_provider_kind,
};
use output::{print_card, print_cards, print_lab_evaluations, print_validation_report};

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
            runtime_provider_plan,
            runtime_image,
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
                    runtime_provider: runtime_provider_plan.map(|provider| {
                        TrustLabRuntimeProviderOptions {
                            provider: runtime_provider_kind(provider),
                            image: runtime_image.clone(),
                            availability: detect_runtime_availability(),
                        }
                    }),
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
mod tests;
