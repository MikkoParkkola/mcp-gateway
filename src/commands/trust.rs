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

use super::{CliExit, fail, usage, verdict};

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
                        return fail(
                            CliExit::LocalFailure,
                            &e,
                            &format!("Check that you can write {}.", output.display()),
                        );
                    }
                    eprintln!("Wrote {}", output.display());
                }
                print_cards(&cards, format)
            }
            Err(e) => capabilities_failure(&capabilities, &e),
        },
        TrustCommand::Inspect {
            name,
            capabilities,
            format,
        } => match generate_cards_from_capabilities(&capabilities).await {
            Ok(cards) => {
                if let Some(card) = cards.iter().find(|card| card.server.name == name) {
                    print_card(card, format)
                } else {
                    fail(
                        CliExit::LocalFailure,
                        &format!(
                            "no capability named '{name}' found under {}",
                            capabilities.display()
                        ),
                        "Run 'mcp-gateway trust generate' on the same folder to see the names.",
                    )
                }
            }
            Err(e) => capabilities_failure(&capabilities, &e),
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
                        return fail(
                            CliExit::LocalFailure,
                            &e,
                            &format!("Check that {} exists and is a TrustCard.", file.display()),
                        );
                    }
                }
            } else {
                match generate_cards_from_capabilities(&capabilities).await {
                    Ok(cards) => cards,
                    Err(e) => return capabilities_failure(&capabilities, &e),
                }
            };

            let printed = print_validation_report(&cards, format);
            if printed != ExitCode::SUCCESS {
                return printed;
            }
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
            // A flag missing its partner is a wrong invocation, refused before the evaluation writes anything.
            if update_baseline_registry && baseline_registry.is_none() {
                return usage(
                    "trust lab evaluate",
                    "--update-baseline-registry requires --baseline-registry",
                );
            }
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
                    let printed = print_lab_evaluations(&report.evaluations, format);
                    if printed != ExitCode::SUCCESS {
                        return printed;
                    }
                    lab_exit_code(&report.evaluations, enforce)
                }
                // The evaluation reads the capabilities and any baseline, registry or fixture file it was given.
                Err(e) => fail(
                    CliExit::LocalFailure,
                    &e,
                    &format!(
                        "Check {} and any baseline, registry or fixture file the message names, then rerun.",
                        capabilities.display()
                    ),
                ),
            }
        }
    }
}

/// The capabilities under `capabilities` could not be read or carded: the remedy names the folder.
fn capabilities_failure(capabilities: &Path, error: &str) -> ExitCode {
    fail(
        CliExit::LocalFailure,
        error,
        &format!(
            "Check that {} exists and holds capability files.",
            capabilities.display()
        ),
    )
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
        .or_else(|_| crate::yaml::from_str::<TrustCard>(&content))
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
        verdict(1)
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

#[cfg(tp2)]
#[cfg(test)]
mod tests;
