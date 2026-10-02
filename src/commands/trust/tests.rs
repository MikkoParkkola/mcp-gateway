// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the `trust` command handlers.

use super::*;
use super::{
    baseline::{
        TRUST_LAB_BASELINE_REGISTRY_DIR, TRUST_LAB_BASELINE_REGISTRY_MANIFEST,
        TRUST_LAB_BASELINE_REGISTRY_VERSION, TrustLabBaselineRegistryManifest,
        lab_baseline_from_cards, lab_registry_baseline_file_name, read_lab_baseline,
    },
    lab::{
        LabEvaluationOptions, TrustLabActiveFixtureMode, TrustLabRuntimeProviderOptions,
        evaluate_lab_from_capabilities, lab_exit_code, run_lab_evaluation,
    },
    output::ValidationRow,
};
use mcp_gateway::{
    runtime::{RuntimeAvailability, RuntimeProviderKind},
    trust::{
        TrustAuthMode,
        lab::{
            TrustLabFixtureCallStatus, TrustLabPolicy, TrustLabPolicyVerdict, TrustLabScannerStatus,
        },
    },
};
use std::path::Path;
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

fn write_loopback_executable_capability(dir: &Path, name: &str, base_url: &str) {
    let yaml = format!(
        r#"
name: {name}
description: Active fixture test capability
providers:
  primary:
    service: rest
    config:
      base_url: "{base_url}"
      path: /fixture/{{city}}
      method: GET
auth:
  required: false
  type: none
metadata:
  read_only: true
  destructive: false
  idempotent: true
  open_world: false
schema:
  input:
    type: object
    properties:
      city:
        type: string
"#
    );
    std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
}

mod active_fixtures;
mod fixture_server;

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

    let evaluations = evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
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

    let evaluations = evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
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
            runtime_provider: None,
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
            runtime_provider: None,
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
            runtime_provider: None,
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
            runtime_provider: None,
            baseline_id: "missing-baseline",
        },
    )
    .await
    .unwrap_err();

    assert!(err.contains("no TrustLab baseline 'missing-baseline' found"));
}

#[tokio::test]
async fn lab_runtime_provider_plan_attaches_docker_evidence() {
    let temp = TempDir::new().unwrap();
    write_capability(temp.path(), "weather");
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
            policy: TrustLabPolicy::default(),
            baseline_path: None,
            write_baseline_path: None,
            baseline_registry_path: None,
            update_baseline_registry: false,
            active_fixtures_path: Some(&fixtures_path),
            active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
            runtime_provider: Some(TrustLabRuntimeProviderOptions {
                provider: RuntimeProviderKind::Docker,
                image: Some("ghcr.io/example/weather-fixture:latest".to_string()),
                availability: RuntimeAvailability::with_docker(),
            }),
            baseline_id: "weather-baseline",
        },
    )
    .await
    .unwrap();

    let plan = report.evaluations[0]
        .runtime
        .runtime_provider_plan
        .as_ref()
        .expect("runtime provider plan evidence");
    assert_eq!(plan.provider_kind, "docker");
    assert_eq!(plan.license_tier, "free_core");
    assert_eq!(plan.launch_program.as_deref(), Some("docker"));
    assert_eq!(
        plan.launch_args_digest_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert!(plan.denied_reasons.is_empty());
    assert!(
        plan.preflight_checks
            .iter()
            .any(|check| check == "docker info")
    );
}

#[tokio::test]
async fn lab_runtime_provider_plan_denial_blocks_certification() {
    let temp = TempDir::new().unwrap();
    write_capability(temp.path(), "weather");
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
            active_fixture_mode: TrustLabActiveFixtureMode::DryRun,
            runtime_provider: Some(TrustLabRuntimeProviderOptions {
                provider: RuntimeProviderKind::Docker,
                image: None,
                availability: RuntimeAvailability::with_docker(),
            }),
            baseline_id: "weather-baseline",
        },
    )
    .await
    .unwrap();

    let evaluation = &report.evaluations[0];
    let plan = evaluation
        .runtime
        .runtime_provider_plan
        .as_ref()
        .expect("runtime provider plan evidence");
    assert_eq!(plan.denied_reasons, vec!["missing_container_image"]);
    assert!(
        evaluation
            .findings
            .iter()
            .any(|finding| finding.code == "TRUSTLAB_RUNTIME_PROVIDER_PLAN_DENIED")
    );
    assert_eq!(evaluation.policy_verdict, TrustLabPolicyVerdict::Block);
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
