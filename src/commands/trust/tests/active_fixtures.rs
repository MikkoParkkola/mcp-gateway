// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustLab` active-fixture tests.

use super::fixture_server::spawn_loopback_fixture_server;
use super::*;

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
            runtime_provider: None,
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
            runtime_provider: None,
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
            runtime_provider: None,
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
async fn lab_execute_active_fixtures_runs_safe_loopback_fixture_when_isolated() {
    let temp = TempDir::new().unwrap();
    let (base_url, request_rx) = spawn_loopback_fixture_server();
    write_loopback_executable_capability(temp.path(), "weather", &base_url);
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
            runtime_provider: None,
            baseline_id: "weather-baseline",
        },
    )
    .await
    .unwrap();

    let request = request_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        request.starts_with("GET /fixture/Helsinki "),
        "fixture request should carry the substituted safe argument: {request}"
    );

    let evaluation = &report.evaluations[0];
    assert!(evaluation.runtime.isolated);
    assert!(evaluation.runtime.active_eval);
    assert_eq!(evaluation.runtime.provider, "cli_local_capability_executor");
    assert_eq!(evaluation.runtime.fixture_calls.len(), 1);
    assert_eq!(
        evaluation.runtime.fixture_calls[0].status,
        TrustLabFixtureCallStatus::Passed
    );
    assert!(evaluation.runtime.fixture_calls[0].invoked);
    assert_eq!(
        evaluation.runtime.fixture_calls[0]
            .result_digest_sha256
            .as_deref()
            .map(str::len),
        Some(64)
    );
    assert!(evaluation.scanners.iter().any(|scanner| {
        scanner.scanner_id == mcp_gateway::trust::lab::TRUST_LAB_ACTIVE_FIXTURE_SCANNER
            && scanner.status == TrustLabScannerStatus::Pass
    }));
    assert!(!evaluation.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "TRUSTLAB_ACTIVE_RUNTIME_NOT_ISOLATED"
                | "TRUSTLAB_ACTIVE_FIXTURE_DRY_RUN"
                | "TRUSTLAB_ACTIVE_FIXTURE_FAILED"
        )
    }));

    let serialized = serde_json::to_string(evaluation).unwrap();
    assert!(!serialized.contains("Helsinki"));
    assert!(!serialized.contains("sunny"));
    assert!(!serialized.contains("raw_fixture_payload"));
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
            runtime_provider: None,
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
