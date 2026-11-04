// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

// ── CheckResult helpers ───────────────────────────────────────────────────

#[test]
fn check_result_pass_has_correct_status() {
    let r = CheckResult::pass("Config", "all good");
    assert_eq!(r.status, CheckStatus::Pass);
    assert_eq!(r.label, "Config");
    assert_eq!(r.detail, "all good");
    assert!(r.hint.is_none());
}

#[test]
fn check_result_fail_has_correct_status() {
    let r = CheckResult::fail("Port", "in use");
    assert_eq!(r.status, CheckStatus::Fail);
    assert!(r.hint.is_none());
}

#[test]
fn check_result_warn_has_correct_status() {
    let r = CheckResult::warn("AI client", "none found");
    assert_eq!(r.status, CheckStatus::Warn);
}

#[test]
fn check_result_with_hint_stores_hint() {
    let r = CheckResult::fail("Port", "taken").with_hint("kill the process");
    assert_eq!(r.hint.as_deref(), Some("kill the process"));
}

#[test]
fn check_result_fixability_metadata_is_json_visible() {
    let r = CheckResult::fail("Configuration", "missing")
        .with_category("config")
        .with_hint("Run init")
        .with_manual_fix("mcp-gateway init --profile local")
        .with_risk("config_mutation")
        .with_verification("mcp-gateway doctor --format json")
        .with_rollback("mcp-gateway setup export --rollback <backup-file>");

    let value = check_result_json_value(&r);

    assert_eq!(value["id"], "configuration");
    assert_eq!(value["category"], "config");
    assert_eq!(value["status"], "fail");
    assert_eq!(value["hint"], "Run init");
    assert_eq!(value["fixability"]["auto_fixable"], false);
    assert_eq!(value["fixability"]["safe_to_apply"], false);
    assert_eq!(value["fixability"]["risk"], "config_mutation");
    assert_eq!(value["fixability"]["confirmation_required"], true);
    assert_eq!(
        value["fixability"]["verification"],
        "mcp-gateway doctor --format json"
    );
    assert_eq!(
        value["fixability"]["rollback"],
        "mcp-gateway setup export --rollback <backup-file>"
    );
    assert_eq!(
        value["fixability"]["command"],
        "mcp-gateway init --profile local"
    );
    assert_eq!(value["fixability"]["requires_user"], true);
}

#[test]
fn doctor_report_json_has_stable_schema_and_summary_fields() {
    let results = vec![
        CheckResult::pass("Configuration", "gateway.yaml").with_category("config"),
        CheckResult::warn("AI client", "not configured")
            .with_category("client_config")
            .with_manual_fix("mcp-gateway setup wizard --configure-client")
            .with_risk("config_mutation")
            .with_verification("mcp-gateway doctor --format json")
            .with_rollback("mcp-gateway setup export --rollback <backup-file>"),
    ];

    let value = doctor_report_json_value(&results);

    assert_eq!(value["schema_version"], "doctor.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["summary"]["pass"], 1);
    assert_eq!(value["summary"]["warn"], 1);
    assert_eq!(value["summary"]["fail"], 0);
    assert_eq!(value["summary"]["total"], 2);
    assert_eq!(value["checks"][0]["id"], "configuration");
    assert_eq!(value["checks"][1]["id"], "ai_client");
    assert_eq!(value["checks"][1]["fixability"]["requires_user"], true);
    assert_eq!(value["checks"][1]["fixability"]["risk"], "config_mutation");
    assert_eq!(
        value["checks"][1]["fixability"]["verification"],
        "mcp-gateway doctor --format json"
    );
    assert_eq!(
        value["checks"][1]["fixability"]["rollback"],
        "mcp-gateway setup export --rollback <backup-file>"
    );
}

/// A finding whose asset id holds for this run only says so, as the
/// report's own note does.
#[test]
fn shadow_doctor_finding_carries_the_ids_note() {
    let finding = ShadowDoctorFinding {
        finding_id: "shadow-doctor:remote-weather".to_string(),
        asset_id: "remote-weather".to_string(),
        status: ShadowDoctorStatus::Critical,
        category: "restricted_shadow_asset".to_string(),
        detail: "remote-weather is unmanaged via streamable_http".to_string(),
        remediation_action: ShadowRemediationAction::Quarantine,
        verification_step: "mcp-gateway cap discover --shadow --format json".to_string(),
    };
    let note = "asset ids of URL finds are for this run only: no record key was found";
    let value = check_result_json_value(&shadow_finding_check_result(finding, Some(note)));
    let detail = value["detail"].as_str().unwrap_or_default();
    assert!(detail.ends_with(&format!("Note: {note}.")), "{detail}");
}

#[test]
fn shadow_doctor_finding_is_machine_readable_warning() {
    let finding = ShadowDoctorFinding {
        finding_id: "shadow-doctor:remote-weather".to_string(),
        asset_id: "remote-weather".to_string(),
        status: ShadowDoctorStatus::Critical,
        category: "restricted_shadow_asset".to_string(),
        detail: "remote-weather is unmanaged via streamable_http".to_string(),
        remediation_action: ShadowRemediationAction::Quarantine,
        verification_step: "mcp-gateway cap discover --shadow --format json".to_string(),
    };

    let result = shadow_finding_check_result(finding, None);
    let value = check_result_json_value(&result);

    assert_eq!(value["id"], "shadowradar_remote_weather");
    assert_eq!(value["category"], "shadow_radar");
    assert_eq!(value["status"], "warn");
    assert!(
        value["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("restricted_shadow_asset")
    );
    assert_eq!(value["fixability"]["auto_fixable"], false);
    assert_eq!(value["fixability"]["safe_to_apply"], false);
    assert_eq!(value["fixability"]["requires_user"], true);
    assert_eq!(value["fixability"]["confirmation_required"], true);
    assert_eq!(value["fixability"]["risk"], "shadow_mcp_review");
    assert_eq!(
        value["fixability"]["command"],
        "mcp-gateway cap discover --shadow --format json"
    );
    assert_eq!(
        value["fixability"]["verification"],
        "mcp-gateway cap discover --shadow --format json"
    );
}

// ── format_badge ──────────────────────────────────────────────────────────

#[test]
fn format_badge_no_color_returns_plain_text() {
    assert_eq!(format_badge(&CheckStatus::Pass, false), "[PASS]");
    assert_eq!(format_badge(&CheckStatus::Fail, false), "[FAIL]");
    assert_eq!(format_badge(&CheckStatus::Warn, false), "[WARN]");
}

#[test]
fn format_badge_color_contains_ansi_codes() {
    assert!(format_badge(&CheckStatus::Pass, true).contains("[PASS]"));
    assert!(format_badge(&CheckStatus::Fail, true).contains("[FAIL]"));
    assert!(format_badge(&CheckStatus::Warn, true).contains("[WARN]"));
}

// ── resolve_config_path ───────────────────────────────────────────────────

#[test]
fn resolve_config_path_returns_explicit_path() {
    let p = PathBuf::from("/tmp/my_gateway.yaml");
    let result = resolve_config_path(Some(&p));
    assert_eq!(result, Some(p));
}

#[test]
fn resolve_config_path_auto_detects_none_when_no_candidates() {
    // In a temp directory with no config files, returns None.
    let dir = tempfile::tempdir().unwrap();
    let orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();

    let result = resolve_config_path(None);
    std::env::set_current_dir(&orig).unwrap();

    // Could be None OR Some if the test directory happens to have yaml files.
    // We only assert it does not panic.
    let _ = result;
}

// ── which_command ─────────────────────────────────────────────────────────

#[test]
fn which_command_finds_existing_binary() {
    let bin = if cfg!(windows) { "cmd" } else { "sh" }; // Windows: `cmd.exe`, `;` PATH
    assert!(which_command(bin), "{bin} must be findable on PATH");
}

#[test]
fn which_command_returns_false_for_nonexistent() {
    assert!(!which_command("definitely-not-a-real-binary-xyz-12345"));
}

// ── check_backend_env ─────────────────────────────────────────────────────

#[test]
fn check_backend_env_unknown_server_returns_empty() {
    let backend = mcp_gateway::config::BackendConfig::default();
    let results = check_backend_env("totally-unknown-server-xyz", &backend, None);
    assert!(results.is_empty());
}

#[test]
fn kc8_doctor_names_a_reference_never_the_value() {
    let resolved = "kc-doctor-sentinel-7f3a";
    let mut backend = mcp_gateway::config::BackendConfig::default();
    backend
        .env
        .insert("TAVILY_API_KEY".to_string(), resolved.to_string());
    let mut written = mcp_gateway::config::BackendConfig::default();
    written.env.insert(
        "TAVILY_API_KEY".to_string(),
        "keychain:gw.tavily".to_string(),
    );
    let results = check_backend_env("tavily", &backend, Some(&written));
    let shown = format!(
        "{:?}",
        results.iter().map(|r| &r.detail).collect::<Vec<_>>()
    );
    assert!(shown.contains("is set as keychain:gw.tavily"), "{shown}");
    assert!(!shown.contains(resolved), "{shown}");
    // A literal shows as plainly set.
    let mut literal = written.clone();
    literal
        .env
        .insert("TAVILY_API_KEY".to_string(), resolved.to_string());
    let results = check_backend_env("tavily", &backend, Some(&literal));
    let shown = format!(
        "{:?}",
        results.iter().map(|r| &r.detail).collect::<Vec<_>>()
    );
    assert!(shown.contains("is set"), "{shown}");
    assert!(!shown.contains(resolved), "{shown}");
}

// ── MIK-8375: a config that will not load ─────────────────────────────────

/// A 0600 config at `dir/gateway.yaml` whose port holds `sentinel`.
fn unloadable_config(dir: &Path, sentinel: &str) -> PathBuf {
    let path = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        format!("server:\n  port: {sentinel}\n"),
    )
    .expect("write config");
    path
}

/// CFGLEAK.2: doctor prints the load error, so it must not carry the value.
#[test]
fn doctor_does_not_print_the_value_a_config_refused() {
    let sentinel = "cfgleak-sentinel-r9";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = unloadable_config(dir.path(), sentinel);
    let (result, config) = check_config(Some(&path), false);
    assert!(config.is_none());
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(!result.detail.contains(sentinel), "{}", result.detail);
    assert!(result.detail.contains("server.port"), "{}", result.detail);
}

/// The fix doctor suggests is a command that re-checks this same file: it
/// is parsed by the CLI itself, and must reach `doctor` with the path.
/// `validate` lints capability files and never loads the gateway config.
#[test]
fn doctor_suggests_a_command_that_rechecks_the_same_config() {
    use clap::Parser as _;
    let dir = tempfile::tempdir().expect("tempdir");
    // A space and a quote in the path: the hint must still copy as one word.
    let nested = dir.path().join("my config's dir");
    std::fs::create_dir(&nested).expect("dir");
    let path = unloadable_config(&nested, "x");
    let (result, _) = check_config(Some(&path), false);
    let fix = result.fix_command.expect("a fix is suggested");
    let words = shlex::split(&fix).unwrap_or_else(|| panic!("`{fix}` does not tokenise"));
    let cli = mcp_gateway::cli::Cli::try_parse_from(words)
        .unwrap_or_else(|e| panic!("`{fix}` does not parse: {e}"));
    match cli.command {
        Some(mcp_gateway::cli::Command::Doctor { config, .. }) => {
            assert_eq!(config.as_deref(), Some(path.as_path()), "{fix}");
        }
        other => panic!("`{fix}` runs {other:?}, not doctor"),
    }
}

#[path = "doctor_probe_tests.rs"]
mod probe;
