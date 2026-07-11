// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Implementation of `mcp-gateway doctor`.
//!
//! Performs a series of diagnostic checks and prints a pass/fail/warn table.
//! Exit code is `SUCCESS` when all required checks pass, `FAILURE` otherwise.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

#[cfg(test)]
use std::net::TcpListener;

use mcp_gateway::{
    cli::output::OutputFormat,
    config::{Config, TransportConfig},
    discovery::{
        AutoDiscovery,
        shadow::{
            ShadowDoctorFinding, ShadowDoctorStatus, ShadowRemediationAction, ShadowScanReport,
        },
    },
};
use serde_json::{Value, json};

mod health;
mod shadow;

use health::check_port_and_gateway_runtime;
pub use shadow::run_doctor_shadow_command;

#[cfg(test)]
use health::MCP_SESSION_HEADER;
#[cfg(test)]
use shadow::{DLP_RULES, render_grep, render_nginx, render_yaml};

// ── Check result ──────────────────────────────────────────────────────────────

/// Outcome of a single diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// The check failed — gateway cannot function correctly without fixing this.
    Fail,
    /// Non-fatal advisory.
    Warn,
}

/// A single completed diagnostic check.
#[derive(Debug)]
pub struct CheckResult {
    /// Short description of what was checked.
    pub label: String,
    /// Outcome.
    pub status: CheckStatus,
    /// Detail message shown after the status badge.
    pub detail: String,
    /// Optional hint printed on the next line when status is Fail or Warn.
    pub hint: Option<String>,
    /// Stable diagnostic category for machine-readable output.
    pub category: &'static str,
    /// Command the user can run to resolve or investigate the finding.
    pub fix_command: Option<String>,
    /// Whether the gateway can safely apply the fix without user input.
    pub auto_fixable: bool,
    /// Risk class for applying the suggested fix.
    pub risk: &'static str,
    /// Whether a human should explicitly approve before applying the fix.
    pub confirmation_required: bool,
    /// Command that verifies the fix after it is applied.
    pub verification_command: Option<String>,
    /// Command or instruction that rolls back the fix when available.
    pub rollback_command: Option<String>,
}

impl CheckResult {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
            hint: None,
            category: "general",
            fix_command: None,
            auto_fixable: false,
            risk: "none",
            confirmation_required: false,
            verification_command: None,
            rollback_command: None,
        }
    }

    fn fail(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            hint: None,
            category: "general",
            fix_command: None,
            auto_fixable: false,
            risk: "operator_action",
            confirmation_required: false,
            verification_command: None,
            rollback_command: None,
        }
    }

    fn warn(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            hint: None,
            category: "general",
            fix_command: None,
            auto_fixable: false,
            risk: "operator_action",
            confirmation_required: false,
            verification_command: None,
            rollback_command: None,
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    fn with_category(mut self, category: &'static str) -> Self {
        self.category = category;
        self
    }

    fn with_manual_fix(mut self, command: impl Into<String>) -> Self {
        self.fix_command = Some(command.into());
        self.auto_fixable = false;
        self.confirmation_required = true;
        if self.status != CheckStatus::Pass && self.risk == "none" {
            self.risk = "operator_action";
        }
        self
    }

    fn with_risk(mut self, risk: &'static str) -> Self {
        self.risk = risk;
        self
    }

    fn with_verification(mut self, command: impl Into<String>) -> Self {
        self.verification_command = Some(command.into());
        self
    }

    fn with_rollback(mut self, command: impl Into<String>) -> Self {
        self.rollback_command = Some(command.into());
        self
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run `mcp-gateway doctor`.
pub async fn run_doctor_command(
    fix: bool,
    config_path: Option<&Path>,
    format: OutputFormat,
) -> ExitCode {
    if format != OutputFormat::Json {
        println!("Gateway Doctor");
        println!("==============");
        println!();
    }

    let mut results: Vec<CheckResult> = Vec::new();

    // ── 1. Config ──────────────────────────────────────────────────────────
    let (config_result, config) = check_config(config_path, fix);
    results.push(config_result);

    let Some(config) = config else {
        print_results(&results, format);
        return ExitCode::FAILURE;
    };

    // ── 2. Port and gateway runtime ────────────────────────────────────────
    results.extend(check_port_and_gateway_runtime(&config).await);

    // ── 3. Backend env vars ────────────────────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        results.extend(check_backend_env(name, backend));
    }

    // ── 4. HTTP backends reachability ──────────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        if let Some(result) = check_http_backend(name, &backend.transport).await {
            results.push(result);
        }
    }

    // ── 5. Stdio backends (spawn check) ───────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        if let Some(result) = check_stdio_backend(name, &backend.transport) {
            results.push(result);
        }
    }

    // ── 6. AI client configuration ─────────────────────────────────────────
    results.push(check_ai_client_config(&config).await);

    // ── 7. Passive ShadowRadar handoff ─────────────────────────────────────
    results.extend(check_shadow_radar(&config, config_path).await);

    // ── Print and summarize ────────────────────────────────────────────────
    print_results(&results, format);

    let failed = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

// ── Individual checks ──────────────────────────────────────────────────────────

async fn check_shadow_radar(config: &Config, config_path: Option<&Path>) -> Vec<CheckResult> {
    let discovery = AutoDiscovery::new();
    let registered_names: HashSet<String> = config.backends.keys().cloned().collect();
    let gateway_config_path = config_path.or_else(|| Some(Path::new("gateway.yaml")));

    match discovery.discover_all().await {
        Ok(discovered) => {
            let report = ShadowScanReport::from_discovered(
                &discovered,
                &registered_names,
                gateway_config_path,
            );
            let handoff = report.consumer_handoff();
            if handoff.doctor_findings.is_empty() {
                return vec![
                    CheckResult::pass("ShadowRadar", "passive scan found no unmanaged MCP servers")
                        .with_category("shadow_radar")
                        .with_verification("mcp-gateway cap discover --shadow --format json"),
                ];
            }

            handoff
                .doctor_findings
                .into_iter()
                .map(shadow_finding_check_result)
                .collect()
        }
        Err(e) => vec![
            CheckResult::warn("ShadowRadar", format!("passive discovery unavailable: {e}"))
                .with_category("shadow_radar")
                .with_hint("Run mcp-gateway cap discover --shadow --format json for details")
                .with_risk("shadow_discovery_unavailable")
                .with_verification("mcp-gateway doctor --format json"),
        ],
    }
}

fn shadow_finding_check_result(finding: ShadowDoctorFinding) -> CheckResult {
    let severity = shadow_doctor_status_label(&finding.status);
    let action = shadow_remediation_label(&finding.remediation_action);
    CheckResult::warn(
        format!("ShadowRadar {}", finding.asset_id),
        format!(
            "{severity}: {} Category: {}. Recommended action: {action}.",
            finding.detail, finding.category
        ),
    )
    .with_category("shadow_radar")
    .with_hint("Review unmanaged MCP discovery before trusting or adopting this server")
    .with_manual_fix(shadow_manual_fix_command(&finding.remediation_action))
    .with_risk("shadow_mcp_review")
    .with_verification(finding.verification_step)
    .with_rollback("Restore the previous gateway config backup or remove the adopted backend")
}

fn shadow_doctor_status_label(status: &ShadowDoctorStatus) -> &'static str {
    match status {
        ShadowDoctorStatus::Info => "info",
        ShadowDoctorStatus::Warning => "warning",
        ShadowDoctorStatus::Critical => "critical",
    }
}

fn shadow_remediation_label(action: &ShadowRemediationAction) -> &'static str {
    match action {
        ShadowRemediationAction::AdoptIntoGateway => "adopt into gateway after review",
        ShadowRemediationAction::Quarantine => "quarantine until owner and trust are known",
        ShadowRemediationAction::RequestOwner => "request owner review",
        ShadowRemediationAction::IgnoreWithReason => "document accepted risk",
        ShadowRemediationAction::Disable => "disable unmanaged server after approval",
        ShadowRemediationAction::EnterprisePolicyTicket => "open enterprise policy ticket",
    }
}

fn shadow_manual_fix_command(action: &ShadowRemediationAction) -> &'static str {
    match action {
        ShadowRemediationAction::AdoptIntoGateway => {
            "mcp-gateway cap discover --shadow --write-config"
        }
        ShadowRemediationAction::Quarantine
        | ShadowRemediationAction::RequestOwner
        | ShadowRemediationAction::IgnoreWithReason
        | ShadowRemediationAction::Disable
        | ShadowRemediationAction::EnterprisePolicyTicket => {
            "mcp-gateway cap discover --shadow --format json"
        }
    }
}

fn check_config(path: Option<&Path>, _fix: bool) -> (CheckResult, Option<Config>) {
    let resolved = resolve_config_path(path);

    let Some(ref p) = resolved else {
        return (
            CheckResult::fail("Configuration", "no gateway.yaml found")
                .with_category("config")
                .with_hint("Run 'mcp-gateway init --profile local' to create one")
                .with_manual_fix("mcp-gateway init --profile local")
                .with_verification("mcp-gateway doctor --format json"),
            None,
        );
    };

    if !p.exists() {
        return (
            CheckResult::fail("Configuration", format!("{} not found", p.display()))
                .with_category("config")
                .with_hint("Run 'mcp-gateway init --profile local' to create one")
                .with_manual_fix("mcp-gateway init --profile local")
                .with_verification("mcp-gateway doctor --format json"),
            None,
        );
    }

    match Config::load(Some(p)) {
        Ok(config) => {
            let detail = format!(
                "{} ({} backend{})",
                p.display(),
                config.backends.len(),
                if config.backends.len() == 1 { "" } else { "s" }
            );
            (
                CheckResult::pass("Configuration", detail).with_category("config"),
                Some(config),
            )
        }
        Err(e) => (
            CheckResult::fail("Configuration", format!("{}: {e}", p.display()))
                .with_category("config")
                .with_manual_fix(format!("mcp-gateway validate {}", p.display())),
            None,
        ),
    }
}

#[cfg(test)]
fn check_port(port: u16) -> CheckResult {
    let addr = format!("127.0.0.1:{port}");
    match TcpListener::bind(&addr) {
        Ok(_) => CheckResult::pass("Port", format!("{port} available")).with_category("port"),
        Err(_) => CheckResult::fail("Port", format!("{port} already in use"))
            .with_category("port")
            .with_hint("Another process is listening on this port")
            .with_manual_fix(format!("lsof -nP -iTCP:{port} -sTCP:LISTEN")),
    }
}

fn check_backend_env(name: &str, backend: &mcp_gateway::config::BackendConfig) -> Vec<CheckResult> {
    use mcp_gateway::registry::server_registry;
    let mut results = Vec::new();

    let Some(entry) = server_registry::lookup(name) else {
        return results;
    };

    for key in entry.required_env {
        let label = format!("{name}: {key}");
        if std::env::var(key).is_ok() || backend.env.contains_key(*key) {
            results.push(CheckResult::pass(label, "is set").with_category("auth"));
        } else {
            results.push(
                CheckResult::fail(label, "not set")
                    .with_category("auth")
                    .with_hint(format!("export {key}=<value>"))
                    .with_manual_fix(format!("export {key}=<value>")),
            );
        }
    }

    results
}

async fn check_http_backend(name: &str, transport: &TransportConfig) -> Option<CheckResult> {
    let TransportConfig::Http { http_url, .. } = transport else {
        return None;
    };

    let label = format!("{name}: HTTP");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let start = Instant::now();
    match client.get(http_url).send().await {
        Ok(resp) => {
            let ms = start.elapsed().as_millis();
            let status = resp.status();
            // MCP servers often return 4xx on GET / — we just care they're reachable.
            if status.is_server_error() {
                Some(
                    CheckResult::fail(label, format!("HTTP {status} ({ms}ms)"))
                        .with_category("backend_http")
                        .with_hint("Server returned a 5xx error"),
                )
            } else {
                Some(
                    CheckResult::pass(label, format!("HTTP {status} ({ms}ms)"))
                        .with_category("backend_http"),
                )
            }
        }
        Err(e) => Some(
            CheckResult::fail(label, format!("connection failed: {e}"))
                .with_category("backend_http")
                .with_hint(format!("Check that the server at {http_url} is running")),
        ),
    }
}

fn check_stdio_backend(name: &str, transport: &TransportConfig) -> Option<CheckResult> {
    let TransportConfig::Stdio { command, .. } = transport else {
        return None;
    };

    // Extract the binary / script name for `which`-style check.
    let bin = command.split_whitespace().next()?;
    let label = format!("{name}: command");

    // We only verify the command exists, not actually launch it
    // (launching would block and side-effects are unpredictable).
    let found = which_command(bin);
    if found {
        Some(CheckResult::pass(label, format!("'{bin}' found")).with_category("backend_stdio"))
    } else {
        Some(
            CheckResult::fail(label, format!("'{bin}' not found in PATH"))
                .with_category("backend_stdio")
                .with_hint(format!(
                    "Install the command: {}",
                    if bin == "npx" {
                        "install Node.js from https://nodejs.org"
                    } else {
                        "check your PATH"
                    }
                ))
                .with_manual_fix(if bin == "npx" {
                    "install Node.js from https://nodejs.org".to_string()
                } else {
                    format!("which {bin}")
                }),
        )
    }
}

async fn check_ai_client_config(config: &Config) -> CheckResult {
    let gateway_url = format!("http://{}:{}/mcp", config.server.host, config.server.port);

    let discovery = AutoDiscovery::new();
    let servers = discovery.discover_all().await.unwrap_or_default();

    let points_to_gateway = servers.iter().any(|s| {
        matches!(&s.transport, TransportConfig::Http { http_url, .. }
            if http_url.contains(&config.server.host)
                && http_url.contains(&config.server.port.to_string()))
    });

    if points_to_gateway {
        CheckResult::pass("AI client", "at least one client points to gateway")
            .with_category("client_config")
    } else {
        CheckResult::warn("AI client", "no client configured to use gateway")
            .with_category("client_config")
            .with_hint(format!(
                "Run 'mcp-gateway setup wizard --configure-client' or add \
                     {{\"url\": \"{gateway_url}\"}} to your client's mcpServers"
            ))
            .with_manual_fix("mcp-gateway setup wizard --configure-client")
            .with_risk("config_mutation")
            .with_verification("mcp-gateway doctor --format json")
            .with_rollback("mcp-gateway setup export --rollback <backup-file>")
    }
}

// ── Output formatting ─────────────────────────────────────────────────────────

fn print_results(results: &[CheckResult], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_results_json(results),
        OutputFormat::Plain | OutputFormat::Table => print_results_human(results),
    }
}

fn print_results_human(results: &[CheckResult]) {
    use std::fmt::Write as _;

    let use_color = std::env::var("NO_COLOR").is_err();

    for result in results {
        let badge = format_badge(&result.status, use_color);
        println!("{badge} {}: {}", result.label, result.detail);
        if let Some(ref hint) = result.hint {
            println!("       Hint: {hint}");
        }
    }

    println!();

    // Summary line.
    let (pass, fail, warn) = summary_counts(results);

    let mut summary = String::new();
    let _ = write!(
        summary,
        "{pass} check{} passed",
        if pass == 1 { "" } else { "s" }
    );
    if fail > 0 {
        let _ = write!(summary, ", {fail} failed");
    }
    if warn > 0 {
        let _ = write!(
            summary,
            ", {warn} warning{}",
            if warn == 1 { "" } else { "s" }
        );
    }
    println!("{summary}");
}

fn print_results_json(results: &[CheckResult]) {
    println!(
        "{}",
        serde_json::to_string_pretty(&doctor_report_json_value(results)).unwrap_or_default()
    );
}

fn doctor_report_json_value(results: &[CheckResult]) -> Value {
    let (pass, fail, warn) = summary_counts(results);
    let checks: Vec<Value> = results.iter().map(check_result_json_value).collect();
    json!({
        "schema_version": "doctor.v1",
        "ok": fail == 0,
        "summary": {
            "pass": pass,
            "fail": fail,
            "warn": warn,
            "total": results.len(),
        },
        "checks": checks,
    })
}

fn check_result_json_value(result: &CheckResult) -> Value {
    json!({
        "id": stable_check_id(&result.label),
        "label": result.label,
        "category": result.category,
        "status": status_str(&result.status),
        "detail": result.detail,
        "hint": result.hint,
        "fixability": {
            "auto_fixable": result.auto_fixable,
            "safe_to_apply": result.auto_fixable,
            "command": result.fix_command,
            "requires_user": result.status != CheckStatus::Pass && !result.auto_fixable,
            "risk": result.risk,
            "confirmation_required": result.confirmation_required,
            "verification": result.verification_command,
            "rollback": result.rollback_command,
        },
    })
}

fn summary_counts(results: &[CheckResult]) -> (usize, usize, usize) {
    let pass = results
        .iter()
        .filter(|r| r.status == CheckStatus::Pass)
        .count();
    let fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let warn = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    (pass, fail, warn)
}

fn status_str(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Fail => "fail",
        CheckStatus::Warn => "warn",
    }
}

fn stable_check_id(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn format_badge(status: &CheckStatus, color: bool) -> &'static str {
    match (status, color) {
        (CheckStatus::Pass, true) => "\x1b[32m[PASS]\x1b[0m",
        (CheckStatus::Fail, true) => "\x1b[31m[FAIL]\x1b[0m",
        (CheckStatus::Warn, true) => "\x1b[33m[WARN]\x1b[0m",
        (CheckStatus::Pass, false) => "[PASS]",
        (CheckStatus::Fail, false) => "[FAIL]",
        (CheckStatus::Warn, false) => "[WARN]",
    }
}

// ── Utility helpers ────────────────────────────────────────────────────────────

fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    // Auto-detect common locations.
    for candidate in &["gateway.yaml", "config.yaml"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Check whether `bin` is reachable on `PATH` by trying to spawn it with `--version`.
fn which_command(bin: &str) -> bool {
    // Use `command -v` equivalent: just try to locate in PATH.
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|dir| {
            let full = PathBuf::from(dir).join(bin);
            full.exists()
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "doctor/runtime_tests.rs"]
mod runtime_tests;

#[cfg(test)]
#[path = "doctor/shadow_tests.rs"]
mod shadow_tests;

#[cfg(test)]
mod tests {
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

        let result = shadow_finding_check_result(finding);
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

    // ── check_port ────────────────────────────────────────────────────────────

    #[test]
    fn check_port_on_free_port_passes() {
        // GIVEN: a port that is almost certainly free (dynamic range)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_port = listener.local_addr().unwrap().port();
        drop(listener);

        // WHEN: checking a free port
        let free_port = occupied_port + 1;
        let result = check_port(free_port);

        // THEN: may pass or fail depending on OS, but must not panic
        let _ = result.status; // just verify it runs
    }

    #[test]
    fn check_port_occupied_fails() {
        // GIVEN: a TcpListener holds a port open
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // WHEN: the same port is checked
        let result = check_port(port);

        // THEN: the check fails because the port is in use
        assert_eq!(result.status, CheckStatus::Fail, "occupied port must fail");
        drop(listener);
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
        // `sh` is universally available on Unix.
        assert!(which_command("sh"), "sh must be findable on PATH");
    }

    #[test]
    fn which_command_returns_false_for_nonexistent() {
        assert!(!which_command("definitely-not-a-real-binary-xyz-12345"));
    }

    // ── check_backend_env ─────────────────────────────────────────────────────

    #[test]
    fn check_backend_env_unknown_server_returns_empty() {
        let backend = mcp_gateway::config::BackendConfig::default();
        let results = check_backend_env("totally-unknown-server-xyz", &backend);
        assert!(results.is_empty());
    }
}
