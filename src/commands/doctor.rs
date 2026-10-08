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
mod hidden_keys;
mod posture;
mod provenance;
mod remedy;
mod shadow;
mod ws_reach;

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
    stdio_probe: StdioProbe,
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
    if let Some(path) = resolve_config_path(config_path) {
        results.extend(hidden_keys::check_hidden_keys(&path));
    }

    // ── 2. Port and gateway runtime ────────────────────────────────────────
    results.extend(check_port_and_gateway_runtime(&config).await);

    // ── 3. Backend env vars ────────────────────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        results.extend(check_backend_env(name, backend));
    }

    // ── 4. HTTP backends reachability ──────────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        let result = match check_http_backend(name, &backend.transport).await {
            None => ws_reach::check_ws_backend(name, &backend.transport).await,
            some => some,
        };
        results.extend(result);
    }

    // ── 5. Stdio backends (spawn check) ───────────────────────────────────
    for (name, backend) in config.enabled_backends() {
        results.extend(start_stdio::stdio_row(stdio_probe, name, backend).await);
    }

    // ── 6. AI client configuration ─────────────────────────────────────────
    results.push(check_ai_client_config(&config).await);
    results.push(posture::check_security_posture(&config));

    // ── 7. Passive ShadowRadar handoff ─────────────────────────────────────
    results.extend(check_shadow_radar(&config, config_path).await);
    // ── 8. Remote backend provenance (#1943) ──────────────────────────────
    results.extend(provenance::check_remote_provenance(&config));

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
            CheckResult::fail(
                label,
                format!(
                    "connection failed: {}",
                    mcp_gateway::security::request_error_category(&e)
                ),
            )
            .with_category("backend_http")
            .with_hint(format!(
                "Check that the server at {} is running",
                mcp_gateway::security::diagnostic_url(http_url)
            )),
        ),
    }
}

fn check_stdio_backend(name: &str, transport: &TransportConfig) -> Option<CheckResult> {
    let TransportConfig::Stdio { command, .. } = transport else {
        return None;
    };

    let label = format!("{name}: command");

    // Same parser spawn will use — a config that cannot split cannot PASS.
    let parts = match mcp_gateway::transport::split_command(command) {
        None => {
            return Some(
                CheckResult::fail(label, "invalid command quoting")
                    .with_category("backend_stdio")
                    .with_hint(
                        "Fix quoting in backends.*.command (host platform rules; unterminated quotes are rejected)"
                            .to_string(),
                    ),
            );
        }
        Some(parts) if parts.is_empty() => {
            return Some(
                CheckResult::fail(label, "empty command")
                    .with_category("backend_stdio")
                    .with_hint(
                        "Set backends.*.command to an executable plus arguments".to_string(),
                    ),
            );
        }
        Some(parts) => parts,
    };
    let bin = parts[0].as_str();

    // We only verify the command exists, not actually launch it
    // (launching would block and side-effects are unpredictable).
    let found = which_command(bin);
    if found {
        Some(CheckResult::pass(label, format!("'{bin}' found")).with_category("backend_stdio"))
    } else {
        let remedy = remedy::missing_binary_remedy(bin, remedy::runs_in_a_container());
        Some(
            CheckResult::fail(label, format!("'{bin}' not found in PATH"))
                .with_category("backend_stdio")
                .with_hint(remedy.as_ref().map_or_else(
                    || "Install the command: check your PATH".to_string(),
                    |remedy| remedy.hint.clone(),
                ))
                .with_manual_fix(remedy.map_or_else(|| format!("which {bin}"), |r| r.manual_fix)),
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

/// Whether `bin` is on `PATH`; nothing is run. PATH only: a Windows spawn also
/// searches its own and the system directories, which this does not.
pub(super) fn which_command(bin: &str) -> bool {
    // PATH split the platform's way (':' broke `C:\...`), plus on Windows the
    // `.exe` a spawn resolves a bare name to (not `.cmd`/`.bat`: nor does a spawn).
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .any(|p| {
            let mut exe = p.clone().into_os_string();
            exe.push(".exe");
            p.exists() || (cfg!(windows) && PathBuf::from(exe).exists())
        })
}

#[path = "doctor/start_stdio.rs"]
mod start_stdio;
pub use start_stdio::StdioProbe;
#[cfg(test)]
#[path = "doctor/runtime_tests.rs"]
mod runtime_tests;
#[cfg(test)]
#[path = "doctor/shadow_tests.rs"]
mod shadow_tests;

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
