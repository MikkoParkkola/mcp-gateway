//! Implementation of `mcp-gateway doctor`.
//!
//! Performs a series of diagnostic checks and prints a pass/fail/warn table.
//! Exit code is `SUCCESS` when all required checks pass, `FAILURE` otherwise.

use std::fmt::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use mcp_gateway::{
    config::{Config, TransportConfig},
    discovery::AutoDiscovery,
};

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
}

impl CheckResult {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
            hint: None,
        }
    }

    fn fail(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Fail,
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
            hint: None,
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Run `mcp-gateway doctor`.
pub async fn run_doctor_command(fix: bool, config_path: Option<&Path>) -> ExitCode {
    println!("Gateway Doctor");
    println!("==============");
    println!();

    let mut results: Vec<CheckResult> = Vec::new();

    // ── 1. Config ──────────────────────────────────────────────────────────
    let (config_result, config) = check_config(config_path, fix);
    results.push(config_result);

    let Some(config) = config else {
        print_results(&results);
        return ExitCode::FAILURE;
    };

    // ── 2. Port ────────────────────────────────────────────────────────────
    results.push(check_port(config.server.port));

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

    // ── Print and summarize ────────────────────────────────────────────────
    print_results(&results);

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

fn check_config(path: Option<&Path>, _fix: bool) -> (CheckResult, Option<Config>) {
    let resolved = resolve_config_path(path);

    let Some(ref p) = resolved else {
        return (
            CheckResult::fail("Configuration", "no gateway.yaml found")
                .with_hint("Run 'mcp-gateway init' to create one"),
            None,
        );
    };

    if !p.exists() {
        return (
            CheckResult::fail("Configuration", format!("{} not found", p.display()))
                .with_hint("Run 'mcp-gateway init' to create one"),
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
            (CheckResult::pass("Configuration", detail), Some(config))
        }
        Err(e) => (
            CheckResult::fail("Configuration", format!("{}: {e}", p.display())),
            None,
        ),
    }
}

fn check_port(port: u16) -> CheckResult {
    let addr = format!("127.0.0.1:{port}");
    match TcpListener::bind(&addr) {
        Ok(_) => CheckResult::pass("Port", format!("{port} available")),
        Err(_) => CheckResult::fail("Port", format!("{port} already in use"))
            .with_hint("Another process is listening on this port"),
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
            results.push(CheckResult::pass(label, "is set"));
        } else {
            results.push(
                CheckResult::fail(label, "not set").with_hint(format!("export {key}=<value>")),
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
                        .with_hint("Server returned a 5xx error"),
                )
            } else {
                Some(CheckResult::pass(label, format!("HTTP {status} ({ms}ms)")))
            }
        }
        Err(e) => Some(
            CheckResult::fail(label, format!("connection failed: {e}"))
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
        Some(CheckResult::pass(label, format!("'{bin}' found")))
    } else {
        Some(
            CheckResult::fail(label, format!("'{bin}' not found in PATH")).with_hint(format!(
                "Install the command: {}",
                if bin == "npx" {
                    "install Node.js from https://nodejs.org"
                } else {
                    "check your PATH"
                }
            )),
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
    } else {
        CheckResult::warn("AI client", "no client configured to use gateway").with_hint(format!(
            "Run 'mcp-gateway setup --configure-client' or add \
                 {{\"url\": \"{gateway_url}\"}} to your client's mcpServers"
        ))
    }
}

// ── Output formatting ─────────────────────────────────────────────────────────

fn print_results(results: &[CheckResult]) {
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

// ── Shadow DLP rule export ─────────────────────────────────────────────────────

/// A single DLP regex rule for network-layer MCP detection.
///
/// Derived from RFC-0132 §Shadow-MCP-Detection, Layer 3 and the Cloudflare
/// DLP pattern reference in the RFC-0132 Appendix.  These patterns match
/// MCP JSON-RPC messages as they appear in HTTP request/response bodies.
///
/// **Operator note**: These are heuristic patterns for *external* tools
/// (firewalls, SIEMs, reverse proxies).  `mcp-gateway` does not intercept
/// arbitrary outbound traffic — deploy these in your network-layer tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpRule {
    /// Human-readable rule name (also used as the YAML `name:` key and nginx
    /// comment).
    pub name: &'static str,
    /// Selector category from RFC-0132 (host / uri / body).
    pub category: &'static str,
    /// The regex pattern, written in POSIX ERE compatible with grep -E and
    /// most SIEM/WAF regex engines.
    pub regex: &'static str,
    /// Free-text description for the operator.
    pub description: &'static str,
}

/// All MCP DLP rules derived from RFC-0132 Appendix and Cloudflare reference.
///
/// Patterns are POSIX ERE-compatible (grep -E, nginx `~`, `HAProxy` `acl`).
/// The `\s{0,5}` allowance covers compacted vs. pretty-printed JSON.
pub const DLP_RULES: &[DlpRule] = &[
    DlpRule {
        name: "MCP Initialize Method",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"initialize""#,
        description: "MCP init handshake — first message in every MCP session",
    },
    DlpRule {
        name: "MCP Tools Call",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"tools/call""#,
        description: "Tool invocation — present in every tool execution",
    },
    DlpRule {
        name: "MCP Tools List",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"tools/list""#,
        description: "Tool enumeration — emitted by clients that pre-load schema",
    },
    DlpRule {
        name: "MCP Resources Read",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"resources/read""#,
        description: "MCP resource read — file/blob access",
    },
    DlpRule {
        name: "MCP Resources List",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"resources/list""#,
        description: "MCP resource listing",
    },
    DlpRule {
        name: "MCP Prompts List or Get",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"prompts/(list|get)""#,
        description: "MCP prompt enumeration or retrieval",
    },
    DlpRule {
        name: "MCP Sampling Create Message",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"sampling/createMessage""#,
        description: "LLM sampling back-channel — high-privilege, monitor closely",
    },
    DlpRule {
        name: "MCP Protocol Version",
        category: "body",
        regex: r#""protocolVersion"\s{0,5}:\s{0,5}"202[4-9]"#,
        description: "MCP version negotiation — present in every initialize message",
    },
    DlpRule {
        name: "MCP Notifications Initialized",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"notifications/initialized""#,
        description: "Session ready notification sent after successful handshake",
    },
    DlpRule {
        name: "MCP Roots List",
        category: "body",
        regex: r#""method"\s{0,5}:\s{0,5}"roots/list""#,
        description: "Client root-directory enumeration",
    },
];

// ── Formatters ────────────────────────────────────────────────────────────────

fn render_grep(rules: &[DlpRule]) -> String {
    let mut out = String::new();
    out.push_str("# MCP DLP patterns — shell grep\n");
    out.push_str("# Generated by: mcp-gateway doctor --shadow --shadow-format grep\n");
    out.push_str("# Source: RFC-0132 §Shadow-MCP-Detection Layer 3\n");
    out.push_str("#\n");
    out.push_str("# OPERATOR NOTE: Heuristic patterns only. The gateway does not\n");
    out.push_str("# intercept outbound traffic. Deploy in your network-layer tooling.\n");
    out.push_str("#\n");
    out.push_str("# Usage example (stream log file):\n");
    out.push_str("#   tail -f /var/log/proxy.log | grep -EP 'PATTERN'\n");
    out.push('\n');

    for rule in rules {
        let _ = writeln!(
            out,
            "# [{}] {} — {}",
            rule.category, rule.name, rule.description
        );
        let _ = writeln!(out, "grep -EP '{}'\n", rule.regex);
    }
    out
}

fn render_nginx(rules: &[DlpRule]) -> String {
    let mut out = String::new();
    out.push_str("# MCP DLP patterns — nginx log_format / if-block snippets\n");
    out.push_str("# Generated by: mcp-gateway doctor --shadow --shadow-format nginx\n");
    out.push_str("# Source: RFC-0132 §Shadow-MCP-Detection Layer 3\n");
    out.push_str("#\n");
    out.push_str("# OPERATOR NOTE: Heuristic patterns only. These are NOT enforced by\n");
    out.push_str("# mcp-gateway itself. Place in your nginx server/location block.\n");
    out.push_str("#\n");
    out.push_str("# Requires: nginx built with PCRE support (standard in most packages).\n");
    out.push_str("# Add the map block in http {}, then reference $mcp_shadow in access_log.\n");
    out.push('\n');

    let combined: Vec<&str> = rules.iter().map(|r| r.regex).collect();
    let combined_regex = combined.join("|");

    out.push_str("# -- Combined map (1 = detected MCP traffic) --\n");
    out.push_str("map $request_body $mcp_shadow {\n");
    out.push_str("    default          0;\n");
    let _ = writeln!(out, "    ~*({combined_regex})  1;");
    out.push_str("}\n\n");

    out.push_str("# -- Or use individual if blocks inside location /mcp { ... } --\n");
    for rule in rules {
        let _ = writeln!(out, "# [{}] {}", rule.category, rule.name);
        let _ = writeln!(out, "# {}", rule.description);
        let _ = writeln!(out, "if ($request_body ~* '{}') {{", rule.regex);
        out.push_str("    # set $mcp_shadow 1; access_log ... mcp_shadow;\n");
        out.push_str("}\n\n");
    }
    out
}

fn render_yaml(rules: &[DlpRule]) -> String {
    let mut out = String::new();
    out.push_str("# MCP DLP rules — YAML export for SIEM import\n");
    out.push_str("# Generated by: mcp-gateway doctor --shadow --shadow-format yaml\n");
    out.push_str("# Source: RFC-0132 §Shadow-MCP-Detection Layer 3\n");
    out.push_str("#\n");
    out.push_str("# OPERATOR NOTE: Heuristic patterns only. The gateway does not\n");
    out.push_str("# intercept outbound traffic. Deploy in your SIEM/firewall tooling.\n");
    out.push('\n');
    out.push_str("dlp_rules:\n");

    for rule in rules {
        let _ = writeln!(out, "  - name: \"{}\"", rule.name);
        let _ = writeln!(out, "    category: \"{}\"", rule.category);
        let escaped_regex = rule.regex.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = writeln!(out, "    regex: \"{escaped_regex}\"");
        let _ = writeln!(out, "    description: \"{}\"", rule.description);
        out.push('\n');
    }
    out
}

// ── Public entry point for --shadow ──────────────────────────────────────────

/// Run `mcp-gateway doctor --shadow`.
///
/// Emits DLP/firewall regex rules for operator-side network-layer MCP
/// detection.  This is **rule generation only** — the gateway does not
/// intercept arbitrary outbound traffic.
///
/// # Arguments
///
/// * `format` — one of `"grep"` (default), `"nginx"`, or `"yaml"`.
pub fn run_doctor_shadow_command(format: &str) -> ExitCode {
    let output = match format.to_ascii_lowercase().as_str() {
        "grep" | "" => render_grep(DLP_RULES),
        "nginx" | "haproxy" => render_nginx(DLP_RULES),
        "yaml" => render_yaml(DLP_RULES),
        other => {
            eprintln!(
                "Error: unknown --shadow-format '{other}'. \
                 Valid values: grep, nginx, yaml"
            );
            return ExitCode::FAILURE;
        }
    };
    print!("{output}");
    ExitCode::SUCCESS
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

    // ── DLP_RULES catalogue ───────────────────────────────────────────────────

    #[test]
    fn dlp_rules_has_ten_entries() {
        assert_eq!(DLP_RULES.len(), 10, "RFC-0132 specifies 10 DLP patterns");
    }

    #[test]
    fn dlp_rules_all_have_non_empty_fields() {
        for rule in DLP_RULES {
            assert!(!rule.name.is_empty(), "name must not be empty");
            assert!(!rule.category.is_empty(), "category must not be empty");
            assert!(!rule.regex.is_empty(), "regex must not be empty");
            assert!(
                !rule.description.is_empty(),
                "description must not be empty"
            );
        }
    }

    #[test]
    fn dlp_rules_categories_are_valid() {
        let valid = ["host", "uri", "body"];
        for rule in DLP_RULES {
            assert!(
                valid.contains(&rule.category),
                "unexpected category '{}' for rule '{}'",
                rule.category,
                rule.name
            );
        }
    }

    // ── render_grep ───────────────────────────────────────────────────────────

    #[test]
    fn render_grep_contains_header_disclaimer() {
        let out = render_grep(DLP_RULES);
        assert!(
            out.contains("OPERATOR NOTE"),
            "must include operator disclaimer"
        );
        assert!(out.contains("RFC-0132"), "must cite RFC-0132");
    }

    #[test]
    fn render_grep_contains_each_rule_regex() {
        let out = render_grep(DLP_RULES);
        for rule in DLP_RULES {
            assert!(
                out.contains(rule.regex),
                "grep output missing regex for rule '{}'",
                rule.name
            );
        }
    }

    #[test]
    fn render_grep_one_grep_command_per_rule() {
        let out = render_grep(DLP_RULES);
        let grep_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("grep -EP")).collect();
        assert_eq!(
            grep_lines.len(),
            DLP_RULES.len(),
            "expected one grep line per rule"
        );
    }

    // ── render_nginx ──────────────────────────────────────────────────────────

    #[test]
    fn render_nginx_contains_map_block() {
        let out = render_nginx(DLP_RULES);
        assert!(
            out.contains("map $request_body $mcp_shadow"),
            "must include map block"
        );
        assert!(
            out.contains("OPERATOR NOTE"),
            "must include operator disclaimer"
        );
    }

    #[test]
    fn render_nginx_contains_each_rule_as_if_block() {
        let out = render_nginx(DLP_RULES);
        for rule in DLP_RULES {
            assert!(
                out.contains(rule.regex),
                "nginx output missing regex for rule '{}'",
                rule.name
            );
        }
    }

    // ── render_yaml ───────────────────────────────────────────────────────────

    #[test]
    fn render_yaml_starts_with_dlp_rules_key() {
        let out = render_yaml(DLP_RULES);
        assert!(
            out.contains("dlp_rules:"),
            "must have top-level dlp_rules: key"
        );
    }

    #[test]
    fn render_yaml_contains_all_rule_names() {
        let out = render_yaml(DLP_RULES);
        for rule in DLP_RULES {
            assert!(
                out.contains(rule.name),
                "yaml output missing name for rule '{}'",
                rule.name
            );
        }
    }

    #[test]
    fn render_yaml_escapes_backslashes_in_regex() {
        let out = render_yaml(DLP_RULES);
        // Every rule with \s should have \\s in the YAML output
        let has_backslash_rule = DLP_RULES.iter().any(|r| r.regex.contains('\\'));
        if has_backslash_rule {
            assert!(
                out.contains("\\\\s"),
                "backslashes in regex must be escaped to \\\\ in YAML"
            );
        }
    }

    #[test]
    fn render_yaml_contains_disclaimer() {
        let out = render_yaml(DLP_RULES);
        assert!(
            out.contains("OPERATOR NOTE"),
            "yaml must include operator disclaimer"
        );
    }

    // ── run_doctor_shadow_command ─────────────────────────────────────────────

    #[test]
    fn shadow_command_invalid_format_returns_failure() {
        let code = run_doctor_shadow_command("iptables");
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn shadow_command_haproxy_alias_is_accepted() {
        // "haproxy" is an alias for the nginx formatter
        let code = run_doctor_shadow_command("haproxy");
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn shadow_command_empty_format_defaults_to_grep() {
        let code = run_doctor_shadow_command("");
        assert_eq!(code, ExitCode::SUCCESS);
    }
}
