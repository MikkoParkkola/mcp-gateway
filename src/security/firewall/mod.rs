//! MCP Security Firewall — unified request/response inspection layer.
//!
//! Composes existing security modules (`sanitize`, `response_scanner`, `policy`,
//! `ssrf`, `data_flow`, `tool_integrity`) into a single enforcement point with
//! configurable actions and structured audit logging.
//!
//! # Pipeline
//!
//! ```text
//! Pre-invocation:  InputScanner → AnomalyDetector → resolve_action → AuditLogger
//! Post-invocation: ResponseScanner → Redactor     → resolve_action → AuditLogger
//! ```
//!
//! # Feature gate
//!
//! All items in this module are gated behind `#[cfg(feature = "firewall")]`.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::ResponseScanner;
use crate::transition::TransitionTracker;

pub mod anomaly;
pub mod audit;
pub mod input_scanner;
pub mod redactor;

// ─── Config ──────────────────────────────────────────────────────────────────

/// Firewall configuration, loaded from `gateway.yaml` under `security.firewall`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
// Multiple boolean flags are intentional here: each represents a distinct
// independent feature that operators may enable or disable separately.
// An enum state machine would not capture the combinatorial semantics.
#[allow(clippy::struct_excessive_bools)]
pub struct FirewallConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Scan tool invocation arguments for injection patterns.
    pub scan_requests: bool,
    /// Scan tool response content for credentials, PII, prompt injection.
    pub scan_responses: bool,
    /// Detect prompt injection patterns in tool outputs.
    pub prompt_injection_detection: bool,
    /// Detect and optionally redact credentials in responses.
    pub credential_redaction: bool,
    /// Use tool sequence data for anomaly detection (warn-only).
    pub anomaly_detection: bool,
    /// Path to the NDJSON audit log file.
    pub audit_log: Option<PathBuf>,
    /// Per-tool/per-pattern policy overrides (first match wins).
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    /// Minimum anomaly score (0.0–1.0) to emit a log warning.
    ///
    /// Maps to OWASP ASI10 "log threshold" — scores at or above this value
    /// produce a `SequenceAnomaly` finding at `Severity::Low` (audit only).
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
    /// Score at or above which the request is **blocked** (OWASP ASI10 blocking).
    ///
    /// When `None` (the default), anomaly detection remains retrospective:
    /// it logs warnings but never rejects requests, preserving backward
    /// compatibility. Set to a value in `(anomaly_threshold, 1.0]` to enable
    /// prospective blocking — e.g. `0.9`.
    ///
    /// ```yaml
    /// security:
    ///   firewall:
    ///     anomaly_detection: true
    ///     anomaly_threshold: 0.7       # log threshold
    ///     anomaly_block_threshold: 0.9 # block threshold
    /// ```
    #[serde(default)]
    pub anomaly_block_threshold: Option<f64>,
}

fn default_anomaly_threshold() -> f64 {
    0.7
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_requests: true,
            scan_responses: true,
            prompt_injection_detection: true,
            credential_redaction: true,
            anomaly_detection: false, // opt-in: needs accumulated transition data
            audit_log: None,
            rules: Vec::new(),
            anomaly_threshold: default_anomaly_threshold(),
            anomaly_block_threshold: None, // opt-in: None = log-only (backward compat)
        }
    }
}

/// A firewall rule: match tool name with a glob pattern and override the
/// default severity-based action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Glob pattern matching tool names (e.g., `"exec_*"`, `"*_delete*"`, `"*"`).
    ///
    /// Uses the `glob` crate — supports `*`, `?`, `[abc]`, `[!abc]`.
    #[serde(rename = "match")]
    pub tool_match: String,
    /// Action to take when a threat is detected for a matching tool.
    pub action: FirewallAction,
    /// Optional human-readable reason for the rule (logged in audit entries).
    #[serde(default)]
    pub reason: Option<String>,
    /// Which scan types to apply to matching tools. Empty = all scans.
    #[serde(default)]
    pub scan: Vec<ScanType>,
}

/// Action the firewall takes when a threat is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    /// Allow the request/response (audit log only).
    Allow,
    /// Allow but emit a warning in logs and response annotations.
    Warn,
    /// Block the request and return an error to the client.
    Block,
}

/// Types of scans that can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    /// Scan for credential patterns (AWS keys, API tokens, etc.)
    Credentials,
    /// Scan for PII patterns (emails, phone numbers, SSNs).
    Pii,
    /// Scan for prompt injection patterns in tool responses.
    PromptInjection,
    /// Scan for shell injection in request arguments.
    ShellInjection,
    /// Scan for path traversal in request arguments.
    PathTraversal,
    /// Scan for SQL injection in request arguments.
    SqlInjection,
    /// Anomaly detected in tool call sequence.
    SequenceAnomaly,
}

// ─── Runtime types ───────────────────────────────────────────────────────────

/// Compiled firewall engine — the runtime enforcement point.
///
/// Created once at gateway startup from `FirewallConfig`. Thread-safe via
/// interior immutability; all mutable state lives in sub-modules behind locks.
pub struct Firewall {
    config: FirewallConfig,
    /// Compiled tool-match rules (glob → action).
    rules: Vec<CompiledRule>,
    /// Reuse existing response scanner for prompt injection.
    response_scanner: ResponseScanner,
    /// Input pattern scanner for request arguments.
    input_scanner: input_scanner::InputScanner,
    /// Credential/PII redactor for response content.
    redactor: redactor::Redactor,
    /// Anomaly detector using transition data.
    anomaly: Option<anomaly::AnomalyDetector>,
    /// Structured audit logger.
    audit: Option<audit::AuditLogger>,
}

/// A compiled firewall rule with a pre-processed glob pattern.
struct CompiledRule {
    pattern: glob::Pattern,
    action: FirewallAction,
    #[allow(dead_code)]
    scans: Vec<ScanType>,
    #[allow(dead_code)]
    reason: Option<String>,
}

/// Verdict from the firewall for a single tool invocation.
#[derive(Debug, Clone)]
pub struct FirewallVerdict {
    /// Whether the request is allowed to proceed.
    pub allowed: bool,
    /// Action taken (for logging/response annotation).
    pub action: FirewallAction,
    /// Findings from all scans.
    pub findings: Vec<Finding>,
    /// Anomaly score if anomaly detection is enabled.
    pub anomaly_score: Option<f64>,
}

/// A single finding from a scan.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Which scan produced this finding.
    pub scan_type: ScanType,
    /// Severity: high (block), medium (warn), low (log).
    pub severity: Severity,
    /// Human-readable description of the finding.
    pub description: String,
    /// The matched pattern or fragment (truncated for logging).
    pub matched: String,
    /// Where the finding was detected.
    pub location: FindingLocation,
}

/// Finding severity, which drives the default action when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Deterministic pattern — block by default.
    High,
    /// Heuristic pattern — warn by default.
    Medium,
    /// Statistical anomaly — log only by default.
    Low,
}

/// Where a finding was detected in the invocation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLocation {
    /// Found in tool invocation arguments.
    RequestArgs,
    /// Found in tool response content.
    ResponseContent,
    /// Derived from tool call sequence patterns.
    SequenceAnomaly,
}

// ─── Firewall impl ───────────────────────────────────────────────────────────

impl Firewall {
    /// Create a new firewall from config.
    ///
    /// Compiles all rules, initialises scanners, and opens the audit log if
    /// configured. Falls back to stderr logging when the log file cannot be
    /// opened.
    pub fn from_config(
        config: FirewallConfig,
        transition_tracker: Option<Arc<TransitionTracker>>,
    ) -> Self {
        let rules = config.rules.iter().map(compile_rule).collect();
        let response_scanner = ResponseScanner::new();
        let input_scanner = input_scanner::InputScanner::new();
        let redactor = redactor::Redactor::new();
        let anomaly = if config.anomaly_detection {
            transition_tracker.map(|tt| anomaly::AnomalyDetector::new(tt, config.anomaly_threshold))
        } else {
            None
        };
        let audit = config.audit_log.as_ref().map(|path| {
            audit::AuditLogger::new(path).unwrap_or_else(|e| {
                tracing::warn!("Cannot open audit log {}: {e}", path.display());
                audit::AuditLogger::stderr()
            })
        });

        Self {
            config,
            rules,
            response_scanner,
            input_scanner,
            redactor,
            anomaly,
            audit,
        }
    }

    /// Pre-invocation check: scan request arguments for threats.
    ///
    /// Returns a verdict. If `allowed` is `false`, the caller **must not**
    /// forward the request to the backend.
    pub fn check_request(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        args: &Value,
        caller: &str,
    ) -> FirewallVerdict {
        if !self.config.enabled || !self.config.scan_requests {
            return FirewallVerdict::allow();
        }

        let mut findings = Vec::new();

        // 1. Input pattern scan (shell injection, path traversal, SQL).
        if let Value::Object(map) = args {
            findings.extend(self.input_scanner.scan_args(map));
        }

        // 2. Anomaly detection — score how unusual this tool call sequence is.
        let anomaly_score = self
            .anomaly
            .as_ref()
            .map(|a| a.score_transition(session_id, server, tool));

        if let Some(score) = anomaly_score {
            let above_block = self
                .config
                .anomaly_block_threshold
                .is_some_and(|t| score >= t);
            let above_log = score >= self.config.anomaly_threshold;

            if above_block {
                tracing::warn!(
                    session_id = session_id,
                    server = server,
                    tool = tool,
                    anomaly_score = score,
                    "OWASP ASI10: rogue-agent anomaly blocked (score {score:.2})"
                );
                findings.push(Finding {
                    scan_type: ScanType::SequenceAnomaly,
                    severity: Severity::High,
                    description: format!(
                        "Anomaly detection triggered: unusual tool sequence blocked \
                         (score {score:.2} ≥ block_threshold {:.2})",
                        self.config.anomaly_block_threshold.unwrap_or(1.0),
                    ),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
            } else if above_log {
                findings.push(Finding {
                    scan_type: ScanType::SequenceAnomaly,
                    severity: Severity::Low,
                    description: format!("Unusual tool sequence (anomaly score: {score:.2})"),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
            }
        }

        // 3. Determine action from rules + finding severity.
        let action = self.resolve_action(tool, &findings);
        let allowed = action != FirewallAction::Block;

        let verdict = FirewallVerdict {
            allowed,
            action,
            findings,
            anomaly_score,
        };

        // 4. Audit log every request (including clean ones).
        if let Some(ref audit) = self.audit {
            audit.log_request(session_id, server, tool, caller, args, &verdict);
        }

        verdict
    }

    /// Post-invocation check: scan response content for credentials/injection.
    ///
    /// May redact credentials/PII from the response value in place (returns
    /// the potentially-modified value).
    pub fn check_response(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        response: &mut Value,
        caller: &str,
    ) -> FirewallVerdict {
        if !self.config.enabled || !self.config.scan_responses {
            return FirewallVerdict::allow();
        }

        let mut findings = Vec::new();

        // 1. Prompt injection detection (reuse ResponseScanner).
        //    Immutable borrow must complete before the mutable borrow in step 2.
        if self.config.prompt_injection_detection {
            let pi_matches = self
                .response_scanner
                .scan_response(server, tool, &*response);
            for m in pi_matches {
                findings.push(Finding {
                    scan_type: ScanType::PromptInjection,
                    severity: Severity::Medium,
                    description: m.pattern_description,
                    matched: m.matched_fragment,
                    location: FindingLocation::ResponseContent,
                });
            }
        }

        // 2. Credential detection + redaction (takes `&mut Value` for in-place replacement).
        if self.config.credential_redaction {
            let cred_findings = self.redactor.scan_and_redact(response);
            findings.extend(cred_findings);
        }

        // 3. Determine action.
        let action = self.resolve_action(tool, &findings);
        let allowed = action != FirewallAction::Block;

        let verdict = FirewallVerdict {
            allowed,
            action,
            findings,
            anomaly_score: None,
        };

        // 4. Audit log.
        if let Some(ref audit) = self.audit {
            audit.log_response(session_id, server, tool, caller, &verdict);
        }

        verdict
    }

    /// Match tool name against rules; fall back to severity-based default action.
    ///
    /// First matching rule wins. When no rule matches, the highest-severity
    /// finding determines the action: High→Block, Medium→Warn, Low→Allow.
    fn resolve_action(&self, tool: &str, findings: &[Finding]) -> FirewallAction {
        let highest_severity = strongest_finding_severity(findings);
        let matching_rule_action =
            highest_severity.and_then(|_| first_matching_rule_action(&self.rules, tool));

        decide_firewall_action(matching_rule_action, highest_severity)
    }

    /// Clean up per-session state in the anomaly detector.
    ///
    /// Must be called (via the `SessionLifecycle` hook) when a session
    /// disconnects to prevent unbounded memory growth.
    pub fn on_session_end(&self, session_id: &str) {
        if let Some(ref a) = self.anomaly {
            a.remove_session(session_id);
        }
    }
}

impl FirewallVerdict {
    /// Construct an unconditional allow verdict (used when scanning is disabled).
    fn allow() -> Self {
        Self {
            allowed: true,
            action: FirewallAction::Allow,
            findings: Vec::new(),
            anomaly_score: None,
        }
    }

    /// Returns `true` when the block was triggered solely by anomaly detection
    /// (OWASP ASI10 — Rogue Agents), i.e. every blocking finding is a
    /// `SequenceAnomaly` at `Severity::High`.
    ///
    /// Callers should use JSON-RPC error code `-32002` for anomaly blocks to
    /// distinguish them from generic security blocks (`-32600`).
    pub fn is_anomaly_block(&self) -> bool {
        !self.allowed
            && !self.findings.is_empty()
            && self
                .findings
                .iter()
                .all(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::High)
    }
}

// ─── Rule helpers ─────────────────────────────────────────────────────────────

fn compile_rule(rule: &FirewallRule) -> CompiledRule {
    let pattern = glob::Pattern::new(&rule.tool_match)
        .unwrap_or_else(|_| glob::Pattern::new("*").expect("fallback pattern compiles"));
    CompiledRule {
        pattern,
        action: rule.action,
        scans: rule.scan.clone(),
        reason: rule.reason.clone(),
    }
}

fn rule_matches(rule: &CompiledRule, tool: &str) -> bool {
    rule.pattern.matches(tool)
}

fn first_matching_rule_action(rules: &[CompiledRule], tool: &str) -> Option<FirewallAction> {
    rules
        .iter()
        .find(|rule| rule_matches(rule, tool))
        .map(|rule| rule.action)
}

fn strongest_finding_severity(findings: &[Finding]) -> Option<Severity> {
    findings
        .iter()
        .map(|finding| finding.severity)
        .min_by_key(|severity| severity_rank(*severity))
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
    }
}

const fn default_action_for_severity(severity: Severity) -> FirewallAction {
    match severity {
        Severity::High => FirewallAction::Block,
        Severity::Medium => FirewallAction::Warn,
        Severity::Low => FirewallAction::Allow,
    }
}

const fn decide_firewall_action(
    matching_rule_action: Option<FirewallAction>,
    highest_severity: Option<Severity>,
) -> FirewallAction {
    match highest_severity {
        None => FirewallAction::Allow,
        Some(severity) => match matching_rule_action {
            Some(action) => action,
            None => default_action_for_severity(severity),
        },
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    fn any_firewall_action() -> FirewallAction {
        match kani::any::<u8>() % 3 {
            0 => FirewallAction::Allow,
            1 => FirewallAction::Warn,
            _ => FirewallAction::Block,
        }
    }

    fn any_severity() -> Severity {
        match kani::any::<u8>() % 3 {
            0 => Severity::High,
            1 => Severity::Medium,
            _ => Severity::Low,
        }
    }

    #[kani::proof]
    fn firewall_action_resolution_contract() {
        let has_findings: bool = kani::any();
        let has_matching_rule: bool = kani::any();

        let highest_severity = if has_findings {
            Some(any_severity())
        } else {
            None
        };
        let matching_rule_action = if has_matching_rule {
            Some(any_firewall_action())
        } else {
            None
        };

        let action = decide_firewall_action(matching_rule_action, highest_severity);

        match highest_severity {
            None => assert_eq!(action, FirewallAction::Allow),
            Some(severity) => {
                if let Some(rule_action) = matching_rule_action {
                    assert_eq!(action, rule_action);
                } else {
                    assert_eq!(action, default_action_for_severity(severity));
                }
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_firewall() -> Firewall {
        Firewall::from_config(FirewallConfig::default(), None)
    }

    // ── FirewallConfig defaults ───────────────────────────────────────────────

    #[test]
    fn disabled_firewall_allows_everything() {
        let cfg = FirewallConfig {
            enabled: false,
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        let args = json!({ "cmd": "; rm -rf /" });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
        assert!(verdict.findings.is_empty());
    }

    #[test]
    fn scan_requests_disabled_allows_injection() {
        let cfg = FirewallConfig {
            scan_requests: false,
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        let args = json!({ "cmd": "; rm -rf /" });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.allowed);
    }

    #[test]
    fn scan_responses_disabled_skips_response_scan() {
        let cfg = FirewallConfig {
            scan_responses: false,
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        let mut response = json!({ "text": "AKIAIOSFODNN7EXAMPLE12345" });
        let verdict = fw.check_response("s1", "srv", "tool", &mut response, "caller");
        assert!(verdict.allowed);
        assert!(verdict.findings.is_empty());
    }

    // ── Severity → action mapping ─────────────────────────────────────────────

    #[test]
    fn high_severity_finding_blocks() {
        let fw = default_firewall();
        // Shell injection is HIGH severity
        let args = json!({ "cmd": "; rm -rf / " });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(!verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Block);
    }

    #[test]
    fn medium_severity_finding_warns() {
        let fw = default_firewall();
        // SQL injection is MEDIUM severity
        let args = json!({ "q": "' OR 1=1" });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Warn);
    }

    #[test]
    fn clean_args_produce_allow_verdict() {
        let fw = default_firewall();
        let args = json!({ "name": "hello", "count": 42 });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
        assert!(verdict.findings.is_empty());
    }

    // ── Rule override ─────────────────────────────────────────────────────────

    #[test]
    fn rule_overrides_default_action_to_block() {
        let cfg = FirewallConfig {
            rules: vec![FirewallRule {
                tool_match: "exec_*".to_string(),
                action: FirewallAction::Block,
                reason: Some("Shell execution blocked".to_string()),
                scan: vec![],
            }],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        // SQL injection is normally MEDIUM (warn), but exec_* rule blocks it
        let args = json!({ "q": "' OR 1=1" });
        let verdict = fw.check_request("s1", "srv", "exec_command", &args, "caller");
        assert!(!verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Block);
    }

    #[test]
    fn rule_overrides_default_action_to_warn() {
        let cfg = FirewallConfig {
            rules: vec![FirewallRule {
                tool_match: "safe_shell".to_string(),
                action: FirewallAction::Warn,
                reason: None,
                scan: vec![],
            }],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        // Shell injection is normally HIGH (block), but safe_shell rule warns only
        let args = json!({ "cmd": "; rm -rf / " });
        let verdict = fw.check_request("s1", "srv", "safe_shell", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Warn);
    }

    #[test]
    fn glob_rule_matches_prefix() {
        let cfg = FirewallConfig {
            rules: vec![FirewallRule {
                tool_match: "exec_*".to_string(),
                action: FirewallAction::Block,
                reason: None,
                scan: vec![],
            }],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        assert!(rule_matches(&fw.rules[0], "exec_command"));
        assert!(rule_matches(&fw.rules[0], "exec_shell"));
        assert!(!rule_matches(&fw.rules[0], "list_tools"));
    }

    #[test]
    fn wildcard_rule_matches_all_tools() {
        let cfg = FirewallConfig {
            rules: vec![FirewallRule {
                tool_match: "*".to_string(),
                action: FirewallAction::Allow,
                reason: None,
                scan: vec![],
            }],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        // Shell injection would normally block, but * rule overrides to Allow
        let args = json!({ "cmd": "; rm -rf / " });
        let verdict = fw.check_request("s1", "srv", "any_tool", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
    }

    #[test]
    fn first_matching_rule_wins() {
        let cfg = FirewallConfig {
            rules: vec![
                FirewallRule {
                    tool_match: "*".to_string(),
                    action: FirewallAction::Warn,
                    reason: Some("Catch-all warning".to_string()),
                    scan: vec![],
                },
                FirewallRule {
                    tool_match: "exec_*".to_string(),
                    action: FirewallAction::Block,
                    reason: Some("Specific block".to_string()),
                    scan: vec![],
                },
            ],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        let args = json!({ "cmd": "; rm -rf / " });
        let verdict = fw.check_request("s1", "srv", "exec_command", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Warn);
    }

    #[test]
    fn clean_args_ignore_matching_rules() {
        let cfg = FirewallConfig {
            rules: vec![FirewallRule {
                tool_match: "*".to_string(),
                action: FirewallAction::Block,
                reason: Some("Only applies when a finding exists".to_string()),
                scan: vec![],
            }],
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(cfg, None);
        let args = json!({ "name": "hello", "count": 42 });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Allow);
    }

    // ── Response scan ─────────────────────────────────────────────────────────

    #[test]
    fn verdict_contains_all_findings() {
        let fw = default_firewall();
        let args = json!({
            "cmd": "; rm -rf / ",
            "q": "' OR 1=1"
        });
        let verdict = fw.check_request("s1", "srv", "tool", &args, "caller");
        assert!(verdict.findings.len() >= 2);
    }

    #[test]
    fn response_scan_detects_credential() {
        let fw = default_firewall();
        let mut response = json!({ "output": "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890" });
        let verdict = fw.check_response("s1", "srv", "tool", &mut response, "caller");
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::Credentials)
        );
    }

    // ── on_session_end ────────────────────────────────────────────────────────

    #[test]
    fn session_end_is_noop_without_anomaly_detector() {
        let fw = default_firewall();
        fw.on_session_end("session-xyz"); // must not panic
    }

    // ── OWASP ASI10 anomaly blocking ──────────────────────────────────────────

    /// Build a firewall with anomaly detection enabled and trained transition
    /// data so that a never-seen transition scores 0.95.
    fn anomaly_firewall(log_threshold: f64, block_threshold: Option<f64>) -> Firewall {
        use crate::transition::TransitionTracker;
        let tracker = Arc::new(TransitionTracker::new());
        // Train: tool_a → tool_b (10×) so predecessor data exists.
        for _ in 0..10 {
            tracker.record_transition("train", "srv:tool_a");
            tracker.record_transition("train", "srv:tool_b");
        }
        let cfg = FirewallConfig {
            anomaly_detection: true,
            anomaly_threshold: log_threshold,
            anomaly_block_threshold: block_threshold,
            ..FirewallConfig::default()
        };
        Firewall::from_config(cfg, Some(tracker))
    }

    /// Prime the session so `tool_a` is recorded as the last tool.
    fn prime_session(fw: &Firewall, session: &str) {
        fw.check_request(session, "srv", "tool_a", &json!({}), "caller");
    }

    #[test]
    fn anomaly_below_log_threshold_passes_silently() {
        // Cold-start score is 0.5; log_threshold is 0.7 → no finding at all.
        let fw = anomaly_firewall(0.7, None);
        let args = json!({});
        // First call is always cold-start (score 0.5).
        let verdict = fw.check_request("sess", "srv", "tool_a", &args, "caller");
        assert!(verdict.allowed);
        assert!(
            verdict.findings.is_empty(),
            "Cold-start score 0.5 must not produce a finding below log_threshold 0.7"
        );
    }

    #[test]
    fn anomaly_above_log_threshold_logs_but_passes() {
        // Never-seen transition scores 0.95; log_threshold=0.7, no block_threshold.
        let fw = anomaly_firewall(0.7, None);
        prime_session(&fw, "sess");
        let verdict = fw.check_request("sess", "srv", "never_seen_tool", &json!({}), "caller");
        assert!(
            verdict.allowed,
            "Without block_threshold, anomaly findings must not block"
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::Low),
            "Score 0.95 above log_threshold 0.7 must produce a Low SequenceAnomaly finding"
        );
        assert!(
            !verdict.is_anomaly_block(),
            "is_anomaly_block must be false when block_threshold is not set"
        );
    }

    #[test]
    fn anomaly_above_block_threshold_is_rejected() {
        // Never-seen transition scores 0.95; block_threshold=0.9 → block.
        let fw = anomaly_firewall(0.7, Some(0.9));
        prime_session(&fw, "sess");
        let verdict = fw.check_request("sess", "srv", "never_seen_tool", &json!({}), "caller");
        assert!(
            !verdict.allowed,
            "Score 0.95 ≥ block_threshold 0.9 must be rejected"
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::High),
            "Blocked anomaly finding must be Severity::High"
        );
        assert!(
            verdict.is_anomaly_block(),
            "is_anomaly_block must be true when only anomaly findings are present"
        );
    }

    #[test]
    fn anomaly_block_threshold_unset_preserves_backward_compatibility() {
        // block_threshold=None: even a score of 0.95 must never block.
        let fw = anomaly_firewall(0.7, None);
        prime_session(&fw, "sess");
        let verdict = fw.check_request("sess", "srv", "never_seen_tool", &json!({}), "caller");
        assert!(
            verdict.allowed,
            "With no block_threshold, all requests pass regardless of anomaly score"
        );
    }

    #[test]
    fn anomaly_finding_is_high_severity_only_when_above_block_threshold() {
        // Score 0.95 is above log (0.7) but below block (0.99) → Low, not High.
        let fw = anomaly_firewall(0.7, Some(0.99));
        prime_session(&fw, "sess");
        let verdict = fw.check_request("sess", "srv", "never_seen_tool", &json!({}), "caller");
        assert!(
            verdict.allowed,
            "Score 0.95 < block_threshold 0.99 must pass"
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::Low),
            "Finding must be Low (log-only) when score is below block_threshold"
        );
        assert!(
            !verdict.is_anomaly_block(),
            "is_anomaly_block must be false when score is below block_threshold"
        );
    }
}
