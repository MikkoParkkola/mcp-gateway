// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    CollusionConfig, Deserialize, PathBuf, Serialize, budget_guard,
    default_anomaly_min_observations, default_anomaly_threshold, memory_scanner, tenant_guard,
};

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
    /// Memory-poisoning detection for OWASP ASI06 (Excessive Agency via memory).
    ///
    /// Scans arguments of memory-write tools (`remember`, `store`, `kv_set`, …)
    /// for LLM control tokens, role-confusion phrases, exfiltration payloads,
    /// and oversized entries.
    ///
    /// ```yaml
    /// security:
    ///   firewall:
    ///     memory_poisoning:
    ///       enabled: true
    ///       max_entry_size_bytes: 10240
    ///       scan_tools: ["remember", "batch_remember", "store", "kv_set", "kv_search"]
    /// ```
    #[serde(default)]
    pub memory_poisoning: memory_scanner::MemoryPoisoningConfig,
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
    /// Keyless legacy callers (authentication off, or on with the path public)
    /// that resume no established session share one history, so the threshold
    /// applies to them collectively: interleaved calls from several such
    /// clients are scored as one caller's sequence (MIK-7971).
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
    /// Transitions a predecessor needs before its successors are scored (default 20).
    #[serde(default = "default_anomaly_min_observations")]
    pub anomaly_min_observations: u64,
    /// Cross-tenant data-minimisation guard (MIK-7116.TENANT.1).
    ///
    /// Keys on the authenticated principal — never a session — and refuses a
    /// principal that reaches across more distinct tenants than the
    /// configured limit inside the configured window.
    #[serde(default)]
    pub tenant_guard: tenant_guard::TenantGuardConfig,
    /// Principal-keyed call budget (MIK-7215.CONTROL.2).
    ///
    /// A per-session budget under statelessness is an unlimited budget: see
    /// [`budget_guard`] for why the key is the principal, not the session.
    #[serde(default)]
    pub budget: budget_guard::BudgetGuardConfig,
    /// Verbatim cross-principal relay detection (OWASP ASI10, COLLUDE.1).
    ///
    /// ```yaml
    /// security:
    ///   firewall:
    ///     collusion:
    ///       action: observe          # off (default) | observe | block
    ///       sources: ["crm:*"]       # results always treated as sensitive
    ///       non_egress: ["notes:read_*"]
    ///       allowed_flows:           # expected collaboration, not a relay
    ///         - {source: "docs:read", egress: "mail:send_*"}
    /// ```
    #[serde(default)]
    pub collusion: CollusionConfig,
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
            memory_poisoning: memory_scanner::MemoryPoisoningConfig::default(),
            audit_log: None,
            rules: Vec::new(),
            anomaly_threshold: default_anomaly_threshold(),
            anomaly_block_threshold: None, // opt-in: None = log-only (backward compat)
            anomaly_min_observations: default_anomaly_min_observations(),
            tenant_guard: tenant_guard::TenantGuardConfig::default(), // opt-in: enabled=false
            budget: budget_guard::BudgetGuardConfig::default(),
            collusion: CollusionConfig::default(), // opt-in: action=off
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
    /// Memory-write tool argument contains a poisoning pattern (OWASP ASI06).
    MemoryPoisoning,
    /// A principal reached across more distinct tenants than the
    /// data-minimisation guard allows (MIK-7116.TENANT.1).
    CrossTenantReach,
    /// Principal exceeded its call budget for the window (MIK-7215.CONTROL.2).
    BudgetExceeded,
    /// Content delivered to one principal left through another's call
    /// (OWASP ASI10, COLLUDE.1).
    CollusionRelay,
}
