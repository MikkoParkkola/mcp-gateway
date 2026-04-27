//! Security configuration for the gateway.

use serde::{Deserialize, Serialize};

pub use crate::security::agent_identity::AgentIdentityConfig;
use crate::security::policy::ToolPolicyConfig;

// ── TransparencyLogConfig ─────────────────────────────────────────────────────

/// Configuration for the tamper-evident hash-chain transparency log (issue #133, D3).
///
/// When `enabled = true` every completed tool invocation is appended to a
/// file-backed NDJSON hash-chain so any post-hoc tampering is detectable.
///
/// ```yaml
/// security:
///   transparency_log:
///     enabled: true
///     path: "~/.mcp-gateway/transparency/transparency.jsonl"
///     shared_secret: "${MCP_GATEWAY_TRANSPARENCY_SECRET}"
///     key_id: "v1"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransparencyLogConfig {
    /// Enable the transparency log. Default: `false` (opt-in).
    pub enabled: bool,
    /// Path to the NDJSON log file (`~` is expanded at startup).
    pub path: String,
    /// Key identifier written into `key_id` for rotation tracking.
    pub key_id: String,
    /// HMAC shared secret (resolved from env var at load time).
    ///
    /// When empty, `sig` / `key_id` are omitted from each entry — the hash
    /// chain alone still provides tamper evidence.
    pub shared_secret: String,
}

impl Default for TransparencyLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "~/.mcp-gateway/transparency/transparency.jsonl".to_string(),
            key_id: "default".to_string(),
            shared_secret: String::new(),
        }
    }
}

// ── MessageSigningConfig ──────────────────────────────────────────────────────

/// Configuration for inter-agent HMAC-SHA256 message signing (ADR-001).
///
/// When `enabled = true` the gateway:
/// 1. Appends a `_signature` block to every `gateway_invoke` response.
/// 2. Rejects replayed request nonces within the `replay_window`.
///
/// The `shared_secret` MUST be at least 32 bytes (256 bits). Use an env-var
/// reference so the secret is never stored in plaintext YAML:
///
/// ```yaml
/// security:
///   message_signing:
///     enabled: true
///     shared_secret: "${MCP_GATEWAY_SIGNING_SECRET}"
///     replay_window: 300
///     key_id: "default"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageSigningConfig {
    /// Enable message signing. Default: `false` (opt-in).
    pub enabled: bool,
    /// HMAC shared secret (resolved from env var at load time).
    ///
    /// Must be at least 32 bytes when `enabled = true`.
    pub shared_secret: String,
    /// Previous secret for zero-downtime rotation. Empty means no rotation active.
    pub previous_secret: String,
    /// When `true`, requests without a `nonce` field are rejected (`-32001`).
    /// Default: `false` (backward-compatible).
    pub require_nonce: bool,
    /// Replay window in seconds. Nonces seen within this window are rejected.
    /// Default: 300 (5 minutes).
    pub replay_window: u64,
    /// Key identifier included in `_signature.key_id` for rotation tracking.
    pub key_id: String,
}

impl Default for MessageSigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shared_secret: String::new(),
            previous_secret: String::new(),
            require_nonce: false,
            replay_window: 300,
            key_id: "default".to_string(),
        }
    }
}

// ── ResponseInspectionConfig ──────────────────────────────────────────────────

/// Configuration for response-side anomaly screening (issue #133, D2).
///
/// Scans every tool response for secrets (API keys, private keys), code
/// injection patterns (base64|bash, pip/npm install), and exfiltration URLs
/// before the result is returned to the client.
///
/// Two modes:
/// - **Observe** (`action_mode = false`, default): logs findings but never
///   blocks. Use while calibrating false-positive rates.
/// - **Action** (`action_mode = true`): blocks any response with a HIGH or
///   CRITICAL finding, returning a security error to the caller.
///
/// ```yaml
/// security:
///   response_inspection:
///     enabled: true
///     action_mode: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseInspectionConfig {
    /// Enable response inspection. Default: `true` (observe mode by default).
    pub enabled: bool,
    /// Block responses with HIGH/CRITICAL findings. Default: `false` (observe only).
    ///
    /// Set to `true` to enforce fail-closed behaviour for detected threats.
    pub action_mode: bool,
}

impl Default for ResponseInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action_mode: false,
        }
    }
}

// ── ResponseContractConfig ────────────────────────────────────────────────────

/// Per-tool response contract entry (issue #133, D1).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ToolContractConfig {
    /// Maximum allowed text size in bytes. `null` means unlimited.
    pub max_bytes: Option<usize>,
    /// Regex patterns that must NOT appear in the response text.
    pub forbidden_patterns: Vec<String>,
    /// Override global action_mode for this tool. `null` means use global.
    pub action_mode: Option<bool>,
}

/// Response contract configuration (issue #133, D1).
///
/// Validates every tool response against a declared per-tool contract before
/// delivery to the client.  Supports size limits and forbidden regex patterns.
///
/// ```yaml
/// security:
///   response_contract:
///     enabled: true
///     action_mode: true
///     fail_closed: false
///     default_max_bytes: 102400
///     tools:
///       my_sensitive_tool:
///         max_bytes: 4096
///         forbidden_patterns:
///           - 'sk-[a-zA-Z0-9]{48}'
///           - 'BEGIN PRIVATE KEY'
///         action_mode: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ResponseContractConfig {
    /// Enable the contract gate. Default: `false` (opt-in).
    pub enabled: bool,
    /// Block violating responses (action_mode=true) or just observe. Default: `false`.
    pub action_mode: bool,
    /// Default max response bytes for all tools (overridable per-tool). Default: `None`.
    pub default_max_bytes: Option<usize>,
    /// When `true`, responses from tools with NO declared contract are blocked.
    /// Default: `false` (backward-compatible pass-through for unconfigured tools).
    pub fail_closed: bool,
    /// Per-tool contracts keyed by tool name.
    pub tools: std::collections::HashMap<String, ToolContractConfig>,
}

// ── SecurityConfig ────────────────────────────────────────────────────────────

/// Security configuration for the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Enable input sanitization (null byte rejection, control char stripping, NFC).
    pub sanitize_input: bool,
    /// Enable SSRF protection for outbound URLs.
    pub ssrf_protection: bool,
    /// Tool allow/deny policy.
    pub tool_policy: ToolPolicyConfig,
    /// Security firewall — bidirectional request/response scanning (RFC-0071).
    #[cfg(feature = "firewall")]
    #[serde(default)]
    pub firewall: crate::security::firewall::FirewallConfig,
    /// Inter-agent message signing (ADR-001, OWASP ASI07). Default: disabled.
    #[serde(default)]
    pub message_signing: MessageSigningConfig,
    /// Per-agent identity verification (OWASP ASI03). Default: disabled.
    #[serde(default)]
    pub agent_identity: AgentIdentityConfig,
    /// Tamper-evident hash-chain transparency log (issue #133, D3). Default: disabled.
    #[serde(default)]
    pub transparency_log: TransparencyLogConfig,
    /// Response-side anomaly screening (issue #133, D2). Default: enabled, observe mode.
    #[serde(default)]
    pub response_inspection: ResponseInspectionConfig,
    /// Per-tool fail-closed response contract gate (issue #133, D1). Default: disabled.
    #[serde(default)]
    pub response_contract: ResponseContractConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            ssrf_protection: true,
            tool_policy: ToolPolicyConfig::default(),
            #[cfg(feature = "firewall")]
            firewall: crate::security::firewall::FirewallConfig::default(),
            message_signing: MessageSigningConfig::default(),
            agent_identity: AgentIdentityConfig::default(),
            transparency_log: TransparencyLogConfig::default(),
            response_inspection: ResponseInspectionConfig::default(),
            response_contract: ResponseContractConfig::default(),
        }
    }
}
