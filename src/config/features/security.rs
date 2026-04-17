//! Security configuration for the gateway.

use serde::{Deserialize, Serialize};

pub use crate::security::agent_identity::AgentIdentityConfig;
use crate::security::policy::ToolPolicyConfig;

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
        }
    }
}
