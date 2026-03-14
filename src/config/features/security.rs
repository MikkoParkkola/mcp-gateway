//! Security configuration for the gateway.

use serde::{Deserialize, Serialize};

use crate::security::policy::ToolPolicyConfig;

// ── Security ───────────────────────────────────────────────────────────────────

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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            ssrf_protection: true,
            tool_policy: ToolPolicyConfig::default(),
            #[cfg(feature = "firewall")]
            firewall: crate::security::firewall::FirewallConfig::default(),
        }
    }
}
