// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Security configuration for the gateway.

use serde::{Deserialize, Serialize};

use crate::context_integrity::{ContextIntegrityPolicy, ContextIntegrityPolicyPreset};
pub use crate::security::agent_identity::AgentIdentityConfig;
use crate::security::policy::ToolPolicyConfig;
pub use crate::security::remote_provenance::RemoteServerSigningConfig;

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
#[derive(Clone, Serialize, Deserialize)]
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

// Manual `Debug` that redacts the HMAC shared secret (CWE-532, mirrors PR
// #323). A derived `Debug` would print the signing secret verbatim into any
// trace or error context; only its presence is surfaced.
impl std::fmt::Debug for TransparencyLogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparencyLogConfig")
            .field("enabled", &self.enabled)
            .field("path", &self.path)
            .field("key_id", &self.key_id)
            .field(
                "shared_secret",
                &if self.shared_secret.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
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
/// 1. Appends a `_signature` block to successful external `gateway_invoke` responses.
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageSigningConfig {
    /// Enable message signing. Default: `false` (opt-in).
    pub enabled: bool,
    /// HMAC shared secret (resolved from env var at load time).
    ///
    /// Must be at least 32 bytes when `enabled = true`.
    pub shared_secret: String,
    /// Previous key material, validated when supplied. Empty means absent.
    /// Only the current key signs gateway responses.
    pub previous_secret: String,
    /// When `true`, requests without a `nonce` field are rejected (`-32001`).
    /// Default: `false` (backward-compatible).
    pub require_nonce: bool,
    /// Replay window in seconds. Nonces seen within this window are rejected.
    /// Default: 300 (5 minutes).
    pub replay_window: u64,
    /// Key identifier included in `_signature.key_id` for rotation tracking.
    pub key_id: String,
    // Effective key bytes are opaque. A public field mutation invalidates only
    // that field's marker; clones retain markers, deserialization never does.
    #[serde(skip)]
    resolved_shared_secret: Option<[u8; 32]>,
    #[serde(skip)]
    resolved_previous_secret: Option<[u8; 32]>,
    // Preserve configured-reference identity across evaluation, without keeping
    // another copy of raw key material or publishing these markers.
    #[serde(skip)]
    configured_shared_secret: Option<[u8; 32]>,
    #[serde(skip)]
    configured_previous_secret: Option<[u8; 32]>,
}

// Manual `Debug` that redacts both HMAC signing secrets (CWE-532, mirrors PR
// #323). A derived `Debug` would print the current and previous signing
// material verbatim — leaking either lets an attacker forge signed responses.
// Only secret presence is surfaced.
impl std::fmt::Debug for MessageSigningConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |s: &str| {
            if s.is_empty() {
                "<empty>"
            } else {
                "<redacted>"
            }
        };
        f.debug_struct("MessageSigningConfig")
            .field("enabled", &self.enabled)
            .field("shared_secret", &redact(&self.shared_secret))
            .field("previous_secret", &redact(&self.previous_secret))
            .field("require_nonce", &self.require_nonce)
            .field("replay_window", &self.replay_window)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
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
            resolved_shared_secret: None,
            resolved_previous_secret: None,
            configured_shared_secret: None,
            configured_previous_secret: None,
        }
    }
}

impl MessageSigningConfig {
    /// Resolve and validate signing settings without changing the literal config.
    ///
    /// Disabled settings are dormant. Errors identify only the field: neither
    /// a secret nor its environment reference belongs in a diagnostic.
    pub(crate) fn resolve_with_env(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Self> {
        if !self.enabled {
            return Ok(self.clone());
        }
        if self.key_id.trim().is_empty() {
            return Err(Self::signing_config_error("key_id", "must not be blank"));
        }
        if self.replay_window == 0 {
            return Err(Self::signing_config_error(
                "replay_window",
                "must be greater than zero",
            ));
        }
        let mut resolved = self.clone();
        if self.resolved_shared_secret != Some(Self::key_identity(&self.shared_secret)) {
            resolved.configured_shared_secret = Some(Self::key_identity(&self.shared_secret));
            resolved.shared_secret =
                Self::resolve_key(&self.shared_secret, "shared_secret", overlay)?;
            resolved.resolved_shared_secret = Some(Self::key_identity(&resolved.shared_secret));
        }
        if self.previous_secret.is_empty() {
            resolved.resolved_previous_secret = None;
            resolved.configured_previous_secret = None;
        } else if self.resolved_previous_secret != Some(Self::key_identity(&self.previous_secret)) {
            resolved.configured_previous_secret = Some(Self::key_identity(&self.previous_secret));
            resolved.previous_secret =
                Self::resolve_key(&self.previous_secret, "previous_secret", overlay)?;
            resolved.resolved_previous_secret = Some(Self::key_identity(&resolved.previous_secret));
        }
        Ok(resolved)
    }

    /// A signer and its replay state retain startup settings. Compare both the
    /// configured key source and effective bytes, including equal-byte reference
    /// edits that the ordinary effective-config diff cannot see.
    pub(crate) fn restart_changed_field(
        &self,
        candidate: &Self,
        startup_overlay: &crate::config::EnvOverlay,
        candidate_overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Option<&'static str>> {
        let running = self.resolve_with_env(startup_overlay)?;
        let proposed = candidate.resolve_with_env(candidate_overlay)?;
        let field = if running.enabled != proposed.enabled {
            Some("enabled")
        } else if running.shared_secret != proposed.shared_secret
            || running
                .configured_shared_secret
                .unwrap_or_else(|| Self::key_identity(&running.shared_secret))
                != proposed
                    .configured_shared_secret
                    .unwrap_or_else(|| Self::key_identity(&proposed.shared_secret))
        {
            Some("shared_secret")
        } else if running.previous_secret != proposed.previous_secret
            || running
                .configured_previous_secret
                .unwrap_or_else(|| Self::key_identity(&running.previous_secret))
                != proposed
                    .configured_previous_secret
                    .unwrap_or_else(|| Self::key_identity(&proposed.previous_secret))
        {
            Some("previous_secret")
        } else if running.key_id != proposed.key_id {
            Some("key_id")
        } else if running.require_nonce != proposed.require_nonce {
            Some("require_nonce")
        } else if running.replay_window != proposed.replay_window {
            Some("replay_window")
        } else {
            None
        };
        Ok(field)
    }

    fn key_identity(value: &str) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(value.as_bytes()).into()
    }

    fn resolve_key(
        literal: &str,
        field: &str,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<String> {
        let missing =
            || Self::signing_config_error(field, "requires an available environment value");
        let resolved = if let Some(name) = literal.strip_prefix("env:") {
            overlay.resolve(name).ok_or_else(missing)?
        } else {
            // Match the existing config expansion grammar, but refuse a missing
            // required variable instead of silently substituting an empty key.
            let pattern = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")
                .expect("constant signing environment pattern");
            let mut result = String::with_capacity(literal.len());
            let mut end = 0;
            for captures in pattern.captures_iter(literal) {
                let matched = captures.get(0).expect("matched environment reference");
                result.push_str(&literal[end..matched.start()]);
                let value = overlay
                    .resolve(&captures[1])
                    .or_else(|| captures.get(2).map(|default| default.as_str().to_owned()))
                    .ok_or_else(missing)?;
                result.push_str(&value);
                end = matched.end();
            }
            result.push_str(&literal[end..]);
            result
        };
        if resolved.len() < 32 || resolved.bytes().all(|byte| byte == 0) {
            return Err(Self::signing_config_error(
                field,
                "must contain at least 32 bytes and must not be all zero",
            ));
        }
        Ok(resolved)
    }

    fn signing_config_error(field: &str, reason: &str) -> crate::Error {
        crate::Error::ConfigValidation(format!("security.message_signing.{field} {reason}"))
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
    /// Override global `action_mode` for this tool. `null` means use global.
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
    /// Block violating responses (`action_mode=true`) or just observe. Default: `false`.
    pub action_mode: bool,
    /// Default max response bytes for all tools (overridable per-tool). Default: `None`.
    pub default_max_bytes: Option<usize>,
    /// When `true`, responses from tools with NO declared contract are blocked.
    /// Default: `false` (backward-compatible pass-through for unconfigured tools).
    pub fail_closed: bool,
    /// Per-tool contracts keyed by tool name.
    pub tools: std::collections::HashMap<String, ToolContractConfig>,
}

// ── IdentityGrantsConfig ─────────────────────────────────────────────────────

/// Local identity-grants file configuration.
///
/// When enabled, the gateway loads a JSON or YAML file containing
/// `IdentityGrant` rows and applies them to personal capability dispatch.
/// This is the free/core local operator path; org-wide grant storage and
/// delegated approvals remain enterprise control-plane concerns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityGrantsConfig {
    /// Load local identity grants at startup. Default: `false`.
    pub enabled: bool,
    /// JSON or YAML file containing `IdentityGrant` rows.
    pub path: String,
    /// Fail startup if the configured file cannot be read or parsed. Default:
    /// `true` so operators do not silently run with an empty grant store.
    pub fail_on_error: bool,
    /// Trust caller identity headers from an already-authenticated edge proxy.
    ///
    /// Default: `false`. Enable only when direct clients cannot reach the
    /// gateway and the edge strips or overwrites these headers.
    pub trust_caller_identity_headers: bool,
}

impl Default for IdentityGrantsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "~/.mcp-gateway/identity-grants.yaml".to_string(),
            fail_on_error: true,
            trust_caller_identity_headers: false,
        }
    }
}

// ── ContextIntegrityConfig ───────────────────────────────────────────────────

/// Gateway-wide context-integrity policy preset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityPresetConfig {
    /// Preserve the historical default: evaluate risky output and attach
    /// metadata, but deliver content unchanged.
    #[default]
    MonitorOnly,
    /// Developer-local monitor mode with gentler would-strip defaults.
    LocalDeveloper,
    /// Shared-team enforcement baseline.
    TeamShared,
    /// Evidence-only monitor mode.
    AuditOnly,
    /// Enterprise-license strict preset for stronger guarded-material handling.
    EnterpriseStrict,
}

impl ContextIntegrityPresetConfig {
    /// Return the license tier that owns this preset.
    #[must_use]
    pub const fn license_tier(self) -> &'static str {
        match self {
            Self::EnterpriseStrict => "enterprise",
            Self::MonitorOnly | Self::LocalDeveloper | Self::TeamShared | Self::AuditOnly => {
                "free_core"
            }
        }
    }

    /// Compile the config preset into an explicit kernel policy.
    #[must_use]
    pub const fn policy(self) -> ContextIntegrityPolicy {
        match self {
            Self::MonitorOnly => ContextIntegrityPolicy::monitor_only(),
            Self::LocalDeveloper => {
                ContextIntegrityPolicy::from_preset(ContextIntegrityPolicyPreset::LocalDeveloper)
            }
            Self::TeamShared => {
                ContextIntegrityPolicy::from_preset(ContextIntegrityPolicyPreset::TeamShared)
            }
            Self::AuditOnly => {
                ContextIntegrityPolicy::from_preset(ContextIntegrityPolicyPreset::AuditOnly)
            }
            Self::EnterpriseStrict => {
                ContextIntegrityPolicy::from_preset(ContextIntegrityPolicyPreset::EnterpriseStrict)
            }
        }
    }
}

/// Context-integrity gateway configuration.
///
/// ```yaml
/// security:
///   context_integrity:
///     preset: team_shared
///     non_bypassable: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContextIntegrityConfig {
    /// Named policy preset for live `gateway_invoke` tool-result wrapping.
    pub preset: ContextIntegrityPresetConfig,
    /// Make the render guard non-bypassable: enforce even if the preset is
    /// monitor-only. Off by default so the auth/observability surface is
    /// unchanged unless an operator opts in.
    #[serde(default)]
    pub non_bypassable: bool,
}

impl ContextIntegrityConfig {
    /// Compile this config into an explicit kernel policy.
    #[must_use]
    pub const fn policy(&self) -> ContextIntegrityPolicy {
        let mut policy = self.preset.policy();
        policy.non_bypassable = self.non_bypassable;
        policy
    }

    /// Return the license tier associated with this preset.
    #[must_use]
    pub const fn license_tier(&self) -> &'static str {
        self.preset.license_tier()
    }
}

// ── ClaimCaptureConfig ───────────────────────────────────────────────────────

/// Shadow claim-capture at the tool-result stamping chokepoint (MIK-6908,
/// rung 3.1). Only takes effect when [`SecurityConfig::provenance_stamping`]
/// is also `true` — capture has nothing to record without a signed receipt.
///
/// ```yaml
/// security:
///   provenance_stamping: true
///   claim_capture:
///     enabled: true
///     path: "~/.mcp-gateway/claim-capture/claims.jsonl"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaimCaptureConfig {
    /// Enable shadow claim capture. Default: `false` (opt-in).
    pub enabled: bool,
    /// Path to the append-only NDJSON capture file (`~` is expanded at startup).
    pub path: String,
}

impl Default for ClaimCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "~/.mcp-gateway/claim-capture/claims.jsonl".to_string(),
        }
    }
}

// ── SecurityConfig ────────────────────────────────────────────────────────────

/// Security configuration for the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // config surface: independent on/off feature flags
pub struct SecurityConfig {
    /// Enable input sanitization (null byte rejection, control char stripping, NFC).
    pub sanitize_input: bool,
    /// Enable SSRF protection for outbound URLs.
    pub ssrf_protection: bool,
    /// Treat URLs declared in `backends:` (servers.yaml / on-disk config) as
    /// pre-authorised: skip the runtime SSRF check at proxy time for them.
    ///
    /// Rationale: a URL that the operator put into the on-disk config is a
    /// declared trust boundary; re-validating it at every proxy hop is
    /// friendly fire that blocks legitimate same-host backends (e.g. a local
    /// `hebb` daemon on `127.0.0.1`). See MIK-3529.
    ///
    /// Tool-argument URLs (LLM-supplied, capability fetch tools, UI imports of
    /// *new* backend specs) keep going through `validate_url_not_ssrf` —
    /// those are untrusted input and are unaffected by this flag.
    ///
    /// Default: `true`. Set `false` to restore strict pre-MIK-3529 behaviour.
    #[serde(default = "default_trust_configured_backends")]
    pub trust_configured_backends: bool,
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
    /// Local personal-capability grant file. Default: disabled.
    #[serde(default)]
    pub identity_grants: IdentityGrantsConfig,
    /// Context-integrity tool-result boundary policy. Default: monitor-only.
    #[serde(default)]
    pub context_integrity: ContextIntegrityConfig,
    /// Remote MCP server provenance verification (OWASP ASI04). Default: disabled.
    #[serde(default)]
    pub remote_server_signing: RemoteServerSigningConfig,
    /// Sign a runtime provenance receipt into `_meta.provenance` on every
    /// aggregated tool result (MIK-6905). Reuses the attestation signing key.
    /// Additive metadata only; off by default so payloads are unchanged.
    #[serde(default)]
    pub provenance_stamping: bool,
    /// Shadow-capture derived claims alongside signed receipts for offline
    /// scoring (MIK-6908, rung 3.1). Default: disabled.
    #[serde(default)]
    pub claim_capture: ClaimCaptureConfig,
}

const fn default_trust_configured_backends() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            ssrf_protection: true,
            trust_configured_backends: default_trust_configured_backends(),
            tool_policy: ToolPolicyConfig::default(),
            #[cfg(feature = "firewall")]
            firewall: crate::security::firewall::FirewallConfig::default(),
            message_signing: MessageSigningConfig::default(),
            agent_identity: AgentIdentityConfig::default(),
            transparency_log: TransparencyLogConfig::default(),
            response_inspection: ResponseInspectionConfig::default(),
            response_contract: ResponseContractConfig::default(),
            identity_grants: IdentityGrantsConfig::default(),
            context_integrity: ContextIntegrityConfig::default(),
            remote_server_signing: RemoteServerSigningConfig::default(),
            provenance_stamping: false,
            claim_capture: ClaimCaptureConfig::default(),
        }
    }
}

#[cfg(test)]
mod context_integrity_config_tests {
    use super::ContextIntegrityConfig;
    use crate::context_integrity::ContextIntegrityPolicyMode;

    #[test]
    fn non_bypassable_flows_from_config_to_policy() {
        let cfg = ContextIntegrityConfig {
            non_bypassable: true,
            ..ContextIntegrityConfig::default()
        };
        let policy = cfg.policy();
        assert!(policy.non_bypassable);
        // Default preset is monitor-only; non_bypassable upgrades effective mode.
        assert_eq!(policy.effective_mode(), ContextIntegrityPolicyMode::Enforce);
    }

    #[test]
    fn default_config_is_not_non_bypassable() {
        let policy = ContextIntegrityConfig::default().policy();
        assert!(!policy.non_bypassable);
        assert_eq!(
            policy.effective_mode(),
            ContextIntegrityPolicyMode::MonitorOnly
        );
    }
}

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // TransparencyLogConfig::Debug must never surface the HMAC shared secret.
    #[test]
    fn transparency_log_config_debug_redacts_shared_secret() {
        let cfg = TransparencyLogConfig {
            shared_secret: SENTINEL.to_string(),
            ..TransparencyLogConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked shared_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }

    // MessageSigningConfig::Debug must redact both the current and previous
    // rotation secrets.
    #[test]
    fn message_signing_config_debug_redacts_both_secrets() {
        let cfg = MessageSigningConfig {
            shared_secret: SENTINEL.to_string(),
            previous_secret: format!("{SENTINEL}-prev"),
            ..MessageSigningConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked signing secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }
}
