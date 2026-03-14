//! Key Server configuration — OIDC identity to temporary scoped API keys.

use std::env;

use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;
const DEFAULT_MAX_TOKENS_PER_IDENTITY: u32 = 5;
const DEFAULT_MAX_OIDC_TOKEN_AGE_SECS: u64 = 300;
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

// ── Key Server ─────────────────────────────────────────────────────────────────

/// Key Server configuration — OIDC identity to temporary scoped API keys.
///
/// Disabled by default. Enable with `key_server.enabled: true`.
///
/// # Example
///
/// ```yaml
/// key_server:
///   enabled: true
///   token_ttl_secs: 3600
///   oidc:
///     - issuer: "https://accounts.google.com"
///       audiences: ["my-gateway-client-id"]
///       allowed_domains: ["company.com"]
///   policies:
///     - match: { domain: "company.com" }
///       scopes:
///         backends: ["*"]
///         tools: ["*"]
///         rate_limit: 100
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyServerConfig {
    /// Enable the key server (default: `false`).
    pub enabled: bool,
    /// Issued token lifetime in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// Maximum active tokens per identity before new issuance is rejected (default: 5).
    #[serde(default = "default_max_tokens_per_identity")]
    pub max_tokens_per_identity: u32,
    /// Maximum age of an incoming OIDC token in seconds (replay protection, default: 300).
    #[serde(default = "default_max_oidc_token_age_secs")]
    pub max_oidc_token_age_secs: u64,
    /// How often to reap expired tokens from the in-memory store (seconds, default: 60).
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    /// OIDC provider configurations.
    #[serde(default)]
    pub oidc: Vec<KeyServerProviderConfig>,
    /// Access policy rules (first-match-wins).
    #[serde(default)]
    pub policies: Vec<KeyServerPolicyConfig>,
    /// Admin bearer token for revocation endpoints (`env:VAR_NAME` supported).
    /// If `None`, revocation endpoints return 503.
    #[serde(default)]
    pub admin_token: Option<String>,
}

fn default_token_ttl_secs() -> u64 {
    DEFAULT_TOKEN_TTL_SECS
}
fn default_max_tokens_per_identity() -> u32 {
    DEFAULT_MAX_TOKENS_PER_IDENTITY
}
fn default_max_oidc_token_age_secs() -> u64 {
    DEFAULT_MAX_OIDC_TOKEN_AGE_SECS
}
fn default_cleanup_interval_secs() -> u64 {
    DEFAULT_CLEANUP_INTERVAL_SECS
}

impl Default for KeyServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            max_tokens_per_identity: DEFAULT_MAX_TOKENS_PER_IDENTITY,
            max_oidc_token_age_secs: DEFAULT_MAX_OIDC_TOKEN_AGE_SECS,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            oidc: Vec::new(),
            policies: Vec::new(),
            admin_token: None,
        }
    }
}

impl KeyServerConfig {
    /// Resolve the admin token, expanding `env:VAR_NAME` syntax.
    #[must_use]
    pub fn resolve_admin_token(&self) -> Option<String> {
        self.admin_token.as_ref().map(|t| {
            if let Some(var) = t.strip_prefix("env:") {
                env::var(var).unwrap_or_else(|_| t.clone())
            } else {
                t.clone()
            }
        })
    }
}

/// Configuration for a single OIDC identity provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerProviderConfig {
    /// The OIDC issuer URL (must match the `iss` claim in tokens).
    pub issuer: String,
    /// Override JWKS URI. Defaults to `{issuer}/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Expected audience values (`aud` claim). Empty = any audience accepted.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Restrict to these email domains. Empty = any domain accepted.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

/// An access policy rule: match criteria + granted scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerPolicyConfig {
    /// Criteria that must be satisfied for this rule to match.
    #[serde(rename = "match")]
    pub match_criteria: PolicyMatchConfig,
    /// Scopes granted when this rule matches.
    pub scopes: PolicyScopesConfig,
}

/// Match criteria for a policy rule. All non-`None` fields must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMatchConfig {
    /// Email domain suffix (e.g., `"company.com"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Exact OIDC issuer URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Exact email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Required group membership.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Scopes granted by a policy rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyScopesConfig {
    /// Allowed backends. `["*"]` or empty = all.
    #[serde(default)]
    pub backends: Vec<String>,
    /// Allowed tools. `["*"]` or empty = all.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Rate limit in requests/minute (0 = unlimited).
    #[serde(default)]
    pub rate_limit: u32,
}

/// Runtime OIDC verification parameters (derived from `KeyServerConfig`).
#[derive(Debug, Clone)]
pub struct KeyServerOidcConfig {
    /// Maximum age of an incoming OIDC token (seconds).
    pub max_token_age_secs: u64,
}
