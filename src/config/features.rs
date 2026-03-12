//! Feature-specific configuration types.
//!
//! Covers: key server, code mode, cache, playbooks, webhooks, security,
//! capabilities, auth, streaming, failsafe, and their sub-structs.

use std::{env, time::Duration};

use serde::{Deserialize, Serialize};

use crate::security::policy::ToolPolicyConfig;

// ── Key Server ────────────────────────────────────────────────────────────────

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
    #[serde(default = "default_key_server_token_ttl")]
    pub token_ttl_secs: u64,
    /// Maximum active tokens per identity before new issuance is rejected (default: 5).
    #[serde(default = "default_max_tokens_per_identity")]
    pub max_tokens_per_identity: u32,
    /// Maximum age of an incoming OIDC token in seconds (replay protection, default: 300).
    #[serde(default = "default_max_oidc_token_age")]
    pub max_oidc_token_age_secs: u64,
    /// How often to reap expired tokens from the in-memory store (seconds, default: 60).
    #[serde(default = "default_cleanup_interval")]
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

fn default_key_server_token_ttl() -> u64 { 3600 }
fn default_max_tokens_per_identity() -> u32 { 5 }
fn default_max_oidc_token_age() -> u64 { 300 }
fn default_cleanup_interval() -> u64 { 60 }

impl Default for KeyServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_ttl_secs: default_key_server_token_ttl(),
            max_tokens_per_identity: default_max_tokens_per_identity(),
            max_oidc_token_age_secs: default_max_oidc_token_age(),
            cleanup_interval_secs: default_cleanup_interval(),
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

// ── Code Mode ─────────────────────────────────────────────────────────────────

/// Code Mode configuration — the search+execute pattern for minimal context usage.
///
/// When enabled, `tools/list` returns only two meta-tools (`gateway_search` and
/// `gateway_execute`) instead of the full meta-tool set.
///
/// # Example
///
/// ```yaml
/// code_mode:
///   enabled: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CodeModeConfig {
    /// Enable Code Mode.
    pub enabled: bool,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Cache configuration for response caching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable response caching.
    pub enabled: bool,
    /// Default TTL for cached responses.
    #[serde(with = "crate::config::humantime_serde")]
    pub default_ttl: Duration,
    /// Maximum number of entries before eviction.
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: Duration::from_secs(60),
            max_entries: 10_000,
        }
    }
}

// ── Playbooks ─────────────────────────────────────────────────────────────────

/// Playbook configuration for multi-step tool chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlaybooksConfig {
    /// Enable playbook engine.
    pub enabled: bool,
    /// Directories to load playbook definitions from.
    pub directories: Vec<String>,
}

impl Default for PlaybooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec!["playbooks".to_string()],
        }
    }
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

/// Webhook receiver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    /// Enable the webhook receiver.
    pub enabled: bool,
    /// Base path prefix for all webhook endpoints (e.g., "/webhooks").
    pub base_path: String,
    /// Require HMAC signature on all webhooks (can be overridden per definition).
    pub require_signature: bool,
    /// Rate limit for webhook endpoints (requests per minute, 0 = unlimited).
    pub rate_limit: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_path: "/webhooks".to_string(),
            require_signature: true,
            rate_limit: 100,
        }
    }
}

// ── Security ──────────────────────────────────────────────────────────────────

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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            ssrf_protection: true,
            tool_policy: ToolPolicyConfig::default(),
        }
    }
}

// ── Capabilities ──────────────────────────────────────────────────────────────

/// Capability configuration for direct REST API integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Enable capability system.
    pub enabled: bool,
    /// Backend name for capabilities (shown in `gateway_list_servers`).
    pub name: String,
    /// Directories to load capability definitions from.
    pub directories: Vec<String>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "gateway".to_string(),
            directories: {
                let mut dirs = vec!["capabilities".to_string()];
                if let Some(home) = std::env::var_os("HOME") {
                    let private_dir = std::path::Path::new(&home)
                        .join("github/mcp-gateway-private/capabilities");
                    if private_dir.is_dir() {
                        dirs.push(private_dir.to_string_lossy().into_owned());
                    }
                }
                dirs
            },
        }
    }
}

// ── Agent Auth ────────────────────────────────────────────────────────────────

/// Configuration for agent-scoped OAuth 2.0 tool permissions (issue #80).
///
/// When enabled, every tool invocation must carry a valid agent JWT.
/// Agents are registered with a `client_id` and a set of permitted tool scopes.
///
/// # Example
///
/// ```yaml
/// agent_auth:
///   enabled: true
///   agents:
///     - client_id: "my-backend-agent"
///       name: "My Backend Agent"
///       hs256_secret: "env:AGENT_SECRET"
///       scopes:
///         - "tools:surreal:*"
///         - "tools:brave:search:read"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AgentAuthConfig {
    /// Enable agent auth (default: false).
    pub enabled: bool,
    /// Statically configured agents.
    #[serde(default)]
    pub agents: Vec<AgentDefinitionConfig>,
}


/// Static agent definition in the configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDefinitionConfig {
    /// Unique client identifier.
    pub client_id: String,
    /// Human-readable display name.
    pub name: String,
    /// HS256 shared secret. Supports `env:VAR_NAME`.
    #[serde(default)]
    pub hs256_secret: Option<String>,
    /// PEM-encoded RSA public key for RS256 verification.
    #[serde(default)]
    pub rs256_public_key: Option<String>,
    /// Granted scopes (e.g., `tools:surreal:*`).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Expected issuer (`iss` claim). Optional.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience (`aud` claim). Optional.
    #[serde(default)]
    pub audience: Option<String>,
}

impl AgentDefinitionConfig {
    /// Resolve the HS256 secret, expanding `env:VAR_NAME` syntax.
    #[must_use]
    pub fn resolved_hs256_secret(&self) -> Option<String> {
        self.hs256_secret.as_ref().map(|s| {
            if let Some(var) = s.strip_prefix("env:") {
                env::var(var).unwrap_or_else(|_| s.clone())
            } else {
                s.clone()
            }
        })
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/// Authentication configuration for gateway access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Enable authentication (default: false for backwards compatibility).
    pub enabled: bool,
    /// Bearer token for simple authentication.
    /// Supports: literal value, `env:VAR_NAME`, or `auto` (generates random token).
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// API keys for multi-client access with optional restrictions.
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    /// Paths that bypass authentication (default: `["/health"]`).
    #[serde(default = "default_public_paths")]
    pub public_paths: Vec<String>,
}

fn default_public_paths() -> Vec<String> {
    vec!["/health".to_string()]
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: None,
            api_keys: Vec::new(),
            public_paths: default_public_paths(),
        }
    }
}

impl AuthConfig {
    /// Resolve the bearer token (expand env vars, generate if `auto`).
    #[must_use]
    pub fn resolve_bearer_token(&self) -> Option<String> {
        self.bearer_token.as_ref().map(|token| {
            if token == "auto" {
                use rand::Rng;
                let random_bytes: [u8; 32] = rand::rng().random();
                format!(
                    "mcp_{}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        random_bytes
                    )
                )
            } else if let Some(var_name) = token.strip_prefix("env:") {
                env::var(var_name).unwrap_or_else(|_| token.clone())
            } else {
                token.clone()
            }
        })
    }
}

/// API key configuration for multi-client access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The API key value (supports `env:VAR_NAME`).
    pub key: String,
    /// Human-readable name for this client.
    #[serde(default)]
    pub name: String,
    /// Rate limit (requests per minute, 0 = unlimited).
    #[serde(default)]
    pub rate_limit: u32,
    /// Allowed backends (empty = all backends).
    #[serde(default)]
    pub backends: Vec<String>,
    /// Allowed tools (if Some, ONLY these tools are accessible).
    /// Supports glob patterns. Acts as an allowlist.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (if Some, these tools are blocked).
    /// Supports glob patterns. Acts as a blocklist on top of global policy.
    #[serde(default)]
    pub denied_tools: Option<Vec<String>>,
}

impl ApiKeyConfig {
    /// Resolve the API key (expand env vars).
    #[must_use]
    pub fn resolve_key(&self) -> String {
        if let Some(var_name) = self.key.strip_prefix("env:") {
            env::var(var_name).unwrap_or_else(|_| self.key.clone())
        } else {
            self.key.clone()
        }
    }

    /// Check if this key has access to a backend.
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }
}

// ── Streaming ─────────────────────────────────────────────────────────────────

/// Streaming configuration (for real-time notifications).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamingConfig {
    /// Enable streaming (GET /mcp for notifications).
    pub enabled: bool,
    /// Notification buffer size per client.
    pub buffer_size: usize,
    /// Keep-alive interval for SSE streams.
    #[serde(with = "crate::config::humantime_serde")]
    pub keep_alive_interval: Duration,
    /// Backends to auto-subscribe for notifications.
    #[serde(default)]
    pub auto_subscribe: Vec<String>,
    /// Maximum session lifetime before reaping (default: 30 min).
    #[serde(with = "crate::config::humantime_serde")]
    pub session_ttl: Duration,
    /// How often the session reaper runs (default: 60 s).
    #[serde(with = "crate::config::humantime_serde")]
    pub session_reaper_interval: Duration,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 100,
            keep_alive_interval: Duration::from_secs(15),
            auto_subscribe: Vec::new(),
            session_ttl: Duration::from_secs(1800),
            session_reaper_interval: Duration::from_secs(60),
        }
    }
}

// ── Failsafe ──────────────────────────────────────────────────────────────────

/// Failsafe configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FailsafeConfig {
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Retry configuration.
    pub retry: RetryConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// Health check configuration.
    pub health_check: HealthCheckConfig,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker.
    pub enabled: bool,
    /// Failure threshold before opening.
    pub failure_threshold: u32,
    /// Success threshold to close.
    pub success_threshold: u32,
    /// Time to wait before half-open.
    #[serde(with = "crate::config::humantime_serde")]
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            success_threshold: 3,
            reset_timeout: Duration::from_secs(30),
        }
    }
}

/// Retry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Enable retries.
    pub enabled: bool,
    /// Maximum retry attempts.
    pub max_attempts: u32,
    /// Initial backoff duration.
    #[serde(with = "crate::config::humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    #[serde(with = "crate::config::humantime_serde")]
    pub max_backoff: Duration,
    /// Backoff multiplier.
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Requests per second per backend.
    pub requests_per_second: u32,
    /// Burst size.
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
        }
    }
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// Enable health checks.
    pub enabled: bool,
    /// Health check interval.
    #[serde(with = "crate::config::humantime_serde")]
    pub interval: Duration,
    /// Health check timeout.
    #[serde(with = "crate::config::humantime_serde")]
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
        }
    }
}
