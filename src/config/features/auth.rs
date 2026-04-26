//! Authentication configuration for gateway access.

use std::env;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ── Auth ───────────────────────────────────────────────────────────────────────

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
    ///
    /// # Errors
    ///
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
    pub fn resolve_bearer_token(&self) -> Result<Option<String>> {
        self.bearer_token.as_ref().map_or(Ok(None), |token| {
            if token == "auto" {
                use rand::RngExt;
                let random_bytes: [u8; 32] = rand::rng().random();
                Ok(Some(format!(
                    "mcp_{}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        random_bytes
                    )
                )))
            } else if let Some(var_name) = token.strip_prefix("env:") {
                env::var(var_name).map(Some).map_err(|_| {
                    Error::ConfigValidation(format!(
                        "auth.bearer_token references missing environment variable '{var_name}'"
                    ))
                })
            } else {
                Ok(Some(token.clone()))
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
    /// Whether this API key can use admin-only HTTP UI and management tools.
    #[serde(default)]
    pub admin: bool,
}

impl ApiKeyConfig {
    /// Resolve the API key (expand env vars).
    ///
    /// # Errors
    ///
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
    pub fn resolve_key(&self) -> Result<String> {
        if let Some(var_name) = self.key.strip_prefix("env:") {
            env::var(var_name).map_err(|_| {
                Error::ConfigValidation(format!(
                    "auth.api_keys[].key references missing environment variable '{var_name}'"
                ))
            })
        } else {
            Ok(self.key.clone())
        }
    }

    /// Check if this key has access to a backend.
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }
}

// ── Agent Auth ─────────────────────────────────────────────────────────────────

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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
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
    ///
    /// # Errors
    ///
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
    pub fn resolved_hs256_secret(&self) -> Result<Option<String>> {
        self.hs256_secret.as_ref().map_or(Ok(None), |s| {
            if let Some(var) = s.strip_prefix("env:") {
                env::var(var).map(Some).map_err(|_| {
                    Error::ConfigValidation(format!(
                        "agent_auth.agents[].hs256_secret references missing environment variable '{var}'"
                    ))
                })
            } else {
                Ok(Some(s.clone()))
            }
        })
    }
}
