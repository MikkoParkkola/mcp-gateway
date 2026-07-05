//! Key Server configuration — OIDC identity to temporary scoped API keys.

use std::env;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

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
    /// Accept a raw OIDC ID token (JWT) as a bearer directly on the gateway
    /// endpoint — "delegated auth" — instead of requiring a prior token
    /// exchange. Default `false`: leaving it off keeps the auth surface
    /// byte-identical (raw OIDC bearers are still accepted only via the
    /// `/auth/token` exchange). Verification still requires a matching OIDC
    /// provider and a policy rule, so enabling it does not bypass policy.
    #[serde(default)]
    pub delegated_bearer: bool,
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
const fn default_auto_discover() -> bool {
    true
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
            delegated_bearer: false,
        }
    }
}

impl KeyServerConfig {
    /// Resolve the admin token, expanding `env:VAR_NAME` syntax.
    ///
    /// # Errors
    ///
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
    pub fn resolve_admin_token(&self) -> Result<Option<String>> {
        self.admin_token.as_ref().map_or(Ok(None), |t| {
            if let Some(var) = t.strip_prefix("env:") {
                env::var(var).map(Some).map_err(|_| {
                    Error::ConfigValidation(format!(
                        "key_server.admin_token references missing environment variable '{var}'"
                    ))
                })
            } else {
                Ok(Some(t.clone()))
            }
        })
    }

    /// Validate the key-server config at load time (MIK-6784, GW.4).
    ///
    /// A disabled key server is not validated (its providers are inert). When
    /// enabled, every OIDC provider MUST declare a non-empty `audiences` list:
    /// an empty list would accept a token minted for *any* client
    /// (audience-confusion). The runtime verifier historically skipped the
    /// `aud` check when `audiences` was empty, so the guard must live here — at
    /// config load — to fail closed before any token is accepted. This mirrors
    /// the non-empty-audience enforcement in
    /// [`crate::identity_propagation::IdentityPropagationConfig::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] for the first provider with an empty
    /// (or whitespace-only) audience list.
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for (idx, provider) in self.oidc.iter().enumerate() {
            let has_audience = provider.audiences.iter().any(|a| !a.trim().is_empty());
            if !has_audience {
                return Err(Error::ConfigValidation(format!(
                    "key_server.oidc[{idx}] (issuer '{}') must declare at least one non-empty \
                     audience; an empty `audiences` list accepts a token minted for any client \
                     (audience-confusion, MIK-6784)",
                    provider.issuer
                )));
            }
        }
        Ok(())
    }
}

/// Configuration for a single OIDC identity provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyServerProviderConfig {
    /// The OIDC issuer URL (must match the `iss` claim in tokens).
    pub issuer: String,
    /// Override JWKS URI. When set, takes precedence over discovery and the
    /// `{issuer}/.well-known/jwks.json` fallback.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Override the OIDC discovery document URL. Defaults to
    /// `{issuer}/.well-known/openid-configuration` when `auto_discover` is on.
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Resolve `jwks_uri` from the provider's OIDC discovery document
    /// (`.well-known/openid-configuration`) instead of guessing it. Enabled by
    /// default; an explicit `jwks_uri` still wins. Disable to fall back to the
    /// legacy `{issuer}/.well-known/jwks.json` guess.
    #[serde(default = "default_auto_discover")]
    pub auto_discover: bool,
    /// Expected audience values (`aud` claim). When the key server is enabled
    /// this MUST be non-empty (enforced by [`KeyServerConfig::validate`],
    /// MIK-6784): an empty list would accept a token minted for any client
    /// (audience-confusion).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(issuer: &str, audiences: Vec<&str>) -> KeyServerProviderConfig {
        KeyServerProviderConfig {
            issuer: issuer.to_string(),
            jwks_uri: None,
            discovery_url: None,
            auto_discover: true,
            audiences: audiences.into_iter().map(String::from).collect(),
            allowed_domains: Vec::new(),
        }
    }

    fn enabled_with(providers: Vec<KeyServerProviderConfig>) -> KeyServerConfig {
        KeyServerConfig {
            enabled: true,
            oidc: providers,
            ..KeyServerConfig::default()
        }
    }

    /// GW.4: an enabled provider with a non-empty audience passes validation.
    #[test]
    fn validate_accepts_non_empty_audience() {
        let cfg = enabled_with(vec![provider(
            "https://accounts.google.com",
            vec!["client-id"],
        )]);
        assert!(cfg.validate().is_ok());
    }

    /// GW.4: an enabled provider with an empty audience list is rejected at load
    /// (audience-confusion fail-closed).
    #[test]
    fn validate_rejects_empty_audience_list() {
        let cfg = enabled_with(vec![provider("https://issuer.example", vec![])]);
        let err = cfg
            .validate()
            .expect_err("empty audiences must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("audience"),
            "message names the audience gap: {msg}"
        );
        assert!(
            msg.contains("issuer.example"),
            "message names the offending issuer: {msg}"
        );
    }

    /// GW.4: a whitespace-only audience is not a real audience — still rejected.
    #[test]
    fn validate_rejects_whitespace_only_audience() {
        let cfg = enabled_with(vec![provider("https://issuer.example", vec!["   "])]);
        assert!(cfg.validate().is_err());
    }

    /// GW.4: the second provider's empty audience is caught even when the first
    /// is valid.
    #[test]
    fn validate_rejects_when_any_provider_lacks_audience() {
        let cfg = enabled_with(vec![
            provider("https://good.example", vec!["aud"]),
            provider("https://bad.example", vec![]),
        ]);
        let err = cfg.validate().expect_err("any bad provider must fail");
        assert!(err.to_string().contains("bad.example"));
    }

    /// A disabled key server is inert: its providers are never validated.
    #[test]
    fn validate_skips_disabled_key_server() {
        let cfg = KeyServerConfig {
            enabled: false,
            oidc: vec![provider("https://issuer.example", vec![])],
            ..KeyServerConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }
}
