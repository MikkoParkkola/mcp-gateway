// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Authentication configuration for gateway access.

use serde::{Deserialize, Serialize};

use super::api_key::ApiKeyConfig;
use super::failsafe::CircuitBreakerConfig;
use crate::{Error, Result};

// ── Auth ───────────────────────────────────────────────────────────────────────

/// Authentication configuration for gateway access.
#[derive(Clone, Serialize, Deserialize)]
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
    /// `/livez` and `/readyz` follow `/health` without being listed.
    #[serde(default = "default_public_paths")]
    pub public_paths: Vec<String>,
    /// Optional per-client circuit breaker applied after authenticated identity is established.
    #[serde(default)]
    pub client_circuit_breaker: Option<CircuitBreakerConfig>,
    /// ADR-008 INV-2 (MIK-6752): explicit operator declaration that this
    /// authenticated gateway serves exactly one principal.
    ///
    /// Default `false` is deliberately fail-closed: a single shared API key or
    /// bearer token can be handed to a whole team, and the gateway cannot prove
    /// from credential count alone that only one human is behind the auth. So
    /// unless the operator asserts `single_user = true`, any enabled auth is
    /// treated as multi-user and the per-user OAuth isolation guard stays on.
    /// More than one credential (API keys and the bearer token) or any OIDC
    /// issuer is a hard multi-user signal that overrides this hint (see
    /// [`AuthConfig::implies_multi_user`]).
    #[serde(default)]
    pub single_user: bool,
    /// How long a dashboard browser session lives (MIK-7570.SESSION.1).
    #[serde(default)]
    pub dashboard_session: DashboardSessionConfig,
}

/// Lifetime of a dashboard browser session.
///
/// A session ends after `idle_timeout_secs` without operator activity, or
/// `absolute_timeout_secs` after it was opened, whichever comes first. The
/// dashboard's own 5-second refresh is not activity. Read on every check, so a
/// reload applies to sessions already open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DashboardSessionConfig {
    /// Seconds without activity before a session ends (default 1800).
    #[serde(deserialize_with = "crate::duration_bound::secs")]
    pub idle_timeout_secs: u64,
    /// Seconds from sign-in before a session ends in any case (default 28800).
    #[serde(deserialize_with = "crate::duration_bound::secs")]
    pub absolute_timeout_secs: u64,
}

impl Default for DashboardSessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 1800,
            absolute_timeout_secs: 28_800,
        }
    }
}

impl DashboardSessionConfig {
    /// Refuse a zero limit, and an idle limit longer than the absolute one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] naming the violated bound.
    pub(crate) fn validate(&self) -> Result<()> {
        let (idle, absolute) = (self.idle_timeout_secs, self.absolute_timeout_secs);
        if idle == 0 {
            return Err(Error::ConfigValidation(
                "auth.dashboard_session.idle_timeout_secs is 0, which ends every session at \
                 once; set a positive number of seconds (default 1800)"
                    .into(),
            ));
        }
        if absolute == 0 {
            return Err(Error::ConfigValidation(
                "auth.dashboard_session.absolute_timeout_secs is 0, which ends every session \
                 at once; set a positive number of seconds (default 28800)"
                    .into(),
            ));
        }
        if idle > absolute {
            return Err(Error::ConfigValidation(format!(
                "auth.dashboard_session.idle_timeout_secs ({idle}) exceeds \
                 absolute_timeout_secs ({absolute}); the idle limit could never apply"
            )));
        }
        Ok(())
    }
}

// Manual `Debug` that redacts the bearer token and API keys (CWE-532, mirrors
// PR #323). A derived `Debug` would print the plaintext bearer token and every
// API key verbatim into any trace or error context. The bearer presence and
// the API-key count are surfaced so diagnostics stay useful.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("bearer_token", &redact_opt(&self.bearer_token))
            .field("api_keys", &format!("<{} entries>", self.api_keys.len()))
            .field("public_paths", &self.public_paths)
            .field("client_circuit_breaker", &self.client_circuit_breaker)
            .field("single_user", &self.single_user)
            .field("dashboard_session", &self.dashboard_session)
            .finish()
    }
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
            client_circuit_breaker: None,
            single_user: false,
            dashboard_session: DashboardSessionConfig::default(),
        }
    }
}

impl AuthConfig {
    /// This section as a reload compares it for "restart required": without
    /// `dashboard_session`, which is read on every session check and so
    /// applies live. Field order is fixed and there are no maps, so plain
    /// JSON is canonical.
    pub(crate) fn restart_only_json(&self) -> String {
        let view = Self {
            dashboard_session: DashboardSessionConfig::default(),
            ..self.clone()
        };
        serde_json::to_string(&view).unwrap_or_default()
    }

    /// ADR-008 INV-2 (MIK-6752): does this auth configuration imply the gateway
    /// may serve more than one principal?
    ///
    /// Fail-closed. When auth is disabled there is no cross-user boundary to
    /// protect, so this is `false`. When auth is enabled we assume multiple
    /// principals *could* be behind it — a single shared API key or bearer token
    /// can be distributed to a whole team and the gateway cannot prove otherwise
    /// — UNLESS the operator explicitly declares [`single_user`](Self::single_user).
    /// More than one credential (API keys and the bearer token), or any
    /// configured OIDC issuer (`has_oidc`), is a hard multi-user signal that
    /// overrides the `single_user` hint.
    #[must_use]
    pub fn implies_multi_user(&self, has_oidc: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let hard_multi_user = self.credential_count() > 1 || has_oidc;
        hard_multi_user || !self.single_user
    }

    /// MIK-6744 (STORE.1, open item O3): may this gateway mint the sole-operator
    /// principal that a solo deployment's stored OAuth grants are keyed to?
    ///
    /// NECESSARY, NEVER SUFFICIENT. This answers a question about the
    /// DEPLOYMENT. Whether a given request may be served under that principal
    /// also needs a fact about the REQUEST — that a credential validated — and
    /// configuration cannot see it. The shipped starter config
    /// (`commands::generate_config`) sets `enabled` and `single_user` AND lists
    /// `/mcp` under `public_paths`, so this returns `true` on a default install
    /// that also serves anonymous callers. The request-side half lives in
    /// `identity_propagation::CallerProof`.
    ///
    /// DELIBERATELY NOT `!implies_multi_user(has_oidc)`. That predicate asks
    /// "could more than one principal be behind this auth?" and answers `false`
    /// when authentication is switched off entirely, because with no auth
    /// boundary the isolation question is moot. Negating it reads "exactly one
    /// user is present", which is the opposite of what an unauthenticated
    /// gateway means, and would hand the stored OAuth grants to anyone who can
    /// reach the port. Absence of authentication is not the presence of one
    /// user. Stated positively here so the enabled term cannot be lost.
    ///
    /// Consistent with ADR-008 INV-2's fail-closed reasoning rather than
    /// competing with it: `single_user` is the operator's ASSERTION, and more
    /// than one credential or any OIDC issuer overrides it, exactly as there.
    #[must_use]
    pub fn grants_single_user_principal(&self, has_oidc: bool) -> bool {
        self.enabled && self.single_user && self.credential_count() <= 1 && !has_oidc
    }

    /// How many credentials the middleware accepts: each API key, and the
    /// bearer token in any spelling (`auto` is generated at load, `env:` is
    /// resolved or the load fails). Each is a caller of its own (#2241).
    fn credential_count(&self) -> usize {
        self.api_keys.len() + usize::from(self.bearer_token.is_some())
    }

    /// `public_paths` as enforced: the orchestrator probes are public exactly
    /// when `/health` is. Every shipped config and operator copy lists only
    /// `/health`, so a probe that needed its own entry would answer 401 to the
    /// kubelet on upgrade — the outage the probes exist to end.
    pub(crate) fn enforced_public_paths(&self) -> Vec<String> {
        let mut paths = self.public_paths.clone();
        if paths.iter().any(|p| "/health".starts_with(p.as_str())) {
            paths.extend(["/livez".to_string(), "/readyz".to_string()]);
        }
        paths
    }
}

impl AuthConfig {
    /// One WARN per key that lists no backends: it now reaches none
    /// (BACKENDGRANT.1), where 3.x read an empty list as all. Admin keys are
    /// included; the wording tells a UI-only admin key it may ignore it.
    pub(crate) fn warn_keys_without_backends(&self) {
        for key in self.api_keys.iter().filter(|k| k.backends.is_empty()) {
            tracing::warn!(
                "auth.api_keys['{}'] lists no backends and reaches none (3.x treated this as all); if this key needs backend access, set backends: [\"*\"] or list them",
                key.name
            );
        }
    }

    /// Refuse API keys whose names are empty, padded, or shared.
    ///
    /// A key's name is its identity-grant subject (`api_key:<name>`), so two
    /// keys sharing a name hold each other's grants and a nameless key can
    /// hold none. Checked whether or not auth is enabled: enabling it later
    /// must not be what surfaces the collision.
    pub(crate) fn validate_api_key_names(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for key in &self.api_keys {
            if key.name.trim().is_empty() {
                return Err(Error::ConfigValidation(
                    "auth.api_keys[].name must be non-empty: it is the key's identity-grant \
                     subject (api_key:<name>)"
                        .to_string(),
                ));
            }
            if key.name.trim() != key.name {
                return Err(Error::ConfigValidation(format!(
                    "auth.api_keys[].name '{}' has leading or trailing whitespace; it would \
                     be a different identity-grant subject from the trimmed name",
                    key.name
                )));
            }
            if !seen.insert(key.name.as_str()) {
                return Err(Error::ConfigValidation(format!(
                    "auth.api_keys[].name '{}' is used by more than one key; names must be \
                     unique because each is that key's identity-grant subject",
                    key.name
                )));
            }
        }
        Ok(())
    }

    /// Resolve the bearer token (expand env vars, generate if `auto`).
    ///
    /// # Errors
    ///
    /// Returns an error if the value is an empty literal, or an `env:VAR_NAME`
    /// reference whose variable is unset or empty in `overlay` (C4).
    pub fn resolve_bearer_token(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> Result<Option<String>> {
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
            } else {
                crate::config::secret_ref::SecretRef::parse(token)
                    .resolve("auth.bearer_token", overlay)
                    .map(Some)
            }
        })
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
///       audience: "mcp-gateway-prod"
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
#[derive(Clone, Serialize, Deserialize)]
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
    /// Granted scopes (e.g., `tools:surreal:*`): `tools:<backend>:<tool>:<action>`,
    /// backend and tool each an exact name or `*` alone, and the action `read`,
    /// `write`, `execute` or `*` (MIK-8298).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Expected issuer (`iss` claim). Optional.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience (`aud` claim).
    ///
    /// Required whenever `agent_auth` is enabled: configuration validation
    /// refuses an agent that sets none, because the signing key may be shared
    /// with other relying parties and an unchecked `aud` would then accept
    /// their tokens. An empty or whitespace-only value is refused on the same
    /// grounds -- it names no relying party, so it cannot distinguish one.
    /// `Option` only so an absent field yields a named error rather than a
    /// serde failure.
    #[serde(default)]
    pub audience: Option<String>,
}

// Manual `Debug` that redacts the HS256 shared secret (CWE-532, mirrors PR
// #323). A derived `Debug` would print the signing secret verbatim; the RSA
// *public* key is not secret and stays visible.
impl std::fmt::Debug for AgentDefinitionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("AgentDefinitionConfig")
            .field("client_id", &self.client_id)
            .field("name", &self.name)
            .field("hs256_secret", &redact_opt(&self.hs256_secret))
            .field("rs256_public_key", &self.rs256_public_key)
            .field("scopes", &self.scopes)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl AgentDefinitionConfig {
    /// Resolve the HS256 secret, expanding `env:VAR_NAME` syntax.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is an empty literal, or an `env:VAR_NAME`
    /// reference whose variable is unset or empty in `overlay` (C4).
    pub fn resolved_hs256_secret(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> Result<Option<String>> {
        self.hs256_secret.as_ref().map_or(Ok(None), |s| {
            crate::config::secret_ref::SecretRef::parse(s)
                .resolve(
                    &format!("agent_auth.agents['{}'].hs256_secret", self.client_id),
                    overlay,
                )
                .map(Some)
        })
    }
}

#[cfg(test)]
#[path = "auth_multi_user_tests.rs"]
mod multi_user_tests;

// #2241: the bearer token is a credential too.
#[cfg(test)]
#[path = "auth_credential_count_tests.rs"]
mod credential_count_tests;

/// MIK-6744 (STORE.1 / O3): the sole-operator principal's own predicate.
///
/// Separate module from `multi_user_tests` on purpose. These are not the same
/// question asked twice: `implies_multi_user` asks "could more than one human be
/// behind this auth?", and this asks "is exactly one human proven to be?". The
/// auth-disabled case below is where the two answers differ, and it is the whole
/// reason this predicate is not a negation of that one.
#[cfg(test)]
#[path = "auth_single_user_principal_tests.rs"]
mod single_user_principal_tests;

#[cfg(test)]
#[path = "auth_debug_redaction_tests.rs"]
mod cwe532_debug_redaction;

#[cfg(test)]
#[path = "auth_api_key_name_tests.rs"]
mod api_key_name_tests;

#[cfg(test)]
#[path = "api_key_digest_tests.rs"]
mod api_key_digest_tests;

#[cfg(test)]
#[path = "auth_dashboard_session_tests.rs"]
mod dashboard_session_limits_tests;
