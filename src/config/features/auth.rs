// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Authentication configuration for gateway access.

use serde::{Deserialize, Serialize};

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
    /// More than one API key or any OIDC issuer is a hard multi-user signal that
    /// overrides this hint (see [`AuthConfig::implies_multi_user`]).
    #[serde(default)]
    pub single_user: bool,
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
        }
    }
}

impl AuthConfig {
    /// ADR-008 INV-2 (MIK-6752): does this auth configuration imply the gateway
    /// may serve more than one principal?
    ///
    /// Fail-closed. When auth is disabled there is no cross-user boundary to
    /// protect, so this is `false`. When auth is enabled we assume multiple
    /// principals *could* be behind it — a single shared API key or bearer token
    /// can be distributed to a whole team and the gateway cannot prove otherwise
    /// — UNLESS the operator explicitly declares [`single_user`](Self::single_user).
    /// More than one API key, or any configured OIDC issuer (`has_oidc`), is a
    /// hard multi-user signal that overrides the `single_user` hint.
    #[must_use]
    pub fn implies_multi_user(&self, has_oidc: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let hard_multi_user = self.api_keys.len() > 1 || has_oidc;
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
    /// than one API key or any OIDC issuer overrides it, exactly as there.
    #[must_use]
    pub fn grants_single_user_principal(&self, has_oidc: bool) -> bool {
        self.enabled && self.single_user && self.api_keys.len() <= 1 && !has_oidc
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
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
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

/// API key configuration for multi-client access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The API key value (supports `env:VAR_NAME`).
    pub key: String,
    /// Name for this client: non-empty, unique across `api_keys`, and the
    /// key's identity-grant subject (`api_key:<name>`).
    #[serde(default)]
    pub name: String,
    /// Rate limit (requests per minute, 0 = unlimited).
    #[serde(default)]
    pub rate_limit: u32,
    /// Allowed backends. `["*"]` is all; empty or absent is none.
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
    pub fn resolve_key(&self, overlay: &crate::config::EnvOverlay) -> Result<String> {
        crate::config::secret_ref::SecretRef::parse(&self.key)
            .resolve(&format!("auth.api_keys['{}'].key", self.name), overlay)
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
    /// Granted scopes (e.g., `tools:surreal:*`).
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
    /// Returns an error if an `env:VAR_NAME` reference cannot be resolved.
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
mod multi_user_tests {
    use super::*;

    fn api_key(name: &str) -> ApiKeyConfig {
        ApiKeyConfig {
            key: format!("k-{name}"),
            name: name.to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        }
    }

    #[test]
    fn disabled_auth_is_never_multi_user() {
        let cfg = AuthConfig::default(); // enabled=false
        assert!(!cfg.implies_multi_user(false));
        assert!(
            !cfg.implies_multi_user(true),
            "no auth boundary = nothing to isolate"
        );
    }

    #[test]
    fn single_shared_api_key_fails_closed_to_multi_user() {
        // The MIK-6752 fix: one API key handed to a team must NOT read as single-user.
        let cfg = AuthConfig {
            enabled: true,
            api_keys: vec![api_key("team")],
            ..AuthConfig::default()
        };
        assert!(
            cfg.implies_multi_user(false),
            "a single shared API key is treated as multi-user unless explicitly declared single_user"
        );
    }

    #[test]
    fn shared_bearer_only_fails_closed_to_multi_user() {
        // Previously the bearer-token path was ignored entirely by count-based detection.
        let cfg = AuthConfig {
            enabled: true,
            bearer_token: Some("shared-secret".to_string()),
            api_keys: Vec::new(),
            ..AuthConfig::default()
        };
        assert!(
            cfg.implies_multi_user(false),
            "a shared bearer with no api_keys still fails closed"
        );
    }

    #[test]
    fn explicit_single_user_opts_out() {
        let cfg = AuthConfig {
            enabled: true,
            api_keys: vec![api_key("me")],
            single_user: true,
            ..AuthConfig::default()
        };
        assert!(
            !cfg.implies_multi_user(false),
            "operator may declare a genuine single-user deployment"
        );
    }

    #[test]
    fn multiple_api_keys_are_hard_multi_user_even_if_single_user_set() {
        let cfg = AuthConfig {
            enabled: true,
            api_keys: vec![api_key("a"), api_key("b")],
            single_user: true, // contradictory hint is overridden by the hard signal
            ..AuthConfig::default()
        };
        assert!(
            cfg.implies_multi_user(false),
            ">1 API key is a hard multi-user signal"
        );
    }

    #[test]
    fn oidc_is_hard_multi_user_even_if_single_user_set() {
        let cfg = AuthConfig {
            enabled: true,
            single_user: true,
            ..AuthConfig::default()
        };
        assert!(
            cfg.implies_multi_user(true),
            "any OIDC issuer means many end users"
        );
    }
}

/// MIK-6744 (STORE.1 / O3): the sole-operator principal's own predicate.
///
/// Separate module from `multi_user_tests` on purpose. These are not the same
/// question asked twice: `implies_multi_user` asks "could more than one human be
/// behind this auth?", and this asks "is exactly one human proven to be?". The
/// auth-disabled case below is where the two answers differ, and it is the whole
/// reason this predicate is not a negation of that one.
#[cfg(test)]
mod single_user_principal_tests {
    use super::*;

    fn api_key(name: &str) -> ApiKeyConfig {
        ApiKeyConfig {
            key: format!("k-{name}"),
            name: name.to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        }
    }

    /// The population this exists for: a 3.x personal gateway that took the
    /// upgrade advice at `commands/upgrade.rs:144` and set `single_user: true`.
    fn solo() -> AuthConfig {
        AuthConfig {
            enabled: true,
            bearer_token: Some("the-operator's-own-token".to_string()),
            single_user: true,
            ..AuthConfig::default()
        }
    }

    #[test]
    fn asserted_solo_gateway_may_mint_the_principal() {
        assert!(
            solo().grants_single_user_principal(false),
            "enabled auth + the operator's explicit assertion + no second credential is the \
             whole positive case"
        );
    }

    #[test]
    fn one_api_key_still_mints_the_principal() {
        // `<= 1`, not `== 1`: a bearer-only gateway and a one-key gateway are
        // the same deployment shape, and the operator asserted both are one
        // person. Neither has a second credential to hand to anyone.
        let cfg = AuthConfig {
            api_keys: vec![api_key("me")],
            ..solo()
        };
        assert!(cfg.grants_single_user_principal(false));
    }

    /// THE SECURITY CASE. This is the defect §4.1a of the design doc records:
    /// `implies_multi_user` returns `false` when auth is switched off, because
    /// with no auth boundary the per-user isolation question is moot. Its
    /// negation therefore reads "one user is present", which is the opposite of
    /// what an unauthenticated gateway means. Minting here would hand the stored
    /// OAuth grants to any anonymous caller that can reach the port.
    #[test]
    fn disabled_auth_never_mints_the_principal() {
        let cfg = AuthConfig {
            enabled: false,
            ..solo()
        };
        assert!(
            !cfg.grants_single_user_principal(false),
            "absence of authentication is not the presence of one user"
        );
        assert!(
            !AuthConfig::default().grants_single_user_principal(false),
            "the shipped default mints nothing"
        );
    }

    #[test]
    fn two_api_keys_never_mint_the_principal() {
        let cfg = AuthConfig {
            api_keys: vec![api_key("laptop"), api_key("phone")],
            ..solo()
        };
        assert!(
            !cfg.grants_single_user_principal(false),
            "a second credential can be handed to a second human; the assertion is overridden"
        );
    }

    #[test]
    fn any_identity_provider_never_mints_the_principal() {
        assert!(
            !solo().grants_single_user_principal(true),
            "an IdP means real per-user principals exist and the assertion is overridden"
        );
    }

    /// Without the operator saying so, nothing is asserted and nothing is minted
    /// — the same fail-closed default `single_user` already carries (ADR-008
    /// INV-2).
    #[test]
    fn unasserted_auth_never_mints_the_principal() {
        let cfg = AuthConfig {
            single_user: false,
            ..solo()
        };
        assert!(!cfg.grants_single_user_principal(false));
    }

    /// An OIDC issuer is the only authority a real `VerifiedIdentity` can carry
    /// (`key_server/oidc.rs`), and this predicate is false whenever one is
    /// configured. So the sole-operator authority and the OIDC issuer namespace
    /// never coexist in one deployment.
    ///
    /// Structural, not enforced: nothing validates that `principal_authority` is
    /// a URL (design doc §3), so this is a consequence of the configuration
    /// rather than a rule the code checks. Recorded as such rather than
    /// presented as a boundary.
    #[test]
    fn the_two_authority_namespaces_never_coexist() {
        for enabled in [true, false] {
            for single_user in [true, false] {
                for keys in 0..3 {
                    let cfg = AuthConfig {
                        enabled,
                        single_user,
                        api_keys: (0..keys).map(|i| api_key(&i.to_string())).collect(),
                        ..AuthConfig::default()
                    };
                    assert!(
                        !cfg.grants_single_user_principal(true),
                        "no configuration with an IdP may also mint the sole-operator principal"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // AuthConfig::Debug must redact the bearer token and never print API keys.
    #[test]
    fn auth_config_debug_redacts_bearer_token() {
        let cfg = AuthConfig {
            enabled: true,
            bearer_token: Some(SENTINEL.to_string()),
            ..AuthConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked bearer_token: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }

    // AgentDefinitionConfig::Debug must redact the HS256 secret while keeping
    // the (non-secret) RSA public key visible.
    #[test]
    fn agent_definition_config_debug_redacts_hs256_secret() {
        let cfg = AgentDefinitionConfig {
            client_id: "agent-1".to_string(),
            name: "Agent One".to_string(),
            hs256_secret: Some(SENTINEL.to_string()),
            rs256_public_key: Some("-----BEGIN PUBLIC KEY-----".to_string()),
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: None,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked hs256_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("BEGIN PUBLIC KEY"),
            "public key is not secret and should stay visible: {dbg}"
        );
    }
}

#[cfg(test)]
mod api_key_name_tests {
    use super::*;
    use crate::config::Config;

    fn config_with_key_names(names: &[&str]) -> Config {
        let mut config = Config::default();
        config.auth.api_keys = names
            .iter()
            .enumerate()
            .map(|(index, name)| ApiKeyConfig {
                key: format!("secret-{index}"),
                name: (*name).to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
            })
            .collect();
        config
    }

    // A key's name is its identity-grant subject (`api_key:<name>`), so two
    // keys sharing a name would hold each other's grants and a nameless key
    // could hold none. Both are refused at load, whether or not auth is on.
    #[test]
    fn duplicate_api_key_names_are_refused_at_load() {
        let err = config_with_key_names(&["ops", "laptop", "ops"])
            .validate()
            .expect_err("two keys named 'ops' would share one grant identity");
        assert!(err.to_string().contains("ops"), "{err}");
    }

    #[test]
    fn an_empty_api_key_name_is_refused_at_load() {
        for blank in ["", "  "] {
            let err = config_with_key_names(&["laptop", blank])
                .validate()
                .expect_err("a nameless key has no grant identity");
            assert!(err.to_string().contains("name"), "{err}");
        }
    }

    // `alice ` would be a distinct subject from `alice`, so a grant written
    // for `api_key:alice` would silently never match the padded key.
    #[test]
    fn a_padded_api_key_name_is_refused_at_load() {
        for padded in ["alice ", " alice", "\talice"] {
            let err = config_with_key_names(&[padded])
                .validate()
                .expect_err("a padded name is not the subject a grant names");
            assert!(err.to_string().contains("whitespace"), "{err}");
        }
    }

    #[test]
    fn unique_named_api_keys_load() {
        config_with_key_names(&["laptop", "phone"])
            .validate()
            .expect("distinct non-empty names are the valid shape");
    }
}
