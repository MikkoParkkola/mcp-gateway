// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Authentication middleware for MCP Gateway
//!
//! Supports:
//! - Bearer token authentication
//! - API key authentication with per-key restrictions
//! - Rate limiting per client
//! - Public paths that bypass authentication

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use tracing::{debug, warn};

use super::middleware::{
    bearer_unauthorized_response, circuit_open_response, rate_limited_response,
};
use crate::Result;
use crate::config::{AuthConfig, CircuitBreakerConfig};
use crate::failsafe::{CircuitBreaker, CircuitState};
use crate::key_server::KeyServer;

/// Type alias for our rate limiter
type ClientRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Short, non-reversible fingerprint of a secret for log correlation (CWE-532).
///
/// Returns the first 12 hex chars of the SHA-256 digest — enough to correlate
/// which credential is active across logs, useless as a credential itself.
fn bearer_token_fingerprint(token: &str) -> String {
    crate::hashing::sha256_hex(token.as_bytes())[..12].to_string()
}

/// Resolved authentication configuration (tokens expanded)
pub struct ResolvedAuthConfig {
    /// Whether auth is enabled
    pub enabled: bool,
    /// Resolved bearer token
    pub bearer_token: Option<String>,
    /// Resolved API keys
    pub api_keys: Vec<ResolvedApiKey>,
    /// Public paths
    pub public_paths: Vec<String>,
    /// Rate limiters per client (keyed by resolved authenticated identity).
    rate_limiters: DashMap<String, Arc<ClientRateLimiter>>,
    /// Optional client circuit-breaker policy shared across per-client breaker instances.
    client_circuit_breaker: Option<CircuitBreakerConfig>,
    /// Circuit breakers per authenticated client (keyed by resolved authenticated identity).
    client_circuit_breakers: DashMap<String, Arc<CircuitBreaker>>,
}

/// Resolved API key with expanded values
#[derive(Clone)]
pub struct ResolvedApiKey {
    /// The actual key value
    pub key: String,
    /// Client name
    pub name: String,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    /// Allowed backends
    pub backends: Vec<String>,
    /// Allowed tools (allowlist if Some)
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (blocklist if Some)
    pub denied_tools: Option<Vec<String>>,
    /// Admin-level UI and management tool access.
    pub admin: bool,
}

// Manual `Debug` that redacts resolved secrets (CWE-532, mirrors MIK-6733).
// A derived `Debug` would print the bearer token / API key verbatim into any
// trace or error context. Only a non-reversible fingerprint is shown.
impl std::fmt::Debug for ResolvedAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAuthConfig")
            .field("enabled", &self.enabled)
            .field(
                "bearer_token",
                &self
                    .bearer_token
                    .as_deref()
                    .map(|t| format!("<redacted:{}>", bearer_token_fingerprint(t))),
            )
            .field("api_keys", &self.api_keys)
            .field("public_paths", &self.public_paths)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ResolvedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedApiKey")
            .field(
                "key",
                &format!("<redacted:{}>", bearer_token_fingerprint(&self.key)),
            )
            .field("name", &self.name)
            .field("rate_limit", &self.rate_limit)
            .field("backends", &self.backends)
            .field("allowed_tools", &self.allowed_tools)
            .field("denied_tools", &self.denied_tools)
            .field("admin", &self.admin)
            .finish()
    }
}

impl ResolvedAuthConfig {
    /// Create resolved config from `AuthConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if any `env:VAR_NAME` secret reference cannot be resolved.
    pub fn try_from_config(config: &AuthConfig) -> Result<Self> {
        let bearer_token = config.resolve_bearer_token()?;

        // Signal auto-generation WITHOUT logging the secret (CWE-532). The
        // plaintext bearer is a master gateway credential; INFO logs ship to
        // files, journald, and aggregators where log-read access would become
        // full auth bypass. Emit only a short non-reversible fingerprint so
        // operators can correlate the active token without it being usable.
        if config.bearer_token.as_deref() == Some("auto")
            && let Some(ref token) = bearer_token
        {
            tracing::info!(
                "Auto-generated bearer token (fingerprint {})",
                bearer_token_fingerprint(token)
            );
        }

        let api_keys: Vec<ResolvedApiKey> = config
            .api_keys
            .iter()
            .map(|k| {
                Ok(ResolvedApiKey {
                    key: k.resolve_key()?,
                    name: k.name.clone(),
                    rate_limit: k.rate_limit,
                    backends: k.backends.clone(),
                    allowed_tools: k.allowed_tools.clone(),
                    denied_tools: k.denied_tools.clone(),
                    admin: k.admin,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Pre-create rate limiters for clients with rate limits
        let rate_limiters = DashMap::new();
        for key in &api_keys {
            if key.rate_limit > 0
                && let Some(quota) = NonZeroU32::new(key.rate_limit)
            {
                let limiter = RateLimiter::direct(Quota::per_minute(quota));
                rate_limiters.insert(key.name.clone(), Arc::new(limiter));
            }
        }

        Ok(Self {
            enabled: config.enabled,
            bearer_token,
            api_keys,
            public_paths: config.public_paths.clone(),
            rate_limiters,
            client_circuit_breaker: config.client_circuit_breaker.clone(),
            client_circuit_breakers: DashMap::new(),
        })
    }

    /// Create resolved config from `AuthConfig`.
    ///
    /// Panics if a configured environment-backed secret is missing. Runtime startup
    /// paths should prefer [`Self::try_from_config`] so the error is returned.
    #[must_use]
    pub fn from_config(config: &AuthConfig) -> Self {
        Self::try_from_config(config).expect("auth config secret references should resolve")
    }

    /// Check if a path is public (bypasses auth)
    #[must_use]
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// Validate a token and return the client info if valid
    #[must_use]
    pub fn validate_token(&self, token: &str) -> Option<AuthenticatedClient> {
        use subtle::ConstantTimeEq;

        // Check bearer token first. Constant-time comparison prevents a timing
        // side-channel (CWE-208) on the primary auth path — every request,
        // including the admin bearer token, is validated here.
        if let Some(ref bearer) = self.bearer_token
            && token.as_bytes().ct_eq(bearer.as_bytes()).into()
        {
            return Some(AuthenticatedClient {
                name: "bearer".to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: true,
            });
        }

        // Check API keys (constant-time to avoid a per-key timing oracle).
        for key in &self.api_keys {
            if token.as_bytes().ct_eq(key.key.as_bytes()).into() {
                return Some(AuthenticatedClient {
                    name: key.name.clone(),
                    rate_limit: key.rate_limit,
                    backends: key.backends.clone(),
                    allowed_tools: key.allowed_tools.clone(),
                    denied_tools: key.denied_tools.clone(),
                    admin: key.admin,
                });
            }
        }

        None
    }

    /// Check rate limit for a client. Returns true if allowed, false if rate limited.
    #[must_use]
    pub fn check_rate_limit(&self, client_name: &str) -> bool {
        if let Some(limiter) = self.rate_limiters.get(client_name) {
            limiter.check().is_ok()
        } else {
            // No rate limiter = unlimited
            true
        }
    }

    /// Check rate limiting for a fully resolved authenticated client.
    ///
    /// Static API keys are pre-created at startup; temporary key-server identities
    /// create their per-client bucket on first use from the verified OIDC identity.
    #[must_use]
    pub fn check_authenticated_client_rate_limit(&self, client: &AuthenticatedClient) -> bool {
        if client.rate_limit == 0 {
            return true;
        }

        let Some(quota) = NonZeroU32::new(client.rate_limit) else {
            return true;
        };
        let limiter = self
            .rate_limiters
            .entry(client.name.clone())
            .or_insert_with(|| Arc::new(RateLimiter::direct(Quota::per_minute(quota))))
            .clone();
        limiter.check().is_ok()
    }

    /// Check whether this authenticated client's dispatch circuit allows a request.
    #[must_use]
    pub fn check_client_circuit_breaker(&self, client_name: &str) -> bool {
        let Some(config) = self.client_circuit_breaker.as_ref() else {
            return true;
        };
        if !config.enabled {
            return true;
        }

        self.client_circuit_breaker_for(client_name, config)
            .can_proceed()
    }

    /// Record a successful dispatch for this authenticated client.
    pub fn record_client_success(&self, client_name: &str) {
        if let Some(breaker) = self.active_client_circuit_breaker(client_name) {
            breaker.record_success();
        }
    }

    /// Record a failed dispatch for this authenticated client.
    pub fn record_client_failure(&self, client_name: &str) {
        if let Some(breaker) = self.active_client_circuit_breaker(client_name) {
            breaker.record_failure("client_dispatch_failure", std::time::Duration::ZERO);
        }
    }

    /// Return the current circuit state for tests and observability adapters.
    #[must_use]
    pub fn client_circuit_state(&self, client_name: &str) -> Option<CircuitState> {
        self.client_circuit_breakers
            .get(client_name)
            .map(|breaker| breaker.state())
    }

    fn active_client_circuit_breaker(&self, client_name: &str) -> Option<Arc<CircuitBreaker>> {
        let config = self.client_circuit_breaker.as_ref()?;
        if !config.enabled {
            return None;
        }
        Some(self.client_circuit_breaker_for(client_name, config))
    }

    fn client_circuit_breaker_for(
        &self,
        client_name: &str,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        self.client_circuit_breakers
            .entry(client_name.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::new(
                    &format!("client:{client_name}"),
                    config,
                ))
            })
            .clone()
    }
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Client name
    pub name: String,
    /// Rate limit (0 = unlimited)
    pub rate_limit: u32,
    /// Allowed backends (empty or `["*"]` = all)
    pub backends: Vec<String>,
    /// Allowed tools (allowlist if Some). Supports glob patterns.
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (blocklist if Some). Supports glob patterns.
    pub denied_tools: Option<Vec<String>>,
    /// Admin-level UI and management tool access.
    pub admin: bool,
}

impl AuthenticatedClient {
    /// Check if this client can access a backend
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }

    /// Check if this client can access a tool (per-client scope).
    ///
    /// Logic:
    /// - If `allowed_tools` is Some, only tools matching the allowlist are permitted.
    /// - If `denied_tools` is Some, tools matching the denylist are blocked.
    /// - If both are None, fall back to global policy (caller's responsibility).
    ///
    /// Returns `Ok(())` if allowed, `Err(message)` if denied.
    pub fn check_tool_scope(&self, server: &str, tool: &str) -> std::result::Result<(), String> {
        let qualified = format!("{server}:{tool}");

        // If allowlist is set, ONLY tools in the list are permitted
        if let Some(ref allowed) = self.allowed_tools
            && !Self::matches_any_pattern(allowed, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is not in the allowlist for client '{}'",
                self.name
            ));
        }

        // If denylist is set, tools in the list are blocked
        if let Some(ref denied) = self.denied_tools
            && Self::matches_any_pattern(denied, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is blocked by client '{}' policy",
                self.name
            ));
        }

        Ok(())
    }

    /// Check if a tool name matches any pattern in the list.
    /// Supports exact match and glob suffix patterns (e.g., `"search_*"`).
    fn matches_any_pattern(patterns: &[String], tool: &str, qualified: &str) -> bool {
        patterns.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('*') {
                // Glob pattern: check prefix match on both tool and qualified name
                tool.starts_with(prefix) || qualified.starts_with(prefix)
            } else {
                // Exact match on both tool and qualified name
                tool == pattern || qualified == pattern
            }
        })
    }
}

/// Combined auth state: static config + optional key server.
#[derive(Clone)]
pub struct AuthState {
    /// Static key / bearer token configuration.
    pub auth_config: Arc<ResolvedAuthConfig>,
    /// Key server for OIDC-issued temporary tokens (optional).
    pub key_server: Option<Arc<KeyServer>>,
}

/// Authentication middleware
///
/// Validation order (for performance and backward compatibility):
/// 1. Static auth (existing `ResolvedAuthConfig`) — O(n) comparison.
/// 2. Temporary token (key server `DashMap` lookup) — O(1).
/// 3. Reject.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let auth_config = &state.auth_config;

    // If auth is disabled, pass through with anonymous client
    if !auth_config.enabled {
        request.extensions_mut().insert(AuthenticatedClient {
            name: "anonymous".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
        });
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Check if path is public
    if auth_config.is_public_path(path) {
        debug!(path = %path, "Public path, skipping auth");
        request.extensions_mut().insert(AuthenticatedClient {
            name: "public".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        });
        return next.run(request).await;
    }

    // Extract token from Authorization header
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    let Some(token) = token else {
        warn!(path = %path, "Missing Authorization header");
        return bearer_unauthorized_response(
            "Missing Authorization header. Use: Authorization: Bearer <token>",
        );
    };

    // 1. Try static auth (existing behavior)
    if let Some(client) = auth_config.validate_token(token) {
        if let Some(deny) = client_preflight(auth_config, &client, path) {
            return deny;
        }
        debug!(client = %client.name, path = %path, "Authenticated via static key");
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 2. Try temporary token (key server)
    if let Some(ref ks) = state.key_server
        && let Some((client, identity_token)) = ks.validate_token(token).await
    {
        if let Some(deny) = client_preflight(auth_config, &client, path) {
            return deny;
        }
        debug!(client = %client.name, path = %path, "Authenticated via temporary token");
        request
            .extensions_mut()
            .insert(identity_token.identity.clone());
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 3. Try a raw OIDC ID token presented directly as a bearer (delegated
    //    auth, MIK-6648). Gated on `delegated_bearer` and a cheap JWT-shape
    //    check so we never run JWKS verification on opaque/static tokens. The
    //    verified subject is bound into request extensions so downstream grant
    //    evaluation can scope capabilities to the caller identity.
    if let Some(ref ks) = state.key_server
        && ks.config.delegated_bearer
        && looks_like_jwt(token)
        && let Some((client, identity)) = ks.verify_bearer_identity(token).await
    {
        if let Some(deny) = client_preflight(auth_config, &client, path) {
            return deny;
        }
        debug!(client = %client.name, path = %path, "Authenticated via delegated OIDC bearer");
        request.extensions_mut().insert(identity);
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 4. Reject
    warn!(path = %path, "Invalid token");
    bearer_unauthorized_response("Invalid token")
}

/// Per-client rate-limit + circuit-breaker preflight shared by every auth path.
/// Returns `Some(response)` to short-circuit with an error, `None` to proceed.
fn client_preflight(
    auth_config: &ResolvedAuthConfig,
    client: &AuthenticatedClient,
    path: &str,
) -> Option<Response> {
    if !auth_config.check_authenticated_client_rate_limit(client) {
        warn!(client = %client.name, path = %path, "Rate limit exceeded");
        return Some(rate_limited_response(format!(
            "Rate limit exceeded for client '{}'. Try again later.",
            client.name
        )));
    }
    if !auth_config.check_client_circuit_breaker(&client.name) {
        warn!(client = %client.name, path = %path, "Client circuit breaker open");
        return Some(circuit_open_response(format!(
            "Client '{}' circuit breaker is open. Try again later.",
            client.name
        )));
    }
    None
}

/// Cheap structural check: a JWT is three non-empty base64url segments joined
/// by `.`. Used to avoid running OIDC/JWKS verification on opaque static keys
/// or exchanged tokens, which never have this shape.
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !h.is_empty()
        && !p.is_empty()
        && !s.is_empty()
        && [h, p, s].iter().all(|seg| {
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_jwt_accepts_three_base64url_segments() {
        // Build from parts so no JWT-shaped literal trips the secret scanner.
        let jwt = format!("{}.{}.{}", "abc-_", "def-_", "ghi-_");
        assert!(looks_like_jwt(&jwt));
        assert!(looks_like_jwt("aGVhZGVy.cGF5bG9hZA.c2ln"));
    }

    #[test]
    fn looks_like_jwt_rejects_non_jwt_tokens() {
        // opaque static keys / exchanged tokens have no JWT shape
        assert!(!looks_like_jwt("static-key-12345"));
        assert!(!looks_like_jwt("two.parts"));
        assert!(!looks_like_jwt("four.parts.here.nope"));
        assert!(!looks_like_jwt("a..c")); // empty middle segment
        assert!(!looks_like_jwt("")); // empty
        assert!(!looks_like_jwt("has spaces.in.it"));
        assert!(!looks_like_jwt("plus+slash/.b.c")); // base64 (not url) chars
    }

    #[test]
    fn test_public_path_check() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("test".to_string()),
            api_keys: vec![],
            public_paths: vec!["/health".to_string(), "/metrics".to_string()],
            rate_limiters: DashMap::new(),
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };

        assert!(config.is_public_path("/health"));
        assert!(config.is_public_path("/health/"));
        assert!(config.is_public_path("/metrics"));
        assert!(!config.is_public_path("/mcp"));
        assert!(!config.is_public_path("/"));
    }

    #[test]
    fn debug_output_redacts_bearer_and_api_keys() {
        // CWE-532 / MIK-6733 sibling: {:?} must never leak resolved secrets.
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("super-secret-bearer-VALUE".to_string()),
            api_keys: vec![ResolvedApiKey {
                key: "api-key-SECRET-VALUE".to_string(),
                name: "client-a".to_string(),
                rate_limit: 60,
                backends: vec![],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
            }],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };
        let dbg = format!("{config:?}");
        assert!(
            !dbg.contains("super-secret-bearer-VALUE"),
            "Debug leaked the bearer token: {dbg}"
        );
        assert!(
            !dbg.contains("api-key-SECRET-VALUE"),
            "Debug leaked the API key: {dbg}"
        );
        assert!(
            dbg.contains("<redacted"),
            "expected redaction marker: {dbg}"
        );
        // Non-secret fields stay visible for diagnostics.
        assert!(
            dbg.contains("client-a"),
            "api key name should remain visible"
        );
    }

    #[test]
    fn fingerprint_is_not_the_secret() {
        let fp = bearer_token_fingerprint("super-secret-bearer-VALUE");
        assert_eq!(fp.len(), 12);
        assert!(!fp.contains("secret"));
        assert_ne!(fp, "super-secret-bearer-VALUE");
    }

    #[test]
    fn test_bearer_token_validation() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("secret123".to_string()),
            api_keys: vec![],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };

        let client = config.validate_token("secret123");
        assert!(client.is_some());
        assert_eq!(client.unwrap().name, "bearer");
        assert!(config.validate_token("wrong").is_none());
    }

    #[test]
    fn constant_time_token_comparison_accepts_correct_rejects_wrong() {
        // CWE-208: `validate_token` compares bearer + API keys with
        // `subtle::ConstantTimeEq`. Timing cannot be asserted in a unit test,
        // so this pins the *functional* contract the constant-time path must
        // preserve: exact match authenticates; any mismatch (wrong value,
        // length mismatch, empty) is rejected.
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: Some("bearer-EXACT".to_string()),
            api_keys: vec![ResolvedApiKey {
                key: "apikey-EXACT".to_string(),
                name: "client-ct".to_string(),
                rate_limit: 10,
                backends: vec![],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
            }],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };

        // Correct bearer authenticates as the admin "bearer" client.
        let bearer = config.validate_token("bearer-EXACT").expect("bearer valid");
        assert_eq!(bearer.name, "bearer");
        assert!(bearer.admin);

        // Correct API key authenticates as the named client.
        let keyed = config
            .validate_token("apikey-EXACT")
            .expect("api key valid");
        assert_eq!(keyed.name, "client-ct");
        assert!(!keyed.admin);

        // Mismatches are rejected: wrong value, length mismatch, empty, and a
        // prefix of a valid secret (guards against non-constant-time shortcuts).
        for wrong in [
            "bearer-WRONG",
            "apikey-WRONG",
            "bearer-EXAC",
            "",
            "bearer-EXACTx",
        ] {
            assert!(
                config.validate_token(wrong).is_none(),
                "token {wrong:?} must not authenticate"
            );
        }
    }

    #[test]
    fn test_api_key_validation() {
        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![
                ResolvedApiKey {
                    key: "key1".to_string(),
                    name: "Client A".to_string(),
                    rate_limit: 100,
                    backends: vec!["tavily".to_string()],
                    allowed_tools: None,
                    denied_tools: None,
                    admin: false,
                },
                ResolvedApiKey {
                    key: "key2".to_string(),
                    name: "Client B".to_string(),
                    rate_limit: 0,
                    backends: vec![],
                    allowed_tools: None,
                    denied_tools: None,
                    admin: false,
                },
            ],
            public_paths: vec![],
            rate_limiters: DashMap::new(),
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };

        let client_a = config.validate_token("key1").unwrap();
        assert_eq!(client_a.name, "Client A");
        assert!(client_a.can_access_backend("tavily"));
        assert!(!client_a.can_access_backend("brave"));

        let client_b = config.validate_token("key2").unwrap();
        assert_eq!(client_b.name, "Client B");
        assert!(client_b.can_access_backend("anything"));

        assert!(config.validate_token("wrong").is_none());
    }

    #[test]
    fn test_rate_limiting() {
        let rate_limiters = DashMap::new();
        // Create a rate limiter with 2 requests per minute for testing
        let limiter = RateLimiter::direct(Quota::per_minute(NonZeroU32::new(2).unwrap()));
        rate_limiters.insert("limited_client".to_string(), Arc::new(limiter));

        let config = ResolvedAuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![],
            public_paths: vec![],
            rate_limiters,
            client_circuit_breaker: None,
            client_circuit_breakers: DashMap::new(),
        };

        // First two requests should succeed
        assert!(config.check_rate_limit("limited_client"));
        assert!(config.check_rate_limit("limited_client"));
        // Third request should be rate limited
        assert!(!config.check_rate_limit("limited_client"));
        // Unknown client (no limiter) should always succeed
        assert!(config.check_rate_limit("unknown_client"));
    }

    #[test]
    fn test_backend_access_control() {
        let client_restricted = AuthenticatedClient {
            name: "restricted".to_string(),
            rate_limit: 0,
            backends: vec!["tavily".to_string(), "brave".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        };

        let client_unrestricted = AuthenticatedClient {
            name: "unrestricted".to_string(),
            rate_limit: 0,
            backends: vec![], // empty = all access
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        };

        let client_wildcard = AuthenticatedClient {
            name: "wildcard".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        };

        // Restricted client
        assert!(client_restricted.can_access_backend("tavily"));
        assert!(client_restricted.can_access_backend("brave"));
        assert!(!client_restricted.can_access_backend("context7"));

        // Unrestricted client (empty backends = all)
        assert!(client_unrestricted.can_access_backend("anything"));

        // Wildcard client
        assert!(client_wildcard.can_access_backend("anything"));
    }

    // ── Tool scope tests ──────────────────────────────────────────────────

    #[test]
    fn test_tool_scope_no_restrictions() {
        let client = AuthenticatedClient {
            name: "unrestricted".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        };

        // No restrictions = all tools allowed (fallback to global policy)
        assert!(client.check_tool_scope("server", "any_tool").is_ok());
        assert!(client.check_tool_scope("server", "write_file").is_ok());
    }

    #[test]
    fn test_tool_scope_allowlist_exact_match() {
        let client = AuthenticatedClient {
            name: "restricted".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: Some(vec!["search_web".to_string(), "read_file".to_string()]),
            denied_tools: None,
            admin: false,
        };

        // Tools in allowlist
        assert!(client.check_tool_scope("server", "search_web").is_ok());
        assert!(client.check_tool_scope("server", "read_file").is_ok());

        // Tools NOT in allowlist
        assert!(client.check_tool_scope("server", "write_file").is_err());
        assert!(client.check_tool_scope("server", "delete_file").is_err());
    }

    #[test]
    fn test_tool_scope_allowlist_glob_pattern() {
        let client = AuthenticatedClient {
            name: "search_only".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: Some(vec!["search_*".to_string(), "read_*".to_string()]),
            denied_tools: None,
            admin: false,
        };

        // Tools matching glob patterns
        assert!(client.check_tool_scope("server", "search_web").is_ok());
        assert!(client.check_tool_scope("server", "search_local").is_ok());
        assert!(client.check_tool_scope("server", "read_file").is_ok());
        assert!(client.check_tool_scope("server", "read_database").is_ok());

        // Tools NOT matching glob patterns
        assert!(client.check_tool_scope("server", "write_file").is_err());
        assert!(
            client
                .check_tool_scope("server", "execute_command")
                .is_err()
        );
    }

    #[test]
    fn test_tool_scope_denylist_exact_match() {
        let client = AuthenticatedClient {
            name: "no_writes".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: None,
            denied_tools: Some(vec!["write_file".to_string(), "delete_file".to_string()]),
            admin: false,
        };

        // Tools in denylist
        assert!(client.check_tool_scope("server", "write_file").is_err());
        assert!(client.check_tool_scope("server", "delete_file").is_err());

        // Tools NOT in denylist
        assert!(client.check_tool_scope("server", "read_file").is_ok());
        assert!(client.check_tool_scope("server", "search_web").is_ok());
    }

    #[test]
    fn test_tool_scope_denylist_glob_pattern() {
        let client = AuthenticatedClient {
            name: "no_filesystem".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: None,
            denied_tools: Some(vec!["filesystem_*".to_string(), "exec_*".to_string()]),
            admin: false,
        };

        // Tools matching deny glob patterns
        assert!(
            client
                .check_tool_scope("server", "filesystem_read")
                .is_err()
        );
        assert!(
            client
                .check_tool_scope("server", "filesystem_write")
                .is_err()
        );
        assert!(client.check_tool_scope("server", "exec_command").is_err());
        assert!(client.check_tool_scope("server", "exec_shell").is_err());

        // Tools NOT matching deny patterns
        assert!(client.check_tool_scope("server", "search_web").is_ok());
        assert!(client.check_tool_scope("server", "database_query").is_ok());
    }

    #[test]
    fn test_tool_scope_qualified_name_match() {
        let client = AuthenticatedClient {
            name: "specific_server".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: Some(vec![
                "filesystem:read_file".to_string(),
                "search_*".to_string(),
            ]),
            denied_tools: None,
            admin: false,
        };

        // Qualified match: only filesystem:read_file allowed, not other servers
        assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
        assert!(client.check_tool_scope("other", "read_file").is_err());

        // Glob still matches across all servers
        assert!(client.check_tool_scope("any_server", "search_web").is_ok());
    }

    #[test]
    fn test_tool_scope_both_allow_and_deny() {
        let client = AuthenticatedClient {
            name: "complex".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: Some(vec!["filesystem_*".to_string(), "search_*".to_string()]),
            denied_tools: Some(vec![
                "filesystem_write".to_string(),
                "filesystem_delete".to_string(),
            ]),
            admin: false,
        };

        // In allowlist and NOT in denylist
        assert!(client.check_tool_scope("server", "filesystem_read").is_ok());
        assert!(client.check_tool_scope("server", "search_web").is_ok());

        // In allowlist BUT in denylist (denylist wins)
        assert!(
            client
                .check_tool_scope("server", "filesystem_write")
                .is_err()
        );
        assert!(
            client
                .check_tool_scope("server", "filesystem_delete")
                .is_err()
        );

        // NOT in allowlist
        assert!(
            client
                .check_tool_scope("server", "execute_command")
                .is_err()
        );
    }

    #[test]
    fn test_tool_scope_error_messages() {
        let client_allow = AuthenticatedClient {
            name: "frontend".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: Some(vec!["search_*".to_string()]),
            denied_tools: None,
            admin: false,
        };

        let err = client_allow
            .check_tool_scope("server", "write_file")
            .unwrap_err();
        assert!(err.contains("write_file"));
        assert!(err.contains("server"));
        assert!(err.contains("allowlist"));
        assert!(err.contains("frontend"));

        let client_deny = AuthenticatedClient {
            name: "restricted_bot".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: None,
            denied_tools: Some(vec!["exec_*".to_string()]),
            admin: false,
        };

        let err = client_deny
            .check_tool_scope("server", "exec_command")
            .unwrap_err();
        assert!(err.contains("exec_command"));
        assert!(err.contains("server"));
        assert!(err.contains("blocked"));
        assert!(err.contains("restricted_bot"));
    }
}
