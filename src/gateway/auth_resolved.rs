// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `ResolvedAuthConfig`: config resolution, token validation, and the
//! per-client rate limiters and circuit breakers.

use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use tracing::warn;

use super::{
    AUTH_TARGET, AuthenticatedClient, NamedApiKey, QuotaPrincipal, ResolvedApiKey,
    ResolvedAuthConfig, bearer_token_fingerprint, principal_of,
};
use crate::Result;
use crate::config::{AuthConfig, CircuitBreakerConfig};
use crate::failsafe::{CircuitBreaker, CircuitState};

impl ResolvedAuthConfig {
    /// Create resolved config from `AuthConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if any `env:VAR_NAME` secret reference cannot be
    /// resolved in `overlay` (the env files the config was loaded with, then
    /// the process environment).
    pub fn try_from_config(
        config: &AuthConfig,
        overlay: &crate::config::EnvOverlay,
    ) -> Result<Self> {
        // An empty credential compares equal to an empty presented token; the
        // resolvers refuse one (C4, `SecretRef::resolve`), so every caller that
        // builds this comparator is covered.
        let bearer_token = config.resolve_bearer_token(overlay)?;
        let bearer_quota_principal = bearer_token
            .as_deref()
            .map(QuotaPrincipal::configured_bearer);

        // Signal auto-generation WITHOUT logging the secret (CWE-532). The
        // plaintext bearer is a master gateway credential; INFO logs ship to
        // files, journald, and aggregators where log-read access would become
        // full auth bypass. Emit only a short non-reversible fingerprint so
        // operators can correlate the active token without it being usable.
        if config.bearer_token.as_deref() == Some("auto")
            && let Some(ref token) = bearer_token
        {
            tracing::info!(target: AUTH_TARGET,
                "Auto-generated bearer token (fingerprint {})",
                bearer_token_fingerprint(token)
            );
        }

        config.warn_keys_without_backends();
        config.warn_expired_keys(chrono::Utc::now());
        let api_keys: Vec<ResolvedApiKey> = config
            .api_keys
            .iter()
            .map(|k| {
                let digest = k.resolve_digest(overlay)?;
                Ok(ResolvedApiKey {
                    digest,
                    expires_at: k.expires_at,
                    quota_principal: QuotaPrincipal::api_key(&digest),
                    name: k.name.clone(),
                    rate_limit: k.rate_limit,
                    backends: k.backends.clone(),
                    allowed_tools: k.allowed_tools.clone(),
                    denied_tools: k.denied_tools.clone(),
                    admin: k.admin,
                    personal: k.kind == crate::config::ApiKeyKind::Personal,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // MIK-7973: the one place every bearer form, `auto` included, is known.
        super::refuse_shared_principals(
            bearer_token.as_deref(),
            api_keys.iter().map(|k| (k.name.as_str(), &k.digest)),
        )?;

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
            bearer_quota_principal,
            api_keys,
            public_paths: config.enforced_public_paths(),
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
        Self::try_from_config(config, &crate::config::EnvOverlay::none())
            .expect("auth config secret references should resolve")
    }

    /// Check if a path is public (bypasses auth)
    #[must_use]
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// Validate a token and return the client info if valid
    #[must_use]
    pub fn validate_token(&self, token: &str) -> Option<AuthenticatedClient> {
        self.validate_token_with_origin(token)
            .map(|(client, _origin)| client)
    }

    /// Whether `token` is a configured API key past its expiry. Hashed again
    /// only on the reject path, to tell an expired key from a wrong one (D4).
    pub(super) fn is_expired_key(&self, token: &str) -> bool {
        use subtle::ConstantTimeEq;
        let presented = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes());
        self.api_keys.iter().any(|k| {
            bool::from(presented.as_slice().ct_eq(k.digest.as_slice()))
                && crate::config::api_key_expired(k.expires_at, chrono::Utc::now())
        })
    }

    /// The same validation, also saying WHICH configured credential matched.
    ///
    /// `AuthenticatedClient::name` cannot answer that question: the bearer
    /// identity is named `"bearer"`, a key-server identity is named from a
    /// verified OIDC subject, and an operator may name an API key anything at
    /// all — so a rule written against the name would let a non-API-key
    /// identity claim an API key's privileges by being called the same thing.
    /// The provenance is therefore recorded HERE, at the one place that
    /// actually compares a presented secret against `api_keys`, and nowhere
    /// else can mint it. `validate_token` delegates so both callers keep one
    /// precedence: a token equal to the bearer is the bearer, never a key.
    #[must_use]
    pub(crate) fn validate_token_with_origin(
        &self,
        token: &str,
    ) -> Option<(AuthenticatedClient, Option<NamedApiKey>)> {
        use subtle::ConstantTimeEq;

        // Check bearer token first. Constant-time comparison prevents a timing
        // side-channel (CWE-208) on the primary auth path — every request,
        // including the admin bearer token, is validated here.
        if let Some(ref bearer) = self.bearer_token
            && token.as_bytes().ct_eq(bearer.as_bytes()).into()
        {
            return Some((
                AuthenticatedClient {
                    quota_principal: self.bearer_quota_principal.clone(),
                    name: "bearer".to_string(),
                    principal: principal_of(token),
                    rate_limit: 0,
                    backends: vec!["*".to_string()],
                    allowed_tools: None,
                    denied_tools: None,
                    admin: true,
                    authenticated: true,
                    credential_kind: crate::security::audit::CredentialKind::StaticBearer,
                },
                // The bearer is NOT an API key, whatever an operator named their
                // keys: no adapter allow-list entry may be satisfied by it.
                None,
            ));
        }

        // API keys: hash once, then compare against EVERY digest in constant time,
        // so neither a match nor its position is visible in the timing.
        let presented = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes());
        let key = self.api_keys.iter().fold(None, |hit, k| {
            let eq: bool = presented.as_slice().ct_eq(k.digest.as_slice()).into();
            hit.or(eq.then_some(k))
        })?;
        // After the match: an expired key is never an authenticated caller.
        if crate::config::api_key_expired(key.expires_at, chrono::Utc::now()) {
            warn!(target: AUTH_TARGET, key = %key.name, "expired API key");
            return None;
        }
        Some((
            Self::client_of(key),
            Some(NamedApiKey {
                name: key.name.clone(),
                personal: key.personal,
            }),
        ))
    }

    /// The caller a validated API key authenticates as: the one construction
    /// the token path and [`Self::client_for_key`] share.
    fn client_of(key: &ResolvedApiKey) -> AuthenticatedClient {
        AuthenticatedClient {
            quota_principal: Some(key.quota_principal.clone()),
            name: key.name.clone(),
            // MIK-6704.IDENT.1a: the validated key's digest, = principal_of(key).
            principal: super::principal_of_digest(&key.digest),
            rate_limit: key.rate_limit,
            backends: key.backends.clone(),
            allowed_tools: key.allowed_tools.clone(),
            denied_tools: key.denied_tools.clone(),
            admin: key.admin,
            authenticated: true,
            credential_kind: crate::security::audit::CredentialKind::ApiKey,
        }
    }

    /// The caller an API key named `name` with principal `principal` (the
    /// first 6 bytes of its digest, hex) authenticates as now, for work done
    /// on its behalf without a request (an event watch's poll). `None` when no
    /// live key matches both, or the key expired: a key re-issued under the
    /// same name has another digest and does not match.
    pub(crate) fn client_for_key(
        &self,
        name: &str,
        principal: &str,
    ) -> Option<AuthenticatedClient> {
        let key = self
            .api_keys
            .iter()
            .find(|k| k.name == name && hex::encode(&k.digest[..6]) == principal)?;
        (!crate::config::api_key_expired(key.expires_at, chrono::Utc::now()))
            .then(|| Self::client_of(key))
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
