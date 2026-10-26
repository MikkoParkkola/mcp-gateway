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
    AUTH_TARGET, AuthenticatedClient, NamedApiKey, PreviousDigest, QuotaPrincipal, ResolvedApiKey,
    ResolvedAuthConfig, principal_of,
};
use crate::Result;
use crate::config::{AuthConfig, CircuitBreakerConfig};
use crate::failsafe::{CircuitBreaker, CircuitState};
use crate::gateway::record_principal::RecordPrincipalKey;

impl ResolvedAuthConfig {
    /// Create resolved config from `AuthConfig`, keyed by the resolved record
    /// key text (MIK-8697: `security.record_principal_key` or its fallback file).
    ///
    /// # Errors
    ///
    /// Returns an error if any `env:VAR_NAME` secret reference cannot be
    /// resolved in `overlay` (the env files the config was loaded with, then
    /// the process environment), or if `record_key` is shorter than 32 bytes.
    pub fn try_from_config(
        config: &AuthConfig,
        overlay: &crate::config::EnvOverlay,
        record_key: &str,
    ) -> Result<Self> {
        let key = RecordPrincipalKey::from_text(record_key)?;
        Self::try_from_config_keyed(config, overlay, Arc::new(key))
    }

    /// [`Self::try_from_config`] with the process's one resolved key, shared
    /// with every other record writer. Takes the key given; never picks one.
    pub(crate) fn try_from_config_keyed(
        config: &AuthConfig,
        overlay: &crate::config::EnvOverlay,
        record_key: Arc<RecordPrincipalKey>,
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
            // Its record principal, as the audit records name it (MIK-8697):
            // operators correlate the token without a stored-principal digest.
            tracing::info!(target: AUTH_TARGET,
                "Auto-generated bearer token (record principal {})",
                principal_of(token)
                    .record_form(&record_key)
                    .as_str()
            );
        }

        config.warn_keys_without_backends();
        match crate::clock::utc_now() {
            Ok(now) => config.warn_expired_keys(now),
            // Advisory only: a clock that cannot date a key lists none.
            // Admission itself is an access check and already fails closed.
            Err(error) => {
                warn!(target: AUTH_TARGET, %error, "host clock reads before 1970: expired API keys are not listed");
            }
        }
        let api_keys: Vec<ResolvedApiKey> = config
            .api_keys
            .iter()
            .map(|k| {
                let digest = k.resolve_digest(overlay)?;
                // A previous digest without its expiry is refused at load; never
                // carried, so it can never match by omission.
                let previous = match (k.resolve_previous_digest(overlay)?, k.previous_expires_at) {
                    (Some(digest), Some(expires_at)) => Some(PreviousDigest { digest, expires_at }),
                    _ => None,
                };
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
                    principal: k.principal_for(&digest),
                    previous,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // MIK-7973: the one place every bearer form, `auto` included, is known.
        super::refuse_shared_principals(
            bearer_token.as_deref(),
            api_keys.iter().map(|k| (k.name.as_str(), &k.digest)),
        )?;

        Ok(Self {
            enabled: config.enabled,
            bearer_token,
            bearer_quota_principal,
            api_keys,
            public_paths: config.enforced_public_paths(),
            rate_limiters: DashMap::new(),
            client_circuit_breaker: config.client_circuit_breaker.clone(),
            client_circuit_breakers: DashMap::new(),
            record_key,
        })
    }

    /// Create resolved config from `AuthConfig`.
    ///
    /// Panics if a configured environment-backed secret is missing, or if
    /// `record_key` is shorter than 32 bytes. Runtime startup paths should
    /// prefer [`Self::try_from_config`] so the error is returned.
    #[must_use]
    pub fn from_config(config: &AuthConfig, record_key: &str) -> Self {
        Self::try_from_config(config, &crate::config::EnvOverlay::none(), record_key)
            .expect("auth config secret references should resolve")
    }

    /// The record key clients minted here are keyed with (MIK-8697 §16.11).
    pub(crate) fn record_key(&self) -> &RecordPrincipalKey {
        &self.record_key
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
                && crate::config::api_key_expired_now(k.expires_at)
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
        self.validate_token_judged(token, crate::config::api_key_expired_now)
    }

    /// [`Self::validate_token`] judged at `now`, the caller's reading of the
    /// clock; reads no clock (MIK-8202).
    #[must_use]
    pub(crate) fn validate_token_at(
        &self,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<AuthenticatedClient> {
        self.validate_token_judged(token, |at| crate::config::api_key_expired(at, now))
            .map(|(client, _origin)| client)
    }

    /// The one matcher behind both clocks. `expired` judges an optional expiry
    /// instant; the wall-clock caller passes `api_key_expired_now`, which
    /// fails closed when the clock cannot be read.
    fn validate_token_judged(
        &self,
        token: &str,
        expired: impl Fn(Option<chrono::DateTime<chrono::Utc>>) -> bool,
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
        if expired(key.expires_at) {
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
        (!crate::config::api_key_expired_now(key.expires_at)).then(|| Self::client_of(key))
    }

    /// [`Self::client_for_key`] judged at `now`, the caller's reading of the
    /// clock; reads no clock (MIK-8202).
    pub(crate) fn client_for_key_at(
        &self,
        name: &str,
        principal: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<AuthenticatedClient> {
        let key = self
            .api_keys
            .iter()
            .find(|k| k.name == name && hex::encode(&k.digest[..6]) == principal)?;
        (!crate::config::api_key_expired(key.expires_at, now)).then(|| Self::client_of(key))
    }

    /// Check rate limiting for a fully resolved authenticated client.
    ///
    /// The bucket is created on first use from the client's own `rate_limit`
    /// and keyed by [`client_state_key`], so it belongs to the credential
    /// (MIK-8489): two keys sharing a display name keep separate limits, and
    /// two key-server tokens of one OIDC identity share one.
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
            .entry(client_state_key(client))
            .or_insert_with(|| Arc::new(RateLimiter::direct(Quota::per_minute(quota))))
            .clone();
        limiter.check().is_ok()
    }

    /// Check whether this authenticated client's dispatch circuit allows a request.
    #[must_use]
    pub fn check_client_circuit_breaker(&self, client: &AuthenticatedClient) -> bool {
        let Some(config) = self.client_circuit_breaker.as_ref() else {
            return true;
        };
        // The section's presence is the switch (MIK-8783).
        self.client_circuit_breaker_for(client, config)
            .can_proceed()
    }

    /// Record a successful dispatch for this authenticated client.
    pub fn record_client_success(&self, client: &AuthenticatedClient) {
        if let Some(breaker) = self.active_client_circuit_breaker(client) {
            breaker.record_success();
        }
    }

    /// Record a failed dispatch for this authenticated client.
    pub fn record_client_failure(&self, client: &AuthenticatedClient) {
        if let Some(breaker) = self.active_client_circuit_breaker(client) {
            breaker.record_failure("client_dispatch_failure", std::time::Duration::ZERO);
        }
    }

    /// Return the current circuit state for tests and observability adapters.
    #[must_use]
    pub fn client_circuit_state(&self, client: &AuthenticatedClient) -> Option<CircuitState> {
        self.client_circuit_breakers
            .get(&client_state_key(client))
            .map(|breaker| breaker.state())
    }

    fn active_client_circuit_breaker(
        &self,
        client: &AuthenticatedClient,
    ) -> Option<Arc<CircuitBreaker>> {
        let config = self.client_circuit_breaker.as_ref()?;
        Some(self.client_circuit_breaker_for(client, config))
    }

    fn client_circuit_breaker_for(
        &self,
        client: &AuthenticatedClient,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        self.client_circuit_breakers
            .entry(client_state_key(client))
            .or_insert_with(|| {
                // The label is for logs only; the map key is the credential.
                Arc::new(CircuitBreaker::new(
                    &format!("client:{}", client.name),
                    config,
                ))
            })
            .clone()
    }
}

/// The key of a client's rate-limit bucket and circuit breaker (MIK-8489).
///
/// The credential's quota principal (an API key's digest, the bearer, an OIDC
/// issuer and subject, the dashboard session, an OAuth `client_id`), never the
/// display name: a name is operator-chosen and may repeat, or equal the name
/// another identity kind uses (`bearer`, an OIDC actor id). Identities that
/// carry no quota principal (anonymous, public, stdio) key on a tagged label,
/// which cannot equal a quota key: those are 64 hex digits, never `:`.
fn client_state_key(client: &AuthenticatedClient) -> String {
    client.quota_principal.as_ref().map_or_else(
        || format!("label:{}", client.name),
        |quota| quota.as_store_key().to_owned(),
    )
}

#[cfg(test)]
thread_local! {
    /// Test-only stand-in for the dummy digest a key with no previous secret
    /// is compared against, so a test can aim it at a known token.
    static DUMMY_DIGEST_OVERRIDE: std::cell::Cell<Option<[u8; 32]>> =
        const { std::cell::Cell::new(None) };
}

/// Runs `f` with the dummy digest set to `digest` on this thread, then
/// restores it, so a test can prove the dummy is masked rather than merely
/// improbable.
#[cfg(test)]
pub(super) fn with_dummy_digest<R>(digest: [u8; 32], f: impl FnOnce() -> R) -> R {
    struct Restore(Option<[u8; 32]>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DUMMY_DIGEST_OVERRIDE.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(DUMMY_DIGEST_OVERRIDE.with(|cell| cell.replace(Some(digest))));
    f()
}
