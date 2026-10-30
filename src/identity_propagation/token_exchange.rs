// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! RFC 8693 OAuth 2.0 Token Exchange identity-propagation strategy (MIK-6729).
//!
//! # Flow
//!
//! 1. Mint a short-lived gateway-signed identity assertion for the end user —
//!    reusing [`SignedAssertionStrategy::mint`] verbatim, so the crypto that
//!    proves "this call really is user U" lives in exactly one place.
//! 2. POST that assertion as the RFC 8693 `subject_token` to the backend's
//!    configured token-exchange endpoint, authenticating the gateway itself
//!    to the endpoint via RFC 7523 `private_key_jwt` (a `client_assertion`
//!    signed with the SAME gateway key — no shared `client_secret` ever
//!    leaves the gateway process).
//! 3. Parse the endpoint's `access_token` + `expires_in` and inject the
//!    downstream token as the outbound `Authorization` header.
//! 4. Cache the exchanged token in-memory, keyed by `(subject, audience,
//!    token_exchange_endpoint, scope)` — a superset of the
//!    `(subject, audience)` binding every other strategy uses — so a second
//!    call inside the TTL window costs zero HTTP round-trips, and two
//!    backends that happen to share an `audience` but differ in endpoint or
//!    scope can never collide on the same cache entry (MIK-6729 review M1).
//!
//! Nothing durable is written: the cache is an in-process `DashMap` that
//! disappears with the process, matching the "stores nothing durably"
//! constraint shared with [`SignedAssertionStrategy`].
//!
//! # Safety invariants (ADR-007, see [`super`] module docs)
//!
//! - IDP.2 fail-closed: any failure to mint, exchange, or parse a downstream
//!   token returns [`PropagationError::Refuse`] — never a silent fallback to
//!   a static/shared credential.
//! - IDP.3 tenant-isolation: the cache is keyed on
//!   [`PropagatedCredential::cache_binding`], widened (relative to
//!   [`SignedAssertionStrategy`]'s `(subject, audience)`-only binding) to also
//!   fold in `token_exchange_endpoint` and `scope` — the exchanged token IS
//!   endpoint- and scope-specific, unlike a `SignedAssertionStrategy`
//!   assertion, which is audience-scoped regardless of which endpoint would
//!   consume it (MIK-6729 review M1).
//! - IDP.6 credential hygiene: the cached token is discarded once
//!   `expires_in` elapses; the `client_assertion` used to authenticate to
//!   the STS is itself short-lived (60s) and single-use in spirit (a fresh
//!   `jti` per exchange).

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::{
    BackendDescriptor, IdentityPropagation, PropagatedCredential, PropagationError,
    SignedAssertionStrategy, cache_binding, sign_es256_jwt,
};
use crate::gateway::oauth::GatewayKeyPair;
use crate::key_server::oidc::VerifiedIdentity;

/// RFC 8693 §2.1 grant type identifier.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 §3 token-type identifier for a JWT `subject_token` (the gateway's
/// signed assertion minted by [`SignedAssertionStrategy::mint`] is a JWT).
const SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
/// RFC 7523 §2.2 client-assertion type identifier for `private_key_jwt`.
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The gateway's own OAuth client identifier when authenticating to a
/// token-exchange endpoint (RFC 7523 `iss`/`sub`). Fixed rather than
/// configurable: it identifies the *gateway process*, not a per-backend or
/// per-user value, and matches [`SignedAssertionStrategy::ISSUER`] so a
/// backend operator sees one consistent gateway identity across both the
/// minted assertion and the client-assertion authentication.
const CLIENT_ID: &str = "mcp-gateway";
/// Lifetime of the RFC 7523 client assertion (seconds). Short because it
/// authenticates a single token-exchange call, not a session.
const CLIENT_ASSERTION_TTL_SECS: i64 = 60;
/// Fallback TTL (seconds) applied when a token-exchange endpoint omits
/// `expires_in` from its response. RFC 8693 marks `expires_in` `RECOMMENDED`,
/// not required; a short, conservative default keeps a cache entry from
/// living indefinitely if an endpoint leaves it out.
const DEFAULT_EXCHANGED_TOKEN_TTL_SECS: i64 = 300;
// ponytail: MAX_CACHE_ENTRIES caps resident exchanged-token entries at 10_000.
// The cache is keyed by (subject, audience, endpoint, scope) (MIK-6729 review
// M1), so a process serving many distinct users against many audiences/
// endpoints/scopes would otherwise grow the map without bound:
// `cached()` treats expired entries as absent but never removes them, so every
// distinct subject leaves a permanently resident entry. On reaching the cap we
// drop expired entries first (cheap `DashMap::retain`, no LRU crate); the ceiling
// is a coarse safety valve, not a precise working-set limit.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// A cached exchanged downstream token, keyed by [`exchange_cache_key`].
struct CachedExchange {
    access_token: String,
    expires_at: i64,
    /// `expires_at` is the default TTL, not an `expires_in` the issuer sent.
    synthetic_expiry: bool,
    scopes: Vec<String>,
}

/// Cache key for an exchanged downstream token (MIK-6729 review M1).
///
/// Widens the shared [`cache_binding`] (`subject`, `audience`) with
/// `token_exchange_endpoint` and `scope`: two backends that share an
/// `audience` but differ in endpoint or scope must never collide on the same
/// cached token, because — unlike [`SignedAssertionStrategy`]'s
/// audience-scoped assertion, which is equally valid to present at any
/// endpoint — the exchanged token here IS the specific endpoint's response
/// for that specific scope request. Serving backend B a token minted for
/// backend A's (different) endpoint/scope would be a credential-confusion
/// bug: over- or under-privileged access depending on which side is wider.
///
/// Built by appending length-prefixed segments on top of [`cache_binding`]'s
/// own length-prefixed `(subject, audience)` encoding, so the composite
/// string stays collision-safe even if `endpoint` or `scope` embeds the `:`
/// separator.
#[must_use]
pub(super) fn exchange_cache_key(
    subject_key: &str,
    audience: &str,
    endpoint: &str,
    scope: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        cache_binding(subject_key, audience),
        endpoint.len(),
        endpoint,
        scope.len(),
        scope,
    )
}

/// RFC 7523 `private_key_jwt` client-assertion claims. This authenticates the
/// **gateway** to the token-exchange endpoint as an OAuth client; it is a
/// distinct assertion from the RFC 8693 `subject_token` (which asserts the
/// **end user's** identity, minted separately via
/// [`SignedAssertionStrategy::mint`]).
#[derive(Debug, Serialize)]
struct ClientAssertionClaims {
    /// Issuer — the gateway's own client id (RFC 7523 requires `iss` == `sub`
    /// for `private_key_jwt`).
    iss: String,
    /// Subject — same as `iss` per RFC 7523 §2.2.
    sub: String,
    /// Audience — the token-exchange endpoint URL.
    aud: String,
    /// Issued-at (unix seconds).
    iat: i64,
    /// Expiry (unix seconds).
    exp: i64,
    /// Unique assertion id (replay defense).
    jti: String,
}

/// The fields this strategy needs from an RFC 8693 token-exchange response.
/// Other spec-defined fields (`issued_token_type`, ...) are ignored.
#[derive(Deserialize)]
struct TokenExchangeResponseBody {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
}

// Manual `Debug` redacts the exchanged downstream bearer (CWE-532, mirrors the
// key-server `TokenExchangeResponse` redaction) so a future debug or error log
// of this body can never leak `access_token`.
impl std::fmt::Debug for TokenExchangeResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeResponseBody")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// RFC 8693 OAuth 2.0 Token Exchange strategy (MIK-6729).
///
/// Presents a gateway-signed identity assertion (minted the same way as
/// [`SignedAssertionStrategy`]) as the `subject_token` at a backend-configured
/// token-exchange endpoint, authenticating itself via RFC 7523
/// `private_key_jwt`, and injects the returned scoped downstream token.
pub struct TokenExchangeStrategy {
    /// The gateway's own signing key — used both for the subject-token
    /// assertion (via `assertion`) and for the RFC 7523 client assertion.
    key: Arc<GatewayKeyPair>,
    /// Reused verbatim to mint the RFC 8693 `subject_token` — the assertion
    /// minting code (ES256 signing, claims shape, TTL clamp) lives in exactly
    /// one place.
    assertion: SignedAssertionStrategy,
    http: reqwest::Client,
    /// In-memory only (never persisted) cache of exchanged downstream tokens,
    /// keyed by [`exchange_cache_key`] (subject, audience, endpoint, scope —
    /// MIK-6729 review M1). IDP.6: entries past `expires_at` are treated as
    /// absent and re-exchanged, never served stale.
    cache: DashMap<String, CachedExchange>,
}

impl TokenExchangeStrategy {
    /// Create a strategy signing subject-token assertions and client
    /// assertions with the gateway key pair. `assertion_ttl_secs` bounds the
    /// `subject_token` lifetime (clamped by
    /// [`SignedAssertionStrategy::new`], `>=1s`, `<=1h`).
    #[must_use]
    pub fn new(key: Arc<GatewayKeyPair>, assertion_ttl_secs: i64) -> Self {
        Self::with_http_client(key, assertion_ttl_secs, default_http_client())
    }

    /// Same as [`Self::new`] but with an injectable HTTP client — the seam an
    /// in-process integration test uses to point the token-exchange POST at a
    /// self-signed-certificate test server (MIK-6729, mirrors
    /// [`crate::key_server::oidc::JwksCache::with_http_client`]). Kept
    /// `pub(crate)` (not `#[cfg(test)]`) rather than test-gated because a
    /// non-test caller may reasonably want a custom timeout/proxy client;
    /// nothing about it weakens production behavior since the default
    /// constructor still hands it an `https_only` client.
    #[must_use]
    pub(crate) fn with_http_client(
        key: Arc<GatewayKeyPair>,
        assertion_ttl_secs: i64,
        http: reqwest::Client,
    ) -> Self {
        Self {
            assertion: SignedAssertionStrategy::new(Arc::clone(&key), assertion_ttl_secs),
            key,
            http,
            cache: DashMap::new(),
        }
    }

    /// Mint the RFC 7523 `private_key_jwt` client assertion authenticating
    /// the gateway itself to `endpoint`.
    fn mint_client_assertion(&self, endpoint: &str) -> Result<String, PropagationError> {
        let now = SignedAssertionStrategy::now_secs()?;
        let claims = ClientAssertionClaims {
            iss: CLIENT_ID.to_string(),
            sub: CLIENT_ID.to_string(),
            aud: endpoint.to_string(),
            iat: now,
            exp: now + CLIENT_ASSERTION_TTL_SECS,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        sign_es256_jwt(&self.key, &claims)
    }

    /// Return a still-valid cached exchange for `binding`, if any.
    fn cached(&self, binding: &str) -> Option<PropagatedCredential> {
        let entry = self.cache.get(binding)?;
        // An unreadable clock serves nothing from the cache (MIK-8202).
        if !SignedAssertionStrategy::now_secs().is_ok_and(|now| now < entry.expires_at) {
            return None;
        }
        Some(PropagatedCredential {
            expiry_synthetic: entry.synthetic_expiry,
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {}", entry.access_token),
            )],
            expires_at: entry.expires_at,
            subject_key: String::new(), // overwritten by caller
            audience: String::new(),    // overwritten by caller
            scopes: entry.scopes.clone(),
            cache_binding: binding.to_string(),
        })
    }

    /// Drop every cache entry whose token has already expired. Called by
    /// [`Self::store`] when the map reaches [`MAX_CACHE_ENTRIES`], so an
    /// endless stream of one-shot subjects cannot grow the cache without bound.
    fn reap_expired(&self) {
        // Retention: on an unreadable clock this pass is skipped, never
        // turned into deleting everything (MIK-8202).
        let Ok(now) = SignedAssertionStrategy::now_secs() else {
            return;
        };
        self.cache.retain(|_, e| e.expires_at > now);
    }

    /// Insert an exchanged token, reaping expired entries first if the cache
    /// has reached its bound. Keeps the cache from growing without limit while
    /// preserving still-valid entries (IDP.6, MIK-6729 review S3).
    fn store(&self, binding: String, entry: CachedExchange) {
        if self.cache.len() >= MAX_CACHE_ENTRIES {
            self.reap_expired();
        }
        self.cache.insert(binding, entry);
    }

    /// Perform the RFC 8693 token-exchange HTTP round-trip and parse the
    /// response. Isolated from [`Self::propagate`] to keep that method under
    /// the function-length budget and to give the request-building /
    /// response-parsing logic its own testable seam.
    async fn exchange(
        &self,
        endpoint: &str,
        subject_token: &str,
        backend: &BackendDescriptor,
    ) -> Result<TokenExchangeResponseBody, PropagationError> {
        let client_assertion = self.mint_client_assertion(endpoint)?;
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", GRANT_TYPE.to_string()),
            ("subject_token", subject_token.to_string()),
            ("subject_token_type", SUBJECT_TOKEN_TYPE.to_string()),
            ("resource", backend.audience.clone()),
            ("audience", backend.audience.clone()),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()),
            ("client_assertion", client_assertion),
        ];
        if let Some(scope) = backend
            .token_exchange_scope
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            form.push(("scope", scope.to_string()));
        }

        let resp = self
            .http
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| PropagationError::Refuse(format!("token-exchange request failed: {e}")))?;

        if resp.status().is_redirection() {
            return Err(PropagationError::Refuse(format!(
                "token-exchange endpoint returned HTTP {}, a redirect, which is not followed",
                resp.status()
            )));
        }

        if !resp.status().is_success() {
            return Err(PropagationError::Refuse(format!(
                "token-exchange endpoint returned HTTP {}",
                resp.status()
            )));
        }

        let body: TokenExchangeResponseBody = resp.json().await.map_err(|e| {
            PropagationError::Refuse(format!("token-exchange response unparsable: {e}"))
        })?;
        if body.access_token.trim().is_empty() {
            return Err(PropagationError::Refuse(
                "token-exchange response missing access_token".to_string(),
            ));
        }
        Ok(body)
    }
}

/// The production HTTP client: HTTPS-only, matching every other outbound
/// identity-provider client in this codebase
/// (e.g. [`crate::key_server::oidc::JwksCache::new`]).
///
/// Fails closed: a builder failure (only reachable if the TLS backend cannot
/// initialize, a catastrophic startup-only condition) panics rather than
/// falling back to a default client, because a default client carries neither
/// `https_only` nor a timeout. Silently returning that degraded client would
/// let the token-exchange POST run over plaintext http with no timeout, the
/// exact security-relevant downgrade this strategy exists to prevent. Panicking
/// at construction is a hard fail-closed at startup and matches the last-resort
/// `expect` on gateway key generation in `gateway::server`.
///
/// It follows no redirect: see [`token_exchange_redirect_policy`].
fn default_http_client() -> reqwest::Client {
    crate::debug_trust_roots::extra_roots(reqwest::Client::builder())
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .redirect(token_exchange_redirect_policy())
        .build()
        .expect("failed to build HTTPS-only token-exchange HTTP client (TLS backend init)")
}

/// A token endpoint has no reason to redirect, and following a 307/308 would
/// re-POST the form, `subject_token` included, to the redirect target.
fn token_exchange_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::none()
}

#[async_trait::async_trait]
impl IdentityPropagation for TokenExchangeStrategy {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        if backend.audience.trim().is_empty() {
            return Err(PropagationError::Misconfigured(
                "backend audience is empty (IDP.3)".to_string(),
            ));
        }
        let endpoint = backend
            .token_exchange_endpoint
            .as_deref()
            .filter(|e| !e.trim().is_empty())
            .ok_or_else(|| {
                PropagationError::Misconfigured(
                    "backend has no token_exchange_endpoint configured (MIK-6729)".to_string(),
                )
            })?;

        let subject_key = identity.stable_actor_id();
        let scope = backend.token_exchange_scope.as_deref().unwrap_or("");
        let binding = exchange_cache_key(&subject_key, &backend.audience, endpoint, scope);

        if let Some(mut cred) = self.cached(&binding) {
            cred.subject_key = subject_key;
            cred.audience.clone_from(&backend.audience);
            return Ok(cred);
        }

        let (subject_token, _assertion_exp) = self.assertion.mint(identity, &backend.audience)?;
        let body = self.exchange(endpoint, &subject_token, backend).await?;

        let now = SignedAssertionStrategy::now_secs()?;
        let synthetic_expiry = body.expires_in.is_none();
        let ttl = body
            .expires_in
            .unwrap_or(DEFAULT_EXCHANGED_TOKEN_TTL_SECS)
            .max(1);
        // A hostile or broken STS answering `expires_in` near `i64::MAX` must
        // not overflow (MIK-6729 review L2), nor be trusted for centuries: an
        // answer above the 100-year bound is malformed and refused (MIK-8207).
        let expires_at = u64::try_from(now)
            .ok()
            .and_then(|now| crate::duration_bound::expiry_from_expires_in(now, ttl.unsigned_abs()))
            .and_then(|at| i64::try_from(at).ok())
            .ok_or_else(|| {
                PropagationError::Refuse(format!(
                    "token-exchange endpoint {} answered expires_in {ttl}, \
                     more than 100 years; the answer is refused as malformed",
                    crate::security::sanitize::redact_url_for_diagnostics(endpoint)
                ))
            })?;
        let scopes: Vec<String> = body
            .scope
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();

        self.store(
            binding.clone(),
            CachedExchange {
                access_token: body.access_token.clone(),
                expires_at,
                synthetic_expiry,
                scopes: scopes.clone(),
            },
        );

        Ok(PropagatedCredential {
            expiry_synthetic: synthetic_expiry,
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {}", body.access_token),
            )],
            expires_at,
            cache_binding: binding,
            subject_key,
            audience: backend.audience.clone(),
            scopes,
        })
    }
}

#[cfg(test)]
#[path = "token_exchange_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "token_exchange_refusal_tests.rs"]
mod refusal_tests;

#[cfg(test)]
#[path = "token_exchange_expiry_tests.rs"]
mod expiry_tests;
