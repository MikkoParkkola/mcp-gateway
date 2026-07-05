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
//! 4. Cache the exchanged token in-memory, keyed by the same
//!    `(subject, audience)` cache binding every other strategy uses, so a
//!    second call inside the TTL window costs zero HTTP round-trips.
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
//!   [`PropagatedCredential::cache_binding`], identical in shape to
//!   [`SignedAssertionStrategy`]'s binding.
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
// The cache is keyed by (subject, audience), so a process serving many distinct
// users against many audiences would otherwise grow the map without bound:
// `cached()` treats expired entries as absent but never removes them, so every
// distinct subject leaves a permanently resident entry. On reaching the cap we
// drop expired entries first (cheap `DashMap::retain`, no LRU crate); the ceiling
// is a coarse safety valve, not a precise working-set limit.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// A cached exchanged downstream token, keyed by [`cache_binding`].
struct CachedExchange {
    access_token: String,
    expires_at: i64,
    scopes: Vec<String>,
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
    /// keyed by [`cache_binding`]. IDP.6: entries past `expires_at` are
    /// treated as absent and re-exchanged, never served stale.
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
        let now = SignedAssertionStrategy::now_secs();
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
        if entry.expires_at <= SignedAssertionStrategy::now_secs() {
            return None;
        }
        Some(PropagatedCredential {
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
        let now = SignedAssertionStrategy::now_secs();
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
fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTPS-only token-exchange HTTP client (TLS backend init)")
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
        let binding = cache_binding(&subject_key, &backend.audience);

        if let Some(mut cred) = self.cached(&binding) {
            cred.subject_key = subject_key;
            cred.audience.clone_from(&backend.audience);
            return Ok(cred);
        }

        let (subject_token, _assertion_exp) = self.assertion.mint(identity, &backend.audience)?;
        let body = self.exchange(endpoint, &subject_token, backend).await?;

        let now = SignedAssertionStrategy::now_secs();
        let ttl = body
            .expires_in
            .unwrap_or(DEFAULT_EXCHANGED_TOKEN_TTL_SECS)
            .max(1);
        let expires_at = now + ttl;
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
                scopes: scopes.clone(),
            },
        );

        Ok(PropagatedCredential {
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
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    fn identity(subject: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@corp"),
            name: None,
            groups: vec!["eng".to_string()],
            issuer: "https://idp".to_string(),
        }
    }

    fn backend(endpoint: Option<&str>) -> BackendDescriptor {
        BackendDescriptor {
            id: "mail".to_string(),
            audience: "https://mail.internal".to_string(),
            token_exchange_endpoint: endpoint.map(str::to_string),
            token_exchange_scope: Some("mail.read".to_string()),
        }
    }

    fn strategy() -> TokenExchangeStrategy {
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        TokenExchangeStrategy::new(key, 300)
    }

    // IDP.2 — no endpoint configured must refuse, never fall through to a
    // static credential.
    #[tokio::test]
    async fn missing_endpoint_is_refused() {
        let s = strategy();
        let err = s
            .propagate(&identity("alice"), &backend(None))
            .await
            .expect_err("missing endpoint must refuse");
        assert!(matches!(err, PropagationError::Misconfigured(_)));
    }

    // IDP.3 — empty audience is refused before any network call is attempted.
    #[tokio::test]
    async fn empty_audience_is_refused() {
        let s = strategy();
        let mut bad = backend(Some("https://sts.internal/token"));
        bad.audience = "  ".to_string();
        let err = s
            .propagate(&identity("alice"), &bad)
            .await
            .expect_err("empty audience must refuse");
        assert!(matches!(err, PropagationError::Misconfigured(_)));
    }

    // A request to an unreachable endpoint must refuse (fail-closed), not
    // panic or silently downgrade.
    #[tokio::test]
    async fn unreachable_endpoint_is_refused() {
        let s = strategy();
        // Port 0 host is never reachable / instantly refused by the OS.
        let bad = backend(Some("https://127.0.0.1:0/token"));
        let err = s
            .propagate(&identity("alice"), &bad)
            .await
            .expect_err("unreachable endpoint must refuse");
        assert!(matches!(err, PropagationError::Refuse(_)));
    }

    #[test]
    fn client_assertion_carries_gateway_identity_and_endpoint_audience() {
        let s = strategy();
        let jwt = s
            .mint_client_assertion("https://sts.internal/token")
            .expect("client assertion must mint");
        let payload = jwt.split('.').nth(1).expect("jwt has a payload");
        let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert_eq!(claims["aud"], "https://sts.internal/token");
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
    }

    // S3 (MIK-6729 review): an expired cache entry must not survive a reap,
    // and reaping preserves still-valid entries. `store` runs this reap when the
    // cache reaches MAX_CACHE_ENTRIES, bounding growth from one-shot subjects.
    #[test]
    fn reap_drops_expired_entries_only() {
        let s = strategy();
        let now = SignedAssertionStrategy::now_secs();
        s.cache.insert(
            "live".to_string(),
            CachedExchange {
                access_token: "a".to_string(),
                expires_at: now + 100,
                scopes: vec![],
            },
        );
        s.cache.insert(
            "dead".to_string(),
            CachedExchange {
                access_token: "b".to_string(),
                expires_at: now - 1,
                scopes: vec![],
            },
        );

        s.reap_expired();

        assert!(
            s.cache.contains_key("live"),
            "valid entry must survive reap"
        );
        assert!(
            !s.cache.contains_key("dead"),
            "expired entry must not survive reap"
        );
    }
}
