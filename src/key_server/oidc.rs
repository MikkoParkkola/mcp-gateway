// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! OIDC token verification — JWT signature validation and JWKS caching.
//!
//! # Verification flow
//!
//! 1. Decode the JWT header (no verification) to extract `kid` and `alg`.
//! 2. Find the matching OIDC provider config by `iss` claim.
//! 3. Fetch the provider's JWKS (cached for 1 hour; refreshed on unknown `kid`).
//! 4. Verify the JWT signature and standard claims (`exp`, `iat`, `aud`, `iss`).
//! 5. Apply domain/audience restrictions from the provider config.
//! 6. Return a [`VerifiedIdentity`] with the extracted claims.
//!
//! # Security properties
//!
//! - JWKS fetched only over HTTPS (enforced by the `reqwest` TLS requirement).
//! - Unknown `kid` triggers a single cache refresh before failing; prevents
//!   indefinite re-fetching if the key truly does not exist.
//! - Clock leeway of 60 seconds tolerates minor clock skew between the `IdP` and
//!   the gateway host.
//! - `iat` is checked: tokens issued more than `max_token_age` ago are rejected
//!   to prevent OIDC token replay (default 5 minutes).
//!
//! # PQC Migration Note (issue #116)
//!
//! RS256 / RS384 / RS512 algorithms are accepted here because external OIDC
//! providers (Google, GitHub, Azure AD) issue RSA-signed ID tokens and we cannot
//! control their signing algorithm.  RSA is broken by Shor's algorithm on a CRQC.
//!
//! This module will migrate to ECDSA (ES256/ES384) and EDDSA (Ed25519) when those
//! algorithms are widely supported by `IdP` JWKS endpoints.  ES256 is already
//! supported in this codebase — operators running their own `IdP` (Keycloak, Dex,
//! Authentik) should configure it to issue ES256 tokens as the PQC-transition
//! interim step.  ES256 is not broken by Grover's algorithm at 256-bit key sizes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::{
    Algorithm, DecodingKey, Header, TokenData, Validation,
    jwk::{AlgorithmParameters, JwkSet},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::{KeyServerOidcConfig, KeyServerProviderConfig};
use crate::key_server::TokenAgeCap;

/// Error variants for OIDC verification failures.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// JWT decode / signature verification failed.
    #[error("JWT verification failed: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    /// The token's issuer does not match any configured provider.
    #[error("Unknown issuer: {0}")]
    UnknownIssuer(String),

    /// The JWT header contains no `kid` field.
    #[error("JWT missing 'kid' field in header")]
    MissingKeyId,

    /// The `kid` in the JWT header is not in the provider's JWKS.
    #[error("Unknown key ID: {0}")]
    UnknownKeyId(String),

    /// The token's `email` domain is not in the configured allow-list.
    #[error("Email domain not allowed: {0}")]
    DomainNotAllowed(String),

    /// No policy rule matches this identity.
    #[error("No policy matched for identity: {0}")]
    NoPolicyMatch(String),

    /// Network or HTTP error while fetching JWKS.
    #[error("JWKS fetch error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// The OIDC token is older than `max_token_age` (replay protection).
    #[error("OIDC token too old (issued {iat_ago}s ago, max {max}s)")]
    TokenTooOld {
        /// Seconds since the token was issued.
        iat_ago: u64,
        /// Maximum allowed age in seconds.
        max: u64,
    },

    /// The token's issuer in the `iss` claim did not match the config issuer URL.
    #[error("Issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch {
        /// Expected issuer URL.
        expected: String,
        /// Actual issuer URL found in the token.
        actual: String,
    },

    /// The OIDC discovery document returned a non-HTTPS `jwks_uri`.
    #[error("OIDC discovery returned insecure (non-HTTPS) jwks_uri: {0}")]
    InsecureJwksUri(String),
}

/// Verified identity extracted from a valid OIDC ID token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    /// OIDC `sub` claim (opaque user ID).
    pub subject: String,
    /// Email address from the token claims.
    pub email: String,
    /// Display name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group memberships (from custom claims).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Issuer URL.
    pub issuer: String,
}

impl VerifiedIdentity {
    /// Stable, collision-safe actor identifier derived from `issuer` + `subject`.
    ///
    /// A naive `format!("oidc:{issuer}:{subject}")` collides when an issuer
    /// contains `:` — e.g. issuer `https://idp/a` + subject `b:c` vs issuer
    /// `https://idp/a:b` + subject `c` both render `oidc:https://idp/a:b:c`
    /// (MIK-6702 CP.ID.1). Length-prefixing each component makes the boundary
    /// unambiguous, so distinct (issuer, subject) pairs always map to distinct
    /// ids. Not a role-escalation path (roles come from the verified identity,
    /// not the id), but it prevents audit / user-identity row collisions.
    #[must_use]
    pub fn stable_actor_id(&self) -> String {
        format!(
            "oidc:{}:{}:{}:{}",
            self.issuer.len(),
            self.issuer,
            self.subject.len(),
            self.subject
        )
    }
}

/// The domain of `email` when it has exactly one `@` with a non-empty local
/// part and domain; `None` otherwise. Callers compare the result with
/// `eq_ignore_ascii_case`.
///
/// ponytail: ASCII case folding only; IDN/Unicode domains compare exactly.
/// Add punycode normalisation if a tenant needs it.
pub(crate) fn email_domain(email: &str) -> Option<&str> {
    let (local, domain) = email.split_once('@')?;
    (!local.is_empty() && !domain.is_empty() && !domain.contains('@')).then_some(domain)
}

/// Raw claims extracted from an OIDC ID token.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    /// Issuer
    iss: String,
    /// Subject
    sub: String,
    /// Audience (may be a single string or an array)
    #[serde(default)]
    aud: serde_json::Value,
    /// Expiry (Unix timestamp) — validated by jsonwebtoken internally
    #[allow(dead_code)]
    exp: u64,
    /// Issued-at (Unix timestamp)
    iat: u64,
    /// Email
    #[serde(default)]
    email: Option<String>,
    /// Whether the identity provider verified `email`. JSON `true` or the
    /// string `"true"` (sent by some providers) count as verified; anything
    /// else does not.
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    /// Name
    #[serde(default)]
    name: Option<String>,
    /// Groups (custom claim)
    #[serde(default)]
    groups: Option<Vec<String>>,
}

/// Cached JWKS entry.
struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedJwks {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// Minimal OIDC discovery document (`.well-known/openid-configuration`).
/// Only the fields needed to locate and trust the signing keys are parsed.
#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// Cached `jwks_uri` resolved from an issuer's discovery document.
struct CachedDiscovery {
    jwks_uri: String,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedDiscovery {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// JWKS cache — one entry per OIDC issuer.
pub struct JwksCache {
    inner: DashMap<String, CachedJwks>,
    /// Resolved `jwks_uri` per issuer, from the OIDC discovery document.
    discovery: DashMap<String, CachedDiscovery>,
    http: reqwest::Client,
    /// How long to cache a fetched JWKS (default 1 hour).
    ttl: Duration,
}

impl JwksCache {
    /// Create with default 1-hour TTL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            discovery: DashMap::new(),
            http: reqwest::Client::builder()
                .https_only(true)
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            ttl: Duration::from_secs(3600),
        }
    }

    /// Test-only constructor injecting a custom HTTP client.
    ///
    /// Lets an in-process integration test point the JWKS fetch at a
    /// self-signed-certificate test server (e.g. the gateway's own
    /// `/auth/token` handler under test, MIK-6729) without weakening the
    /// production `https_only(true)` default client built by [`Self::new`].
    /// Compiled out of non-test builds entirely — there is no way to reach
    /// this constructor from production code.
    #[cfg(test)]
    pub(crate) fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            inner: DashMap::new(),
            discovery: DashMap::new(),
            http,
            ttl: Duration::from_secs(3600),
        }
    }

    /// Resolve the `jwks_uri` for `issuer` from its OIDC discovery document
    /// (`discovery_url`, conventionally `{issuer}/.well-known/openid-configuration`).
    ///
    /// The discovered `issuer` field MUST equal the requested issuer (mix-up
    /// defense, `OpenID Connect Discovery` §4.3), and the returned `jwks_uri` must
    /// be HTTPS. Results are cached for the same TTL as JWKS.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] on fetch/parse failure, issuer mismatch, or a
    /// non-HTTPS `jwks_uri`.
    pub async fn resolve_jwks_uri(
        &self,
        issuer: &str,
        discovery_url: &str,
    ) -> Result<String, OidcError> {
        if let Some(cached) = self.discovery.get(issuer)
            && !cached.is_stale()
        {
            return Ok(cached.jwks_uri.clone());
        }

        debug!(issuer = %issuer, "Fetching OIDC discovery from {discovery_url}");
        let doc: OidcDiscoveryDocument = self.http.get(discovery_url).send().await?.json().await?;
        let jwks_uri = validate_discovery_document(issuer, doc)?;

        self.discovery.insert(
            issuer.to_string(),
            CachedDiscovery {
                jwks_uri: jwks_uri.clone(),
                fetched_at: Instant::now(),
                ttl: self.ttl,
            },
        );
        Ok(jwks_uri)
    }

    /// Return the cached JWKS for `issuer`, or fetch from `jwks_uri` if stale.
    ///
    /// If `force_refresh` is `true`, the cache is bypassed regardless of TTL.
    pub async fn get_or_fetch(
        &self,
        issuer: &str,
        jwks_uri: &str,
        force_refresh: bool,
    ) -> Result<JwkSet, OidcError> {
        if !force_refresh
            && let Some(cached) = self.inner.get(issuer)
            && !cached.is_stale()
        {
            return Ok(cached.keys.clone());
        }

        debug!(issuer = %issuer, "Fetching JWKS from {jwks_uri}");
        let jwks: JwkSet = self.http.get(jwks_uri).send().await?.json().await?;

        self.inner.insert(
            issuer.to_string(),
            CachedJwks {
                keys: jwks.clone(),
                fetched_at: Instant::now(),
                ttl: self.ttl,
            },
        );

        Ok(jwks)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// OIDC token verifier — holds provider configs and the JWKS cache.
pub struct OidcVerifier {
    providers: Vec<KeyServerProviderConfig>,
    jwks_cache: Arc<JwksCache>,
}

impl OidcVerifier {
    /// Create from a list of provider configurations.
    #[must_use]
    pub fn new(providers: Vec<KeyServerProviderConfig>) -> Self {
        Self {
            providers,
            jwks_cache: Arc::new(JwksCache::new()),
        }
    }

    /// A verifier for Cloudflare Access assertions: one provider whose issuer
    /// is `https://<team_domain>` and whose keys are the team's certs.
    #[must_use]
    pub fn cloudflare_access(
        config: &crate::security::caller_identity::CloudflareAccessConfig,
    ) -> Self {
        Self::new(vec![cloudflare_access_provider(config)])
    }

    /// Test-only constructor injecting a custom HTTP client into the JWKS
    /// cache. See [`JwksCache::with_http_client`] — same MIK-6729 rationale.
    #[cfg(test)]
    pub(crate) fn with_http_client(
        providers: Vec<KeyServerProviderConfig>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            providers,
            jwks_cache: Arc::new(JwksCache::with_http_client(http)),
        }
    }

    /// Verify an OIDC ID token and return the extracted identity.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] if the token is invalid, expired, from an unknown
    /// issuer, signed with an unknown key, or violates domain restrictions.
    pub async fn verify(
        &self,
        token: &str,
        config: &KeyServerOidcConfig,
    ) -> Result<VerifiedIdentity, OidcError> {
        // Decode header without verification to extract issuer claim for provider lookup
        let header = jsonwebtoken::decode_header(token)?;

        // Decode unverified to extract the issuer claim for provider lookup
        let unverified_claims = extract_unverified_claims(token)?;
        let issuer = &unverified_claims.iss;

        // Find matching provider config
        let provider = self
            .providers
            .iter()
            .find(|p| &p.issuer == issuer)
            .ok_or_else(|| OidcError::UnknownIssuer(issuer.clone()))?;

        // Validate issuer URL
        if !provider.issuer.starts_with("https://") {
            warn!(issuer = %provider.issuer, "OIDC issuer is not HTTPS");
        }

        // Replay protection: check token age against the caller's cap. The
        // `ExpOnly` arm leaves `exp` (checked in `decode` below) as the bound.
        if let TokenAgeCap::MaxIat(max_age_secs) = config.token_age {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            let iat_ago = now_secs.saturating_sub(unverified_claims.iat);
            if iat_ago > max_age_secs {
                return Err(OidcError::TokenTooOld {
                    iat_ago,
                    max: max_age_secs,
                });
            }
        }

        // Get kid from header (clone so `header` stays intact for build_validation)
        let kid = header.kid.clone().ok_or(OidcError::MissingKeyId)?;

        // Fetch JWKS (cached; refresh once on unknown kid)
        let jwks_uri = if let Some(uri) = provider.jwks_uri.clone() {
            uri
        } else if provider.auto_discover {
            let discovery_url = provider
                .discovery_url
                .clone()
                .unwrap_or_else(|| default_discovery_url(&provider.issuer));
            self.jwks_cache
                .resolve_jwks_uri(&provider.issuer, &discovery_url)
                .await?
        } else {
            default_jwks_uri(&provider.issuer)
        };

        let decoding_key = self
            .find_decoding_key(&kid, &provider.issuer, &jwks_uri)
            .await?;

        // Build validation config
        let mut validation = build_validation(&header);

        // Disable standard audience validation — we handle it manually below
        // to support both single-string and array forms, and to give a clear error.
        validation.validate_aud = false;

        // Verify signature + exp/iat claims
        let token_data: TokenData<IdTokenClaims> =
            jsonwebtoken::decode(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        // Manual audience check. For an enabled key server, `audiences` is
        // guaranteed non-empty by `KeyServerConfig::validate` (MIK-6784, GW.4),
        // so this branch always runs in production; the emptiness guard remains
        // only for directly-constructed providers in unit tests.
        if !provider.audiences.is_empty() {
            check_audience(&claims.aud, &provider.audiences)?;
        }

        // An unverified address is dropped here, once, so every consumer of
        // `VerifiedIdentity.email` (allowed_domains, policy, role mapping,
        // grant label, propagated assertion) sees a verified address or "".
        let email_verified = matches!(&claims.email_verified, Some(serde_json::Value::Bool(true)))
            || matches!(&claims.email_verified, Some(serde_json::Value::String(v)) if v == "true");
        let email = match claims.email {
            Some(email) if email_verified => email,
            Some(_) => {
                debug!(
                    reason = "email_unverified",
                    "Dropping unverified OIDC email"
                );
                String::new()
            }
            None => String::new(),
        };

        // Domain allowlist check
        if !provider.allowed_domains.is_empty() {
            let domain = email_domain(&email);
            if !domain.is_some_and(|domain| {
                provider
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(domain))
            }) {
                return Err(OidcError::DomainNotAllowed(
                    domain.unwrap_or_default().to_string(),
                ));
            }
        }

        Ok(VerifiedIdentity {
            subject: claims.sub,
            email,
            name: claims.name,
            groups: claims.groups.unwrap_or_default(),
            issuer: claims.iss,
        })
    }

    /// Find a decoding key by `kid`, refreshing the JWKS cache if not found.
    async fn find_decoding_key(
        &self,
        kid: &str,
        issuer: &str,
        jwks_uri: &str,
    ) -> Result<DecodingKey, OidcError> {
        // Try cached JWKS first
        let jwks = self
            .jwks_cache
            .get_or_fetch(issuer, jwks_uri, false)
            .await?;
        if let Some(key) = find_key_in_jwks(&jwks, kid) {
            return Ok(key);
        }

        // Unknown kid: refresh once and retry
        debug!(kid = %kid, "Key not found in cached JWKS, refreshing");
        let jwks = self.jwks_cache.get_or_fetch(issuer, jwks_uri, true).await?;
        find_key_in_jwks(&jwks, kid).ok_or_else(|| OidcError::UnknownKeyId(kid.to_string()))
    }
}

/// Extract claims from a JWT without signature verification.
///
/// Used only to read `iss` and `iat` before we know which provider to use.
fn extract_unverified_claims(token: &str) -> Result<IdTokenClaims, OidcError> {
    // Split the JWT into parts; base64-decode the payload
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(OidcError::JwtError(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        )));
    }

    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .map_err(|_| {
                OidcError::JwtError(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ))
            })?;

    serde_json::from_slice::<IdTokenClaims>(&payload).map_err(|_| {
        OidcError::JwtError(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ))
    })
}

/// Find a JWK by `kid` in a `JwkSet` and convert it to a `DecodingKey`.
fn find_key_in_jwks(jwks: &JwkSet, kid: &str) -> Option<DecodingKey> {
    for jwk in &jwks.keys {
        let jwk_kid = jwk.common.key_id.as_deref().unwrap_or("");
        if jwk_kid != kid {
            continue;
        }

        return match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e).ok(),
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y).ok()
            }
            // jsonwebtoken marks this enum non-exhaustive. Unknown future key
            // types, along with known unsupported key families, must remain
            // fail-closed until support is implemented.
            _ => None,
        };
    }
    None
}

/// The single provider an Access assertion is verified against. The certs
/// path and issuer shape are Cloudflare's published ones; `team_domain` is a
/// bare host by config validation.
pub(crate) fn cloudflare_access_provider(
    config: &crate::security::caller_identity::CloudflareAccessConfig,
) -> KeyServerProviderConfig {
    let issuer = format!("https://{}", config.team_domain);
    KeyServerProviderConfig {
        jwks_uri: Some(format!("{issuer}/cdn-cgi/access/certs")),
        issuer,
        discovery_url: None,
        auto_discover: false,
        audiences: config.audiences.clone(),
        allowed_domains: Vec::new(),
    }
}

/// Build a [`Validation`] from the JWT header algorithm.
fn build_validation(header: &Header) -> Validation {
    let alg = match header.alg {
        Algorithm::RS256 => Algorithm::RS256,
        Algorithm::RS384 => Algorithm::RS384,
        Algorithm::RS512 => Algorithm::RS512,
        Algorithm::ES256 => Algorithm::ES256,
        Algorithm::ES384 => Algorithm::ES384,
        other => {
            warn!(alg = ?other, "Unsupported JWT algorithm, defaulting to RS256");
            Algorithm::RS256
        }
    };

    let mut v = Validation::new(alg);
    v.leeway = 60; // 60-second clock skew tolerance
    v
}

/// Validate that the token's `aud` claim contains one of the expected audiences.
fn check_audience(aud_claim: &serde_json::Value, expected: &[String]) -> Result<(), OidcError> {
    let matches = match aud_claim {
        serde_json::Value::String(s) => expected.iter().any(|e| e == s),
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| expected.iter().any(|e| e == s))),
        _ => false,
    };

    if matches {
        Ok(())
    } else {
        Err(OidcError::JwtError(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidAudience,
        )))
    }
}

/// Derive the default JWKS URI from the issuer URL using OIDC discovery conventions.
fn default_jwks_uri(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    format!("{base}/.well-known/jwks.json")
}

/// Derive the default OIDC discovery document URL from the issuer.
/// Per `OpenID Connect Discovery` §4, this is `{issuer}/.well-known/openid-configuration`.
fn default_discovery_url(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    format!("{base}/.well-known/openid-configuration")
}

/// Validate a fetched OIDC discovery document and extract a trusted `jwks_uri`.
///
/// Enforces the `OpenID Connect Discovery` §4.3 mix-up defense (the document's
/// `issuer` must equal the requested issuer) and rejects a non-HTTPS `jwks_uri`.
fn validate_discovery_document(
    requested_issuer: &str,
    doc: OidcDiscoveryDocument,
) -> Result<String, OidcError> {
    if doc.issuer != requested_issuer {
        return Err(OidcError::IssuerMismatch {
            expected: requested_issuer.to_string(),
            actual: doc.issuer,
        });
    }
    if !doc.jwks_uri.starts_with("https://") {
        return Err(OidcError::InsecureJwksUri(doc.jwks_uri));
    }
    Ok(doc.jwks_uri)
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
