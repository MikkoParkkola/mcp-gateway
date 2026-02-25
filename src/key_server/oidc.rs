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
//! - Clock leeway of 60 seconds tolerates minor clock skew between the IdP and
//!   the gateway host.
//! - `iat` is checked: tokens issued more than `max_token_age` ago are rejected
//!   to prevent OIDC token replay (default 5 minutes).

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

/// JWKS cache — one entry per OIDC issuer.
pub struct JwksCache {
    inner: DashMap<String, CachedJwks>,
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
            http: reqwest::Client::builder()
                .https_only(true)
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            ttl: Duration::from_secs(3600),
        }
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
        if !force_refresh {
            if let Some(cached) = self.inner.get(issuer) {
                if !cached.is_stale() {
                    return Ok(cached.keys.clone());
                }
            }
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

    /// Verify an OIDC ID token and return the extracted identity.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] if the token is invalid, expired, from an unknown
    /// issuer, signed with an unknown key, or violates domain restrictions.
    pub async fn verify(&self, token: &str, config: &KeyServerOidcConfig) -> Result<VerifiedIdentity, OidcError> {
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

        // Replay protection: check token age against max_token_age
        let max_age_secs = config.max_token_age_secs;
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

        // Get kid from header (clone so `header` stays intact for build_validation)
        let kid = header.kid.clone().ok_or(OidcError::MissingKeyId)?;

        // Fetch JWKS (cached; refresh once on unknown kid)
        let jwks_uri = provider
            .jwks_uri
            .clone()
            .unwrap_or_else(|| default_jwks_uri(&provider.issuer));

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

        // Manual audience check
        if !provider.audiences.is_empty() {
            check_audience(&claims.aud, &provider.audiences)?;
        }

        // Domain allowlist check
        if !provider.allowed_domains.is_empty() {
            let email = claims.email.as_deref().unwrap_or("");
            let domain = email.split('@').next_back().unwrap_or("");
            if !provider.allowed_domains.iter().any(|d| d == domain) {
                return Err(OidcError::DomainNotAllowed(domain.to_string()));
            }
        }

        Ok(VerifiedIdentity {
            subject: claims.sub,
            email: claims.email.unwrap_or_default(),
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
        let jwks = self.jwks_cache.get_or_fetch(issuer, jwks_uri, false).await?;
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
        return Err(OidcError::JwtError(
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken),
        ));
    }

    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
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
            AlgorithmParameters::RSA(rsa) => {
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).ok()
            }
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y).ok()
            }
            AlgorithmParameters::OctetKey(_) | AlgorithmParameters::OctetKeyPair(_) => None,
        };
    }
    None
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
fn check_audience(
    aud_claim: &serde_json::Value,
    expected: &[String],
) -> Result<(), OidcError> {
    let matches = match aud_claim {
        serde_json::Value::String(s) => expected.iter().any(|e| e == s),
        serde_json::Value::Array(arr) => arr.iter().any(|v| {
            v.as_str()
                .is_some_and(|s| expected.iter().any(|e| e == s))
        }),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_jwks_uri_appends_well_known() {
        // GIVEN/WHEN: an issuer URL
        let uri = default_jwks_uri("https://accounts.google.com");

        // THEN: the standard JWKS discovery path is appended
        assert_eq!(
            uri,
            "https://accounts.google.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn default_jwks_uri_handles_trailing_slash() {
        // GIVEN: issuer with trailing slash
        let uri = default_jwks_uri("https://accounts.google.com/");

        // THEN: no double slash
        assert_eq!(
            uri,
            "https://accounts.google.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn check_audience_accepts_string_match() {
        // GIVEN: string aud claim matching expected
        let aud = serde_json::json!("my-client-id");
        let expected = vec!["my-client-id".to_string()];

        // THEN: no error
        assert!(check_audience(&aud, &expected).is_ok());
    }

    #[test]
    fn check_audience_accepts_array_member_match() {
        // GIVEN: array aud claim where one element matches
        let aud = serde_json::json!(["other-client", "my-client-id"]);
        let expected = vec!["my-client-id".to_string()];

        // THEN: no error
        assert!(check_audience(&aud, &expected).is_ok());
    }

    #[test]
    fn check_audience_rejects_no_match() {
        // GIVEN: aud claim with no matching value
        let aud = serde_json::json!("wrong-client");
        let expected = vec!["my-client-id".to_string()];

        // THEN: error
        assert!(check_audience(&aud, &expected).is_err());
    }

    #[test]
    fn check_audience_rejects_empty_array() {
        // GIVEN: empty aud array
        let aud = serde_json::json!([]);
        let expected = vec!["my-client-id".to_string()];

        // THEN: error
        assert!(check_audience(&aud, &expected).is_err());
    }

    #[test]
    fn extract_unverified_claims_rejects_malformed_token() {
        // GIVEN: a malformed token (not valid base64url parts)
        let result = extract_unverified_claims("not-a-jwt");

        // THEN: error
        assert!(result.is_err());
    }

    #[test]
    fn verified_identity_serializes_to_json() {
        // GIVEN: a verified identity
        let identity = VerifiedIdentity {
            subject: "12345".to_string(),
            email: "alice@company.com".to_string(),
            name: Some("Alice".to_string()),
            groups: vec!["ml-engineers".to_string()],
            issuer: "https://accounts.google.com".to_string(),
        };

        // WHEN: serialized to JSON
        let json = serde_json::to_string(&identity).unwrap();

        // THEN: contains expected fields
        assert!(json.contains("alice@company.com"));
        assert!(json.contains("ml-engineers"));
    }
}
