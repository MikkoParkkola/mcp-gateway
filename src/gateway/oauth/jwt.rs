//! JWT validation for agent tokens.
//!
//! Supports HS256 (shared-secret HMAC) and RS256 (RSA signature) tokens.
//!
//! # Validation Steps
//!
//! 1. Decode the header to determine `alg` (`HS256` or `RS256`).
//! 2. Decode `sub` / `client_id` claim (unverified) to find the matching
//!    [`AgentDefinition`] in the registry.
//! 3. Verify the signature using the agent's key material.
//! 4. Validate standard claims: `exp`, `iss` (if configured), `aud` (if configured).
//! 5. Return the verified [`AgentClaims`].
//!
//! # Security
//!
//! - HS256 keys are compared in full (jsonwebtoken handles constant-time
//!   HMAC comparison internally).
//! - RS256 public keys are PEM-encoded and validated at lookup time.
//! - Tokens with `alg: none` are rejected at the header-decode step.
//! - Clock leeway of 30 seconds tolerates minor skew.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use super::agents::{AgentDefinition, AgentRegistry};
use super::scopes::Scope;

/// Claims extracted from a validated agent JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Subject — the agent's `client_id`.
    pub sub: String,
    /// Optional issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Optional audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// Expiry (Unix timestamp), validated by jsonwebtoken.
    pub exp: u64,
    /// Issued-at (Unix timestamp).
    #[serde(default)]
    pub iat: u64,
    /// Granted scopes (space-separated in the JWT `scope` claim).
    #[serde(default)]
    pub scope: String,
}

/// Error variants for agent JWT validation.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// No agent registered with the claimed `sub` / `client_id`.
    #[error("Unknown agent: {0}")]
    UnknownAgent(String),

    /// The agent definition lacks key material for the claimed algorithm.
    #[error("Missing key for algorithm {alg:?} on agent {agent}")]
    MissingKey {
        /// The agent `client_id`.
        agent: String,
        /// The algorithm that was requested.
        alg: Algorithm,
    },

    /// Invalid PEM for RS256 key.
    #[error("Invalid RS256 public key for agent {0}: {1}")]
    InvalidPublicKey(String, String),

    /// JWT decode / signature / claims verification failed.
    #[error("JWT verification failed: {0}")]
    JwtVerification(#[from] jsonwebtoken::errors::Error),

    /// The JWT header specifies an unsupported algorithm.
    #[error("Unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
}

/// Validated result: claims + resolved agent definition + parsed scopes.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    /// Decoded and verified JWT claims.
    pub claims: AgentClaims,
    /// The matching agent definition from the registry.
    pub agent: AgentDefinition,
    /// Parsed scopes from the agent definition (authoritative grant).
    pub scopes: Vec<Scope>,
}

/// Validate an agent bearer token against the registry.
///
/// # Errors
///
/// Returns [`JwtError`] on any validation failure.
pub fn validate_agent_token(
    token: &str,
    registry: &AgentRegistry,
) -> Result<ValidatedToken, JwtError> {
    // 1. Decode header (no verification) to get algorithm and sub.
    let header = jsonwebtoken::decode_header(token)?;

    // Reject unsupported algorithms up-front.
    let alg = match header.alg {
        Algorithm::HS256 => Algorithm::HS256,
        Algorithm::RS256 => Algorithm::RS256,
        other => return Err(JwtError::UnsupportedAlgorithm(other)),
    };

    // 2. Extract `sub` claim unverified to find the agent.
    let sub = extract_sub_unverified(token)?;
    let agent = registry
        .get(&sub)
        .ok_or_else(|| JwtError::UnknownAgent(sub.clone()))?;

    // 3. Build decoding key from the agent's key material.
    let decoding_key = build_decoding_key(&agent, alg)?;

    // 4. Build validation config.
    let mut validation = Validation::new(alg);
    validation.leeway = 30;

    // Issuer check — set_issuer enables iss validation; if not configured, skip.
    if let Some(ref expected_iss) = agent.issuer {
        validation.set_issuer(&[expected_iss.as_str()]);
    }
    // When no issuer is configured we do not call set_issuer, which leaves
    // iss validation disabled (the default in jsonwebtoken 9.x).

    // Audience check — disable library-level aud check; we handle it manually
    // to support both string and array forms.
    validation.validate_aud = false;

    // 5. Verify signature + exp.
    let token_data =
        jsonwebtoken::decode::<AgentClaims>(token, &decoding_key, &validation)?;
    let claims = token_data.claims;

    // 6. Manual audience check.
    if let Some(ref expected_aud) = agent.audience {
        check_audience_claim(claims.aud.as_ref(), expected_aud)?;
    }

    // 7. Collect scopes from the agent definition (the source of truth for what
    //    the agent is *allowed* to access).  JWT `scope` claim is informational
    //    and may be used for future narrowing, but grants cannot exceed the
    //    registration-time definition.
    let scopes = agent.parsed_scopes();

    Ok(ValidatedToken { claims, agent, scopes })
}

/// Extract the `sub` claim from a JWT without verifying the signature.
fn extract_sub_unverified(token: &str) -> Result<String, JwtError> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(JwtError::JwtVerification(
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken),
        ));
    }

    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        // Accept tokens with or without padding
        parts[1].trim_end_matches('='),
    )
    .map_err(|_| {
        JwtError::JwtVerification(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ))
    })?;

    let value: serde_json::Value = serde_json::from_slice(&payload).map_err(|_| {
        JwtError::JwtVerification(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ))
    })?;

    value
        .get("sub")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            JwtError::JwtVerification(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("sub".to_string()),
            ))
        })
}

/// Build a [`DecodingKey`] from the agent's key material for the given algorithm.
fn build_decoding_key(
    agent: &AgentDefinition,
    alg: Algorithm,
) -> Result<DecodingKey, JwtError> {
    match alg {
        Algorithm::HS256 => {
            let secret = agent.hs256_secret.as_deref().ok_or_else(|| {
                JwtError::MissingKey {
                    agent: agent.client_id.clone(),
                    alg,
                }
            })?;
            Ok(DecodingKey::from_secret(secret.as_bytes()))
        }
        Algorithm::RS256 => {
            let pem = agent.rs256_public_key.as_deref().ok_or_else(|| {
                JwtError::MissingKey {
                    agent: agent.client_id.clone(),
                    alg,
                }
            })?;
            DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                JwtError::InvalidPublicKey(agent.client_id.clone(), e.to_string())
            })
        }
        other => Err(JwtError::UnsupportedAlgorithm(other)),
    }
}

/// Validate the `aud` claim against an expected audience string.
fn check_audience_claim(
    aud: Option<&serde_json::Value>,
    expected: &str,
) -> Result<(), JwtError> {
    let matches = match aud {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(expected))
        }
        _ => false,
    };

    if matches {
        Ok(())
    } else {
        Err(JwtError::JwtVerification(
            jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidAudience,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::oauth::agents::AgentDefinition;
    use jsonwebtoken::{EncodingKey, Header};

    fn make_hs256_agent(id: &str, secret: &str) -> AgentDefinition {
        AgentDefinition {
            client_id: id.to_string(),
            name: id.to_string(),
            hs256_secret: Some(secret.to_string()),
            rs256_public_key: None,
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: None,
        }
    }

    fn hs256_token(sub: &str, secret: &str, exp_offset_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "sub": sub,
            "exp": now + exp_offset_secs,
            "iat": now,
        });

        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    // ── validate_agent_token ──────────────────────────────────────────────

    #[test]
    fn hs256_valid_token_succeeds() {
        let reg = AgentRegistry::new();
        reg.register(make_hs256_agent("agent-1", "my-secret"));

        let token = hs256_token("agent-1", "my-secret", 3600);
        let result = validate_agent_token(&token, &reg);
        assert!(result.is_ok(), "Expected Ok, got: {result:?}");

        let validated = result.unwrap();
        assert_eq!(validated.claims.sub, "agent-1");
        assert!(!validated.scopes.is_empty());
    }

    #[test]
    fn hs256_wrong_secret_fails() {
        let reg = AgentRegistry::new();
        reg.register(make_hs256_agent("agent-1", "correct-secret"));

        let token = hs256_token("agent-1", "wrong-secret", 3600);
        let result = validate_agent_token(&token, &reg);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_agent_sub_fails() {
        let reg = AgentRegistry::new();
        reg.register(make_hs256_agent("agent-1", "secret"));

        let token = hs256_token("no-such-agent", "secret", 3600);
        let result = validate_agent_token(&token, &reg);
        assert!(matches!(result, Err(JwtError::UnknownAgent(_))));
    }

    #[test]
    fn expired_token_fails() {
        let reg = AgentRegistry::new();
        reg.register(make_hs256_agent("agent-1", "secret"));

        // Token expired 100 seconds ago (beyond 30s leeway)
        let token = hs256_token("agent-1", "secret", -100);
        let result = validate_agent_token(&token, &reg);
        assert!(result.is_err());
    }

    #[test]
    fn missing_hs256_secret_returns_missing_key_error() {
        let reg = AgentRegistry::new();
        reg.register(AgentDefinition {
            client_id: "agent-no-key".to_string(),
            name: "NoKey".to_string(),
            hs256_secret: None,
            rs256_public_key: None,
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: None,
        });

        let token = hs256_token("agent-no-key", "any", 3600);
        let result = validate_agent_token(&token, &reg);
        assert!(matches!(result, Err(JwtError::MissingKey { .. })));
    }

    #[test]
    fn audience_check_passes_when_matching() {
        let reg = AgentRegistry::new();
        reg.register(AgentDefinition {
            client_id: "agent-aud".to_string(),
            name: "AudAgent".to_string(),
            hs256_secret: Some("secret".to_string()),
            rs256_public_key: None,
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: Some("my-gateway".to_string()),
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "sub": "agent-aud",
            "exp": now + 3600,
            "iat": now,
            "aud": "my-gateway",
        });

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let result = validate_agent_token(&token, &reg);
        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
    }

    #[test]
    fn audience_check_fails_when_mismatched() {
        let reg = AgentRegistry::new();
        reg.register(AgentDefinition {
            client_id: "agent-aud".to_string(),
            name: "AudAgent".to_string(),
            hs256_secret: Some("secret".to_string()),
            rs256_public_key: None,
            scopes: vec!["tools:*".to_string()],
            issuer: None,
            audience: Some("expected-audience".to_string()),
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "sub": "agent-aud",
            "exp": now + 3600,
            "iat": now,
            "aud": "wrong-audience",
        });

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let result = validate_agent_token(&token, &reg);
        assert!(result.is_err());
    }

    // ── check_audience_claim ──────────────────────────────────────────────

    #[test]
    fn aud_string_match() {
        let aud = serde_json::json!("target");
        assert!(check_audience_claim(Some(&aud), "target").is_ok());
    }

    #[test]
    fn aud_array_match() {
        let aud = serde_json::json!(["other", "target"]);
        assert!(check_audience_claim(Some(&aud), "target").is_ok());
    }

    #[test]
    fn aud_no_match_fails() {
        let aud = serde_json::json!("wrong");
        assert!(check_audience_claim(Some(&aud), "target").is_err());
    }

    #[test]
    fn aud_none_fails() {
        assert!(check_audience_claim(None, "target").is_err());
    }

    // ── extract_sub_unverified ────────────────────────────────────────────

    #[test]
    fn extract_sub_rejects_malformed_token() {
        assert!(extract_sub_unverified("not-a-jwt").is_err());
    }
}
