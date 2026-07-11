// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Attestation token wire format and claims (MIK-5223 AC.2).
//!
//! A token is `base64url(claims_json) + "." + base64url(hmac_sha256_sig)`.
//! Claims carry the agent identity, task UUID, capability allow-list and an
//! RFC-3339 expiration; the signature is produced by the
//! [`crate::attestation::signer::BnautAttestationSigner`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Issuer string stamped into every token signed by bnaut-attestation.
pub const BNAUT_ISSUER: &str = "bnaut-attestation";

/// Signing algorithm identifier.  HMAC-SHA256 from the `RustCrypto` `hmac` +
/// `sha2` crates — the same primitives the gateway already uses for
/// [`crate::security::message_signing`]; no bespoke crypto (B4-PLATFORM).
pub const SIGNING_ALGORITHM: &str = "HS256";

/// Claims carried by an attestation token (MIK-NEW.RUNTIME-A.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    /// Unique token identifier (UUID v4) — every issued token is uniquely
    /// attributable in audit records (B1-IDENT).
    pub token_id: String,
    /// Issuing authority; always [`BNAUT_ISSUER`] for valid tokens.
    pub issuer: String,
    /// Signing algorithm identifier; always [`SIGNING_ALGORITHM`].
    pub algorithm: String,
    /// Identifier of the signing key, namespaced under `bnaut/`.
    pub key_id: String,
    /// Identity of the agent the sandbox runs on behalf of.
    pub agent_identity: String,
    /// UUID of the task the sandbox executes.
    pub task_uuid: String,
    /// Capability allow-list scoping what the sandbox may call.
    pub capabilities: Vec<String>,
    /// RFC-3339 issuance timestamp.
    pub issued_at: String,
    /// RFC-3339 expiration timestamp.
    pub expires_at: String,
    /// `token_id` of the predecessor when this token was minted by rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_of: Option<String>,
}

impl TokenClaims {
    /// Parse the RFC-3339 `expires_at` claim.
    ///
    /// # Errors
    ///
    /// Returns the raw claim string when it is not valid RFC-3339.
    pub fn expires_at_utc(&self) -> Result<DateTime<Utc>, String> {
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| self.expires_at.clone())
    }
}

/// A signed attestation token: parsed claims plus the encoded wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationToken {
    claims: TokenClaims,
    encoded: String,
}

impl AttestationToken {
    /// Assemble a token from claims and a raw signature over the payload.
    #[must_use]
    pub fn from_parts(claims: TokenClaims, payload: &[u8], signature: &[u8]) -> Self {
        let encoded = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        );
        Self { claims, encoded }
    }

    /// The claims this token carries.
    #[must_use]
    pub fn claims(&self) -> &TokenClaims {
        &self.claims
    }

    /// The wire-format string injected into the sandbox environment.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Split an encoded token into raw `(payload, signature)` bytes without
    /// verifying anything.  Callers must verify the signature before
    /// trusting the payload.
    ///
    /// # Errors
    ///
    /// Returns a description of the structural defect for malformed input.
    pub fn split_unverified(encoded: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (payload_b64, sig_b64) = encoded
            .split_once('.')
            .ok_or_else(|| "missing '.' separator".to_string())?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| format!("payload base64: {e}"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| format!("signature base64: {e}"))?;
        Ok((payload, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> TokenClaims {
        TokenClaims {
            token_id: "t-1".to_string(),
            issuer: BNAUT_ISSUER.to_string(),
            algorithm: SIGNING_ALGORITHM.to_string(),
            key_id: "bnaut/test".to_string(),
            agent_identity: "agent".to_string(),
            task_uuid: "task".to_string(),
            capabilities: vec!["read".to_string()],
            issued_at: "2026-06-12T00:00:00+00:00".to_string(),
            expires_at: "2026-06-12T01:00:00+00:00".to_string(),
            rotation_of: None,
        }
    }

    #[test]
    fn round_trips_payload_and_signature() {
        let token = AttestationToken::from_parts(claims(), b"payload", b"sig");
        let (payload, signature) = AttestationToken::split_unverified(token.encoded()).unwrap();
        assert_eq!(payload, b"payload");
        assert_eq!(signature, b"sig");
    }

    #[test]
    fn split_rejects_missing_separator() {
        let err = AttestationToken::split_unverified("no-separator").unwrap_err();
        assert!(err.contains("separator"));
    }

    #[test]
    fn split_rejects_bad_base64() {
        let err = AttestationToken::split_unverified("!!!.###").unwrap_err();
        assert!(err.contains("base64"));
    }

    #[test]
    fn expires_at_parses_rfc3339() {
        let parsed = claims().expires_at_utc().unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-06-12T01:00:00+00:00");
    }

    #[test]
    fn expires_at_rejects_non_rfc3339() {
        let mut c = claims();
        c.expires_at = "tomorrow".to_string();
        assert_eq!(c.expires_at_utc().unwrap_err(), "tomorrow");
    }
}
