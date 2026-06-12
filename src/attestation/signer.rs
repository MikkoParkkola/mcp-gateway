//! Gateway-embedded signing client for the bnaut-attestation platform
//! component (MIK-5223 AC.2, B1-IDENT / B4-PLATFORM).
//!
//! bnaut-attestation owns identity at the platform layer; this module is the
//! gateway-side issuer that signs tokens with bnaut-provisioned key material.
//! Signing is HMAC-SHA256 via the `RustCrypto` `hmac`/`sha2` crates — the same
//! primitives already used by [`crate::security::message_signing`]; no
//! bespoke crypto is introduced.

use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

use super::token::{AttestationToken, BNAUT_ISSUER, SIGNING_ALGORITHM, TokenClaims};

type HmacSha256 = Hmac<Sha256>;

/// What a sandbox boot requests a token for.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// Identity of the agent the sandbox runs on behalf of.
    pub agent_identity: String,
    /// UUID of the task the sandbox executes.
    pub task_uuid: Uuid,
    /// Capability allow-list scoping what the sandbox may call.
    pub capabilities: Vec<String>,
}

/// Issues and verifies attestation tokens with bnaut-attestation key material.
#[derive(Debug)]
pub struct BnautAttestationSigner {
    key: Vec<u8>,
    key_id: String,
}

impl BnautAttestationSigner {
    /// Create a signer from bnaut-provisioned key material.
    ///
    /// `key_id` is namespaced under `bnaut/` so audit records attribute the
    /// signing authority unambiguously.
    #[must_use]
    pub fn new(key: Vec<u8>, key_id: impl Into<String>) -> Self {
        let key_id = key_id.into();
        let key_id = if key_id.starts_with("bnaut/") {
            key_id
        } else {
            format!("bnaut/{key_id}")
        };
        Self { key, key_id }
    }

    /// The namespaced identifier of the signing key.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Issue a signed token for `request`, valid from `now` for `ttl`.
    #[must_use]
    pub fn issue(&self, request: &TokenRequest, now: DateTime<Utc>, ttl: TimeDelta) -> AttestationToken {
        self.mint(request, now, ttl, None)
    }

    /// Mint a successor for `predecessor` with a fresh expiry and a fresh
    /// `token_id`; the successor records the predecessor in `rotation_of`
    /// (MIK-NEW.RUNTIME-A.4).
    #[must_use]
    pub fn rotate(
        &self,
        predecessor: &TokenClaims,
        now: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> AttestationToken {
        let request = TokenRequest {
            agent_identity: predecessor.agent_identity.clone(),
            task_uuid: Uuid::parse_str(&predecessor.task_uuid).unwrap_or_else(|_| Uuid::nil()),
            capabilities: predecessor.capabilities.clone(),
        };
        self.mint(&request, now, ttl, Some(predecessor.token_id.clone()))
    }

    fn mint(
        &self,
        request: &TokenRequest,
        now: DateTime<Utc>,
        ttl: TimeDelta,
        rotation_of: Option<String>,
    ) -> AttestationToken {
        let claims = TokenClaims {
            token_id: Uuid::new_v4().to_string(),
            issuer: BNAUT_ISSUER.to_string(),
            algorithm: SIGNING_ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            agent_identity: request.agent_identity.clone(),
            task_uuid: request.task_uuid.to_string(),
            capabilities: request.capabilities.clone(),
            issued_at: now.to_rfc3339(),
            expires_at: (now + ttl).to_rfc3339(),
            rotation_of,
        };
        // Claims are plain data — serialization cannot fail.
        let payload = serde_json::to_vec(&claims).unwrap_or_default();
        let signature = self.sign_bytes(&payload);
        AttestationToken::from_parts(claims, &payload, &signature)
    }

    /// HMAC-SHA256 over `payload`.
    #[must_use]
    pub fn sign_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    /// Constant-time signature verification (via `Mac::verify_slice`).
    #[must_use]
    pub fn verify_bytes(&self, payload: &[u8], signature: &[u8]) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload);
        mac.verify_slice(signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> BnautAttestationSigner {
        BnautAttestationSigner::new(b"unit-test-key".to_vec(), "unit")
    }

    fn request() -> TokenRequest {
        TokenRequest {
            agent_identity: "agent-7".to_string(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec!["tools:search".to_string()],
        }
    }

    #[test]
    fn key_id_is_bnaut_namespaced() {
        assert_eq!(signer().key_id(), "bnaut/unit");
        let pre = BnautAttestationSigner::new(b"k".to_vec(), "bnaut/already");
        assert_eq!(pre.key_id(), "bnaut/already");
    }

    #[test]
    fn issued_token_verifies_and_carries_bnaut_issuer() {
        let s = signer();
        let token = s.issue(&request(), Utc::now(), TimeDelta::minutes(5));
        let (payload, sig) = AttestationToken::split_unverified(token.encoded()).unwrap();
        assert!(s.verify_bytes(&payload, &sig));
        assert_eq!(token.claims().issuer, BNAUT_ISSUER);
        assert_eq!(token.claims().algorithm, SIGNING_ALGORITHM);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let token = signer().issue(&request(), Utc::now(), TimeDelta::minutes(5));
        let other = BnautAttestationSigner::new(b"different-key".to_vec(), "other");
        let (payload, sig) = AttestationToken::split_unverified(token.encoded()).unwrap();
        assert!(!other.verify_bytes(&payload, &sig));
    }

    #[test]
    fn rotation_links_predecessor_and_gets_fresh_id() {
        let s = signer();
        let now = Utc::now();
        let first = s.issue(&request(), now, TimeDelta::minutes(5));
        let second = s.rotate(first.claims(), now, TimeDelta::minutes(5));
        assert_eq!(
            second.claims().rotation_of.as_deref(),
            Some(first.claims().token_id.as_str())
        );
        assert_ne!(second.claims().token_id, first.claims().token_id);
        assert_eq!(second.claims().agent_identity, first.claims().agent_identity);
        assert_eq!(second.claims().capabilities, first.claims().capabilities);
    }
}
