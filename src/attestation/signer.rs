// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway-embedded signing client for the bnaut-attestation platform
//! component (MIK-5223 AC.2, B1-IDENT / B4-PLATFORM).
//!
//! bnaut-attestation owns identity at the platform layer; this module is the
//! gateway-side issuer that signs tokens with bnaut-provisioned key material.
//! Signing is HMAC-SHA256 via the `RustCrypto` `hmac`/`sha2` crates — the same
//! primitives already used by [`crate::security::message_signing`]; no
//! bespoke crypto is introduced.

use chrono::{DateTime, TimeDelta, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;

use super::token::{AttestationToken, BNAUT_ISSUER, SIGNING_ALGORITHM, TokenClaims};

type HmacSha256 = Hmac<Sha256>;

/// HKDF-SHA256 `info` label that derives the outbound runtime-provenance
/// receipt signing subkey from the operator-configured
/// `GATEWAY_ATTESTATION_SIGNING_KEY` (MIK-6909 item 2).
///
/// Domain-separated from inbound attestation-TOKEN signing/verification,
/// which — as of this constant's introduction — still uses the raw
/// configured key directly (see [`BnautAttestationSigner::derive_domain`]
/// docs for why the token domain is intentionally NOT migrated here).
pub const RESULT_PROVENANCE_DOMAIN_INFO: &[u8] = b"mcp-gateway/result-provenance/v1";

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

    /// Derive a domain-separated subkey signer from this signer's key
    /// material via HKDF-SHA256, keeping the same `key_id` (MIK-6909 item 2).
    ///
    /// The operator-configured `GATEWAY_ATTESTATION_SIGNING_KEY` bytes were
    /// previously used verbatim as the HMAC key for two unrelated trust
    /// domains — inbound attestation tokens and outbound runtime-provenance
    /// receipts — so a leak or signing oracle in one domain could forge the
    /// other. `derive_domain` expands the configured key with HKDF-SHA256
    /// under a domain-specific `info` label, producing an unrelated 32-byte
    /// subkey per domain.
    ///
    /// Salt is fixed/empty (`None`): the input key material is already an
    /// operator-provisioned high-entropy secret, not a low-entropy password,
    /// so a random salt adds no meaningful extraction security margin here
    /// (RFC 5869 §3.1 explicitly permits omitting it) — and every process
    /// deriving this subkey independently must land on the identical value,
    /// which a random salt would prevent.
    ///
    /// Only the receipt domain ([`RESULT_PROVENANCE_DOMAIN_INFO`]) is wired
    /// through this derivation today. The token domain intentionally still
    /// signs/verifies with the raw configured key: attestation tokens are
    /// issued by the external bnaut-attestation platform component (see
    /// [`crate::attestation`] module docs) and presented to this gateway
    /// long after issuance (sandbox boot, cross-boundary calls), so
    /// unilaterally re-deriving the token-domain key here would silently
    /// break verification of every already-issued, in-flight token without
    /// bnaut-attestation also adopting the same derivation. That migration
    /// needs its own cross-service ticket and coordinated rollout, not a
    /// gateway-only change.
    #[must_use]
    pub fn derive_domain(&self, domain_info: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, &self.key);
        let mut subkey = [0u8; 32];
        hk.expand(domain_info, &mut subkey)
            .expect("32 bytes is well within HKDF-SHA256's 8160-byte max output");
        Self {
            key: subkey.to_vec(),
            key_id: self.key_id.clone(),
        }
    }

    /// Issue a signed token for `request`, valid from `now` for `ttl`.
    #[must_use]
    pub fn issue(
        &self,
        request: &TokenRequest,
        now: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> AttestationToken {
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
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    /// Constant-time signature verification (via `Mac::verify_slice`).
    #[must_use]
    pub fn verify_bytes(&self, payload: &[u8], signature: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
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
    fn receipt_domain_subkey_does_not_cross_verify_with_token_domain() {
        // MIK-6909 item 2: the receipt-domain subkey (derived) and the
        // token-domain key (raw, unmodified) must be unrelated HMAC keys —
        // a signature valid under one must never verify under the other.
        let token_domain = signer(); // raw configured key, unchanged
        let receipt_domain = token_domain.derive_domain(RESULT_PROVENANCE_DOMAIN_INFO);
        assert_ne!(
            receipt_domain.sign_bytes(b"same-bytes"),
            token_domain.sign_bytes(b"same-bytes"),
            "domains must not share a signature for identical input"
        );

        let payload = b"runtime-provenance-receipt-bytes";
        let receipt_sig = receipt_domain.sign_bytes(payload);
        let token_sig = token_domain.sign_bytes(payload);

        // A receipt signed in the receipt domain fails under the token key...
        assert!(!token_domain.verify_bytes(payload, &receipt_sig));
        // ...and a token-domain signature fails under the receipt key.
        assert!(!receipt_domain.verify_bytes(payload, &token_sig));
    }

    #[test]
    fn derive_domain_is_deterministic_and_label_sensitive() {
        let base = signer();
        let a = base.derive_domain(b"domain-a");
        let a_again = base.derive_domain(b"domain-a");
        let b = base.derive_domain(b"domain-b");
        assert_eq!(a.sign_bytes(b"x"), a_again.sign_bytes(b"x"));
        assert_ne!(a.sign_bytes(b"x"), b.sign_bytes(b"x"));
        // key_id is preserved unchanged across derivation.
        assert_eq!(a.key_id(), base.key_id());
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
        assert_eq!(
            second.claims().agent_identity,
            first.claims().agent_identity
        );
        assert_eq!(second.claims().capabilities, first.claims().capabilities);
    }
}
