// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Public (Ed25519) provenance signatures (MIK-8398).
//!
//! A second, publicly verifiable signature over each runtime-provenance
//! receipt. The HMAC in [`SignedResultProvenance`] stays the gateway's own
//! seal; the Ed25519 signature travels beside it as the `public_signature`
//! member of the serialized provenance object, so anyone holding the public
//! JWK can verify a receipt without any gateway secret.
//!
//! This file is the red-phase skeleton: every behaviour body returns its inert
//! value, and the tests pin the contract the implementation must meet.

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use super::{RuntimeProvenanceReceipt, SignedResultProvenance};

/// Environment variable holding the STANDARD-base64 Ed25519 seed.
pub(crate) const PROVENANCE_SEED_ENV: &str = "GATEWAY_PROVENANCE_SIGNING_SEED";

/// Environment variable holding this signer's key id.
pub(crate) const PROVENANCE_KEY_ID_ENV: &str = "GATEWAY_PROVENANCE_KEY_ID";

/// The detached public signature: `{"payload": <String>, "sig": <String>}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PublicSignature {
    /// URL-safe-no-pad base64 of the signed JSON payload bytes.
    pub(crate) payload: String,
    /// URL-safe-no-pad base64 of the 64-byte Ed25519 signature.
    pub(crate) sig: String,
}

/// Signs runtime-provenance receipts with the gateway's Ed25519 identity.
pub(crate) struct ProvenancePublicSigner {
    key_pair: ring::signature::Ed25519KeyPair,
    kid: String,
}

// Only the key id: the key pair is secret material.
impl std::fmt::Debug for ProvenancePublicSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvenancePublicSigner")
            .field("kid", &self.kid)
            .finish()
    }
}

impl ProvenancePublicSigner {
    /// This signer's key id.
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// RFC 8037 OKP JWK: `{"kty":"OKP","crv":"Ed25519","kid":kid,"x":b64url(pk)}`.
    ///
    /// Never carries a `d` member.
    pub(crate) fn public_jwk(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// RFC 7638 thumbprint: b64url of the SHA-256 of
    /// `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, with no spaces.
    pub(crate) fn jwk_thumbprint(&self) -> String {
        String::new()
    }

    /// The [`PublicSignature`] for this receipt and optional result.
    pub(crate) fn sign_receipt(
        &self,
        _receipt: &RuntimeProvenanceReceipt,
        _result: Option<&serde_json::Value>,
    ) -> PublicSignature {
        PublicSignature {
            payload: String::new(),
            sig: String::new(),
        }
    }

    /// A signer from a raw seed, for tests only.
    #[cfg(test)]
    pub(crate) fn from_seed_for_test(seed: [u8; 32], kid: &str) -> Self {
        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("a 32-byte seed is always a valid Ed25519 seed");
        Self {
            key_pair,
            kid: kid.to_owned(),
        }
    }
}

/// Resolve the public signer from the environment overlay.
///
/// Absent (seed unset or blank) resolves to `Ok(None)`. Every `Err` carries
/// value-free text that never repeats the seed.
pub(crate) fn resolve_public_signer(
    _env: &crate::config::EnvOverlay,
    _attestation_key_id: &str,
) -> crate::Result<Option<ProvenancePublicSigner>> {
    Ok(None)
}

/// How a receipt verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyStatus {
    /// The signature is valid and the result digest matches.
    Bound,
    /// The signature is valid but the payload carries no result digest.
    Unbound,
    /// The signature is valid; no result was offered to bind.
    SignatureOnly,
}

/// Why verification refused, naming the rule and never the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyRefusal {
    /// The provenance object has no `public_signature` member.
    NoPublicSignature,
    /// `payload`/`sig` are not URL-safe-no-pad base64 of the right length.
    BadEncoding,
    /// A duplicate member in the payload.
    DuplicateMember,
    /// `v` is not 1 or `alg` is not `EdDSA`.
    BadProfile,
    /// The payload `kid` is not in the trust set.
    UnknownKid,
    /// The Ed25519 signature does not verify.
    BadSignature,
    /// The outer receipt differs from the payload receipt.
    OuterReceiptMismatch,
    /// The given result does not match the payload digest.
    ResultMismatch,
    /// The given result is unhashable while the digest is non-null.
    ResultUnhashable,
}

/// A verified receipt: its status, the signing key, and the receipt itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedReceipt {
    /// How it verified.
    pub(crate) status: VerifyStatus,
    /// The signing key id.
    pub(crate) kid: String,
    /// The verified receipt.
    pub(crate) receipt: RuntimeProvenanceReceipt,
}

/// Trusted public keys by key id.
pub(crate) struct TrustSet {
    keys: BTreeMap<String, [u8; 32]>,
}

impl TrustSet {
    /// Parse one JWK object or a `{"keys":[...]}` set.
    pub(crate) fn from_json(_text: &str) -> Result<Self, TrustSetRefusal> {
        Err(TrustSetRefusal::Malformed)
    }
}

/// Why a trust set was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustSetRefusal {
    /// Not JSON, or not a JWK/JWKS shape.
    Malformed,
    /// Two keys share one `kid`.
    DuplicateKid,
    /// `kty` is not `OKP` or `crv` is not `Ed25519`.
    NotEd25519,
    /// `x` is not 32 bytes.
    BadX,
    /// A key carries a `d` (private) member.
    PrivateMember,
    /// A key has no `kid`.
    MissingKid,
}

/// Verify a serialized provenance object against the trust set.
///
/// `prov` is the [`provenance_value`] object: the signed receipt plus its
/// sibling `public_signature` member.
pub(crate) fn verify_public(
    _prov: &serde_json::Value,
    _trust: &TrustSet,
    _result: Option<&serde_json::Value>,
) -> Result<VerifiedReceipt, VerifyRefusal> {
    Err(VerifyRefusal::NoPublicSignature)
}

/// Serialize `signed` and, when `public` is `Some`, add its `public_signature`.
pub(crate) fn provenance_value(
    signed: &SignedResultProvenance,
    _public: Option<(&ProvenancePublicSigner, Option<&serde_json::Value>)>,
) -> serde_json::Value {
    serde_json::to_value(signed).unwrap_or(serde_json::Value::Null)
}

/// Runs `provenance public-key` / `provenance verify`; prints its own stdout/stderr lines.
pub fn run_provenance_command(_cmd: &crate::cli::ProvenanceCommand) -> ExitCode {
    ExitCode::from(1)
}

#[cfg(test)]
#[path = "provenance_public_tests.rs"]
mod tests;
