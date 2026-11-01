// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Public (Ed25519) provenance signatures (MIK-8398).
//!
//! A second, publicly verifiable signature over each runtime-provenance
//! receipt. The HMAC in [`SignedResultProvenance`] stays the gateway's own
//! seal; the Ed25519 signature travels beside it as the `public_signature`
//! member of the serialized provenance object, so anyone holding the public
//! JWK can verify a receipt without any gateway secret.

use std::collections::{BTreeMap, HashSet};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use super::{RuntimeProvenanceReceipt, SignedResultProvenance};

/// Environment variable holding the STANDARD-base64 Ed25519 seed.
pub(crate) const PROVENANCE_SEED_ENV: &str = "GATEWAY_PROVENANCE_SIGNING_SEED";

/// Environment variable holding this signer's key id.
pub(crate) const PROVENANCE_KEY_ID_ENV: &str = "GATEWAY_PROVENANCE_KEY_ID";

/// Domain tag separating this signature from every other envelope.
const DOMAIN_TAG: &[u8] = b"mcp-gateway-provenance-ed25519-v1\0";

/// Domain tag of an Activity export manifest's signature: never the
/// receipt's, so neither signature verifies as the other.
pub(crate) const ACTIVITY_EXPORT_DOMAIN: &[u8] = b"mcp-gateway-activity-export-ed25519-v1\0";

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
            .finish_non_exhaustive()
    }
}

impl ProvenancePublicSigner {
    /// This signer's key id.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// RFC 8037 OKP JWK: `{"kty":"OKP","crv":"Ed25519","kid":kid,"x":b64url(pk)}`.
    ///
    /// Never carries a `d` member.
    pub(crate) fn public_jwk(&self) -> serde_json::Value {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ring::signature::KeyPair as _;
        let x = URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref());
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "x": x,
        })
    }

    /// RFC 7638 thumbprint: b64url of the SHA-256 of
    /// `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, with no spaces.
    pub(crate) fn jwk_thumbprint(&self) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ring::signature::KeyPair as _;
        use sha2::Digest as _;
        let x = URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref());
        let message = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(message.as_bytes()))
    }

    /// The [`PublicSignature`] for this receipt and optional result.
    pub(crate) fn sign_receipt(
        &self,
        receipt: &RuntimeProvenanceReceipt,
        result: Option<&serde_json::Value>,
    ) -> PublicSignature {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let receipt_value = serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null);
        let digest = match result {
            Some(value) => match crate::security::signature_chain::content_digest(value) {
                Ok(hex) => serde_json::Value::from(hex),
                Err(_) => serde_json::Value::Null,
            },
            None => serde_json::Value::Null,
        };
        let payload = serde_json::json!({
            "v": 1,
            "alg": "EdDSA",
            "kid": self.kid,
            "receipt": receipt_value,
            "result_sha256": digest,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let mut message = DOMAIN_TAG.to_vec();
        message.extend_from_slice(&payload_bytes);
        let sig = self.key_pair.sign(&message);
        PublicSignature {
            payload: URL_SAFE_NO_PAD.encode(&payload_bytes),
            sig: URL_SAFE_NO_PAD.encode(sig.as_ref()),
        }
    }

    /// Ed25519 over `domain || message`, as URL-safe-no-pad base64. Each
    /// caller passes its own domain tag, so a signature made for one envelope
    /// never verifies as another's.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn sign_bytes(&self, domain: &[u8], message: &[u8]) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut signed = domain.to_vec();
        signed.extend_from_slice(message);
        URL_SAFE_NO_PAD.encode(self.key_pair.sign(&signed).as_ref())
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

/// A key id is 1-64 bytes of `0x21..=0x7E`.
fn is_valid_kid(kid: &str) -> bool {
    let bytes = kid.as_bytes();
    (1..=64).contains(&bytes.len()) && bytes.iter().all(|b| (0x21..=0x7E).contains(b))
}

/// Resolve the public signer from the environment overlay.
///
/// Absent (seed unset or blank) resolves to `Ok(None)`. Every `Err` carries
/// value-free text that never repeats the seed. The key id must be 1-64 bytes
/// of `0x21..=0x7E`, and must name neither the attestation key id nor its
/// `bnaut/` form.
pub(crate) fn resolve_public_signer(
    env: &crate::config::EnvOverlay,
    attestation_key_id: &str,
) -> crate::Result<Option<ProvenancePublicSigner>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    let trimmed = match env.resolve(PROVENANCE_SEED_ENV) {
        None => return Ok(None),
        Some(text) if text.trim().is_empty() => return Ok(None),
        Some(text) => text.trim().to_owned(),
    };
    let seed = STANDARD.decode(trimmed.as_bytes()).map_err(|_| {
        crate::Error::ConfigValidation(format!(
            "{PROVENANCE_SEED_ENV} must be standard base64 of exactly 32 bytes"
        ))
    })?;
    let kid = env.resolve(PROVENANCE_KEY_ID_ENV).ok_or_else(|| {
        crate::Error::ConfigValidation(format!(
            "{PROVENANCE_KEY_ID_ENV} is required when {PROVENANCE_SEED_ENV} is set"
        ))
    })?;
    if !is_valid_kid(&kid) {
        return Err(crate::Error::ConfigValidation(format!(
            "{PROVENANCE_KEY_ID_ENV} must be 1-64 bytes of 0x21..=0x7E"
        )));
    }
    if kid == attestation_key_id || kid == format!("bnaut/{attestation_key_id}") {
        return Err(crate::Error::ConfigValidation(format!(
            "{PROVENANCE_KEY_ID_ENV} must not equal the attestation key id or its bnaut/ form"
        )));
    }
    // The seed's length is the only thing `from_seed_unchecked` rejects, so
    // its refusal is the length check (a short or long seed lands here).
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| {
        crate::Error::ConfigValidation(format!(
            "{PROVENANCE_SEED_ENV} must be standard base64 of exactly 32 bytes"
        ))
    })?;
    Ok(Some(ProvenancePublicSigner { key_pair, kid }))
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
    pub(crate) fn from_json(text: &str) -> Result<Self, TrustSetRefusal> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| TrustSetRefusal::Malformed)?;
        let obj = value.as_object().ok_or(TrustSetRefusal::Malformed)?;
        if let Some(keys_value) = obj.get("keys") {
            let items = keys_value.as_array().ok_or(TrustSetRefusal::Malformed)?;
            let mut keys = BTreeMap::new();
            for item in items {
                let (kid, bytes) = parse_jwk(item)?;
                if keys.insert(kid, bytes).is_some() {
                    return Err(TrustSetRefusal::DuplicateKid);
                }
            }
            Ok(Self { keys })
        } else {
            let (kid, bytes) = parse_jwk(&value)?;
            let mut keys = BTreeMap::new();
            keys.insert(kid, bytes);
            Ok(Self { keys })
        }
    }
}

impl TrustSet {
    /// Verify a [`ProvenancePublicSigner::sign_bytes`] signature made under
    /// `domain` by the key named `kid`.
    pub(crate) fn verify_bytes(
        &self,
        kid: &str,
        domain: &[u8],
        message: &[u8],
        sig: &str,
    ) -> Result<(), VerifyRefusal> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ring::signature::{ED25519, UnparsedPublicKey};
        let key = self.keys.get(kid).ok_or(VerifyRefusal::UnknownKid)?;
        if sig.contains('=') {
            return Err(VerifyRefusal::BadEncoding);
        }
        let sig = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| VerifyRefusal::BadEncoding)?;
        let mut signed = domain.to_vec();
        signed.extend_from_slice(message);
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&signed, &sig)
            .map_err(|_| VerifyRefusal::BadSignature)
    }
}

/// One JWK object to its kid and 32-byte key.
fn parse_jwk(value: &serde_json::Value) -> Result<(String, [u8; 32]), TrustSetRefusal> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let obj = value.as_object().ok_or(TrustSetRefusal::Malformed)?;
    if obj.contains_key("d") {
        return Err(TrustSetRefusal::PrivateMember);
    }
    let kty_ok = obj.get("kty").and_then(serde_json::Value::as_str) == Some("OKP");
    let crv_ok = obj.get("crv").and_then(serde_json::Value::as_str) == Some("Ed25519");
    if !kty_ok || !crv_ok {
        return Err(TrustSetRefusal::NotEd25519);
    }
    let x = obj
        .get("x")
        .and_then(serde_json::Value::as_str)
        .ok_or(TrustSetRefusal::BadX)?;
    if x.contains('=') {
        return Err(TrustSetRefusal::BadX);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| TrustSetRefusal::BadX)?;
    if decoded.len() != 32 {
        return Err(TrustSetRefusal::BadX);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    let kid = obj.get("kid").ok_or(TrustSetRefusal::MissingKid)?;
    let kid = kid.as_str().ok_or(TrustSetRefusal::MalformedKid)?;
    if !is_valid_kid(kid) {
        return Err(TrustSetRefusal::MalformedKid);
    }
    Ok((kid.to_owned(), bytes))
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
    /// A `kid` is not 1-64 bytes of `0x21..=0x7E` (printable ASCII, no space).
    MalformedKid,
}

/// A JSON value parsed without accepting a repeated member at any depth.
struct NoDupValue(serde_json::Value);

/// Parse JSON, refusing a repeated member at any depth: two readers of a
/// signed document must never see different values for one key.
pub(crate) fn from_slice_no_dup(bytes: &[u8]) -> serde_json::Result<serde_json::Value> {
    serde_json::from_slice::<NoDupValue>(bytes).map(|v| v.0)
}

/// Rebuilds a [`serde_json::Value`] while refusing a repeated object key.
struct NoDupVisitor;

impl<'de> serde::de::Visitor<'de> for NoDupVisitor {
    type Value = NoDupValue;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON without duplicate members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number);
        Ok(NoDupValue(number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDupValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(elem) = seq.next_element::<NoDupValue>()? {
            items.push(elem.0);
        }
        Ok(NoDupValue(serde_json::Value::Array(items)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut obj = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate member"));
            }
            let value: NoDupValue = map.next_value()?;
            obj.insert(key, value.0);
        }
        Ok(NoDupValue(serde_json::Value::Object(obj)))
    }
}

impl<'de> serde::Deserialize<'de> for NoDupValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDupVisitor)
    }
}

/// Verify a serialized provenance object against the trust set.
///
/// `prov` is the [`provenance_value`] object: the signed receipt plus its
/// sibling `public_signature` member. Status lines print only a kid found in
/// the trust set, never the payload's untrusted kid.
pub(crate) fn verify_public(
    prov: &serde_json::Value,
    trust: &TrustSet,
    result: Option<&serde_json::Value>,
) -> Result<VerifiedReceipt, VerifyRefusal> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{ED25519, UnparsedPublicKey};
    let sig_obj = prov
        .get("public_signature")
        .ok_or(VerifyRefusal::NoPublicSignature)?;
    let payload_b64 = sig_obj
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyRefusal::BadEncoding)?;
    let sig_b64 = sig_obj
        .get("sig")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyRefusal::BadEncoding)?;
    if payload_b64.contains('=') || sig_b64.contains('=') {
        return Err(VerifyRefusal::BadEncoding);
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyRefusal::BadEncoding)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerifyRefusal::BadEncoding)?;
    if sig_bytes.len() != 64 {
        return Err(VerifyRefusal::BadEncoding);
    }
    let payload = match serde_json::from_slice::<NoDupValue>(&payload_bytes) {
        Ok(wrapped) => wrapped.0,
        Err(error) if error.to_string().contains("duplicate member") => {
            return Err(VerifyRefusal::DuplicateMember);
        }
        Err(_) => return Err(VerifyRefusal::BadEncoding),
    };
    let kid = payload
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyRefusal::UnknownKid)?;
    let key = trust.keys.get(kid).ok_or(VerifyRefusal::UnknownKid)?;
    let mut message = DOMAIN_TAG.to_vec();
    message.extend_from_slice(&payload_bytes);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&message, &sig_bytes)
        .map_err(|_| VerifyRefusal::BadSignature)?;
    let version_ok = payload.get("v").and_then(serde_json::Value::as_u64) == Some(1);
    let alg_ok = payload.get("alg").and_then(serde_json::Value::as_str) == Some("EdDSA");
    if !version_ok || !alg_ok {
        return Err(VerifyRefusal::BadProfile);
    }
    if prov.get("receipt") != payload.get("receipt") {
        return Err(VerifyRefusal::OuterReceiptMismatch);
    }
    let receipt_value = payload.get("receipt").ok_or(VerifyRefusal::BadProfile)?;
    let receipt: RuntimeProvenanceReceipt =
        serde_json::from_value(receipt_value.clone()).map_err(|_| VerifyRefusal::BadProfile)?;
    match payload.get("result_sha256") {
        None | Some(serde_json::Value::Null) => Ok(VerifiedReceipt {
            status: VerifyStatus::Unbound,
            kid: kid.to_owned(),
            receipt,
        }),
        Some(serde_json::Value::String(expected)) => match result {
            None => Ok(VerifiedReceipt {
                status: VerifyStatus::SignatureOnly,
                kid: kid.to_owned(),
                receipt,
            }),
            Some(offered) => match crate::security::signature_chain::content_digest(offered) {
                Ok(computed) if computed == *expected => Ok(VerifiedReceipt {
                    status: VerifyStatus::Bound,
                    kid: kid.to_owned(),
                    receipt,
                }),
                Ok(_) => Err(VerifyRefusal::ResultMismatch),
                Err(_) => Err(VerifyRefusal::ResultUnhashable),
            },
        },
        Some(_) => Err(VerifyRefusal::BadProfile),
    }
}

/// Serialize `signed` and, when `public` is `Some`, add its `public_signature`.
pub(crate) fn provenance_value(
    signed: &SignedResultProvenance,
    public: Option<(&ProvenancePublicSigner, Option<&serde_json::Value>)>,
) -> serde_json::Value {
    let mut value = serde_json::to_value(signed).unwrap_or(serde_json::Value::Null);
    if let Some((signer, result)) = public {
        let sig = signer.sign_receipt(&signed.receipt, result);
        if let Some(obj) = value.as_object_mut() {
            let sig_value = serde_json::to_value(sig).unwrap_or(serde_json::Value::Null);
            obj.insert("public_signature".to_owned(), sig_value);
        }
    }
    value
}

/// The public signer the configuration at `config` names, if any. Errors
/// are value-free text.
pub(crate) fn configured_signer(
    config: Option<&std::path::Path>,
) -> Result<Option<ProvenancePublicSigner>, String> {
    let loaded = crate::config::Config::load(config).map_err(|e| e.to_string())?;
    let overlay = loaded.env_overlay();
    let attestation = overlay
        .resolve(crate::attestation::ATTESTATION_KEY_ID_ENV)
        .unwrap_or_else(|| "gateway".to_owned());
    resolve_public_signer(&overlay, &attestation).map_err(|e| e.to_string())
}

#[path = "provenance_public_cli.rs"]
mod cli;
pub use cli::run_provenance_command;

#[cfg(test)]
#[path = "provenance_public_kid_tests.rs"]
mod kid_tests;
#[cfg(test)]
#[path = "provenance_public_tests.rs"]
mod tests;
