//! Remote MCP server provenance and signature verification.
//!
//! Capability YAML hash pinning protects local files. Remote MCP backends need a
//! separate trust boundary because their live server identity can change without
//! modifying the local capability or gateway config. This module verifies a
//! signed metadata envelope that binds a backend name, transport, URL, subject,
//! issuer, and issuance timestamp to a trusted publisher key.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Remote server signature-verification policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RemoteServerSigningConfig {
    /// Require signed provenance metadata for every enabled HTTP/A2A backend.
    pub require_for_remote_backends: bool,
    /// Trusted publisher keys keyed by `key_id`.
    pub trusted_keys: BTreeMap<String, TrustedRemoteServerKeyConfig>,
    /// Signed provenance metadata keyed by backend name.
    pub backends: BTreeMap<String, RemoteServerProvenanceConfig>,
}

/// Trusted key used to verify remote server provenance signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedRemoteServerKeyConfig {
    /// Signature algorithm for this key.
    pub algorithm: RemoteServerSignatureAlgorithm,
    /// Base64-encoded raw public key bytes for the selected algorithm.
    pub public_key: String,
}

/// Supported remote server provenance signature algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteServerSignatureAlgorithm {
    /// Ed25519 over the canonical metadata payload.
    Ed25519,
}

/// Signed provenance metadata for a configured remote backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteServerProvenanceConfig {
    /// Stable server identity claim, such as a SPIFFE ID or publisher-owned URI.
    pub subject: String,
    /// Publisher or authority that issued this metadata envelope.
    pub issuer: String,
    /// Issuance timestamp recorded by the publisher.
    pub issued_at: String,
    /// Trusted key identifier used to verify `signature`.
    pub key_id: String,
    /// Base64-encoded signature over the canonical metadata payload.
    pub signature: String,
}

#[derive(Serialize)]
struct RemoteServerProvenancePayload<'a> {
    backend: &'a str,
    transport: &'a str,
    url: &'a str,
    subject: &'a str,
    issuer: &'a str,
    issued_at: &'a str,
}

/// Verify a remote backend's signed provenance metadata.
///
/// The signature covers canonical JSON with these fields in order:
/// `backend`, `transport`, `url`, `subject`, `issuer`, `issued_at`.
///
/// # Errors
///
/// Returns [`Error::ConfigValidation`] when required metadata is missing,
/// references an unknown key, contains malformed base64, or has an invalid
/// signature.
pub fn verify_remote_server_provenance(
    backend: &str,
    transport: &str,
    url: &str,
    metadata: &RemoteServerProvenanceConfig,
    policy: &RemoteServerSigningConfig,
) -> Result<()> {
    let key = policy.trusted_keys.get(&metadata.key_id).ok_or_else(|| {
        Error::ConfigValidation(format!(
            "remote server provenance for backend '{backend}' references unknown key_id '{}'",
            metadata.key_id
        ))
    })?;

    let payload = RemoteServerProvenancePayload {
        backend,
        transport,
        url,
        subject: &metadata.subject,
        issuer: &metadata.issuer,
        issued_at: &metadata.issued_at,
    };
    let payload = serde_json::to_vec(&payload)?;

    match key.algorithm {
        RemoteServerSignatureAlgorithm::Ed25519 => {
            verify_ed25519_signature(backend, &payload, &key.public_key, &metadata.signature)
        }
    }
}

fn verify_ed25519_signature(
    backend: &str,
    payload: &[u8],
    public_key: &str,
    signature: &str,
) -> Result<()> {
    let key_bytes = decode_base64_field(backend, "public_key", public_key)?;
    if key_bytes.len() != 32 {
        return Err(Error::ConfigValidation(format!(
            "remote server provenance public_key for backend '{backend}' must decode to 32 bytes"
        )));
    }

    let sig_bytes = decode_base64_field(backend, "signature", signature)?;
    if sig_bytes.len() != 64 {
        return Err(Error::ConfigValidation(format!(
            "remote server provenance signature for backend '{backend}' must decode to 64 bytes"
        )));
    }

    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key_bytes);
    public_key.verify(payload, &sig_bytes).map_err(|_| {
        Error::ConfigValidation(format!(
            "remote server provenance signature invalid for backend '{backend}'"
        ))
    })
}

fn decode_base64_field(backend: &str, field: &str, value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|e| {
        Error::ConfigValidation(format!(
            "remote server provenance {field} for backend '{backend}' is not valid base64: {e}"
        ))
    })
}
