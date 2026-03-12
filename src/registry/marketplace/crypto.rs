//! Cryptographic primitives for plugin marketplace signatures.
//!
//! Ed25519 signature and public key newtypes with structural validation,
//! plus [`PluginManifest`] checksum computation and signature verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

// ── Ed25519 signature newtype ────────────────────────────────────────────────

/// A 64-byte Ed25519 signature stored as a 128-character lowercase hex string.
///
/// Designed to be a zero-overhead wrapper today, replaceable with a concrete
/// `ed25519_dalek::Signature` if that crate is added as a dependency later.
///
/// The inner string is validated at construction — it must be exactly 128
/// lowercase hex characters (representing 64 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature(String);

impl Ed25519Signature {
    /// Parse a hex-encoded Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `hex` is not exactly 128 lowercase hex
    /// characters (i.e. does not represent 64 bytes).
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 128 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Config(format!(
                "invalid Ed25519 signature: expected 128 hex chars, got {}",
                hex.len()
            )));
        }
        Ok(Self(hex.to_ascii_lowercase()))
    }

    /// Return the raw hex representation.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Decode to raw bytes.
    ///
    /// # Panics
    ///
    /// Never panics — the hex string is validated at construction.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Safe: validated at construction.
        (0..64)
            .map(|i| u8::from_str_radix(&self.0[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }
}

// ── Ed25519 public key newtype ───────────────────────────────────────────────

/// A 32-byte Ed25519 public key stored as a 64-character lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicKey(String);

impl Ed25519PublicKey {
    /// Parse a hex-encoded Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `hex` is not exactly 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Config(format!(
                "invalid Ed25519 public key: expected 64 hex chars, got {}",
                hex.len()
            )));
        }
        Ok(Self(hex.to_ascii_lowercase()))
    }

    /// Return the raw hex representation.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

// ── Core domain types ────────────────────────────────────────────────────────

/// Full description of a plugin as published to the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    /// Unique plugin identifier (e.g. `"stripe-payments"`)
    pub name: String,
    /// Semantic version string (e.g. `"1.2.3"`)
    pub version: String,
    /// Human-readable description shown in search results
    pub description: String,
    /// Publisher / author name
    pub author: String,
    /// Capability names that this plugin exposes
    pub capabilities: Vec<String>,
    /// SHA-256 hex digest of the plugin archive
    pub checksum: String,
    /// Optional Ed25519 publisher signature over the manifest JSON (sans this field)
    pub signature: Option<Ed25519Signature>,
}

/// Canonical content used as the checksum / signature payload.
///
/// Excludes `checksum` and `signature` to avoid circular dependencies:
/// the checksum covers the *content* of the manifest, not its metadata.
#[derive(Serialize)]
pub(super) struct CanonicalContent<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) description: &'a str,
    pub(super) author: &'a str,
    pub(super) capabilities: &'a [String],
}

impl PluginManifest {
    /// Compute the SHA-256 hex digest of the canonical manifest content.
    ///
    /// The canonical form covers `name`, `version`, `description`, `author`,
    /// and `capabilities` only -- `checksum` and `signature` are excluded so
    /// the digest is stable and free of circular dependency.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if serialisation fails (cannot happen in practice
    /// with well-formed fields, but is kept for correctness).
    pub fn compute_checksum(&self) -> Result<String> {
        let canonical = CanonicalContent {
            name: &self.name,
            version: &self.version,
            description: &self.description,
            author: &self.author,
            capabilities: &self.capabilities,
        };
        let bytes = serde_json::to_vec(&canonical)?;
        let digest = Sha256::digest(&bytes);
        Ok(hex::encode(digest))
    }

    /// Verify that [`PluginManifest::checksum`] matches the manifest content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the checksum does not match.
    pub fn verify_checksum(&self) -> Result<()> {
        let expected = self.compute_checksum()?;
        if expected != self.checksum {
            return Err(Error::Config(format!(
                "checksum mismatch for plugin '{}': expected {expected}, got {}",
                self.name, self.checksum
            )));
        }
        Ok(())
    }
}

/// A plugin that has been installed to the local filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    /// The manifest as downloaded from the marketplace
    pub manifest: PluginManifest,
    /// Absolute path to the installed plugin directory
    pub install_path: std::path::PathBuf,
    /// When the plugin was installed (UTC)
    pub installed_at: chrono::DateTime<chrono::Utc>,
}

// ── Signature verification ───────────────────────────────────────────────────

/// Verify an Ed25519 signature over a [`PluginManifest`].
///
/// The signed payload is the canonical JSON bytes produced by
/// [`PluginManifest::compute_checksum`] (i.e. the manifest with
/// `signature = None`).
///
/// # Note on crypto backend
///
/// This implementation currently validates the *structural* properties of the
/// signature without performing actual elliptic-curve verification.  To wire up
/// real verification, add `ed25519-dalek` to `[dependencies]` and replace the
/// body of this function with a call to `dalek::VerifyingKey::verify_strict`.
///
/// # Errors
///
/// - [`Error::Config`] when the manifest carries no signature.
/// - [`Error::Config`] when signature or key encoding is invalid.
pub fn verify_signature(manifest: &PluginManifest, public_key: &Ed25519PublicKey) -> Result<bool> {
    let sig = manifest.signature.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "plugin '{}' has no signature to verify",
            manifest.name
        ))
    })?;

    // Canonical payload = content fields only (matches compute_checksum canonical form).
    let canonical = CanonicalContent {
        name: &manifest.name,
        version: &manifest.version,
        description: &manifest.description,
        author: &manifest.author,
        capabilities: &manifest.capabilities,
    };
    let _payload = serde_json::to_vec(&canonical)?;

    // Structural sanity checks (real crypto would go here).
    let sig_bytes = sig.to_bytes();
    let _key_hex = public_key.as_hex();

    // Placeholder: a real impl would be:
    //   let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)?;
    //   let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    //   key.verify_strict(&payload, &sig).map(|_| true).map_err(|e| Error::Config(e.to_string()))
    //
    // For now: accept any structurally valid 64-byte signature.
    Ok(sig_bytes.len() == 64)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_sig_hex() -> String {
        "a".repeat(128)
    }

    fn valid_key_hex() -> String {
        "b".repeat(64)
    }

    fn make_manifest(name: &str) -> PluginManifest {
        PluginManifest {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: format!("Plugin {name}"),
            author: "test-author".to_string(),
            capabilities: vec!["cap_a".to_string(), "cap_b".to_string()],
            checksum: String::new(),
            signature: None,
        }
    }

    fn make_manifest_with_checksum(name: &str) -> PluginManifest {
        let mut m = make_manifest(name);
        m.checksum = m.compute_checksum().unwrap();
        m
    }

    // ── Ed25519Signature ─────────────────────────────────────────────────────

    #[test]
    fn signature_from_hex_accepts_valid_128_char_hex() {
        let sig = Ed25519Signature::from_hex(&valid_sig_hex());
        assert!(sig.is_ok());
    }

    #[test]
    fn signature_from_hex_rejects_short_string() {
        let result = Ed25519Signature::from_hex("aabbcc");
        assert!(result.is_err());
    }

    #[test]
    fn signature_from_hex_rejects_non_hex_chars() {
        let bad = "z".repeat(128);
        let result = Ed25519Signature::from_hex(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn signature_to_bytes_produces_64_bytes() {
        let sig = Ed25519Signature::from_hex(&valid_sig_hex()).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn signature_round_trip_preserves_hex() {
        let hex = "deadbeef".repeat(16);
        let sig = Ed25519Signature::from_hex(&hex).unwrap();
        assert_eq!(sig.as_hex(), hex.to_ascii_lowercase());
    }

    // ── Ed25519PublicKey ─────────────────────────────────────────────────────

    #[test]
    fn public_key_from_hex_accepts_valid_64_char_hex() {
        let key = Ed25519PublicKey::from_hex(&valid_key_hex());
        assert!(key.is_ok());
    }

    #[test]
    fn public_key_from_hex_rejects_wrong_length() {
        assert!(Ed25519PublicKey::from_hex("abcd").is_err());
        assert!(Ed25519PublicKey::from_hex(&"a".repeat(65)).is_err());
    }

    // ── PluginManifest checksum ─────────────────────────────────────────────

    #[test]
    fn manifest_checksum_is_stable_regardless_of_signature_field() {
        let mut m1 = make_manifest("alpha");
        m1.checksum = m1.compute_checksum().unwrap();

        let mut m2 = m1.clone();
        m2.signature = Some(Ed25519Signature::from_hex(&valid_sig_hex()).unwrap());

        let c1 = m1.compute_checksum().unwrap();
        let c2 = m2.compute_checksum().unwrap();

        assert_eq!(c1, c2);
    }

    #[test]
    fn manifest_verify_checksum_passes_when_correct() {
        let m = make_manifest_with_checksum("beta");
        assert!(m.verify_checksum().is_ok());
    }

    #[test]
    fn manifest_verify_checksum_fails_when_tampered() {
        let mut m = make_manifest_with_checksum("gamma");
        m.checksum = "0".repeat(64);
        assert!(m.verify_checksum().is_err());
    }

    #[test]
    fn manifest_compute_checksum_produces_64_char_hex() {
        let m = make_manifest("delta");
        let cs = m.compute_checksum().unwrap();
        assert_eq!(cs.len(), 64);
        assert!(cs.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn manifest_different_names_produce_different_checksums() {
        let m1 = make_manifest("plugin-a");
        let m2 = make_manifest("plugin-b");
        assert_ne!(
            m1.compute_checksum().unwrap(),
            m2.compute_checksum().unwrap()
        );
    }

    // ── verify_signature ─────────────────────────────────────────────────────

    #[test]
    fn verify_signature_accepts_structurally_valid_signature() {
        let mut m = make_manifest_with_checksum("signed-plugin");
        m.signature = Some(Ed25519Signature::from_hex(&valid_sig_hex()).unwrap());
        let key = Ed25519PublicKey::from_hex(&valid_key_hex()).unwrap();

        let result = verify_signature(&m, &key);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn verify_signature_returns_error_when_no_signature_present() {
        let m = make_manifest_with_checksum("unsigned");
        let key = Ed25519PublicKey::from_hex(&valid_key_hex()).unwrap();

        let result = verify_signature(&m, &key);
        assert!(result.is_err());
    }
}
