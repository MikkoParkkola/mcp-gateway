//! JWKS endpoint — expose gateway's own EC key pair.
//!
//! The `/.well-known/jwks.json` endpoint allows backends to independently
//! verify agent tokens signed by the gateway's private key.
//!
//! # Key Type
//!
//! An in-process ECDSA P-256 key pair is generated at startup and cached for
//! the lifetime of the process.  Key rotation is supported via
//! [`GatewayKeyPair::rotate`].
//!
//! P-256 (ES256) is preferred over RSA because:
//! - Faster key generation
//! - Smaller keys / signatures
//! - `rcgen` (already a dependency) fully supports it
//!
//! # Endpoint
//!
//! `GET /.well-known/jwks.json` returns a standard JWK Set:
//!
//! ```json
//! {
//!   "keys": [
//!     {
//!       "kty": "EC",
//!       "use": "sig",
//!       "alg": "ES256",
//!       "crv": "P-256",
//!       "kid": "<key-id>",
//!       "x": "<base64url x-coordinate>",
//!       "y": "<base64url y-coordinate>"
//!     }
//!   ]
//! }
//! ```

use std::sync::{Arc, RwLock};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::KeyPair as RcgenKeyPair;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single JWK entry (EC public key, signing use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (always `"EC"` for this implementation).
    pub kty: String,
    /// Intended use (always `"sig"` for signing keys).
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm (always `"ES256"`).
    pub alg: String,
    /// Curve (always `"P-256"`).
    pub crv: String,
    /// Key identifier (UUID v4).
    pub kid: String,
    /// Base64url-encoded x-coordinate.
    pub x: String,
    /// Base64url-encoded y-coordinate.
    pub y: String,
}

/// JWK Set response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// The list of JWK entries.
    pub keys: Vec<Jwk>,
}

/// Information for a generated EC key pair.
#[derive(Debug, Clone)]
pub struct GatewayKeyInfo {
    /// Unique key identifier (UUID v4).
    pub kid: String,
    /// PEM-encoded PKCS#8 private key (for ES256 signing).
    pub private_key_pem: String,
    /// Base64url-encoded x-coordinate of the public key.
    pub x: String,
    /// Base64url-encoded y-coordinate of the public key.
    pub y: String,
}

/// Thread-safe, rotatable EC key pair for the gateway.
#[derive(Clone)]
pub struct GatewayKeyPair {
    inner: Arc<RwLock<GatewayKeyInfo>>,
}

impl GatewayKeyPair {
    /// Generate a new ECDSA P-256 key pair.
    ///
    /// # Errors
    ///
    /// Returns an error string if key generation fails.
    pub fn generate() -> Result<Self, String> {
        let key_info = generate_key_info()?;
        Ok(Self {
            inner: Arc::new(RwLock::new(key_info)),
        })
    }

    /// Rotate the key pair — generates a new one and atomically replaces the old.
    ///
    /// Returns the new `kid`.
    ///
    /// # Errors
    ///
    /// Returns an error string if key generation or lock acquisition fails.
    pub fn rotate(&self) -> Result<String, String> {
        let new_info = generate_key_info()?;
        let new_kid = new_info.kid.clone();
        {
            let mut guard = self.inner.write().map_err(|e| e.to_string())?;
            *guard = new_info;
        }
        Ok(new_kid)
    }

    /// Build the JWKS response body.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned (indicates a prior panic
    /// on another thread while holding a write lock, which is a fatal condition).
    pub fn jwks(&self) -> JwkSet {
        let guard = self.inner.read().expect("RwLock poisoned");
        JwkSet {
            keys: vec![Jwk {
                kty: "EC".to_string(),
                use_: "sig".to_string(),
                alg: "ES256".to_string(),
                crv: "P-256".to_string(),
                kid: guard.kid.clone(),
                x: guard.x.clone(),
                y: guard.y.clone(),
            }],
        }
    }

    /// Return the current key info (for token signing).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn key_info(&self) -> GatewayKeyInfo {
        self.inner.read().expect("RwLock poisoned").clone()
    }
}

/// Generate a fresh ECDSA P-256 key pair and extract its public-key components.
fn generate_key_info() -> Result<GatewayKeyInfo, String> {
    // `KeyPair::generate()` defaults to ECDSA P-256 in rcgen 0.13.
    let key_pair = RcgenKeyPair::generate()
        .map_err(|e| format!("Key generation failed: {e}"))?;

    let kid = Uuid::new_v4().to_string();
    let private_key_pem = key_pair.serialize_pem();
    let der = key_pair.public_key_der();

    let (x, y) = extract_ec_public_components(&der)?;

    Ok(GatewayKeyInfo {
        kid,
        private_key_pem,
        x,
        y,
    })
}

/// Extract the EC public key x/y coordinates from a DER-encoded
/// `SubjectPublicKeyInfo` for P-256 (uncompressed point, 65 bytes).
///
/// Layout: `04 || x (32 bytes) || y (32 bytes)` inside the BIT STRING.
fn extract_ec_public_components(der: &[u8]) -> Result<(String, String), String> {
    let bitstring_payload = parse_spki_bitstring_payload(der)
        .ok_or("Failed to parse SubjectPublicKeyInfo BIT STRING")?;

    // P-256 uncompressed point: 0x04 prefix + 32 bytes x + 32 bytes y = 65 bytes.
    if bitstring_payload.len() < 65 || bitstring_payload[0] != 0x04 {
        return Err(format!(
            "Unexpected EC point format: len={}, prefix=0x{:02x}",
            bitstring_payload.len(),
            bitstring_payload.first().copied().unwrap_or(0)
        ));
    }

    let x = URL_SAFE_NO_PAD.encode(&bitstring_payload[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&bitstring_payload[33..65]);
    Ok((x, y))
}

// ── Minimal DER helpers ───────────────────────────────────────────────────────

fn der_read_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        return Some((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || data.len() < 1 + num_bytes {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..=num_bytes] {
        len = (len << 8) | (b as usize);
    }
    Some((len, 1 + num_bytes))
}

/// Read a TLV (tag, length, value) at the start of `data`.
/// Returns `(tag, value_slice, remaining)`.
fn der_read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (len, hdr_bytes) = der_read_len(&data[1..])?;
    let start = 1 + hdr_bytes;
    let end = start.checked_add(len)?;
    if data.len() < end {
        return None;
    }
    Some((tag, &data[start..end], &data[end..]))
}

/// Skip over the `AlgorithmIdentifier` sequence and return the BIT STRING payload.
fn parse_spki_bitstring_payload(der: &[u8]) -> Option<&[u8]> {
    let (tag, outer, _) = der_read_tlv(der)?;
    if tag != 0x30 { return None; } // outer SEQUENCE

    // Skip `AlgorithmIdentifier` SEQUENCE.
    let (_, _alg_seq, rest) = der_read_tlv(outer)?;

    // BIT STRING
    let (tag2, bit_string, _) = der_read_tlv(rest)?;
    if tag2 != 0x03 { return None; }

    // First byte of BIT STRING is the number of unused bits (always 0 for EC).
    if bit_string.is_empty() { return None; }
    Some(&bit_string[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_pair_succeeds() {
        let kp = GatewayKeyPair::generate().expect("key generation should succeed");
        let info = kp.key_info();
        assert!(!info.kid.is_empty());
        assert!(!info.x.is_empty());
        assert!(!info.y.is_empty());
        assert!(info.private_key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn jwks_contains_one_ec_key() {
        let kp = GatewayKeyPair::generate().unwrap();
        let jwks = kp.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "EC");
        assert_eq!(key.use_, "sig");
        assert_eq!(key.alg, "ES256");
        assert_eq!(key.crv, "P-256");
        assert!(!key.kid.is_empty());
        assert!(!key.x.is_empty());
        assert!(!key.y.is_empty());
    }

    #[test]
    fn jwks_serializes_to_valid_json() {
        let kp = GatewayKeyPair::generate().unwrap();
        let jwks = kp.jwks();
        let json = serde_json::to_string(&jwks).unwrap();
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(json.contains("\"use\":\"sig\""));
        assert!(json.contains("\"crv\":\"P-256\""));
    }

    #[test]
    fn rotate_changes_kid() {
        let kp = GatewayKeyPair::generate().unwrap();
        let old_kid = kp.key_info().kid.clone();
        let new_kid = kp.rotate().unwrap();
        assert_ne!(old_kid, new_kid);
        assert_eq!(kp.key_info().kid, new_kid);
    }

    #[test]
    fn rotate_changes_key_material() {
        let kp = GatewayKeyPair::generate().unwrap();
        let old_x = kp.key_info().x.clone();
        kp.rotate().unwrap();
        let new_x = kp.key_info().x.clone();
        // With overwhelming probability a new EC key will have a different x.
        assert_ne!(old_x, new_x);
    }

    #[test]
    fn clone_shares_state() {
        let kp = GatewayKeyPair::generate().unwrap();
        let kp2 = kp.clone();
        let old_kid = kp.key_info().kid.clone();
        kp.rotate().unwrap();
        // Both clones should see the new kid since they share the Arc<RwLock<>>.
        assert_ne!(kp2.key_info().kid, old_kid);
    }
}
