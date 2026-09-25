// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API keys, configured as sha256 digests with an optional expiry (E4).
//!
//! The gateway never needs a key's plaintext after startup: it hashes the
//! presented key and compares digests. So the config stores only the digest,
//! and a plaintext `key` is refused by name rather than silently hashed.

use std::env;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::auth::AuthConfig;
use crate::config::EnvOverlay;
use crate::{Error, Result};

/// The prefix every configured digest carries.
const DIGEST_PREFIX: &str = "sha256:";

/// The `sha256:<hex>` digest `auth.api_keys[].key_sha256` stores for `key`.
///
/// Public so the `mcp-gateway hash-key` binary shares this one definition of
/// the format with the loader instead of re-deriving it.
#[must_use]
pub fn api_key_digest_spec(key: &[u8]) -> String {
    format!("{DIGEST_PREFIX}{}", crate::hashing::sha256_hex(key))
}

/// Parse `sha256:` followed by exactly 64 lowercase hex characters.
#[must_use]
pub(crate) fn parse_api_key_digest(spec: &str) -> Option<[u8; 32]> {
    let hex_part = spec.strip_prefix(DIGEST_PREFIX)?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut digest).ok()?;
    Some(digest)
}

/// API key configuration for multi-client access.
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Legacy plaintext key. Parsed only so the load can refuse it by name;
    /// never written back.
    #[serde(default, skip_serializing)]
    pub key: Option<String>,
    /// `sha256:<64 lowercase hex>`, or `env:VAR` holding that form. Produce it
    /// with `mcp-gateway hash-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sha256: Option<String>,
    /// Optional RFC 3339 expiry. A matched key past it is refused with 401.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Name for this client: non-empty, unique across `api_keys`, and the
    /// key's identity-grant subject (`api_key:<name>`).
    #[serde(default)]
    pub name: String,
    /// Rate limit (requests per minute, 0 = unlimited).
    #[serde(default)]
    pub rate_limit: u32,
    /// Allowed backends. `["*"]` is all; empty or absent is none.
    #[serde(default)]
    pub backends: Vec<String>,
    /// Allowed tools (if Some, ONLY these tools are accessible).
    /// Supports glob patterns. Acts as an allowlist.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (if Some, these tools are blocked).
    /// Supports glob patterns. Acts as a blocklist on top of global policy.
    #[serde(default)]
    pub denied_tools: Option<Vec<String>>,
    /// Whether this API key can use admin-only HTTP UI and management tools.
    #[serde(default)]
    pub admin: bool,
}

// Manual `Debug` (CWE-532): a derived one printed the key. The digest is not a
// secret, but it is an offline-guessing target for a short key, so it stays
// out of logs too.
impl std::fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("ApiKeyConfig")
            .field("key", &redact(&self.key))
            .field("key_sha256", &redact(&self.key_sha256))
            .field("expires_at", &self.expires_at)
            .field("name", &self.name)
            .field("rate_limit", &self.rate_limit)
            .field("backends", &self.backends)
            .field("allowed_tools", &self.allowed_tools)
            .field("denied_tools", &self.denied_tools)
            .field("admin", &self.admin)
            .finish()
    }
}

impl ApiKeyConfig {
    /// The configured digest as raw bytes, expanding an `env:` reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest is absent, an `env:` reference cannot be
    /// resolved, or the value is not `sha256:<64 lowercase hex>`. The error
    /// names the field or variable, never the value.
    pub fn resolve_digest(&self) -> Result<[u8; 32]> {
        let name = &self.name;
        let spec = self.key_sha256.as_deref().ok_or_else(|| {
            Error::ConfigValidation(format!("auth.api_keys['{name}'] has no key_sha256"))
        })?;
        let value = match spec.strip_prefix("env:") {
            Some(var) => env::var(var).map_err(|_| {
                Error::ConfigValidation(format!(
                    "auth.api_keys['{name}'].key_sha256 references missing environment variable '{var}'"
                ))
            })?,
            None => spec.to_string(),
        };
        parse_api_key_digest(&value).ok_or_else(|| malformed(name, spec))
    }

    /// True when `now` is at or past `expires_at`.
    #[must_use]
    pub(crate) fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }
}

fn malformed(name: &str, spec: &str) -> Error {
    match spec.strip_prefix("env:") {
        Some(var) => Error::ConfigValidation(format!(
            "auth.api_keys['{name}'].key_sha256 references env:{var}, whose value is not a \
             sha256:<64 lowercase hex> digest; store the output of `mcp-gateway hash-key` in \
             {var}, not the key itself"
        )),
        None => Error::ConfigValidation(format!(
            "auth.api_keys['{name}'].key_sha256 must be sha256: followed by 64 lowercase hex \
             characters, the output of `mcp-gateway hash-key`"
        )),
    }
}

impl AuthConfig {
    /// Refuse API key material the gateway will not hold (E4, APIKEY.1).
    ///
    /// Runs before any `env:` inlining and before any other reader touches the
    /// value, so a plaintext `key` is refused by name, its variable is never
    /// read, and an `env:` digest error can still name its variable. An unset
    /// variable is left to the required-reference check.
    pub(crate) fn validate_api_key_material(&self, overlay: &EnvOverlay) -> Result<()> {
        for key in &self.api_keys {
            let name = &key.name;
            match (&key.key, &key.key_sha256) {
                (Some(_), Some(_)) => {
                    return Err(Error::ConfigValidation(format!(
                        "auth.api_keys['{name}'] sets both key and key_sha256; delete key, \
                         which holds a plaintext key"
                    )));
                }
                (Some(_), None) => {
                    return Err(Error::ConfigValidation(format!(
                        "auth.api_keys['{name}'].key holds a plaintext key; run `mcp-gateway \
                         hash-key` and set key_sha256"
                    )));
                }
                (None, None) => {
                    return Err(Error::ConfigValidation(format!(
                        "auth.api_keys['{name}'] has no key_sha256; run `mcp-gateway hash-key` \
                         and set key_sha256"
                    )));
                }
                (None, Some(spec)) => {
                    let value = match spec.strip_prefix("env:") {
                        Some(var) => match overlay.resolve(var) {
                            Some(value) => value,
                            None => continue,
                        },
                        None => spec.clone(),
                    };
                    if parse_api_key_digest(&value).is_none() {
                        return Err(malformed(name, spec));
                    }
                }
            }
        }
        Ok(())
    }

    /// One WARN per key that has already expired. Load does not fail on it:
    /// one lapsed key must not keep the gateway from starting.
    pub(crate) fn warn_expired_keys(&self, now: DateTime<Utc>) {
        for key in self.api_keys.iter().filter(|k| k.is_expired_at(now)) {
            tracing::warn!(key = %key.name, "API key has expired and will be refused");
        }
    }
}
