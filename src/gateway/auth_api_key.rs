// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A configured API key after resolution: its digest, never the key (E4).

use super::QuotaPrincipal;

/// Resolved API key with expanded values
#[derive(Clone)]
pub struct ResolvedApiKey {
    /// sha256 of the key. The plaintext is never held (E4).
    pub digest: [u8; 32],
    /// Past this instant a matching key is refused.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) quota_principal: QuotaPrincipal,
    /// Client name
    pub name: String,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    /// Allowed backends
    pub backends: Vec<String>,
    /// Allowed tools (allowlist if Some)
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (blocklist if Some)
    pub denied_tools: Option<Vec<String>>,
    /// Admin-level UI and management tool access.
    pub admin: bool,
    /// Configured `kind: personal`: one holder, so a per-caller identity.
    pub(super) personal: bool,
    /// The key's principal, from the one derivation
    /// (`ApiKeyConfig::principal_from`): stable across rotations (ADR-022).
    pub(crate) principal: super::InternalPrincipal,
    /// The digest before the last rotation and the end of its grace.
    pub(crate) previous: Option<PreviousDigest>,
}

/// A rotated key's previous digest, accepted until `expires_at` (ADR-022).
#[derive(Clone)]
pub(crate) struct PreviousDigest {
    /// sha256 of the previous key. The plaintext is never held (E4).
    pub(crate) digest: [u8; 32],
    /// The end of the grace: at and after it the previous digest is refused.
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for PreviousDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreviousDigest")
            .field("digest", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for ResolvedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedApiKey")
            // Not even a prefix: the digest is the stored principal (MIK-8697).
            .field("digest", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("name", &self.name)
            .field("rate_limit", &self.rate_limit)
            .field("backends", &self.backends)
            .field("allowed_tools", &self.allowed_tools)
            .field("denied_tools", &self.denied_tools)
            .field("admin", &self.admin)
            .field("personal", &self.personal)
            // The principal is persisted as owner keys; out of logs like the digest.
            .field("principal", &"<redacted>")
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}
