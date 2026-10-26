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
    /// The principal the key records, written at its first rotation
    /// (ADR-022). `None` for a key never rotated: [`Self::principal`] then
    /// derives it from the current digest, so a new digest under an old name
    /// never inherits the old identity.
    pub(crate) explicit_principal: Option<String>,
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

impl ResolvedApiKey {
    /// The key's principal, by the one derivation: the recorded one when the
    /// key was rotated, otherwise derived from its current digest. Computed,
    /// never stored, so it cannot fall out of step with the digest.
    // ponytail: allocates one 12-character String per call (once per
    // authenticated request); if auth ever shows in a profile, make the
    // fields private and derive the principal once in a constructor.
    #[must_use]
    pub(crate) fn principal(&self) -> super::InternalPrincipal {
        super::configured_key_principal(self.explicit_principal.as_deref(), &self.digest)
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
            .field(
                "explicit_principal",
                &self.explicit_principal.as_ref().map(|_| "<redacted>"),
            )
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}
