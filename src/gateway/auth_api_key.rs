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
}

impl std::fmt::Debug for ResolvedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedApiKey")
            // The 12 hex characters of `principal`, never more of the digest.
            .field(
                "digest",
                &format!("<redacted:{}>", hex::encode(&self.digest[..6])),
            )
            .field("expires_at", &self.expires_at)
            .field("name", &self.name)
            .field("rate_limit", &self.rate_limit)
            .field("backends", &self.backends)
            .field("allowed_tools", &self.allowed_tools)
            .field("denied_tools", &self.denied_tools)
            .field("admin", &self.admin)
            .finish_non_exhaustive()
    }
}
