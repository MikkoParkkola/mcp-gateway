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
    /// The approver a CLI login key is bound to; `None` for every other key.
    pub(crate) approved_by: Option<crate::config::ApiKeyBinding>,
    /// The host a CLI login key reported, for display only.
    pub(crate) cli_host: Option<String>,
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

/// ADR-022: no two credential digests are equal, among every key's current and
/// previous digest and the bearer's, so one presented secret can match at most
/// one credential, whatever principals they carry.
///
/// The error names the two credentials, never a secret, digest or principal.
pub(crate) fn refuse_shared_digests<'a>(
    bearer: Option<&str>,
    keys: impl IntoIterator<Item = (&'a str, [u8; 32], Option<[u8; 32]>)>,
) -> crate::Result<()> {
    let bearer = bearer.map(|token| {
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()).into();
        ("auth.bearer_token".to_owned(), digest)
    });
    let keys = keys.into_iter().flat_map(|(name, current, previous)| {
        let current = (format!("auth.api_keys['{name}'].key_sha256"), current);
        let previous = previous.map(|digest| {
            (
                format!("auth.api_keys['{name}'].previous_key_sha256"),
                digest,
            )
        });
        std::iter::once(current).chain(previous)
    });
    let mut seen = std::collections::HashMap::new();
    for (label, digest) in bearer.into_iter().chain(keys) {
        if let Some(first) = seen.insert(digest, label.clone()) {
            return Err(crate::Error::ConfigValidation(format!(
                "{first} and {label} are the same credential, so one secret would match both; \
                 replace one of them"
            )));
        }
    }
    Ok(())
}

/// The fingerprint a holder is bound to: the full SHA-256, hex, of the
/// digest the request matched. Full length, so two digests that share a
/// principal's 12-hex prefix never share a tag and a rotation away from one
/// always ends what it opened; hashed, so the key's digest itself is never
/// stored with a holder.
pub(crate) fn digest_tag_of(digest: &[u8; 32]) -> String {
    crate::hashing::sha256_hex(digest)
}

/// The tag of the digest of `secret`, as a request presenting it records.
#[cfg(test)]
pub(crate) fn secret_tag(secret: &str) -> String {
    digest_tag_of(&<sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into())
}

/// Whether the secret fingerprinted `tag` still authenticates: it is the
/// `current` digest's, or the `previous` digest's while `in_grace` holds for
/// the grace's end (ADR-022). The one rule every holder kind is judged by
/// (event subscriptions, watch polls, dashboard sessions); a digest that
/// could not be read is `None` and matches nothing (fail closed).
pub(crate) fn tag_still_valid(
    tag: &str,
    current: Option<&[u8; 32]>,
    previous: Option<(&[u8; 32], chrono::DateTime<chrono::Utc>)>,
    in_grace: impl FnOnce(chrono::DateTime<chrono::Utc>) -> bool,
) -> bool {
    current.is_some_and(|digest| digest_tag_of(digest) == tag)
        || previous.is_some_and(|(digest, end)| digest_tag_of(digest) == tag && in_grace(end))
}
