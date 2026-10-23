// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Keyed principals for everything that leaves the gateway (MIK-8697).
//!
//! The internal principal is an unkeyed digest prefix of a credential, so any
//! copy of it in a record or log is an offline guessing oracle for weak keys.
//! `InternalPrincipal` therefore has exactly two doors: `storage_form` (the
//! unchanged bytes, for stores) and `record_form` (an HMAC under the gateway's
//! record key, for records, logs and anything else that leaves the box).

use std::fmt;

use crate::hashing::{hmac_sha256_hex, sha256_hex};

/// Domain label of the record-principal derivation.
const RECORD_DOMAIN: &[u8] = b"mcp-gateway/record-principal/v1";
/// Domain label of the subscription-alias derivation.
const SUBSCRIPTION_DOMAIN: &[u8] = b"mcp-gateway/subscription/v1";

/// `HMAC(key, domain || 0x00 || value)`, truncated to `hex_len` hex digits.
fn keyed(key: &RecordPrincipalKey, domain: &[u8], value: &str, hex_len: usize) -> String {
    let mut message = Vec::with_capacity(domain.len() + 1 + value.len());
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(value.as_bytes());
    let mut digest = hmac_sha256_hex(&key.0, &message);
    digest.truncate(hex_len);
    digest
}

/// The gateway-held key for record principals and subscription aliases.
///
/// Built from the key *text* (a SecretRef value or the fallback file's
/// contents): the HMAC key is the UTF-8 bytes after one trailing newline is
/// stripped, so a fallback file promoted to a SecretRef keeps every value.
pub(crate) struct RecordPrincipalKey(Vec<u8>);

impl RecordPrincipalKey {
    /// The key from its text form.
    pub(crate) fn from_text(text: &str) -> Self {
        Self(text.strip_suffix('\n').unwrap_or(text).as_bytes().to_vec())
    }

    /// Lowercase hex SHA-256 of the key bytes: names the key without being it.
    pub(crate) fn identity(&self) -> String {
        sha256_hex(&self.0)
    }
}

/// A caller's internal principal: never printed, never serialized.
///
/// `Default` is the empty principal of an identity that presented no credential.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct InternalPrincipal(String);

impl fmt::Debug for InternalPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InternalPrincipal(<redacted>)")
    }
}

impl InternalPrincipal {
    /// Wrap the internal principal string.
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Whether this is the empty principal (no credential presented).
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The exact stored bytes: for stores only (sessions, grants, journals,
    /// task owners, events records, idempotency and cache keys).
    pub(crate) fn storage_form(&self) -> &str {
        &self.0
    }

    /// The keyed form for records and logs.
    pub(crate) fn record_form(&self, key: &RecordPrincipalKey) -> RecordPrincipal {
        RecordPrincipal(keyed(key, RECORD_DOMAIN, &self.0, 12))
    }
}

/// A record principal: 12 hex of a keyed HMAC, safe to write anywhere.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct RecordPrincipal(String);

impl RecordPrincipal {
    /// The record value.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The keyed alias of a stored subscription id: the client-facing handle.
pub(crate) fn subscription_alias(key: &RecordPrincipalKey, stored_id: &str) -> String {
    keyed(key, SUBSCRIPTION_DOMAIN, stored_id, 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const KEY_A5: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    const SUB: &str = "sub_0123456789abcdef0123456789abcdef";

    // T2: Debug never prints the value.
    #[test]
    fn t2_debug_of_an_internal_principal_is_redacted() {
        let p = InternalPrincipal::new("3f2a9c0d1e7b".to_owned());
        let shown = format!("{p:?}");
        assert!(!shown.contains("3f2a9c0d1e7b"), "{shown}");
        assert_eq!(shown, "InternalPrincipal(<redacted>)");
    }

    // D1: independently pinned vectors (Python hmac), two keys x two inputs.
    #[test]
    fn d1_record_form_and_alias_match_pinned_vectors() {
        let cases = [
            (KEY_ZERO, "3f2a9c0d1e7b", "a632b48d93e3"),
            (KEY_ZERO, "credential-xyz", "92d0515d125a"),
            (KEY_A5, "3f2a9c0d1e7b", "eeb5da1c81bf"),
            (KEY_A5, "credential-xyz", "0bb522665692"),
        ];
        for (key, internal, want) in cases {
            let key = RecordPrincipalKey::from_text(key);
            let got = InternalPrincipal::new(internal.to_owned()).record_form(&key);
            assert_eq!(got.as_str(), want, "{internal}");
        }
        assert_eq!(
            subscription_alias(&RecordPrincipalKey::from_text(KEY_ZERO), SUB),
            "eaacd857ae5332fc"
        );
        assert_eq!(
            subscription_alias(&RecordPrincipalKey::from_text(KEY_A5), SUB),
            "a91545474dd38b41"
        );
    }

    // D2: the file form (`<hex>\n`) and the literal form are one key.
    #[test]
    fn d2_key_text_with_its_trailing_newline_is_the_same_key() {
        let file = RecordPrincipalKey::from_text(&format!("{KEY_A5}\n"));
        let literal = RecordPrincipalKey::from_text(KEY_A5);
        assert_eq!(file.identity(), literal.identity());
        let p = InternalPrincipal::new("3f2a9c0d1e7b".to_owned());
        assert_eq!(p.record_form(&file), p.record_form(&literal));
        assert_ne!(
            p.record_form(&literal).as_str(),
            p.storage_form(),
            "keyed, not the storage form"
        );
    }
}
