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
use std::path::Path;

use crate::hashing::hmac_sha256_hex;

/// The fallback key file, in the gateway data directory.
pub(crate) const KEY_FILE: &str = "record-principal.key";
/// The config field that names the key.
pub(crate) const KEY_FIELD: &str = "security.record_principal_key";
/// The record key unit tests pass to `ResolvedAuthConfig::from_config`.
#[cfg(test)]
pub(crate) const TEST_RECORD_KEY: &str = "test-record-key-not-a-secret-0123456789abcdef";
/// The record principal of a caller that presented no credential (§16.6): the
/// shape records already carry for it (src/security/audit.rs `from_parts`).
pub(crate) const NO_CREDENTIAL_RECORD: &str = "";
/// The record key unit-test fixtures key with ([`TEST_RECORD_KEY`]).
#[cfg(test)]
pub(crate) fn test_record_key() -> RecordPrincipalKey {
    RecordPrincipalKey::from_text(TEST_RECORD_KEY).expect("the test key is long enough")
}
/// [`test_record_key`] shared, as a service holds it.
#[cfg(test)]
pub(crate) fn test_key_arc() -> std::sync::Arc<RecordPrincipalKey> {
    std::sync::Arc::new(test_record_key())
}
/// The shortest key accepted, in bytes of key text.
const MIN_KEY_BYTES: usize = 32;

/// Domain label of the record-principal derivation.
const RECORD_DOMAIN: &[u8] = b"mcp-gateway/record-principal/v1";
/// Domain label of the subscription-alias derivation.
const SUBSCRIPTION_DOMAIN: &[u8] = b"mcp-gateway/subscription/v1";
/// Domain label of the shadow radar's endpoint-id derivation.
const SHADOW_ENDPOINT_DOMAIN: &[u8] = b"mcp-gateway/shadow-endpoint/v1";

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
/// Built from the resolved key *text*: the HMAC key is its UTF-8 bytes, taken
/// as given. The one trailing newline of a file is stripped by whichever reader
/// resolved it, so the fallback file and the same text as a `SecretRef` agree.
pub(crate) struct RecordPrincipalKey(Vec<u8>);

impl RecordPrincipalKey {
    /// The key from its resolved text.
    ///
    /// # Errors
    ///
    /// A key shorter than 32 bytes, naming [`KEY_FIELD`].
    pub(crate) fn from_text(text: &str) -> crate::Result<Self> {
        if text.len() < MIN_KEY_BYTES {
            return Err(crate::Error::ConfigValidation(format!(
                "{KEY_FIELD} must be at least {MIN_KEY_BYTES} bytes; generate one with \
                 `openssl rand -hex 32`"
            )));
        }
        Ok(Self(text.as_bytes().to_vec()))
    }

    /// Lowercase hex SHA-256 of the key bytes: names the key without being it.
    pub(crate) fn identity(&self) -> String {
        crate::hashing::sha256_hex(&self.0)
    }
}

/// The record key, only read: the configured reference, else the key file in
/// `data_dir`. `Ok(None)` when neither is there: a reader that must create
/// nothing never falls back to creating it.
///
/// # Errors
///
/// When the configured reference or the key file is there but cannot be read
/// or is not a key.
pub(crate) fn read_key(
    configured: Option<&str>,
    data_dir: &Path,
) -> crate::Result<Option<RecordPrincipalKey>> {
    let overlay = crate::config::EnvOverlay::none();
    let text = crate::config::read_record_key_text(
        configured,
        &overlay,
        &data_dir.join(KEY_FILE),
        KEY_FIELD,
    )?;
    text.map(|text| RecordPrincipalKey::from_text(&text))
        .transpose()
}

/// A key drawn for one use and held in memory only: never written, never
/// logged (the type has no `Debug`). For a report that must not create key
/// material where none exists; ids under it hold for that report alone.
pub(crate) fn one_run_key() -> RecordPrincipalKey {
    use rand::RngExt as _;
    let bytes: [u8; 32] = rand::rng().random();
    RecordPrincipalKey(bytes.to_vec())
}

/// The record key: `configured` (a `SecretRef`) when set, else the fallback file
/// in `data_dir`, created on first use. Fails closed: there is no unkeyed path.
///
/// # Errors
///
/// An unresolvable or short `SecretRef`, naming [`KEY_FIELD`]; a key file that
/// cannot be created or read, or is malformed or too permissive, naming its path.
pub(crate) fn resolve_key(
    configured: Option<&str>,
    overlay: &crate::config::EnvOverlay,
    data_dir: &Path,
) -> crate::Result<RecordPrincipalKey> {
    let text = crate::config::resolve_record_key_text(
        configured,
        overlay,
        &data_dir.join(KEY_FILE),
        KEY_FIELD,
    )?;
    RecordPrincipalKey::from_text(&text)
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
    ///
    /// The empty principal of a caller with no credential is the sentinel
    /// [`NO_CREDENTIAL_RECORD`], not an HMAC: an HMAC of "" would be one
    /// constant shared by every anonymous caller, an identity that carries none
    /// (MIK-8697 §16.8).
    pub(crate) fn record_form(&self, key: &RecordPrincipalKey) -> RecordPrincipal {
        if self.0.is_empty() {
            return RecordPrincipal(NO_CREDENTIAL_RECORD.to_owned());
        }
        RecordPrincipal(keyed(key, RECORD_DOMAIN, &self.0, 12))
    }
}

/// A record principal: 12 hex of a keyed HMAC, safe to write anywhere.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct RecordPrincipal(String);

impl RecordPrincipal {
    /// The no-credential record principal, [`NO_CREDENTIAL_RECORD`]: what
    /// `record_form` gives the empty principal, for a record no caller made.
    pub(crate) fn none() -> Self {
        Self(NO_CREDENTIAL_RECORD.to_owned())
    }

    /// The record value.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A credential-derived owner, keyed for a record (MIK-8697 §16.12, §16.14).
/// Both the owner form `credential:<p>` and the caller-key form
/// `credential:<len>:<p>` become `credential:rp:<record_form(p)>`. The `rp:`
/// mark makes this idempotent: a keyed value passes through, so a writer that
/// keys and the logger that keys again cannot double-key. Any other owner
/// (`oidc:…`, a stdio or anonymous constant) names no credential digest and
/// passes through. Lookup keys keep the original string.
pub(crate) fn record_owner(owner: &str, key: &RecordPrincipalKey) -> String {
    const PREFIX: &str = crate::gateway::auth::CREDENTIAL_OWNER_PREFIX;
    let Some(rest) = owner.strip_prefix(PREFIX) else {
        return owner.to_owned();
    };
    if is_keyed_owner(rest) {
        return owner.to_owned();
    }
    // The caller-key form is length-prefixed (router/identity.rs).
    let principal = rest
        .split_once(':')
        .filter(|(len, p)| len.parse::<usize>().is_ok_and(|n| n == p.len()))
        .map_or(rest, |(_, p)| p);
    let keyed = InternalPrincipal::new(principal.to_owned()).record_form(key);
    format!("{PREFIX}{KEYED_OWNER_MARK}{}", keyed.as_str())
}

/// Marks a `credential:` owner whose digest is already the keyed record form.
const KEYED_OWNER_MARK: &str = "rp:";

/// Whether `rest` (after `credential:`) is exactly the keyed shape: the mark
/// and a 12-lowercase-hex record form. Matching the whole shape, not only the
/// prefix, means a raw principal that happened to start with `rp:` would still
/// be keyed. None can: stored principals are 12 hex (`principal_of`,
/// `principal_of_digest`), `kst:`/`oidc:` + 64 hex (`key_server`
/// `runtime_principal`), or fixed constants (stdio, the dashboard session).
fn is_keyed_owner(rest: &str) -> bool {
    rest.strip_prefix(KEYED_OWNER_MARK).is_some_and(|rf| {
        rf.len() == 12 && rf.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The shadow radar's id part for a found server's URL: keyed, so a report
/// shows nothing of the URL's path and an id cannot be used to test a guess
/// at it, and stable for as long as the record key is.
pub(crate) fn shadow_endpoint_id(key: &RecordPrincipalKey, normalised_url: &str) -> String {
    keyed(key, SHADOW_ENDPOINT_DOMAIN, normalised_url, 16)
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
            let key = RecordPrincipalKey::from_text(key).expect("key");
            let got = InternalPrincipal::new(internal.to_owned()).record_form(&key);
            assert_eq!(got.as_str(), want, "{internal}");
        }
        assert_eq!(
            subscription_alias(&RecordPrincipalKey::from_text(KEY_ZERO).expect("key"), SUB),
            "eaacd857ae5332fc"
        );
        assert_eq!(
            subscription_alias(&RecordPrincipalKey::from_text(KEY_A5).expect("key"), SUB),
            "a91545474dd38b41"
        );
    }

    // D2b: from_text takes the resolved text as given; the readers strip the
    // file's newline once (MIK-8697 §16.6 #3).
    #[test]
    fn d2b_from_text_keeps_a_trailing_newline() {
        let with = RecordPrincipalKey::from_text(&format!("{KEY_A5}\n")).expect("key");
        let without = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        assert_ne!(with.identity(), without.identity());
    }

    // S1: no credential records the "" sentinel, never an HMAC of "", and no
    // real principal's record form is the sentinel.
    #[test]
    fn s1_no_credential_records_the_empty_sentinel() {
        let key = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        let none = InternalPrincipal::default().record_form(&key);
        assert_eq!(none.as_str(), NO_CREDENTIAL_RECORD);
        assert_ne!(none.as_str(), keyed(&key, RECORD_DOMAIN, "", 12));
        let real = InternalPrincipal::new("3f2a9c0d1e7b".to_owned()).record_form(&key);
        assert_ne!(real.as_str(), NO_CREDENTIAL_RECORD);
        assert_eq!(real.as_str().len(), 12);
    }

    // S1b: none(), the only other constructor, builds exactly the sentinel
    // record_form gives an absent principal, and nothing else.
    #[test]
    fn s1b_none_is_the_record_form_of_an_absent_principal() {
        let key = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        assert_eq!(
            RecordPrincipal::none(),
            InternalPrincipal::default().record_form(&key)
        );
        assert_eq!(RecordPrincipal::none().as_str(), NO_CREDENTIAL_RECORD);
    }

    // O1: both credential forms key to one marked shape; any other owner
    // passes through; no form keeps the digest.
    #[test]
    fn o1_record_owner_keys_both_credential_forms_only() {
        let key = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        let rf = InternalPrincipal::new("3f2a9c0d1e7b".to_owned()).record_form(&key);
        let want = format!("credential:rp:{}", rf.as_str());
        assert_eq!(record_owner("credential:3f2a9c0d1e7b", &key), want);
        assert_eq!(record_owner("credential:12:3f2a9c0d1e7b", &key), want);
        for other in ["oidc:3:iss:3:sub", "stdio", ""] {
            assert_eq!(record_owner(other, &key), other);
        }
        assert!(!want.contains("3f2a9c0d1e7b"));
    }

    // O2 (lead): idempotent. A keyed value, or one that is not
    // credential-derived, passes through unchanged, so nothing double-keys.
    #[test]
    fn o2_record_owner_is_idempotent() {
        let key = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        for owner in [
            "credential:3f2a9c0d1e7b",
            "credential:12:3f2a9c0d1e7b",
            "oidc:3:iss:3:sub",
            "stdio",
            "",
        ] {
            let once = record_owner(owner, &key);
            assert_eq!(record_owner(&once, &key), once, "{owner}");
        }
    }

    // O3 (lead): the pass-through matches the exact keyed shape, so a raw
    // owner whose principal starts with `rp:` is still keyed, never passed.
    #[test]
    fn o3_a_raw_principal_starting_with_the_mark_is_keyed() {
        let key = RecordPrincipalKey::from_text(KEY_A5).expect("key");
        for raw in [
            "credential:rp:abc",
            "credential:rp:3f2a9c0d1e7bxx",
            "credential:rp:3F2A9C0D1E7B",
        ] {
            let out = record_owner(raw, &key);
            assert_ne!(out, raw, "{raw} passed through unkeyed");
            assert!(
                is_keyed_owner(out.strip_prefix("credential:").expect("prefix")),
                "{out}"
            );
        }
    }

    // §16.6 #1: fewer than 32 bytes is refused, naming the field.
    #[test]
    fn k0_a_short_key_is_refused_naming_the_field() {
        let Err(err) = RecordPrincipalKey::from_text(&"a".repeat(31)) else {
            panic!("a 31-byte key was accepted");
        };
        assert!(err.to_string().contains(KEY_FIELD), "{err}");
        assert!(RecordPrincipalKey::from_text(&"a".repeat(32)).is_ok());
    }
}

#[cfg(test)]
#[path = "record_principal_key_tests.rs"]
mod key_tests;
#[cfg(test)]
#[path = "record_principal_leak_tests.rs"]
mod leak_tests;
#[cfg(test)]
#[path = "record_principal_scan_tests.rs"]
mod scan_tests;
