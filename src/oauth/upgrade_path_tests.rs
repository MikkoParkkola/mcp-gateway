// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Covering constructs for the two MIK-6744.STORE.1 conjuncts that the
//! 2026-09-12 conjunct audit found uncovered: that a pre-existing 3.x
//! single-user token store is READABLE by 4.0.0, and what happens to it on the
//! upgrade (MIGRATED).
//!
//! Both fixtures are independent of [`TokenStorage`]'s own writer: the record
//! is seeded as literal 3.x JSON at a path this module hashes itself, the way
//! `TokenStorage::storage_key` does. A test that wrote through `save` and read
//! back through `load` would pass just as well if both had moved together, and
//! would prove nothing about a file v3.5.1 left on disk.
//!
//! The second test pins the shipped no-migration behaviour, which is item 1 of
//! [`NOTICE_4_0_0_ITEMS`](crate::commands::upgrade) — a promise already
//! published to operators. It asserts the opposite of the criterion as written
//! on purpose: the criterion is graded against code that deliberately does not
//! migrate, and an unpinned promise is one refactor away from being false in
//! the field while the release note still claims it.

use sha2::{Digest, Sha256};

use super::client::storage_key;
use super::storage::TokenStorage;

/// A backend/resource pair, fixed so both tests address the same record.
const BACKEND: &str = "workspace";
const RESOURCE: &str = "https://mcp.example.test/v1/mcp";
const ISSUER: &str = "https://auth.example.test";

/// 2100-01-01, so the seeded grant is unexpired regardless of when this runs.
const FAR_FUTURE: u64 = 4_102_444_800;

/// The on-disk file name v3.5.1 wrote a backend's tokens to.
///
/// Recomputed here rather than called through `TokenStorage`, whose
/// `storage_key` is private to that module: this is the fixture's own
/// statement of the 3.x layout, so a change to the naming scheme fails these
/// tests instead of silently moving with them.
fn legacy_file_name(backend_name: &str, resource_url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(backend_name.as_bytes());
    hasher.update(b":");
    hasher.update(resource_url.as_bytes());
    let hash = hasher.finalize();
    format!("{}_tokens.json", hex::encode(&hash[..8]))
}

/// Literal 3.x token JSON. Parsing this is the READABLE claim.
///
/// It omits `token_endpoint`, `client_id` and `client_secret`, which 4.0.0 did
/// NOT add: `TokenInfo` is byte-identical between `v3.5.1` and this tree across
/// its whole definition, and all three are declared `Option<String>` at
/// `src/oauth/storage.rs:42`, `:46` and `:50` in both. They are omitted here
/// because a 3.x record written before those fields were populated simply does
/// not carry them, and `serde(default)` absorbs the omission. The distinction
/// matters: "fields 4.0.0 added" implies a schema change across the major
/// version, and a migration designed against that premise goes looking for a
/// decryption or conversion step that does not exist. The real 3.x barrier is
/// the storage KEY, which `legacy_single_user_record_is_not_reachable_under_the_4_0_0_issuer_key`
/// pins.
fn legacy_record_json() -> String {
    format!(
        r#"{{
  "access_token": "legacy-3x-access-token",
  "token_type": "Bearer",
  "refresh_token": "legacy-3x-refresh-token",
  "expires_at": {FAR_FUTURE},
  "scope": "read write"
}}"#
    )
}

/// Seed a store directory with one record keyed the 3.x way, and return the
/// store plus the temp dir that owns it.
fn store_with_legacy_record() -> (tempfile::TempDir, TokenStorage) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(legacy_file_name(BACKEND, RESOURCE));
    // 3.x wrote token files 0600, as 4.0 does; a looser one is refused (F18).
    crate::gateway::test_helpers::write_owner_only(&path, legacy_record_json())
        .expect("seed legacy record");
    let store = TokenStorage::new(dir.path().to_path_buf()).expect("open store");
    (dir, store)
}

/// MIK-6744.STORE.1 (READABLE) — a token record written by v3.5.1 still opens
/// on 4.0.0, fields and all.
///
/// The 3.x payload carries none of `token_endpoint`, `client_id` or
/// `client_secret`; every one of those is `#[serde(default)]` on the 4.0.0
/// `TokenInfo`, so the old file parses without a migration step. This is the
/// half of the criterion that is satisfied by the reader being unchanged.
#[test]
fn legacy_single_user_record_written_by_3_x_still_opens_on_4_0_0() {
    // GIVEN: a store holding one record at the 3.x path, seeded as raw bytes.
    let (_dir, store) = store_with_legacy_record();

    // WHEN: 4.0.0 loads it under the 3.x key — the bare backend name, which is
    // what v3.5.1's `storage.load(&self.backend_name, &self.resource_url)`
    // passed.
    let loaded = store.load(BACKEND, RESOURCE);

    // THEN: the record is readable, unexpired, and every 3.x field survives;
    // the fields 4.0.0 added default to absent rather than failing the parse.
    let token = loaded.expect("3.x record must still be readable on 4.0.0");
    assert_eq!(token.access_token, "legacy-3x-access-token");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(
        token.refresh_token.as_deref(),
        Some("legacy-3x-refresh-token")
    );
    assert_eq!(token.scope.as_deref(), Some("read write"));
    assert!(!token.is_expired(), "seeded grant must be unexpired");
    assert_eq!(
        token.token_endpoint, None,
        "3.x payload has no token_endpoint; it must default, not fail"
    );
    assert_eq!(token.client_id, None);
    assert_eq!(token.client_secret, None);
}

/// MIK-6744.STORE.1 (MIGRATED) — the 3.x record is NOT carried to the 4.0.0
/// issuer-qualified key, and is left intact on disk.
///
/// This pins `NOTICE_4_0_0_ITEMS` item 1 ("Stored tokens from 3.x are not
/// migrated: each OAuth backend re-authenticates once") as behaviour rather
/// than prose. Two things have to hold for that notice to be honest: the new
/// key must miss, so the backend really does re-authorize; and the old file
/// must survive, so an operator who upgrades and rolls back has not lost a
/// credential.
#[test]
fn legacy_single_user_record_is_not_reachable_under_the_4_0_0_issuer_key() {
    // GIVEN: the same 3.x record, and the key 4.0.0 would look under —
    // `backend_name + NUL + issuer`, per src/oauth/client/mod.rs.
    let (dir, store) = store_with_legacy_record();
    let key_4_0_0 = storage_key(BACKEND, ISSUER);
    assert_ne!(key_4_0_0, BACKEND, "4.0.0 key must differ from the 3.x key");

    // WHEN: the record is sought the way 4.0.0's OAuth client seeks it.
    let under_new_key = store.load(&key_4_0_0, RESOURCE);

    // THEN: nothing is found — this is the "re-authenticates once" the shipped
    // notice promises, not an accident of the fixture.
    assert!(
        under_new_key.is_none(),
        "3.x credentials must not resolve under the issuer-qualified key; \
         NOTICE_4_0_0_ITEMS item 1 promises operators they do not"
    );

    // AND: the 3.x file is still there, byte-for-byte. The upgrade strands the
    // credential, it never destroys it.
    let legacy_path = dir.path().join(legacy_file_name(BACKEND, RESOURCE));
    assert_eq!(
        std::fs::read_to_string(&legacy_path).expect("3.x file must survive the upgrade"),
        legacy_record_json(),
        "the 3.x record must be left untouched, not consumed or truncated"
    );
    assert!(
        store.load(BACKEND, RESOURCE).is_some(),
        "the 3.x key must keep resolving after a 4.0.0-key miss"
    );
}
