// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S03 authority-entry version validation — the gap a surviving mutant exposed.
//!
//! Turning any `||` in `entry_version` into `&&` means one malformed version
//! field no longer refuses. On a CONNECTED entry that mutant hides: the
//! record/manifest agreement check downstream rejects the mismatch anyway, so
//! the outcome is `NotAuthentic` either way and nothing is proved. A REVOKED
//! entry reads no record at all — `entry_version` is the only gate, and its
//! four fields are exactly what the tombstone discloses. That is where these
//! vectors sit, and why they kill the mutant instead of stepping around it.

use super::{
    AccountError, AccountKey, AccountLookup, GrantRecord, GrantVersion, PersonalAccountStore,
    StoreConfig, config,
};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

#[derive(serde::Deserialize)]
struct AuthorityVersions {
    key_hex: String,
    instance_id: String,
    fields: [String; 5],
    digest: String,
    basename: String,
    record: GrantRecord,
    record_bytes: String,
    connected_authority: String,
    revoked_authority: String,
    variants: Vec<VersionVariant>,
}

#[derive(serde::Deserialize)]
struct VersionVariant {
    field: String,
    authority: String,
}

fn fixture() -> AuthorityVersions {
    serde_json::from_str(include_str!("fixtures/authority_versions.json")).unwrap()
}

fn account(fixture: &AuthorityVersions) -> AccountKey {
    AccountKey {
        principal_authority: fixture.fields[0].clone(),
        principal_subject: fixture.fields[1].clone(),
        backend_id: fixture.fields[2].clone(),
        resource: fixture.fields[3].clone(),
        oauth_issuer: fixture.fields[4].clone(),
    }
}

/// Install the one account with the supplied authority. The record file is
/// always present, so a refusal is never a missing candidate.
fn install(fixture: &AuthorityVersions, authority: &str) -> (tempfile::TempDir, StoreConfig) {
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    assert_eq!(settings.instance_id, fixture.instance_id);
    assert_eq!(
        settings.keys["current"],
        hex::decode(&fixture.key_hex).unwrap()
    );
    for dir in [&settings.store_dir, &settings.authority_dir] {
        std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
    }
    let write = |path: std::path::PathBuf, bytes: &[u8]| {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    };
    write(
        settings.authority_dir.join("authority.json"),
        authority.as_bytes(),
    );
    write(
        settings.store_dir.join(&fixture.basename),
        fixture.record_bytes.as_bytes(),
    );
    (root, settings)
}

#[test]
fn s03_a_well_formed_entry_still_resolves_both_states() {
    let fixture = fixture();
    let key = account(&fixture);
    assert_eq!(key.digest(), Ok(fixture.digest.clone()));
    let (_connected_root, settings) = install(&fixture, &fixture.connected_authority);
    let store = PersonalAccountStore::open(settings).unwrap();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(fixture.record.clone())),
        "the store, key and associated data are correct before anything is malformed"
    );
    drop(store);
    let (_revoked_root, settings) = install(&fixture, &fixture.revoked_authority);
    let store = PersonalAccountStore::open(settings).unwrap();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Revoked(GrantVersion {
            generation: fixture.record.generation.clone(),
            token_revision: fixture.record.token_revision,
            authorization_epoch: fixture.record.authorization_epoch,
            descriptor_revision: fixture.record.descriptor_revision.clone(),
        })),
        "a well-formed tombstone discloses its version from the manifest alone"
    );
}

#[test]
fn s03_a_malformed_authority_version_field_refuses_disclosure() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .variants
            .iter()
            .map(|variant| variant.field.as_str())
            .collect::<Vec<_>>(),
        [
            "generation",
            "descriptor_revision",
            "token_revision",
            "authorization_epoch"
        ],
        "every validated version field has its own vector"
    );
    let key = account(&fixture);
    for variant in &fixture.variants {
        let (_root, settings) = install(&fixture, &variant.authority);
        // Exactly one field is malformed; the state, pointer and record are the
        // same as the tombstone control that resolves. Only the validation of
        // this field can decide the difference.
        let observed = PersonalAccountStore::open(settings).and_then(|store| store.lookup(&key));
        assert_eq!(
            observed,
            Err(AccountError::NotAuthentic),
            "a malformed authority {} must refuse instead of disclosing a version",
            variant.field
        );
    }
}
