// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S03 wire-bound boundary — the gap a second surviving mutant exposed.
//!
//! `record_file_limit` computes its ciphertext allowance as
//! `(RECORD_BYTES + 16 + 2) / 3 * 4`. Turning that `+` into `*` makes it
//! `16 * 2`, which raises the bound by exactly 20 bytes. The existing
//! maximum-plaintext case only proves the largest valid file is ACCEPTED, and a
//! wider bound still accepts it, so nothing there notices.
//!
//! What separates a tight bound from a widened one is the ERROR CATEGORY one
//! byte past it. `read_record` classifies an oversize file as a physical
//! storage failure before any digest or decryption; a widened bound instead
//! reads the file and reports a hash mismatch. These cases assert the accepted
//! finite bound and that category, and change no arithmetic to do it.

use super::{
    AccountError, AccountKey, AccountLookup, GrantRecord, PersonalAccountStore, StoreConfig, config,
};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

#[derive(serde::Deserialize)]
struct Bounds {
    envelope_bounds: Vec<Variant>,
}

#[derive(serde::Deserialize)]
struct Variant {
    name: String,
    key_id: String,
    authority: String,
    max: Grant,
    ordinary: Grant,
}

#[derive(serde::Deserialize)]
struct Grant {
    fields: [String; 5],
    basename: String,
    record: GrantRecord,
    record_bytes: String,
}

fn account(fields: &[String; 5]) -> AccountKey {
    AccountKey {
        principal_authority: fields[0].clone(),
        principal_subject: fields[1].clone(),
        backend_id: fields[2].clone(),
        resource: fields[3].clone(),
        oauth_issuer: fields[4].clone(),
    }
}

/// The approved retained-key shape: `current` stays current and the long key ID
/// is an extra configured key, so the bound is the widest configured one.
fn install(variant: &Variant) -> (tempfile::TempDir, StoreConfig) {
    let root = tempfile::tempdir().unwrap();
    let mut settings = config(root.path());
    let key = settings.keys["current"].clone();
    assert_ne!(settings.current_key_id, variant.key_id);
    settings.keys.insert(variant.key_id.clone(), key);
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
        variant.authority.as_bytes(),
    );
    for grant in [&variant.max, &variant.ordinary] {
        write(
            settings.store_dir.join(&grant.basename),
            grant.record_bytes.as_bytes(),
        );
    }
    (root, settings)
}

#[test]
fn s03_the_exact_envelope_bound_is_accepted_and_one_more_byte_is_a_storage_refusal() {
    let bounds: Bounds = serde_json::from_str(include_str!("fixtures/lookup_states.json")).unwrap();
    assert_eq!(bounds.envelope_bounds.len(), 2);
    for variant in &bounds.envelope_bounds {
        let key = account(&variant.max.fields);
        let (_root, settings) = install(variant);
        let path = settings.store_dir.join(&variant.max.basename);
        let exact = variant.max.record_bytes.len();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), exact as u64);
        let store = PersonalAccountStore::open(settings.clone()).unwrap();
        assert_eq!(
            store.lookup(&key),
            Ok(AccountLookup::Connected(variant.max.record.clone())),
            "{} at the exact bound is accepted, so the bound is not merely large",
            variant.name
        );
        drop(store);
        // One trailing byte past the largest envelope this configuration can
        // produce. A tight bound refuses it on size; a widened one reads it and
        // reports a hash mismatch instead, which is a different category.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), exact as u64 + 1);
        let store = PersonalAccountStore::open(settings).unwrap();
        assert_eq!(
            store.lookup(&key),
            Err(AccountError::StorageUnavailable),
            "{} one byte past the bound must refuse as physical storage, never as authentication",
            variant.name
        );
        assert_eq!(
            store.lookup(&account(&variant.ordinary.fields)),
            Ok(AccountLookup::Connected(variant.ordinary.record.clone())),
            "the oversize record refuses only itself, not the whole store"
        );
    }
}
