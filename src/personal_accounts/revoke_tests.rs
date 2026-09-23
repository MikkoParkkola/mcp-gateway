// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `revoke_capturing` (design §8.1; T-R2-4 and T-R3-3 at the store boundary).

use super::commit::{account, empty_store};
use super::{AccountLookup, GrantRecord, GrantVersion, grant};
use crate::personal_accounts::provider::TokenTypeHint;
use crate::personal_accounts::store_probe::{self, StoreOp};

fn version(record: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

fn both_tokens(record: &GrantRecord) -> Vec<(String, TokenTypeHint)> {
    vec![
        (
            record.refresh_token.clone().expect("fixture has a refresh token"),
            TokenTypeHint::RefreshToken,
        ),
        (record.access_token.clone(), TokenTypeHint::AccessToken),
    ]
}

#[test]
fn revoke_capturing_connected_returns_refresh_then_access_and_tombstones() {
    // GIVEN: a connected grant
    let (_root, _settings, store) = empty_store(16);
    let key = account("alice");
    let record = grant();
    store.commit_grant(&key, &record).unwrap();
    // WHEN
    let material = store.revoke_capturing(&key).unwrap().expect("tokens held");
    // THEN
    assert_eq!(material.tokens_for_test(), both_tokens(&record));
    assert_eq!(store.lookup(&key), Ok(AccountLookup::Revoked(version(&record))));
}

#[test]
fn revoke_capturing_after_invalid_grant_fence_still_captures_both_tokens() {
    // GIVEN: the provider rejected the refresh, so the grant is fenced (R3-3)
    let (_root, _settings, store) = empty_store(16);
    let key = account("alice");
    let record = grant();
    store.commit_grant(&key, &record).unwrap();
    store.fence_expected_version(&key, &version(&record)).unwrap();
    // WHEN
    let material = store.revoke_capturing(&key).unwrap().expect("retained");
    // THEN: the refresh token is dead but the access token may not be
    assert_eq!(material.tokens_for_test(), both_tokens(&record));
    assert!(matches!(store.lookup(&key), Ok(AccountLookup::Revoked(_))));
}

#[test]
fn revoke_capturing_after_descriptor_fence_still_captures_tokens() {
    // GIVEN: the descriptor revision moved (R2-4, second cause)
    let (_root, _settings, store) = empty_store(16);
    let key = account("alice");
    let record = grant();
    store.commit_grant(&key, &record).unwrap();
    store.mark_reconnect_required(&key, &"1".repeat(64)).unwrap();
    // WHEN
    let material = store.revoke_capturing(&key).unwrap().expect("retained");
    // THEN
    assert_eq!(material.tokens_for_test(), both_tokens(&record));
}

#[test]
fn revoke_capturing_revoked_and_absent_yield_nothing() {
    // GIVEN: one account already revoked, one never committed
    let (_root, _settings, store) = empty_store(16);
    let key = account("alice");
    store.commit_grant(&key, &grant()).unwrap();
    store.revoke_capturing(&key).unwrap();
    // WHEN / THEN
    assert!(store.revoke_capturing(&key).unwrap().is_none());
    assert!(store.revoke_capturing(&account("bob")).unwrap().is_none());
    assert_eq!(store.lookup(&account("bob")), Ok(AccountLookup::Absent));
}

#[test]
fn revoke_capturing_without_refresh_token_sends_access_only() {
    // GIVEN: a grant the provider issued no refresh token for
    let (_root, _settings, store) = empty_store(16);
    let key = account("alice");
    let mut record = grant();
    record.refresh_token = None;
    store.commit_grant(&key, &record).unwrap();
    // WHEN
    let material = store.revoke_capturing(&key).unwrap().expect("access held");
    // THEN
    assert_eq!(
        material.tokens_for_test(),
        vec![(record.access_token.clone(), TokenTypeHint::AccessToken)]
    );
}

#[test]
fn revoke_capturing_reconnect_required_with_corrupt_record_tombstones_with_nothing() {
    // GIVEN: a fenced grant whose ciphertext was overwritten on disk
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    let record = grant();
    store.commit_grant(&key, &record).unwrap();
    store.fence_expected_version(&key, &version(&record)).unwrap();
    for entry in std::fs::read_dir(&settings.store_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().is_some_and(|n| n != ".personal-accounts.lock") {
            std::fs::write(&path, b"{}").unwrap();
        }
    }
    // WHEN
    let material = store.revoke_capturing(&key).unwrap();
    // THEN: still tombstoned, reported as nothing to send
    assert!(material.is_none());
    assert!(matches!(store.lookup(&key), Ok(AccountLookup::Revoked(_))));
}

#[test]
fn revoke_capturing_reads_and_tombstones_under_one_authority_acquisition() {
    // GIVEN: a connected grant and a probe on the store directory
    let (_root, settings, store) = empty_store(16);
    let key = account("alice");
    store.commit_grant(&key, &grant()).unwrap();
    let recording = store_probe::watch(&settings.store_dir);
    // WHEN
    let material = store.revoke_capturing(&key).unwrap();
    // THEN: exactly one acquisition, and it produced material
    let acquisitions = recording
        .ops()
        .into_iter()
        .filter(|op| *op == StoreOp::AuthorityAcquired)
        .count();
    assert_eq!(acquisitions, 1, "a read-then-revoke takes the lock twice");
    assert!(material.is_some());
}
