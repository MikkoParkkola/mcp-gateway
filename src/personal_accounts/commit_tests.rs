// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S04 durability and O1 capacity refusal for the durable store operations.
//! No service, lease or dispatch behaviour is exercised or claimed here.
//!
//! Every durability case selects ONE persistence boundary, proves that boundary
//! was actually reached, pins the error category, and then checks the durable
//! state through a REOPENED store. A refusal that never reached the boundary,
//! or that reopened into neither the prior nor the complete generation, fails.

use super::faults;
use super::{
    AccountError, AccountKey, AccountLookup, GrantRecord, PersonalAccountStore, StoreConfig, alice,
    config, grant,
};

pub(super) fn account(subject: &str) -> AccountKey {
    let mut key = alice();
    key.principal_subject = subject.into();
    key
}

/// A distinct grant generation. Consent and re-consent mint a new one, so a
/// second commit for the same account is never the same record.
pub(super) fn generation(hex: &str) -> GrantRecord {
    let mut record = grant();
    record.generation = hex.into();
    record
}

/// An explicitly initialized empty store with a chosen entry capacity.
pub(super) fn empty_store(
    entries: usize,
) -> (tempfile::TempDir, StoreConfig, PersonalAccountStore) {
    let root = tempfile::tempdir().unwrap();
    let mut settings = config(root.path());
    settings.max_entries = entries;
    let store = PersonalAccountStore::initialize(settings.clone())
        .expect("offline initialization on empty roots");
    (root, settings, store)
}

pub(super) fn reopen(settings: &StoreConfig) -> PersonalAccountStore {
    PersonalAccountStore::open(settings.clone()).expect("the committed authority reopens")
}

#[test]
fn s04_a_committed_grant_is_readable_and_survives_reopen() {
    let (_root, settings, store) = empty_store(16);
    let key = alice();
    let record = grant();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Absent),
        "nothing is committed yet, so absence is the honest starting state"
    );
    assert_eq!(store.commit_grant(&key, &record), Ok(()));
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(record.clone()))
    );
    drop(store);
    assert_eq!(
        reopen(&settings).lookup(&key),
        Ok(AccountLookup::Connected(record)),
        "an acknowledged commit is durable, not merely in memory"
    );
}

#[test]
fn s04_every_persistence_boundary_refuses_and_leaves_a_whole_authority() {
    for boundary in faults::ALL {
        let (_root, settings, store) = empty_store(16);
        let key = alice();
        let first = grant();
        let second = generation("00000000000000000000000000000002");
        assert_eq!(store.commit_grant(&key, &first), Ok(()));

        let armed = faults::arm(boundary);
        let refused = store.commit_grant(&key, &second);
        assert!(
            armed.fired(),
            "{boundary:?} was never reached, so this case would prove nothing"
        );
        assert_eq!(
            refused,
            Err(AccountError::StorageUnavailable),
            "{boundary:?} is a physical-storage failure, not any other category"
        );
        drop(armed);

        // The durable answer, read by a process that shares no memory with the
        // failed attempt. Either the prior generation or the complete new one
        // is acceptable; a partial, empty or corrupt authority is not.
        drop(store);
        let reopened = reopen(&settings);
        let observed = reopened.lookup(&key);
        assert!(
            observed == Ok(AccountLookup::Connected(first.clone()))
                || observed == Ok(AccountLookup::Connected(second.clone())),
            "{boundary:?}: after reopen the authority is the prior or the complete generation, never {observed:?}"
        );

        // Clean retry with nothing armed: the fault refused one attempt, it did
        // not wedge the store, so an unrelated permanent refusal cannot pass.
        assert_eq!(reopened.commit_grant(&key, &second), Ok(()));
        assert_eq!(
            reopened.lookup(&key),
            Ok(AccountLookup::Connected(second.clone()))
        );
        drop(reopened);
        assert_eq!(
            reopen(&settings).lookup(&key),
            Ok(AccountLookup::Connected(second)),
            "{boundary:?}: the retried generation is itself durable"
        );
    }
}

#[test]
fn o1_an_over_capacity_commit_is_refused_and_the_store_reopens_intact() {
    let (_root, settings, store) = empty_store(2);
    let (first, second, third) = (account("alice"), account("bob"), account("carla"));
    assert_eq!(store.commit_grant(&first, &grant()), Ok(()));
    assert_eq!(store.commit_grant(&second, &grant()), Ok(()));
    assert_eq!(
        store.commit_grant(&third, &grant()),
        Err(AccountError::CapacityExhausted),
        "an over-capacity grant is refused before acknowledgment"
    );
    drop(store);
    // Durable, not merely live: a refusal that quietly damaged the persisted
    // authority would look identical through the in-memory copy.
    let reopened = reopen(&settings);
    assert_eq!(
        reopened.lookup(&first),
        Ok(AccountLookup::Connected(grant()))
    );
    assert_eq!(
        reopened.lookup(&second),
        Ok(AccountLookup::Connected(grant())),
        "the refusal evicted no other user's grant"
    );
    assert_eq!(
        reopened.lookup(&third),
        Ok(AccountLookup::Absent),
        "the refused account was not half-created"
    );
}

#[test]
fn o1_a_tombstone_occupies_capacity_and_survives_reopen() {
    let (_root, settings, store) = empty_store(2);
    let (first, second) = (account("alice"), account("bob"));
    assert_eq!(store.commit_grant(&first, &grant()), Ok(()));
    assert_eq!(store.commit_grant(&second, &grant()), Ok(()));
    assert_eq!(store.revoke(&second), Ok(()));
    assert_eq!(
        store.commit_grant(&account("carla"), &grant()),
        Err(AccountError::CapacityExhausted),
        "a revoked entry is retained, so it still counts toward capacity"
    );
    drop(store);
    let reopened = reopen(&settings);
    assert_eq!(
        reopened.lookup(&first),
        Ok(AccountLookup::Connected(grant())),
        "the untouched account is the control against a blanket refusal"
    );
    assert!(matches!(
        reopened.lookup(&second),
        Ok(AccountLookup::Revoked(_))
    ));
    assert_eq!(
        reopened.lookup(&account("carla")),
        Ok(AccountLookup::Absent)
    );
}

#[test]
fn o1_a_full_store_still_reconnects_an_account_that_already_holds_a_slot() {
    let (_root, settings, store) = empty_store(2);
    let (first, second) = (account("alice"), account("bob"));
    assert_eq!(store.commit_grant(&first, &grant()), Ok(()));
    assert_eq!(store.commit_grant(&second, &grant()), Ok(()));
    assert_eq!(store.revoke(&second), Ok(()));
    // Re-consent for an account that already occupies its slot adds no entry,
    // so a full store must not refuse it. Counting tombstones toward capacity
    // must not turn into refusing the reconnect they are counted for.
    let again = generation("00000000000000000000000000000004");
    assert_eq!(store.commit_grant(&second, &again), Ok(()));
    drop(store);
    let reopened = reopen(&settings);
    assert_eq!(
        reopened.lookup(&second),
        Ok(AccountLookup::Connected(again)),
        "the reconnected generation is durable"
    );
    assert_eq!(
        reopened.lookup(&first),
        Ok(AccountLookup::Connected(grant())),
        "and it did not evict the other grant to make room"
    );
}
