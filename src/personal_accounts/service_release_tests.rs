// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lease boundary: what a lease must match to be released, and what a
//! broken store is allowed to look like from outside.

use std::sync::atomic::Ordering;

use super::*;

/// Every field a lease binds, moved one at a time and no more.
///
/// A recheck that compares only the token revision is invisible to a suite that
/// never changes anything else, and such a recheck releases credentials for a
/// superseded generation, a superseded authorization, a changed descriptor, or
/// another account entirely. The four version cases below deliberately KEEP the
/// token revision, so only a full comparison refuses them.
fn one_field_mismatches(lease: &CredentialLease) -> Vec<(&'static str, CredentialLease)> {
    let mut cases = vec![
        (
            "generation",
            CredentialLease {
                generation: "abcdefabcdefabcdefabcdefabcdefab".into(),
                ..lease.clone()
            },
        ),
        (
            "authorization_epoch",
            CredentialLease {
                authorization_epoch: lease.authorization_epoch + 1,
                ..lease.clone()
            },
        ),
        (
            "descriptor_revision",
            CredentialLease {
                descriptor_revision: "1".repeat(64),
                ..lease.clone()
            },
        ),
        (
            "scopes",
            CredentialLease {
                scopes: vec![full_drive_scope()],
                ..lease.clone()
            },
        ),
        (
            "token_revision",
            CredentialLease {
                token_revision: lease.token_revision + 1,
                ..lease.clone()
            },
        ),
    ];
    for (field, account) in one_field_apart() {
        cases.push((
            field,
            CredentialLease {
                account,
                ..lease.clone()
            },
        ));
    }
    // Absence is not an offer to connect at the lease boundary: the caller is
    // holding a lease, so the only honest answer is that it is not valid.
    cases.push((
        "account never held",
        CredentialLease {
            account: mallory(),
            ..lease.clone()
        },
    ));
    cases
}

#[test]
fn release_refuses_every_single_field_mismatch_and_publishes_nothing() {
    let alice_key = alice();
    let record = grant();
    let neighbours = one_field_apart_grants();
    let mut to_seed: Vec<(&AccountKey, GrantRecord)> = vec![(&alice_key, record.clone())];
    for (account, grant) in &neighbours {
        to_seed.push((account, grant.clone()));
    }
    // The neighbours are CONNECTED with grants of their own, so an account
    // mismatch is refused because the lease does not match that account's
    // state — not merely because the store had nothing to say.
    let fx = Fixture::seeded(&to_seed);

    let lease = refuse_scaffold(fx.service.resolve(&alice()), "base lease")
        .expect("connected principal resolves");
    assert_eq!(lease, expected_lease(alice(), &record));

    for (field, mismatched) in one_field_mismatches(&lease) {
        assert_eq!(
            domain_err(fx.service.release(&mismatched), field),
            AccountServiceError::LeaseRetired,
            "{field}: a lease that disagrees with durable state must be retired"
        );
        fx.assert_quiet(field);
    }

    // The control. Without it, a release that refuses everything would pass
    // every case above.
    let credentials = refuse_scaffold(fx.service.release(&lease), "unmodified lease")
        .expect("the lease the store issued still releases");
    assert_eq!(credentials, expected_credentials(&record));
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fx.provider_calls.load(Ordering::SeqCst), 0);

    for (account, grant) in &neighbours {
        let durable = expect_connected(
            fx.service
                .store()
                .lookup(account)
                .expect("neighbour lookup after mismatches"),
        );
        assert!(
            durable == *grant,
            "a refused lease must not write to the account it named"
        );
    }

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen after mismatches");
    assert!(
        expect_connected(store.lookup(&alice()).expect("alice reopen")) == record,
        "no refused lease may have reached disk"
    );
    for (account, grant) in &neighbours {
        assert!(
            expect_connected(store.lookup(account).expect("neighbour reopen")) == *grant,
            "no refused lease may have reached the account it named"
        );
    }
}

/// A store that cannot answer is not an account that is not connected. The
/// difference is the whole user-visible outcome: one is an outage to retry,
/// the other invites a re-consent journey that will not fix anything.
#[test]
fn a_lookup_storage_failure_is_never_reported_as_a_disconnected_account() {
    let fx = Fixture::connected_alice();
    let record = grant();
    let lease = refuse_scaffold(fx.service.resolve(&alice()), "control before the failure")
        .expect("connected principal resolves while the store is healthy");
    assert_eq!(lease, expected_lease(alice(), &record));
    fx.assert_quiet("healthy control");

    let records = record_files(&fx.tmp);
    assert_eq!(
        records.len(),
        1,
        "one seeded account has exactly one sealed record"
    );

    // Present, and not what the manifest authenticated. This case runs FIRST,
    // while the file still exists: truncating an existing file keeps its
    // owner-only mode, so the read reaches the digest comparison. Recreating a
    // deleted one would land on the mode check instead and report the wrong
    // failure — or the right one, depending on the umask, which is worse.
    std::fs::write(&records[0], b"{\"schema_version\":\"tampered\"}")
        .expect("rewrite the sealed record");
    assert_eq!(
        domain_err(
            fx.service.resolve(&alice()),
            "resolve with a tampered record"
        ),
        AccountServiceError::Store(AccountError::NotAuthentic),
        "a record that fails authentication is a storage failure, never absence"
    );
    fx.assert_quiet("tampered record");

    // The lease taken while the store was healthy is not a licence to publish
    // credentials the store can no longer vouch for.
    assert_eq!(
        domain_err(fx.service.release(&lease), "release during the failure"),
        AccountServiceError::Store(AccountError::NotAuthentic),
        "a broken store must surface as itself, not as a retired lease"
    );
    fx.assert_quiet("release during the failure");

    // The sealed record the manifest points at is gone.
    std::fs::remove_file(&records[0]).expect("remove the sealed record");
    assert_eq!(
        domain_err(
            fx.service.resolve(&alice()),
            "resolve with a missing record"
        ),
        AccountServiceError::Store(AccountError::StorageUnavailable),
        "a missing record file is a storage failure, never absence"
    );
    assert_eq!(
        domain_err(fx.service.resolve(&alice()), "resolve retried"),
        AccountServiceError::Store(AccountError::StorageUnavailable),
        "the retry must not adopt the missing record as absence"
    );
    fx.assert_quiet("missing record");
}
