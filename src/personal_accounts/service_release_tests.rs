// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lease boundary: what a lease must match to be released, and what a
//! broken store is allowed to look like from outside.

use std::sync::Arc;
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

/// A holder that was live when the grant was revoked cannot restore it.
///
/// This is the third conjunct of `MIK-6744.STORE.2`, and it is the one the
/// store-boundary suites cannot reach. `fence_tests` says so in its own module
/// doc: it proves a stale snapshot cannot land, but explicitly not "that no new
/// lease is issued, that transport is barred, that caches and connections are
/// retired". The nearest crash-suite row, `s13`, proves restored *ciphertext*
/// is refused — a fact about bytes at rest, not about a live holder still
/// carrying a valid-looking lease.
///
/// A `CredentialLease` is what a task, a warm cache or an open connection
/// holds. The criterion's question is whether holding one across a revocation
/// is worth anything, so the test holds one across a revocation.
///
/// The pre-revoke release is the control, and it is what makes the refusal
/// attributable. Without it, a lease that was malformed from the start would
/// produce the same `LeaseRetired` and the row would prove nothing about
/// revocation. Releasing first pins the lease as genuinely live, so the only
/// thing that changed between the two calls is the revoke.
///
/// The two refusals are deliberately different errors and the test pins both.
/// `release` answers `LeaseRetired` because a caller holding a lease is not
/// asking to connect one, so absence must not read as an offer
/// (`service.rs:296-299`); `resolve` answers `Revoked`, which is the honest
/// state of the account. Collapsing them would turn a revoked account into a
/// re-consent prompt that cannot help.
///
/// Both halves of `invalidate`'s contract are checked, because they fail
/// independently: barring *release* leaves an existing holder able to keep
/// using credentials, and barring *new leases* is what stops the holder from
/// simply asking for a fresh one. A gate that did only the first would let a
/// cache re-resolve its way back in.
#[test]
fn a_lease_held_across_a_revoke_is_retired_and_cannot_be_reacquired() {
    let fx = Fixture::connected_alice();
    let record = grant();

    let lease = refuse_scaffold(fx.service.resolve(&alice()), "pre-revoke lease")
        .expect("a connected principal resolves");
    assert_eq!(lease, expected_lease(alice(), &record));

    // The control: this exact lease works, so the refusal below belongs to the
    // revoke and not to the lease.
    assert_eq!(
        refuse_scaffold(fx.service.release(&lease), "pre-revoke release")
            .expect("the lease releases while the grant is live"),
        expected_credentials(&record)
    );
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);

    fx.service.invalidate(&alice()).expect("durable revoke");

    assert_eq!(
        domain_err(fx.service.release(&lease), "post-revoke release"),
        AccountServiceError::LeaseRetired,
        "a holder that survived the revoke must not still be released"
    );
    assert_eq!(
        domain_err(fx.service.resolve(&alice()), "post-revoke resolve"),
        AccountServiceError::Revoked,
        "and it must not be able to acquire a replacement lease either"
    );
    assert_eq!(
        fx.observer_calls.load(Ordering::SeqCst),
        1,
        "the pre-revoke release is the only publish that may ever happen"
    );
    assert_eq!(fx.provider_calls.load(Ordering::SeqCst), 0);

    // The revoke has to outlive the process, or a restart is the restore path.
    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen after revoke");
    let reopened = Fixture::wrap(tmp, store);
    assert_eq!(
        domain_err(reopened.service.release(&lease), "release after restart"),
        AccountServiceError::LeaseRetired,
        "a restart must not resurrect the grant for the holder"
    );
    reopened.assert_quiet("release after restart");
}

/// Re-consent is the case a revoke alone cannot reach.
///
/// `invalidate_during_held_refresh_discards_stale_provider_success` also holds a
/// refresh across a revoke, but it leaves the account TOMBSTONED, so every
/// refusal there is reachable from the `Revoked` arm alone. Here a new
/// generation is consented while the old holders are still live, so the account
/// is connected again and that arm is gone: the held rotation has to lose the
/// version compare-and-swap, and the populated credential cache has to be
/// refused by the whole-lease recheck rather than by a tombstone.
///
/// The re-consented record moves ONLY the generation and the token bytes — same
/// scopes, same descriptor revision, same token revision, same authorization
/// epoch — so a recheck comparing anything less than the whole lease serves the
/// new grant's credential to the old holder.
#[test]
fn reconsent_under_a_held_refresh_retires_the_cached_credential_and_the_rotation() {
    block_on(async {
        let first = grant();
        let (tmp, store) = seed(&[(&alice(), first.clone())]);
        let provider = ScriptedProvider::new();
        let (provider_calls, entered, release_provider) = provider.hold(
            &alice(),
            Ok(rotation(
                "synthetic-alice-access-stale-private-material-bb22",
                Some(first.scopes.clone()),
            )),
        );
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        // HOLDER 1 and 2: a populated credential cache — the bytes a caller is
        // holding, and the lease its entry is keyed on. Both stay live below.
        let cached_lease = refuse_scaffold(service.resolve(&alice()), "lease before revoke")
            .expect("connected account leases before revoke");
        let cached = refuse_scaffold(service.release(&cached_lease), "credential before revoke")
            .expect("connected account releases before revoke");
        assert_eq!(cached, expected_credentials(&first));
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        // HOLDER 3: a refresh task inside the flight, parked at the provider.
        let held = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.refresh_if_expired(&alice()).await })
        };
        reached(entered, "provider entered before revoke")
            .await
            .expect("provider entered sender dropped");
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

        // The revoke lands with all three live, and the user re-consents before
        // any of them has been given a chance to notice.
        refuse_scaffold(service.invalidate(&alice()), "revoke under held refresh")
            .expect("revoke while the refresh and the cache entry are live");
        let revoked = ConsentExpectation::captured(
            &service.store().lookup(&alice()).expect("capture revoke"),
        );
        let second = GrantRecord {
            generation: "cafebabecafebabecafebabecafebabe".into(),
            access_token: "synthetic-alice-access-reconsented-private-material-cc33".into(),
            refresh_token: Some("synthetic-alice-refresh-reconsented-private-material-dd44".into()),
            expires_at: u64::MAX,
            ..first.clone()
        };
        refuse_scaffold(
            service.commit_grant_if(&alice(), &revoked, &second),
            "re-consent after revoke",
        )
        .expect("a captured revoke re-consents a new generation");

        release_provider
            .send(())
            .expect("held provider still waiting at re-consent");
        let stale = reached(
            async { held.await.expect("held refresh task") },
            "held refresh join",
        )
        .await;

        // (i) The rotation cannot complete a token write. Its compare-and-swap
        // named the retired generation, and the live one is connected rather
        // than tombstoned, so this is a retired lease and not `Revoked`.
        assert_eq!(
            domain_err(stale, "held rotation after re-consent"),
            AccountServiceError::LeaseRetired
        );
        // (ii) The cached credential is not served under the new generation.
        assert_eq!(
            domain_err(
                service.release(&cached_lease),
                "cached credential after re-consent",
            ),
            AccountServiceError::LeaseRetired
        );
        // (iii) Neither holder published anything: `on_release` fires only past
        // the recheck, so the count standing still IS the non-publication.
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        // Retirement, not an account that stopped working: the new generation
        // serves its OWN credential, under a lease the old one cannot equal.
        let fresh = refuse_scaffold(service.resolve(&alice()), "lease under re-consent")
            .expect("the re-consented generation leases");
        assert_ne!(fresh, cached_lease);
        let served = refuse_scaffold(service.release(&fresh), "credential under re-consent")
            .expect("the re-consented generation releases");
        assert_eq!(served, expected_credentials(&second));
        assert_ne!(served, cached);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 2);
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

        // Durably, across a reopen: the held rotation reinstated nothing. A
        // write that landed would have advanced the revision and replaced the
        // token bytes with the ones the retired generation was rotating to.
        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let durable = expect_connected(store.lookup(&alice()).expect("re-consented reopen"));
        assert_eq!(durable.generation, second.generation);
        assert_eq!(durable.token_revision, second.token_revision);
        assert_eq!(durable.authorization_epoch, second.authorization_epoch);
        assert_eq!(durable.access_token, second.access_token);
    });
}
