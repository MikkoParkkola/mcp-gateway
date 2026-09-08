// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refresh outcomes that change the authorization: scope movement, and what a
//! refresh in flight may do when the account is re-authorized underneath it.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;

#[test]
fn narrower_scopes_advance_epoch_and_retire_lease_but_broader_scopes_are_refused() {
    block_on(async {
        let mut alice_record = grant();
        alice_record.scopes.push(metadata_scope());
        alice_record.scopes.sort();
        let bob_record = bob_grant();
        let (tmp, store) = seed(&[
            (&alice(), alice_record.clone()),
            (&bob(), bob_record.clone()),
        ]);
        let provider = ScriptedProvider::new();
        let narrower = vec![alice_record.scopes[0].clone()];
        let _alice_calls = provider.ready(
            &alice(),
            Ok(rotation(
                "synthetic-alice-access-narrowed-private-material-d41a",
                Some(narrower.clone()),
            )),
        );
        let mut broader = bob_record.scopes.clone();
        broader.push(full_drive_scope());
        let bob_calls = provider.ready(
            &bob(),
            Ok(rotation(
                "synthetic-bob-access-broadened-private-material-e90f",
                Some(broader),
            )),
        );
        let (observer, observer_calls) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let broader_err = domain_err(
            service.refresh_if_expired(&bob()).await,
            "broader-scope refresh",
        );
        assert_eq!(broader_err, AccountServiceError::ScopeBroadeningRefused);
        assert_eq!(bob_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);
        let bob_durable = expect_connected(service.store().lookup(&bob()).expect("bob unchanged"));
        assert_eq!(bob_durable.generation, bob_record.generation);
        assert_eq!(bob_durable.token_revision, bob_record.token_revision);
        assert_eq!(
            bob_durable.authorization_epoch,
            bob_record.authorization_epoch
        );
        assert_eq!(bob_durable.scopes, bob_record.scopes);
        assert!(
            bob_durable.access_token == bob_record.access_token,
            "broader refusal must not persist provider access token"
        );

        let prior = refuse_scaffold(service.resolve(&alice()), "alice resolve before narrower")
            .expect("connected expired lease still resolves");
        let refreshed = refuse_scaffold(
            service.refresh_if_expired(&alice()).await,
            "narrower-scope refresh",
        )
        .expect("narrower refresh is accepted");
        assert!(refreshed.authorization_epoch > prior.authorization_epoch);
        assert_eq!(refreshed.scopes, narrower);
        assert_eq!(
            domain_err(service.release(&prior), "prior lease after narrower"),
            AccountServiceError::LeaseRetired
        );
        let credentials = refuse_scaffold(service.release(&refreshed), "new lease after narrower")
            .expect("narrower lease releases");
        assert_eq!(
            credentials,
            ReleasedCredentials {
                access_token: "synthetic-alice-access-narrowed-private-material-d41a".into(),
                token_type: "Bearer".into(),
            }
        );
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let alice_durable = expect_connected(store.lookup(&alice()).expect("alice reopen"));
        assert_eq!(alice_durable.scopes, narrower);
        assert_eq!(
            alice_durable.authorization_epoch,
            refreshed.authorization_epoch
        );
        let bob_reopened = expect_connected(store.lookup(&bob()).expect("bob reopen"));
        assert_eq!(bob_reopened.scopes, bob_record.scopes);
        assert_eq!(bob_reopened.token_revision, bob_record.token_revision);
    });
}

#[test]
fn invalidate_during_held_refresh_discards_stale_provider_success() {
    block_on(async {
        let alice_record = grant();
        let bob_record = bob_grant();
        let (tmp, store) = seed(&[
            (&alice(), alice_record.clone()),
            (&bob(), bob_record.clone()),
        ]);
        let provider = ScriptedProvider::new();
        let (alice_calls, alice_entered, alice_release) = provider.hold(
            &alice(),
            Ok(rotation(
                "synthetic-alice-access-stale-private-material-aa11",
                Some(alice_record.scopes.clone()),
            )),
        );
        let bob_calls = provider.ready(
            &bob(),
            Ok(rotation(
                "synthetic-bob-access-rotated-private-material-c8d03",
                Some(bob_record.scopes.clone()),
            )),
        );
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        let bob_lease = refuse_scaffold(
            service.refresh_if_expired(&bob()).await,
            "positive bob refresh control",
        )
        .expect("control refresh before race");
        refuse_scaffold(service.release(&bob_lease), "positive bob release control")
            .expect("control release before race");
        assert_eq!(bob_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        let prior = refuse_scaffold(service.resolve(&alice()), "alice lease before race")
            .expect("alice lease before held refresh");
        let held = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.refresh_if_expired(&alice()).await })
        };
        reached(alice_entered, "alice provider entered before invalidate")
            .await
            .expect("alice provider entered sender dropped");
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        refuse_scaffold(
            service.invalidate(&alice()),
            "invalidate while refresh held",
        )
        .expect("invalidate while provider refresh held");
        alice_release
            .send(())
            .expect("held alice provider still waiting after invalidate");
        let stale = reached(
            async { held.await.expect("held refresh task") },
            "stale refresh join",
        )
        .await;
        assert_eq!(
            domain_err(stale, "stale refresh after invalidate"),
            AccountServiceError::Revoked
        );
        assert_eq!(
            domain_err(service.release(&prior), "release after raced revoke"),
            AccountServiceError::LeaseRetired
        );
        assert_eq!(
            domain_err(service.resolve(&alice()), "resolve after raced revoke"),
            AccountServiceError::Revoked
        );
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        assert_eq!(
            store.lookup(&alice()).expect("revoked reopen"),
            AccountLookup::Revoked(expected_version(&alice_record))
        );
        let bob_durable = expect_connected(store.lookup(&bob()).expect("bob control reopen"));
        assert!(bob_durable.token_revision > bob_record.token_revision);
    });
}

#[test]
fn invalid_grant_marks_reconnect_required_without_lease_or_release() {
    block_on(async {
        let alice_record = grant();
        let bob_record = bob_grant();
        let (tmp, store) = seed(&[
            (&alice(), alice_record.clone()),
            (&bob(), bob_record.clone()),
        ]);
        let provider = ScriptedProvider::new();
        let alice_calls = provider.ready(&alice(), Err(ProviderRefreshError::InvalidGrant));
        let bob_calls = provider.ready(
            &bob(),
            Ok(rotation(
                "synthetic-bob-access-rotated-private-material-c8d03",
                Some(bob_record.scopes.clone()),
            )),
        );
        let (observer, observer_calls) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let prior = refuse_scaffold(
            service.resolve(&alice()),
            "alice lease before invalid grant",
        )
        .expect("connected lease before invalid grant");
        assert_eq!(
            domain_err(
                service.refresh_if_expired(&alice()).await,
                "alice invalid grant refresh",
            ),
            AccountServiceError::ReconnectRequired
        );
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            domain_err(
                service.resolve(&alice()),
                "alice resolve after invalid grant"
            ),
            AccountServiceError::ReconnectRequired
        );
        assert_eq!(
            domain_err(service.release(&prior), "alice release after invalid grant"),
            AccountServiceError::ReconnectRequired
        );
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            service
                .store()
                .lookup(&alice())
                .expect("alice reconnect lookup"),
            AccountLookup::ReconnectRequired(expected_version(&alice_record))
        );

        let bob_lease = refuse_scaffold(
            service.refresh_if_expired(&bob()).await,
            "unaffected bob refresh",
        )
        .expect("independent account still refreshes");
        refuse_scaffold(service.release(&bob_lease), "unaffected bob release")
            .expect("independent account still releases");
        assert_eq!(bob_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        assert_eq!(
            store.lookup(&alice()).expect("alice reconnect reopen"),
            AccountLookup::ReconnectRequired(expected_version(&alice_record))
        );
        let bob_durable = expect_connected(store.lookup(&bob()).expect("bob reopen"));
        assert!(bob_durable.token_revision > bob_record.token_revision);
    });
}

/// A refresh in flight holds a version that a completed consent journey has
/// already superseded. Revocation is not the only way that happens, and the
/// other two ways are the dangerous ones: a stale SUCCESS can overwrite the new
/// credentials, and a stale `InvalidGrant` can tombstone an account that was
/// just reconnected. Both must lose to the newer durable grant.
///
/// The refusal is `LeaseRetired`: the generation the refresh was rotating no
/// longer exists, so its outcome has nothing to apply to. It is deliberately
/// not `Revoked` (the account is connected) and not `StaleConsentFenced` (that
/// belongs to the consent journey, which this is not).
#[test]
fn a_newer_grant_during_a_held_refresh_survives_the_stale_provider_success() {
    block_on(async {
        let original = grant();
        let (tmp, store) = seed(&[(&alice(), original.clone())]);
        let provider = ScriptedProvider::new();
        let (alice_calls, alice_entered, alice_release) = provider.hold(
            &alice(),
            Ok(rotation(
                "synthetic-alice-access-superseded-private-material-bb22",
                Some(original.scopes.clone()),
            )),
        );
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        let held = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.refresh_if_expired(&alice()).await })
        };
        reached(
            alice_entered,
            "alice provider entered before the newer grant",
        )
        .await
        .expect("alice provider entered sender dropped");
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        // A fresh consent journey lands while the rotation is still in flight.
        let newer = grant_gen("dddddddddddddddddddddddddddddddd");
        service
            .store()
            .commit_grant(&alice(), &newer)
            .expect("newer grant lands during the held refresh");

        alice_release
            .send(())
            .expect("held alice provider still waiting after the newer grant");
        let stale = reached(
            async { held.await.expect("held refresh task") },
            "superseded refresh join",
        )
        .await;
        assert_eq!(
            domain_err(stale, "superseded refresh after a newer grant"),
            AccountServiceError::LeaseRetired
        );
        assert_eq!(
            alice_calls.load(Ordering::SeqCst),
            1,
            "a fenced refresh must not rotate the newer grant it just lost to"
        );
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

        let durable = expect_connected(
            service
                .store()
                .lookup(&alice())
                .expect("alice after superseded refresh"),
        );
        assert!(
            durable.access_token == newer.access_token,
            "the stale rotation must not replace the newer access token"
        );
        assert!(
            durable == newer,
            "the newer grant must be untouched in every field"
        );

        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let reopened = expect_connected(store.lookup(&alice()).expect("alice reopen"));
        assert!(
            reopened == newer,
            "reopen must show the newer grant, not the stale rotation"
        );
    });
}

#[test]
fn a_newer_grant_during_a_held_refresh_is_not_tombstoned_by_a_stale_invalid_grant() {
    block_on(async {
        let original = grant();
        let (tmp, store) = seed(&[(&alice(), original.clone())]);
        let provider = ScriptedProvider::new();
        let (alice_calls, alice_entered, alice_release) =
            provider.hold(&alice(), Err(ProviderRefreshError::InvalidGrant));
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        let held = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.refresh_if_expired(&alice()).await })
        };
        reached(
            alice_entered,
            "alice provider entered before the newer grant",
        )
        .await
        .expect("alice provider entered sender dropped");
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        let newer = grant_gen("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        service
            .store()
            .commit_grant(&alice(), &newer)
            .expect("reconnected grant lands during the held refresh");

        alice_release
            .send(())
            .expect("held alice provider still waiting after the newer grant");
        let stale = reached(
            async { held.await.expect("held refresh task") },
            "superseded invalid-grant join",
        )
        .await;
        assert_eq!(
            domain_err(stale, "superseded invalid grant"),
            AccountServiceError::LeaseRetired
        );
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

        // The invalid grant belonged to the generation that was replaced.
        // Fencing the account here disconnects a user who just reconnected.
        let durable = expect_connected(
            service
                .store()
                .lookup(&alice())
                .expect("alice must remain connected"),
        );
        assert!(
            durable == newer,
            "a stale InvalidGrant must not tombstone the newer grant"
        );
        let lease = refuse_scaffold(
            service.resolve(&alice()),
            "resolve after superseded invalid grant",
        )
        .expect("the reconnected account still resolves");
        assert_eq!(lease, expected_lease(alice(), &newer));

        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let reopened = store.lookup(&alice()).expect("alice reopen");
        assert_eq!(
            lookup_kind(&reopened),
            "connected",
            "reopen must not surface a tombstone the stale refresh wrote"
        );
        assert!(expect_connected(reopened) == newer);
    });
}
