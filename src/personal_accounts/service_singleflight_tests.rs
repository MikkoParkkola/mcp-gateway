// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Single-flight refresh: one round trip per in-flight account, and what
//! "per account" is allowed to mean.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;

/// One distinct rotation per one-field-apart account, so a durable record
/// carrying the wrong one names the account whose credentials leaked.
const VARIANT_ACCESS: [&str; 5] = [
    "synthetic-variant-access-private-material-authority-01",
    "synthetic-variant-access-private-material-subject-02",
    "synthetic-variant-access-private-material-backend-03",
    "synthetic-variant-access-private-material-resource-04",
    "synthetic-variant-access-private-material-issuer-05",
];

#[test]
fn concurrent_expired_refresh_single_flights_one_provider_call_and_unblocks_independent_principal()
{
    block_on(async {
        let alice_record = grant();
        let bob_record = bob_grant();
        let (tmp, store) = seed(&[
            (&alice(), alice_record.clone()),
            (&bob(), bob_record.clone()),
        ]);
        let provider = ScriptedProvider::new();
        let alice_rotation = rotation(
            "synthetic-alice-access-rotated-private-material-b2e14",
            Some(alice_record.scopes.clone()),
        );
        let bob_rotation = rotation(
            "synthetic-bob-access-rotated-private-material-c8d03",
            Some(bob_record.scopes.clone()),
        );
        let (alice_calls, alice_entered, alice_release) =
            provider.hold(&alice(), Ok(alice_rotation));
        let bob_calls = provider.ready(&bob(), Ok(bob_rotation));
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        // Both refreshes must be observed INSIDE the service and parked before
        // the one-call assertion means anything. A spawned task that has not
        // been polled has not reached the single-flight gate, so asserting the
        // call count first would measure the scheduler.
        let (fut_a, pending_a) = first_pending({
            let service = Arc::clone(&service);
            async move { service.refresh_if_expired(&alice()).await }
        });
        let task_a = tokio::spawn(fut_a);
        let (fut_b, pending_b) = first_pending({
            let service = Arc::clone(&service);
            async move { service.refresh_if_expired(&alice()).await }
        });
        let task_b = tokio::spawn(fut_b);

        reached(alice_entered, "alice provider entered")
            .await
            .expect("alice provider entered sender dropped");
        reached(pending_a, "alice refresh task 1 first pending poll")
            .await
            .expect("alice task 1 pending signal dropped");
        reached(pending_b, "alice refresh task 2 first pending poll")
            .await
            .expect("alice task 2 pending signal dropped");
        // Held, so every provider invocation either happened before this line
        // or cannot happen until the release below.
        assert_eq!(
            alice_calls.load(Ordering::SeqCst),
            1,
            "two parked refreshes for one account must share one round trip"
        );
        assert_eq!(bob_calls.load(Ordering::SeqCst), 0);

        let bob_lease = refuse_scaffold(
            reached(
                service.refresh_if_expired(&bob()),
                "independent principal refresh while alice held",
            )
            .await,
            "bob refresh while alice held",
        )
        .expect("independent principal completes while first account held");
        assert_eq!(bob_calls.load(Ordering::SeqCst), 1);
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        alice_release
            .send(())
            .expect("held alice provider still waiting for release");
        let lease_a = refuse_scaffold(
            reached(
                async { task_a.await.expect("alice task 1") },
                "alice refresh task 1",
            )
            .await,
            "alice refresh task 1",
        )
        .expect("first waiter receives refreshed lease");
        let lease_b = refuse_scaffold(
            reached(
                async { task_b.await.expect("alice task 2") },
                "alice refresh task 2",
            )
            .await,
            "alice refresh task 2",
        )
        .expect("second waiter receives refreshed lease");
        assert_eq!(lease_a, lease_b);
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        let alice_durable =
            expect_connected(service.store().lookup(&alice()).expect("alice lookup"));
        let bob_durable = expect_connected(service.store().lookup(&bob()).expect("bob lookup"));
        assert_eq!(lease_a, expected_lease(alice(), &alice_durable));
        assert_eq!(bob_lease, expected_lease(bob(), &bob_durable));
        assert!(alice_durable.token_revision > alice_record.token_revision);
        assert!(bob_durable.token_revision > bob_record.token_revision);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let reopened = expect_connected(store.lookup(&alice()).expect("alice reopen"));
        assert_eq!(reopened.token_revision, alice_durable.token_revision);
        assert_eq!(reopened.scopes, alice_record.scopes);
    });
}

/// An account is the whole five-field tuple. A service that partitions on the
/// subject alone serialises unrelated backends behind one another and, worse,
/// can serve one account's rotation to another. Each case below moves exactly
/// one field, so a partition missing that field fails on that case and names it.
#[test]
fn single_flight_partitions_on_the_complete_account_key_not_the_subject() {
    block_on(async {
        let alice_key = alice();
        let alice_record = grant();
        let variants = one_field_apart();
        let seeded = one_field_apart_grants();
        let mut to_seed: Vec<(&AccountKey, GrantRecord)> = vec![(&alice_key, alice_record.clone())];
        for (account, record) in &seeded {
            to_seed.push((account, record.clone()));
        }
        let (tmp, store) = seed(&to_seed);

        let provider = ScriptedProvider::new();
        let (alice_calls, alice_entered, alice_release) = provider.hold(
            &alice(),
            Ok(rotation(
                "synthetic-alice-access-held-private-material-f70c",
                Some(alice_record.scopes.clone()),
            )),
        );
        let variant_calls: Vec<_> = seeded
            .iter()
            .enumerate()
            .map(|(index, (account, record))| {
                provider.ready(
                    account,
                    Ok(rotation(VARIANT_ACCESS[index], Some(record.scopes.clone()))),
                )
            })
            .collect();
        let (observer, observer_calls) = counting_observer();
        let service = Arc::new(AccountService::new(store, provider, observer));

        let (fut, pending) = first_pending({
            let service = Arc::clone(&service);
            async move { service.refresh_if_expired(&alice()).await }
        });
        let held = tokio::spawn(fut);
        reached(alice_entered, "alice provider entered")
            .await
            .expect("alice provider entered sender dropped");
        reached(pending, "held alice refresh first pending poll")
            .await
            .expect("held alice pending signal dropped");
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);

        for (index, (field, account)) in variants.iter().enumerate() {
            let record = &seeded[index].1;
            let lease = refuse_scaffold(
                reached(
                    service.refresh_if_expired(account),
                    "one-field-apart refresh while alice held",
                )
                .await,
                "one-field-apart refresh",
            )
            .unwrap_or_else(|error| {
                panic!("{field}: an account one field from a held one must refresh: {error:?}")
            });
            assert_eq!(
                &lease.account, account,
                "{field}: the lease must bind the account it was asked for"
            );
            assert_eq!(
                variant_calls[index].load(Ordering::SeqCst),
                1,
                "{field}: exactly one round trip for this account"
            );
            assert_eq!(
                alice_calls.load(Ordering::SeqCst),
                1,
                "{field}: the held account must not be refreshed a second time"
            );

            let durable = expect_connected(
                service
                    .store()
                    .lookup(account)
                    .expect("one-field-apart lookup"),
            );
            assert!(
                durable.access_token == VARIANT_ACCESS[index],
                "{field}: this account must receive its own rotation"
            );
            assert!(
                durable.token_revision > record.token_revision,
                "{field}: this account's own revision advanced"
            );
            assert_eq!(durable.generation, record.generation, "{field}");
            assert_eq!(lease, expected_lease(account.clone(), &durable), "{field}");

            let alice_durable =
                expect_connected(service.store().lookup(&alice()).expect("alice held lookup"));
            assert!(
                alice_durable == alice_record,
                "{field}: the held account's durable grant must not move"
            );
        }

        alice_release
            .send(())
            .expect("held alice provider still waiting for release");
        let alice_lease = refuse_scaffold(
            reached(
                async { held.await.expect("held alice task") },
                "held alice join",
            )
            .await,
            "held alice refresh",
        )
        .expect("the held account refreshes once released");
        assert_eq!(alice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

        let service = Arc::try_unwrap(service)
            .ok()
            .expect("drop all task references before reopen");
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let alice_reopened = expect_connected(store.lookup(&alice()).expect("alice reopen"));
        assert_eq!(alice_lease, expected_lease(alice(), &alice_reopened));
        assert!(
            alice_reopened.access_token == "synthetic-alice-access-held-private-material-f70c",
            "the held account keeps its own rotation across reopen"
        );
        for (index, (field, account)) in variants.iter().enumerate() {
            let reopened = expect_connected(store.lookup(account).expect("variant reopen"));
            assert!(
                reopened.access_token == VARIANT_ACCESS[index],
                "{field}: reopen must show this account's own rotation"
            );
        }
    });
}
