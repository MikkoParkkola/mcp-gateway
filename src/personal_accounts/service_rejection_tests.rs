// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11: an upstream 401 forces at most one refresh per token revision.
//!
//! These cells assert the service's `RejectionOutcome`, never a retry flag: the
//! one mapping from outcome to `UPSTREAM_AUTH_REJECTED`/`retry` lives in
//! `ManagedLease::after_upstream_401` and is pinned there (T14).

use std::sync::atomic::Ordering;

use super::super::RejectionOutcome;
use super::*;
use crate::personal_accounts::ForceClaim;

/// T3 at the service boundary: a backend that answers 401 to every token
/// costs one provider round trip per token revision, however many calls.
#[test]
fn persistent_401_costs_one_forced_refresh() {
    block_on(async {
        let (_tmp, store) = seed(&[(&alice(), unexpired_grant())]);
        let provider = ScriptedProvider::new();
        let calls = provider.ready(
            &alice(),
            Ok(rotation("synthetic-alice-access-forced-a11-t3", None)),
        );
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let lease = refuse_scaffold(service.resolve(&alice()), "resolve")
            .expect("a connected grant resolves");
        let first = refuse_scaffold(service.refresh_after_rejection(&lease).await, "first 401")
            .expect("the first 401 is answered, not refused");
        assert_eq!(first, RejectionOutcome::Rotated);

        for call in 2..=5 {
            let lease = refuse_scaffold(service.resolve(&alice()), "resolve after rotation")
                .expect("the rotated grant is still connected");
            let again = refuse_scaffold(
                service.refresh_after_rejection(&lease).await,
                "repeated 401",
            )
            .expect("a repeated 401 is answered, not refused");
            assert_eq!(again, RejectionOutcome::AlreadyForced, "call {call}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the rotated revision was force-tried once; later 401s must not refresh again"
        );
    });
}

/// T3b: the revision is marked BEFORE the provider answers, so an unavailable
/// provider does not let the next 401 force again.
#[test]
fn unavailable_idp_still_marks_revision() {
    block_on(async {
        let (_tmp, store) = seed(&[(&alice(), unexpired_grant())]);
        let provider = ScriptedProvider::new();
        let calls = provider.ready(&alice(), Err(ProviderRefreshError::Unavailable));
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let lease = refuse_scaffold(service.resolve(&alice()), "resolve").expect("connected");
        let first = refuse_scaffold(service.refresh_after_rejection(&lease).await, "first 401")
            .expect("answered");
        assert_eq!(first, RejectionOutcome::Unavailable);
        let second = refuse_scaffold(service.refresh_after_rejection(&lease).await, "second 401")
            .expect("answered");
        assert_eq!(second, RejectionOutcome::AlreadyForced);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Unavailable is transient: nothing durable fences the account.
        let durable = expect_connected(service.store().lookup(&alice()).expect("lookup"));
        assert_eq!(durable.token_revision, unexpired_grant().token_revision);
    });
}

/// T3c: the mark is durable. A restart does not buy another forced refresh.
#[test]
fn forced_revision_survives_restart() {
    block_on(async {
        let (tmp, store) = seed(&[(&alice(), unexpired_grant())]);
        let provider = ScriptedProvider::new();
        let first_calls = provider.ready(&alice(), Err(ProviderRefreshError::Unavailable));
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);
        let lease = refuse_scaffold(service.resolve(&alice()), "resolve").expect("connected");
        let first = refuse_scaffold(service.refresh_after_rejection(&lease).await, "first 401")
            .expect("answered");
        assert_eq!(first, RejectionOutcome::Unavailable);
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        drop(service);

        let reopened = PersonalAccountStore::open(config(tmp.path())).expect("reopen store");
        let provider = ScriptedProvider::new();
        let after_restart = provider.ready(
            &alice(),
            Ok(rotation("synthetic-alice-access-after-restart-a11", None)),
        );
        let (observer, _) = counting_observer();
        let service = AccountService::new(reopened, provider, observer);
        let lease = refuse_scaffold(service.resolve(&alice()), "resolve after restart")
            .expect("still connected");
        let again = refuse_scaffold(
            service.refresh_after_rejection(&lease).await,
            "401 after restart",
        )
        .expect("answered");

        assert_eq!(again, RejectionOutcome::AlreadyForced);
        assert_eq!(after_restart.load(Ordering::SeqCst), 0);
    });
}

/// T4: a 401 against a lease the store has already rotated past asks nobody.
/// The next call presents the newer token.
#[test]
fn stale_lease_401_does_not_refresh() {
    block_on(async {
        // `grant()` is expired, so `refresh_if_expired` rotates it to revision 2.
        let (_tmp, store) = seed(&[(&alice(), grant())]);
        let provider = ScriptedProvider::new();
        let calls = provider.ready(
            &alice(),
            Ok(rotation("synthetic-alice-access-rotated-a11-t4", None)),
        );
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let stale = refuse_scaffold(service.resolve(&alice()), "resolve rev 1").expect("connected");
        let current = refuse_scaffold(
            service.refresh_if_expired(&alice()).await,
            "expiry rotation",
        )
        .expect("the expired grant rotates");
        assert!(current.token_revision > stale.token_revision);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "setup: the expiry rotation"
        );

        let outcome = refuse_scaffold(service.refresh_after_rejection(&stale).await, "stale 401")
            .expect("answered");
        assert_eq!(outcome, RejectionOutcome::Stale);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a stale lease makes no provider call"
        );
    });
}

/// T11: a natural expiry rotation leaves the NEW revision un-force-tried, so a
/// 401 against it still earns one forced refresh, which fences on
/// `invalid_grant`.
#[test]
fn expiry_rotation_then_401_still_forces_once() {
    block_on(async {
        let (_tmp, store) = seed(&[(&alice(), grant())]);
        let provider = ScriptedProvider::new();
        let expiry_calls = provider.ready(
            &alice(),
            Ok(rotation("synthetic-alice-access-expiry-a11-t11", None)),
        );
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        let rotated = refuse_scaffold(
            service.refresh_if_expired(&alice()).await,
            "expiry rotation",
        )
        .expect("the expired grant rotates");
        assert_eq!(expiry_calls.load(Ordering::SeqCst), 1);

        let forced_calls = service
            .provider
            .ready(&alice(), Err(ProviderRefreshError::InvalidGrant));
        let outcome = service.refresh_after_rejection(&rotated).await;

        assert_eq!(
            domain_err(outcome, "401 after expiry rotation"),
            AccountServiceError::ReconnectRequired
        );
        assert_eq!(
            forced_calls.load(Ordering::SeqCst),
            1,
            "exactly one forced refresh"
        );
        assert!(matches!(
            service.store().lookup(&alice()).expect("lookup"),
            AccountLookup::ReconnectRequired(_)
        ));
    });
}

fn version_of_grant(record: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

/// The store grants a force-claim only to the live, connected version: an
/// account it does not hold and a version it has moved past are both
/// `Superseded`, and neither writes a mark.
#[test]
fn claim_is_refused_for_an_absent_account_and_for_a_moved_version() {
    let (_tmp, store) = seed(&[(&alice(), unexpired_grant())]);
    let live = version_of_grant(&unexpired_grant());

    assert_eq!(
        store.claim_forced_refresh(&bob(), &live).expect("answered"),
        ForceClaim::Superseded,
        "no entry for this account"
    );
    for (what, moved) in [
        (
            "token revision",
            GrantVersion {
                token_revision: live.token_revision + 1,
                ..live.clone()
            },
        ),
        (
            "authorization epoch",
            GrantVersion {
                authorization_epoch: live.authorization_epoch + 1,
                ..live.clone()
            },
        ),
        (
            "generation",
            GrantVersion {
                generation: "ffffffffffffffffffffffffffffffff".into(),
                ..live.clone()
            },
        ),
        (
            "descriptor revision",
            GrantVersion {
                descriptor_revision: "moved".into(),
                ..live.clone()
            },
        ),
    ] {
        assert_eq!(
            store
                .claim_forced_refresh(&alice(), &moved)
                .expect("answered"),
            ForceClaim::Superseded,
            "{what}"
        );
    }
    // No refusal above left a mark: the live version still claims once.
    assert_eq!(
        store.claim_forced_refresh(&alice(), &live).expect("claim"),
        ForceClaim::Claimed
    );
    assert_eq!(
        store.claim_forced_refresh(&alice(), &live).expect("again"),
        ForceClaim::AlreadyForced
    );
    // A tombstoned grant keeps its version, yet only a connected one claims.
    store.revoke(&alice()).expect("revoke");
    assert_eq!(
        store
            .claim_forced_refresh(&alice(), &live)
            .expect("answered"),
        ForceClaim::Superseded,
        "a revoked grant is not claimable at its own version"
    );
}

/// The rotated revision's own mark is written after the rotation is durable.
/// When that second write fails the error surfaces, and the rotation is kept:
/// the cost is one extra provider call later, never a lost or doubled token.
#[test]
fn failed_mark_of_the_rotated_revision_surfaces_and_keeps_the_rotation() {
    block_on(async {
        let (_tmp, store) = seed(&[(&alice(), unexpired_grant())]);
        // Two commits succeed (the claim, the rotation); the third overflows.
        store
            .lock_authority()
            .as_mut()
            .expect("open store")
            .commit_revision = u64::MAX - 2;
        let provider = ScriptedProvider::new();
        let calls = provider.ready(
            &alice(),
            Ok(rotation("synthetic-alice-access-mark-fails", None)),
        );
        let (observer, _) = counting_observer();
        let service = AccountService::new(store, provider, observer);
        let lease = refuse_scaffold(service.resolve(&alice()), "resolve").expect("connected");

        let outcome = service.refresh_after_rejection(&lease).await;

        assert_eq!(
            domain_err(outcome, "mark of the rotated revision"),
            AccountServiceError::Store(AccountError::StorageUnavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let durable = expect_connected(service.store().lookup(&alice()).expect("lookup"));
        assert_eq!(
            durable.token_revision,
            unexpired_grant().token_revision + 1,
            "the rotation is durable"
        );
    });
}
