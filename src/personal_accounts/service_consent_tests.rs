// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Conditional consent: a journey commits against the state it captured, and
//! only if that state is still the authoritative one.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::personal_accounts::consent::witness::{self, Phase};

use super::*;

fn reconnect_descriptor() -> String {
    "1".repeat(64)
}

/// The acceptance predicate for a guarded call, read off the STORE's own lock:
/// one acquisition, held from the moment it was taken to the moment it was
/// released. Nothing here is reported by the code under test — the phases are
/// logged at `PersonalAccountStore::lock_authority`, which is the only way to
/// reach the authority at all.
fn one_authority_session(events: &[(Phase, u64)]) -> bool {
    events.len() == 3
        && events.iter().all(|(_, id)| *id == events[0].1)
        && events.iter().map(|(phase, _)| *phase).eq([
            Phase::Attempt,
            Phase::Acquire,
            Phase::Release,
        ])
}

#[test]
fn stale_consent_expectation_cannot_overwrite_newer_grant_or_revoke() {
    let (tmp, store) = seed(&[]);
    let provider = ScriptedProvider::new();
    let provider_calls = provider.ready(&alice(), Err(ProviderRefreshError::Unavailable));
    let (observer, observer_calls) = counting_observer();
    let service = AccountService::new(store, provider, observer);

    let first = grant();
    let second = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let third = grant_gen("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let fourth = grant_gen("cccccccccccccccccccccccccccccccc");

    service
        .store()
        .commit_grant(&alice(), &first)
        .expect("intervening grant after captured absent");
    assert_eq!(
        domain_err(
            service.commit_grant_if(&alice(), &ConsentExpectation::Absent, &second),
            "stale absent after newer grant",
        ),
        AccountServiceError::StaleConsentFenced
    );
    let after_absent = expect_connected(
        service
            .store()
            .lookup(&alice())
            .expect("after stale absent"),
    );
    assert_eq!(after_absent.generation, first.generation);

    let connected_first = ConsentExpectation::captured(
        &service
            .store()
            .lookup(&alice())
            .expect("capture connected first"),
    );
    refuse_scaffold(
        service.commit_grant_if(&alice(), &connected_first, &second),
        "exact current connected commit",
    )
    .expect("exact current connected expectation commits");
    let after_second = expect_connected(
        service
            .store()
            .lookup(&alice())
            .expect("after current connected"),
    );
    assert_eq!(after_second.generation, second.generation);

    let connected_second = ConsentExpectation::captured(
        &service
            .store()
            .lookup(&alice())
            .expect("capture connected second"),
    );
    refuse_scaffold(service.invalidate(&alice()), "newer revoke after connected")
        .expect("invalidate publishes a newer revoke");
    assert_eq!(
        domain_err(
            service.commit_grant_if(&alice(), &connected_second, &third),
            "stale connected after newer revoke",
        ),
        AccountServiceError::StaleConsentFenced
    );
    assert_eq!(
        domain_err(
            service.commit_grant_if(&alice(), &ConsentExpectation::Absent, &third),
            "stale absent after newer revoke",
        ),
        AccountServiceError::StaleConsentFenced
    );
    assert_eq!(
        service
            .store()
            .lookup(&alice())
            .expect("revoked after stale connected"),
        AccountLookup::Revoked(expected_version(&second))
    );

    let revoked =
        ConsentExpectation::captured(&service.store().lookup(&alice()).expect("capture revoked"));
    service
        .store()
        .commit_grant(&alice(), &third)
        .expect("intervening grant after captured revoke");
    assert_eq!(
        domain_err(
            service.commit_grant_if(&alice(), &revoked, &fourth),
            "stale revoked after newer grant",
        ),
        AccountServiceError::StaleConsentFenced
    );
    let after_third = expect_connected(
        service
            .store()
            .lookup(&alice())
            .expect("after stale revoked"),
    );
    assert_eq!(after_third.generation, third.generation);

    let connected_third = ConsentExpectation::captured(
        &service
            .store()
            .lookup(&alice())
            .expect("capture connected third"),
    );
    refuse_scaffold(
        service.commit_grant_if(&alice(), &connected_third, &fourth),
        "exact current connected commit of fourth",
    )
    .expect("exact current expectation commits");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen after exact commit");
    let reopened = expect_connected(store.lookup(&alice()).expect("reopen after exact commit"));
    assert_eq!(reopened.generation, fourth.generation);
    assert_eq!(reopened.token_revision, fourth.token_revision);
    assert_eq!(reopened.authorization_epoch, fourth.authorization_epoch);
}

/// A first connection captures `Absent`. Without this case an implementation
/// may accept only `Connected` expectations and refuse every new user, and the
/// stale-expectation cases above would still pass.
#[test]
fn a_current_absent_expectation_commits_the_first_grant() {
    let fx = Fixture::seeded(&[]);
    let first = grant();

    refuse_scaffold(
        fx.service
            .commit_grant_if(&alice(), &ConsentExpectation::Absent, &first),
        "current absent commit",
    )
    .expect("a first-time connection commits against a current Absent capture");
    assert!(
        expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("after first grant")
        ) == first
    );
    fx.assert_quiet("current absent commit");

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == first);
}

/// Reconnecting after a revoke captures `Revoked`. Refusing it strands the user
/// on the tombstone their own revoke wrote.
#[test]
fn a_current_revoked_expectation_commits_a_reconnection() {
    let fx = Fixture::connected_alice();
    fx.service
        .store()
        .revoke(&alice())
        .expect("durable revoke before reconnection");
    let captured = ConsentExpectation::captured(
        &fx.service
            .store()
            .lookup(&alice())
            .expect("capture the revoke"),
    );
    assert_eq!(
        captured,
        ConsentExpectation::Revoked(expected_version(&grant()))
    );

    let reconnected = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    refuse_scaffold(
        fx.service
            .commit_grant_if(&alice(), &captured, &reconnected),
        "current revoked commit",
    )
    .expect("a reconnection commits against a current Revoked capture");
    assert!(
        expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("after reconnection")
        ) == reconnected
    );
    fx.assert_quiet("current revoked commit");

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == reconnected);
}

/// A descriptor change fences the account; the reconnect journey that follows
/// captures `ReconnectRequired`. This is the state the gateway itself asks the
/// user to resolve, so refusing its own expectation is a permanent dead end.
#[test]
fn a_current_reconnect_required_expectation_commits_a_reconnection() {
    let fx = Fixture::connected_alice();
    fx.service
        .store()
        .mark_reconnect_required(&alice(), &reconnect_descriptor())
        .expect("fence the grant on a descriptor change");
    let captured = ConsentExpectation::captured(
        &fx.service
            .store()
            .lookup(&alice())
            .expect("capture the fence"),
    );
    assert!(
        matches!(captured, ConsentExpectation::ReconnectRequired(_)),
        "the capture must carry the fenced state, not a connected one"
    );

    let reconnected = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    refuse_scaffold(
        fx.service
            .commit_grant_if(&alice(), &captured, &reconnected),
        "current reconnect-required commit",
    )
    .expect("a reconnection commits against a current ReconnectRequired capture");
    assert!(
        expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("after reconnection")
        ) == reconnected
    );
    fx.assert_quiet("current reconnect-required commit");

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == reconnected);
}

#[test]
fn a_stale_reconnect_required_expectation_is_fenced_by_a_newer_grant() {
    let fx = Fixture::connected_alice();
    fx.service
        .store()
        .mark_reconnect_required(&alice(), &reconnect_descriptor())
        .expect("fence the grant on a descriptor change");
    let captured = ConsentExpectation::captured(
        &fx.service
            .store()
            .lookup(&alice())
            .expect("capture the fence"),
    );

    // Another journey finishes first.
    let winner = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fx.service
        .store()
        .commit_grant(&alice(), &winner)
        .expect("a reconnection lands before the captured journey returns");

    let loser = grant_gen("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert_eq!(
        domain_err(
            fx.service.commit_grant_if(&alice(), &captured, &loser),
            "stale reconnect-required after a newer grant",
        ),
        AccountServiceError::StaleConsentFenced
    );
    assert!(
        expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("after the fenced journey")
        ) == winner,
        "the journey that arrived first keeps the account"
    );
    fx.assert_quiet("stale reconnect-required");

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == winner);
}

/// The sequential cases above cannot tell a guarded commit from
/// lookup-then-commit: both answer identically when nothing is racing. This one
/// can, and it does not ask the implementation anything. The store has exactly
/// one way to reach the authority, and every acquisition through it is logged,
/// so a call that reads under one lock and writes under another logs two
/// sessions no matter how it describes itself.
#[test]
fn a_conditional_consent_commit_takes_the_authority_lock_exactly_once() {
    let fx = Fixture::seeded(&[]);
    let first = grant();

    let recording = witness::watch(fx.service.store());
    let mark = recording.mark();
    refuse_scaffold(
        fx.service
            .commit_grant_if(&alice(), &ConsentExpectation::Absent, &first),
        "witnessed conditional commit",
    )
    .expect("a current expectation commits");
    let events = recording.since(mark);
    drop(recording);

    assert!(
        one_authority_session(&events),
        "a conditional commit takes the authority lock once and holds it across \
         the comparison and the publication; lookup-then-commit logs two \
         sessions. observed: {events:?}"
    );
    assert!(
        expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("after witnessed commit")
        ) == first
    );

    let Fixture { tmp, service, .. } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == first);
}

#[test]
fn the_guarded_store_entrypoint_fences_a_stale_expectation_without_writing() {
    let (tmp, store) = seed(&[(&alice(), grant())]);
    let replacement = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let recording = witness::watch(&store);
    let mark = recording.mark();
    let outcome = refuse_guarded_scaffold(
        store.commit_grant_if_unchanged(&alice(), &ConsentExpectation::Absent, &replacement),
        "stale guarded commit",
    )
    .expect("a stale expectation is an ordinary refusal, not a store failure");
    let events = recording.since(mark);
    drop(recording);

    assert_eq!(outcome, GuardedCommit::Fenced);
    assert!(
        one_authority_session(&events),
        "the expectation is compared under the same single acquisition a commit \
         would have used. observed: {events:?}"
    );
    assert_ne!(
        GuardedCommitError::from(AccountError::CapacityExhausted),
        GuardedCommitError::RuntimeNotImplemented,
        "a store failure and the unimplemented scaffold are different answers"
    );

    let durable = expect_connected(store.lookup(&alice()).expect("after the fenced commit"));
    assert!(durable == grant(), "the fenced commit changed nothing");
    drop(store);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == grant());
}

/// The defect this whole primitive exists for, run as a real race — with the
/// competing writer's blocking DEMONSTRATED rather than assumed.
///
/// The park sits inside the store's acquisition point, so the guarded call
/// stalls while holding the real mutex. The competitor is released against it,
/// and the test then waits for the competitor's OWN logged arrival at that
/// acquisition point. No clock, no final-record inference, no guess about the
/// scheduler: the competitor's arrival is an event, and the guarded session is
/// demonstrably still open when it happens.
///
/// The proof is the causal order of the store's own log:
///
///   attempt(g) acquire(g) attempt(c) release(g) acquire(c) release(c)
///
/// `attempt(c)` before `release(g)`, and `acquire(c)` only after it, is
/// exclusion by a held guard. Lookup-then-commit cannot produce this sequence:
/// its read guard is released while the competitor waits, so the competitor
/// acquires BEFORE the second guarded attempt and the window holds three
/// sessions instead of one.
#[test]
fn a_competing_writer_cannot_land_between_the_comparison_and_the_commit() {
    let (tmp, store) = seed(&[(&alice(), grant())]);
    let store = Arc::new(store);
    let captured =
        ConsentExpectation::captured(&store.lookup(&alice()).expect("capture the current state"));
    let guarded_record = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let competing_record = grant_gen("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let recording = witness::watch(&store);
    let park = recording.arm_park();
    let opened = recording.mark();

    let guarded = {
        let store = Arc::clone(&store);
        let record = guarded_record.clone();
        std::thread::spawn(move || store.commit_grant_if_unchanged(&alice(), &captured, &record))
    };
    // Parked INSIDE the acquisition. The guard is held from here until release.
    park.wait_entered();
    let parked = recording.mark();

    let competing = {
        let store = Arc::clone(&store);
        let record = competing_record.clone();
        std::thread::spawn(move || store.commit_grant(&alice(), &record))
    };
    // Returns on the competitor's own arrival, not on a timeout.
    recording.wait_for_attempt_since(parked);
    assert!(
        recording
            .since(parked)
            .iter()
            .all(|(phase, _)| *phase != Phase::Release),
        "the competitor reached the acquisition point while the guard was still held"
    );
    park.release();

    let outcome = refuse_guarded_scaffold(
        guarded.join().expect("guarded thread"),
        "guarded commit under contention",
    )
    .expect("the captured state was still current when the lock was taken");
    competing
        .join()
        .expect("competing thread")
        .expect("the competing writer commits once the lock is free");
    let events = recording.since(opened);
    drop(recording);

    assert_eq!(outcome, GuardedCommit::Committed);
    assert_eq!(
        events.len(),
        6,
        "one guarded session and one competing session, nothing else. observed: {events:?}"
    );
    let guarded_session = events[0].1;
    let competing_session = events[2].1;
    assert_ne!(guarded_session, competing_session);
    assert_eq!(
        events,
        vec![
            (Phase::Attempt, guarded_session),
            (Phase::Acquire, guarded_session),
            (Phase::Attempt, competing_session),
            (Phase::Release, guarded_session),
            (Phase::Acquire, competing_session),
            (Phase::Release, competing_session),
        ],
        "the competitor must attempt before the guarded release and acquire only after it"
    );
    let durable = expect_connected(store.lookup(&alice()).expect("after the race"));
    assert!(
        durable == competing_record,
        "the writer that took the lock second must be the one on disk"
    );

    let store = Arc::try_unwrap(store)
        .ok()
        .expect("drop all thread references before reopen");
    drop(store);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
    assert!(expect_connected(store.lookup(&alice()).expect("reopen")) == competing_record);
}

/// The falsifier for the predicate the two cases above accept with.
///
/// This performs the FORBIDDEN implementation against a real store — read under
/// one acquisition, write under another, exactly what `commit_grant_if` must
/// never be built from — and requires the predicate to reject it. Without this,
/// `one_authority_session` could be trivially true and nobody would know.
#[test]
fn the_split_acquisition_pattern_is_rejected_by_the_same_predicate() {
    let (_tmp, store) = seed(&[(&alice(), grant())]);
    let replacement = grant_gen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let recording = witness::watch(&store);
    let mark = recording.mark();
    let _read = store.lookup(&alice()).expect("read under one acquisition");
    store
        .commit_grant(&alice(), &replacement)
        .expect("write under another acquisition");
    let events = recording.since(mark);
    drop(recording);

    assert_eq!(
        events.len(),
        6,
        "two acquisitions, three phases each. observed: {events:?}"
    );
    assert_ne!(
        events[0].1, events[3].1,
        "a released and re-taken lock is two sessions"
    );
    assert!(
        !one_authority_session(&events),
        "the predicate the guarded cases pass with must reject lookup-then-commit"
    );
}
