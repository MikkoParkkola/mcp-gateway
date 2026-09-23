// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dispatch-site offer at the store (design §9.3, review H1; §11.2 row
//! T-OFFER3). Read back through `journeys.json`, never an in-memory copy.

use super::tests::{T0, create, fresh, limits, on_disk, request, start};
use super::{CALLBACK_WINDOW, JourneyLimits, JourneyReason, JourneyStatus, START_WINDOW};

/// One creation per minute gateway-wide: a second creation would be refused,
/// so an offer that succeeds twice has reused rather than minted.
fn one_creation_per_minute() -> JourneyLimits {
    JourneyLimits {
        journeys_created_per_minute: 1,
        ..limits()
    }
}

#[test]
fn t_offer3_a_started_journey_is_reused_byte_identically_and_still_connects() {
    // GIVEN: A's journey is started, with the provider step still pending
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0 + 1, &limits, &id, "alice");
    let before = on_disk(&store, &config, &limits).journeys[&id].clone();

    // WHEN: a refused dispatch for the same principal and account asks for an offer
    let (offered, expires_at) = store
        .offer_journey(T0 + 2, &limits, request("alice", "google"))
        .expect("the offer succeeds");

    // THEN: the same journey, untouched, and its callback still connects
    assert_eq!(
        offered, id,
        "the started journey is reused, never superseded"
    );
    assert_eq!(expires_at, T0 + 1 + CALLBACK_WINDOW, "its own callback_by");
    let table = on_disk(&store, &config, &limits);
    assert_eq!(table.journeys.len(), 1, "no second journey was minted");
    assert!(
        table.journeys[&id] == before,
        "status, digests, verifier and callback_by are byte-identical"
    );
    let consumed = store
        .consume_callback(T0 + 3, &limits, &secrets.state, Some(&secrets.binding))
        .expect("the in-flight consent still completes");
    assert_eq!(consumed.journey_id, id);
}

#[test]
fn a_pending_offer_is_reused_without_spending_the_creation_budget() {
    // GIVEN: one creation per minute
    let (_root, config, store) = fresh();
    let limits = one_creation_per_minute();

    // WHEN: three refused dispatches ask for an offer inside one minute
    let offers: Vec<_> = (0..3)
        .map(|n| store.offer_journey(T0 + n, &limits, request("alice", "google")))
        .collect();

    // THEN: every one answers with the one pending journey
    let first = offers[0].clone().expect("the first offer mints").0;
    for offer in &offers {
        assert_eq!(offer.clone().expect("reuse admits no creation").0, first);
    }
    let table = on_disk(&store, &config, &limits);
    assert_eq!(table.journeys.len(), 1);
    assert_eq!(table.journeys[&first].status, JourneyStatus::Pending);
}

#[test]
fn an_offer_past_the_deadline_mints_anew_and_the_old_one_expires_not_supersedes() {
    // GIVEN: a pending journey whose start window has closed
    let (_root, config, store) = fresh();
    let limits = limits();
    let old = create(&store, T0, &limits, "alice");

    // WHEN: an offer arrives at the deadline
    let (fresh_id, _) = store
        .offer_journey(T0 + START_WINDOW, &limits, request("alice", "google"))
        .expect("a new journey is minted");

    // THEN: the old one is expired by the sweep, never superseded
    assert_ne!(fresh_id, old);
    let table = on_disk(&store, &config, &limits);
    assert_eq!(table.journeys[&old].status, JourneyStatus::Expired);
    assert_ne!(table.journeys[&old].reason, Some(JourneyReason::Superseded));
    assert_eq!(table.journeys[&fresh_id].status, JourneyStatus::Pending);
}

#[test]
fn an_offer_never_reuses_another_principals_or_another_accounts_journey() {
    // GIVEN: Bob holds a pending journey for the same account
    let (_root, config, store) = fresh();
    let limits = limits();
    let bobs = create(&store, T0, &limits, "bob");

    // WHEN: Alice is offered the same account, then another account
    let (alices, _) = store
        .offer_journey(T0 + 1, &limits, request("alice", "google"))
        .expect("Alice gets her own");
    let (other, _) = store
        .offer_journey(T0 + 2, &limits, request("alice", "calendar"))
        .expect("a second account gets its own");

    // THEN: three distinct journeys, Bob's untouched
    assert_ne!(alices, bobs);
    assert_ne!(other, alices);
    let table = on_disk(&store, &config, &limits);
    assert_eq!(table.journeys[&bobs].status, JourneyStatus::Pending);
    assert_eq!(table.journeys.len(), 3);
}
