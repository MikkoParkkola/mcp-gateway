// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Review hardening of the journey table: id collisions, the per-key-id HMAC
//! of the callback lookup, and a pending journey that outlives `start_by`.

use super::ids::force_ids;
use super::tests::{
    K1, T0, create, fresh, limits, on_disk, owner, refused, reload, request, start,
};
use super::{
    AccountError, DigestKind, JourneyError, JourneyRefusal, JourneyStatus, START_WINDOW,
    digest_comparisons, hmacs_computed,
};

/// A second key, so records carry two distinct `digest_key_id`s.
const K3: [u8; 32] = [11; 32];

/// An id collision draws once more; a second collision refuses, and neither
/// ever overwrites or supersedes a live record.
#[test]
fn create_journey_redraws_a_colliding_id_once_then_refuses() {
    // GIVEN: bob holds id X
    let (_root, config, store) = fresh();
    let limits = limits();
    let (taken, spare) = ("a".repeat(32), "b".repeat(32));
    force_ids(&[&taken, &"c".repeat(32)]);
    assert_eq!(create(&store, T0, &limits, "bob"), taken);
    // WHEN: alice draws X then Y
    force_ids(&[&taken, &spare]);
    let alice = create(&store, T0, &limits, "alice");
    // THEN: alice gets Y and X is still bob's
    assert_eq!(alice, spare);
    let table = on_disk(&store, &config, &limits);
    assert_eq!(table.journeys[&taken].owner_subject.as_deref(), Some("bob"));
    // WHEN: alice draws X and Y, both live
    force_ids(&[&taken, &spare]);
    let refusal = store.create_journey(T0, &limits, request("alice", "google"));
    // THEN: refused, with the table byte-for-byte what it was
    assert_eq!(
        refusal.unwrap_err(),
        JourneyError::Storage(AccountError::StorageUnavailable)
    );
    let after = on_disk(&store, &config, &limits);
    assert_eq!(after, table, "nothing overwritten, nothing superseded");
    assert_eq!(after.journeys[&spare].status, JourneyStatus::Pending);
}

/// The callback lookup HMACs the state once per distinct `digest_key_id`,
/// and still compares every record's digest in constant time.
#[test]
fn callback_lookup_computes_one_hmac_per_digest_key_id() {
    // GIVEN: two started journeys under k1 and two under k3
    let (_root, config, store) = fresh();
    let limits = limits();
    for who in ["a1", "a2"] {
        let id = create(&store, T0, &limits, who);
        start(&store, T0, &limits, &id, who);
    }
    let (_config, store) = reload(store, &config, "k3", &[("k1", K1), ("k3", K3)]);
    for who in ["b1", "b2"] {
        let id = create(&store, T0, &limits, who);
        start(&store, T0, &limits, &id, who);
    }
    let (hmacs, compared) = (hmacs_computed(), digest_comparisons(DigestKind::State));
    // WHEN
    let refusal = refused(store.consume_callback(T0 + 1, &limits, "unknown", Some("x")));
    // THEN
    assert_eq!(refusal, JourneyRefusal::UnknownState);
    assert_eq!(hmacs_computed() - hmacs, 2, "one HMAC per key id");
    assert_eq!(digest_comparisons(DigestKind::State) - compared, 4);
}

/// A pending journey never started by `start_by` is `Expired`, and a late
/// start is refused rather than reviving it.
#[test]
fn pending_journey_past_start_by_expires_and_refuses_start() {
    // GIVEN
    let (_root, _config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let late = T0 + START_WINDOW;
    // WHEN
    let started = store.start_journey(late, &limits, &id, &owner("alice", "google"));
    // THEN
    assert_eq!(refused(started), JourneyRefusal::NotStartable);
    let view = store.journey_status(late, &limits, &id).unwrap();
    assert_eq!(view.status, JourneyStatus::Expired);
}
