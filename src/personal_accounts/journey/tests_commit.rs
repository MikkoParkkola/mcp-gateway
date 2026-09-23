// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Slice 5c store rows: the admit/consume split across a restart and the
//! journey grant commit under one acquisition (design §5.2, §6.2 step 11, §6.3).

use super::super::super::{AccountKey, GrantRecord, PersonalAccountStore};
use super::grant::JourneyCommit;
use super::tests::{
    K1, T0, create, fresh, limits, on_disk, owner, refused, reload, sealed_grant, start,
};
use super::{ConsentExpectation, Consumed, JourneyReason, JourneyRefusal, JourneyStatus};

fn alice() -> AccountKey {
    owner("alice", "google")
}

fn generation(store: &PersonalAccountStore) -> Option<String> {
    match ConsentExpectation::captured(&store.lookup(&alice()).unwrap()) {
        ConsentExpectation::Connected(version) => Some(version.generation),
        _ => None,
    }
}

fn grant(generation: &str) -> GrantRecord {
    GrantRecord {
        generation: generation.into(),
        ..sealed_grant()
    }
}

/// Created, started, admitted and consumed: the state the exchange runs in.
fn consumed(store: &PersonalAccountStore, now: u64) -> Consumed {
    let limits = limits();
    let id = create(store, now, &limits, "alice");
    let secrets = start(store, now, &limits, &id, "alice");
    let (state, binding) = (secrets.state.as_str(), Some(secrets.binding.as_str()));
    let admitted = store
        .admit_callback(now + 1, &limits, state, binding)
        .unwrap();
    let key = alice();
    let consumed = store
        .consume_callback(now + 1, &limits, state, binding)
        .unwrap();
    // Everything the handler rebuilds the key from, and checks, comes back.
    assert_eq!(admitted.journey_id, consumed.journey_id);
    assert_eq!(admitted.owner_authority, key.principal_authority);
    assert_eq!(admitted.owner_subject, key.principal_subject);
    assert_eq!(admitted.account_id, key.backend_id);
    assert_eq!(admitted.issuer, key.oauth_issuer);
    assert_eq!(admitted.descriptor_revision, "0".repeat(64));
    assert_eq!(admitted.expected, ConsentExpectation::Absent);
    assert_eq!(admitted.return_path, "/settings/accounts");
    consumed
}

#[test]
fn t_c03d_admit_then_consume_is_durable_so_a_replay_after_restart_is_refused() {
    // GIVEN: admitted and consumed, then a crash before the exchange.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    let (state, binding) = (secrets.state.as_str(), Some(secrets.binding.as_str()));
    store
        .admit_callback(T0 + 1, &limits, state, binding)
        .unwrap();
    store
        .consume_callback(T0 + 1, &limits, state, binding)
        .unwrap();
    // WHEN: the store reopens and the same callback is replayed.
    let (config, store) = reload(store, &config, "k1", &[("k1", K1)]);
    let admit = store.admit_callback(T0 + 2, &limits, state, binding);
    let consume = store.consume_callback(T0 + 2, &limits, state, binding);
    // THEN: both refused as replays; no second consume reached the record.
    assert_eq!(refused(admit), JourneyRefusal::Replay);
    assert_eq!(refused(consume), JourneyRefusal::Replay);
    let record = &on_disk(&store, &config, &limits).journeys[&id];
    assert!(record.consumed && record.pkce_verifier.is_none());
    assert_eq!(record.status, JourneyStatus::Started);
    assert_eq!(record.replay_refusals, 2);
}

#[test]
fn a_consumed_journey_commits_its_grant_and_ends_connected_without_its_owner() {
    // GIVEN
    let (_root, config, store) = fresh();
    let limits = limits();
    let journey = consumed(&store, T0);
    // WHEN
    let outcome = store.commit_journey_grant_if(
        T0 + 2,
        &limits,
        &alice(),
        &ConsentExpectation::Absent,
        &grant("11".repeat(16).as_str()),
        &journey.journey_id,
    );
    // THEN
    assert_eq!(outcome, Ok(JourneyCommit::Committed));
    assert_eq!(
        generation(&store).as_deref(),
        Some("11".repeat(16).as_str())
    );
    let record = &on_disk(&store, &config, &limits).journeys[&journey.journey_id];
    assert_eq!(record.status, JourneyStatus::Connected);
    assert!(record.owner_authority.is_none() && record.owner_subject.is_none());
}

#[test]
fn t_c05b_a_stale_journey_is_fenced_by_a_newer_generation_and_does_not_overwrite() {
    // GIVEN: an older journey consumed against `Absent`, then a newer grant.
    let (_root, config, store) = fresh();
    let limits = limits();
    let older = consumed(&store, T0);
    let newer = grant(&"22".repeat(16));
    store
        .commit_grant_if_unchanged(&alice(), &ConsentExpectation::Absent, &newer, None)
        .unwrap();
    // WHEN: the older journey's callback commits.
    let outcome = store.commit_journey_grant_if(
        T0 + 2,
        &limits,
        &alice(),
        &ConsentExpectation::Absent,
        &grant(&"11".repeat(16)),
        &older.journey_id,
    );
    // THEN: fenced; the newer generation survives; the journey ends failed.
    assert_eq!(outcome, Ok(JourneyCommit::Fenced));
    assert_eq!(generation(&store), Some("22".repeat(16)));
    let record = &on_disk(&store, &config, &limits).journeys[&older.journey_id];
    assert_eq!(
        (record.status, record.reason),
        (JourneyStatus::Failed, Some(JourneyReason::SupersededGrant))
    );
}

#[test]
fn a_journey_swept_or_owned_by_another_is_gone_and_commits_nothing() {
    // GIVEN: one journey expired by the sweep, one committed by a stranger.
    let (_root, config, store) = fresh();
    let limits = limits();
    let swept = consumed(&store, T0);
    let late = T0 + super::CALLBACK_WINDOW + 1;
    let mallory = owner("mallory", "google");
    let expected = ConsentExpectation::Absent;
    let record = grant(&"11".repeat(16));
    // WHEN
    let stranger = store.commit_journey_grant_if(
        T0 + 2,
        &limits,
        &mallory,
        &expected,
        &record,
        &swept.journey_id,
    );
    let expired = store.commit_journey_grant_if(
        late,
        &limits,
        &alice(),
        &expected,
        &record,
        &swept.journey_id,
    );
    // THEN
    assert_eq!(stranger, Ok(JourneyCommit::JourneyGone));
    assert_eq!(expired, Ok(JourneyCommit::JourneyGone));
    assert_eq!(generation(&store), None);
    let on_disk = &on_disk(&store, &config, &limits).journeys[&swept.journey_id];
    assert_eq!(on_disk.status, JourneyStatus::Expired, "never resurrected");
}

#[test]
fn t_r2_1_a_journeys_write_failure_after_the_grant_poisons_only_the_journey_slot() {
    use crate::personal_accounts::faults::{Boundary, arm};
    // GIVEN
    let (_root, _config, store) = fresh();
    let limits = limits();
    let journey = consumed(&store, T0);
    let fault = arm(Boundary::JourneysParentSync);
    // WHEN
    let outcome = store.commit_journey_grant_if(
        T0 + 2,
        &limits,
        &alice(),
        &ConsentExpectation::Absent,
        &grant(&"11".repeat(16)),
        &journey.journey_id,
    );
    // THEN: the grant is durable and readable; journey reads refuse.
    assert!(fault.fired());
    assert_eq!(outcome, Ok(JourneyCommit::CommittedStatusUnavailable));
    assert_eq!(generation(&store), Some("11".repeat(16)));
    let status = store.journey_status(T0 + 3, &limits, &journey.journey_id);
    assert!(matches!(status, Err(super::JourneyError::Storage(_))));
}
