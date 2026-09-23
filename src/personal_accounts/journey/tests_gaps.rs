// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Journey-table rules `tests.rs` left unpinned (design §3, §5.2, §5.3, §6.2).
//! Each test names the mutation it kills.

use super::super::super::AccountLookup;
use super::super::super::faults::{Boundary, arm};
use super::tests::{
    T0, create, fresh, limits, on_disk, owner, refused, request, sealed_grant, start,
};
use super::{
    AccountError, CALLBACK_WINDOW, JourneyError, JourneyLimits, JourneyReason, JourneyRefusal,
    JourneyStatus, START_RATE_WINDOW, TERMINAL_RETENTION,
};

fn start_rate(per_minute: u32) -> JourneyLimits {
    JourneyLimits {
        starts_per_minute_per_user: per_minute,
        ..limits()
    }
}

/// Gap 1. Kills: `admit_start` not called, or its window/limit ignored.
#[test]
fn start_rate_n_plus_one_within_a_minute_is_429_then_admitted_after_the_window() {
    // GIVEN: alice may start 2 times a minute, and has 3 journeys to start,
    // one per account so no creation supersedes another.
    let (_root, _config, store) = fresh();
    let limits = start_rate(2);
    let accounts = ["drive", "mail", "calendar"];
    let ids: Vec<_> = accounts
        .iter()
        .map(|account| {
            store
                .create_journey(T0, &limits, request("alice", account))
                .expect("creation succeeds")
        })
        .collect();
    let start_as =
        |now, i: usize| store.start_journey(now, &limits, &ids[i], &owner("alice", accounts[i]));
    // WHEN: she starts all three within the same second.
    start_as(T0, 0).expect("first start");
    start_as(T0 + 1, 1).expect("second start");
    let third = start_as(T0 + 2, 2);
    // THEN: the third is 429 until the oldest start leaves the window.
    assert_eq!(
        refused(third),
        JourneyRefusal::RateLimited {
            retry_after: START_RATE_WINDOW - 2
        }
    );
    let status = store.journey_status(T0 + 2, &limits, &ids[2]).unwrap();
    assert_eq!(
        status.status,
        JourneyStatus::Pending,
        "a refused start arms nothing"
    );
    // AND: bob is not throttled by alice's starts.
    let bob = create(&store, T0 + 2, &limits, "bob");
    start(&store, T0 + 2, &limits, &bob, "bob");
    // AND: once the window slides past the first start, alice starts again.
    start_as(T0 + START_RATE_WINDOW, 2).expect("admitted after the window");
}

/// Gap 2. Kills: a re-start re-arming `callback_by`, or keeping old secrets.
#[test]
fn restart_keeps_the_first_callback_by_and_rotates_the_secrets() {
    // GIVEN: a started journey.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let first = start(&store, T0, &limits, &id, "alice");
    let before = on_disk(&store, &config, &limits).journeys[&id].clone();
    // WHEN: it is re-started later.
    let second = start(&store, T0 + 100, &limits, &id, "alice");
    // THEN: the deadline is the FIRST start's, never extended.
    let after = on_disk(&store, &config, &limits).journeys[&id].clone();
    assert_eq!(after.callback_by, Some(T0 + CALLBACK_WINDOW));
    assert_eq!(after.started_at, Some(T0), "started_at is the first start");
    // AND: every secret rotated, on disk as well as in the answer.
    assert_ne!(first.state, second.state);
    assert_ne!(first.binding, second.binding);
    assert_ne!(first.verifier, second.verifier);
    assert_ne!(before.state_digest, after.state_digest);
    assert_ne!(before.binding_digest, after.binding_digest);
    // AND: the old state no longer locates the journey; the new one does.
    let stale = store.consume_callback(T0 + 101, &limits, &first.state, Some(&first.binding));
    assert_eq!(refused(stale), JourneyRefusal::UnknownState);
    let consumed = store
        .consume_callback(T0 + 102, &limits, &second.state, Some(&second.binding))
        .expect("the rotated secrets validate");
    assert_eq!(consumed.verifier, second.verifier);
    // AND: past the FIRST deadline, a fresh re-start's state is expired.
    let other = create(&store, T0, &limits, "bob");
    start(&store, T0, &limits, &other, "bob");
    let late = start(&store, T0 + CALLBACK_WINDOW - 1, &limits, &other, "bob");
    let expired = store.consume_callback(
        T0 + CALLBACK_WINDOW,
        &limits,
        &late.state,
        Some(&late.binding),
    );
    assert_eq!(refused(expired), JourneyRefusal::Expired);
}

/// Gap 3. Kills: a mismatch that refuses without terminating, or that keeps
/// the binding/verifier, or a `Failed` record accepting a later callback.
#[test]
fn browser_mismatch_fails_the_journey_clears_secrets_and_refuses_the_right_cookie_later() {
    // GIVEN: a started journey.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    // WHEN: the callback carries the wrong browser binding.
    let wrong = store.consume_callback(T0 + 1, &limits, &secrets.state, Some("not-the-cookie"));
    // THEN: refused, and the record is terminal Failed with no secret left.
    assert_eq!(refused(wrong), JourneyRefusal::BrowserMismatch);
    let record = on_disk(&store, &config, &limits).journeys[&id].clone();
    assert_eq!(record.status, JourneyStatus::Failed);
    assert_eq!(record.reason, Some(JourneyReason::BrowserMismatch));
    assert_eq!(record.terminal_at, Some(T0 + 1));
    assert!(record.binding_digest.is_none(), "binding cleared");
    assert!(record.pkce_verifier.is_none(), "verifier cleared");
    assert!(!record.consumed, "a mismatch consumes nothing");
    // AND: the correct binding afterwards is refused, never consumed.
    let retry = store.consume_callback(T0 + 2, &limits, &secrets.state, Some(&secrets.binding));
    assert_eq!(refused(retry), JourneyRefusal::Replay);
    let record = &on_disk(&store, &config, &limits).journeys[&id];
    assert_eq!(
        record.status,
        JourneyStatus::Failed,
        "terminal stays terminal"
    );
    assert!(!record.consumed);
}

/// Gap 4. Kills: collecting at or before 24 h, never collecting, or a
/// collected id answering anything but `not_found`.
#[test]
fn terminal_records_are_collected_exactly_24h_after_terminal_at() {
    // GIVEN: a journey cancelled at T0 + 5.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let terminal_at = T0 + 5;
    store
        .finish_journey(terminal_at, &limits, &id, JourneyStatus::Cancelled, None)
        .unwrap();
    // WHEN: one second before retention ends, THEN: still queryable.
    let edge = terminal_at + TERMINAL_RETENTION;
    let view = store.journey_status(edge - 1, &limits, &id).unwrap();
    assert_eq!(view.status, JourneyStatus::Cancelled);
    assert!(on_disk(&store, &config, &limits).journeys.contains_key(&id));
    // WHEN: retention has elapsed, THEN: collected, on disk too.
    let gone = store.journey_status(edge, &limits, &id);
    assert_eq!(refused(gone), JourneyRefusal::NotFound);
    assert!(!on_disk(&store, &config, &limits).journeys.contains_key(&id));
}

/// Gap 5. Kills: dropping the `is_active` guard in `finish_journey`.
#[test]
fn finish_on_a_terminal_record_is_refused_and_leaves_it_unchanged() {
    // GIVEN: a journey already Connected.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    store
        .finish_journey(T0 + 1, &limits, &id, JourneyStatus::Connected, None)
        .unwrap();
    let before = on_disk(&store, &config, &limits).journeys[&id].clone();
    // WHEN: something tries to finish it again as Failed.
    let again = store.finish_journey(
        T0 + 2,
        &limits,
        &id,
        JourneyStatus::Failed,
        Some(JourneyReason::ProviderError),
    );
    // THEN: refused, and the record is byte-for-byte what it was.
    assert_eq!(refused(again), JourneyRefusal::NotStartable);
    assert_eq!(on_disk(&store, &config, &limits).journeys[&id], before);
}

fn unavailable<T: std::fmt::Debug>(result: Result<T, JourneyError>) {
    assert_eq!(
        result.unwrap_err(),
        JourneyError::Storage(AccountError::StorageUnavailable)
    );
}

/// Gap 6, store-level half of T-R2-1 (the route half is slice 5), with the
/// §5.2 heal. Kills: poisoning the authority on a journeys write failure;
/// serving the in-memory table after a rename; a stale slot healed without a
/// good reread, or never reread at all.
#[test]
fn journeys_parent_sync_fault_poisons_only_the_journey_slot_until_a_good_reread() {
    // GIVEN: a connected grant and an armed journeys directory-sync fault.
    let (_root, config, store) = fresh();
    let limits = limits();
    let alice = owner("alice", "google");
    store.commit_grant(&alice, &sealed_grant()).unwrap();
    let fault = arm(Boundary::JourneysParentSync);
    // WHEN: a journey write reaches the sync after its rename.
    unavailable(store.create_journey(T0, &limits, request("alice", "google")));
    assert!(fault.fired(), "the journeys boundary was reached");
    drop(fault);
    // THEN: the authority is untouched: lookup and a new commit both work.
    assert!(matches!(
        store.lookup(&alice),
        Ok(AccountLookup::Connected(_))
    ));
    store
        .commit_grant(&owner("bob", "google"), &sealed_grant())
        .unwrap();
    // AND: while journeys.json cannot be read, every journey operation,
    // reads included, is unavailable, and each one tries the reread again.
    let path = config.authority_dir.join(super::JOURNEYS_FILE);
    let durable = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{}").unwrap();
    unavailable(store.create_journey(T0 + 1, &limits, request("carol", "google")));
    unavailable(store.journey_status(T0 + 1, &limits, "0".repeat(32).as_str()));
    // AND: once the file reads again, the next operation heals the slot from
    // disk, without a reopen.
    std::fs::write(&path, &durable).unwrap();
    assert_eq!(on_disk(&store, &config, &limits).journeys.len(), 1);
    create(&store, T0 + 2, &limits, "carol");
    assert_eq!(on_disk(&store, &config, &limits).journeys.len(), 2);
}

/// Gap 7, transition level (R3-2). Kills: `journey_transition` handing the
/// closure a `before` snapshot taken AFTER the sweep.
///
/// Why this is the discriminating case, and why it is not a callback test:
/// `is_replay` reads `consumed` and the statuses connected/cancelled/failed/
/// superseded. The sweep only ever writes `Expired` (not a replay status) and
/// never clears `consumed`, so for any record the sweep keeps, `is_replay` is
/// the same pre- and post-sweep, and `consume_callback` cannot tell the two
/// tables apart. The tables DO differ in what the sweep rewrites and removes:
/// a started record past `callback_by` is `Started` before and `Expired`
/// after, and a terminal record past retention is present before and gone
/// after. Reading the post-sweep table as `before` turns both asserts red.
#[test]
fn transition_before_is_the_pre_sweep_table_and_table_is_the_swept_one() {
    // GIVEN: one started journey and one cancelled one.
    let (_root, _config, store) = fresh();
    let limits = limits();
    let live = create(&store, T0, &limits, "alice");
    start(&store, T0, &limits, &live, "alice");
    let dead = create(&store, T0, &limits, "bob");
    store
        .finish_journey(T0, &limits, &dead, JourneyStatus::Cancelled, None)
        .unwrap();
    // WHEN: a transition runs past both the callback deadline and retention.
    let now = T0 + TERMINAL_RETENTION;
    let seen = store
        .journey_transition(now, &limits, |tx| {
            Ok((
                tx.before.journeys.get(&live).map(|r| r.status),
                tx.table.journeys.get(&live).map(|r| r.status),
                tx.before.journeys.contains_key(&dead),
                tx.table.journeys.contains_key(&dead),
            ))
        })
        .unwrap();
    // THEN: `before` is unswept, `table` is swept.
    assert_eq!(
        seen,
        (
            Some(JourneyStatus::Started),
            Some(JourneyStatus::Expired),
            true,
            false
        )
    );
}

/// Gap 7, callback level (R2-3 then R3-2). Kills: checking expiry before
/// replay. A consumed journey whose deadline then passes is a REPLAY
/// (counted), not an expiry, even though the sweep expires it in the same
/// acquisition.
#[test]
fn a_consumed_journey_replayed_after_its_deadline_is_replay_not_expiry() {
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    store
        .consume_callback(T0 + 1, &limits, &secrets.state, Some(&secrets.binding))
        .unwrap();
    let late = T0 + CALLBACK_WINDOW + 1;
    let replay = store.consume_callback(late, &limits, &secrets.state, Some(&secrets.binding));
    assert_eq!(refused(replay), JourneyRefusal::Replay);
    let record = &on_disk(&store, &config, &limits).journeys[&id];
    assert_eq!(record.replay_refusals, 1);
    assert_eq!(record.status, JourneyStatus::Expired, "the sweep still ran");
}
