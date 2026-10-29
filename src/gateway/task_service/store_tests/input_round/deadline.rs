// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round closes at its continuation deadline, and a close is one write.

use super::*;
use crate::gateway::task_service::store::input::RoundClosed;

// ---------------------------------------------------------------------------
// #2429: the round closes at its continuation deadline.
// ---------------------------------------------------------------------------

fn secs(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp()).unwrap()
}

fn due(deadline: u64) -> InputRound {
    InputRound {
        continuation_deadline: Some(deadline),
        ..round("sealed")
    }
}

async fn opened() -> (tempfile::TempDir, TaskStore, Task) {
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::open(&dir.path().join("tasks"), limits())
        .await
        .unwrap();
    (dir, store, task())
}

/// Mutant: the clock read before the ordering lock, or taken from the
/// caller's `at`: an update queued while the round was open is let through
/// after it closed.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "holding the ordering lock across the wait is the race under test"
)]
async fn an_update_queued_across_the_deadline_is_refused_under_the_lock() {
    let (_dir, store, task) = opened().await;
    let deadline = secs(at(30));
    let revision = parked_with(&store, &task, &["confirm"], due(deadline)).await;
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let held = store.hold_order_for_test();
    let queued = {
        let (store, id) = (store.clone(), task.id().to_owned());
        tokio::spawn(async move {
            store
                .provide_input(
                    OWNER,
                    &id,
                    answers(json!({ "confirm": {} })),
                    move || workers.try_acquire_owned().ok(),
                    at(2),
                )
                .await
        })
    };
    // The write has entered the store and is waiting on the held lock, with
    // the clock still before the deadline.
    let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while store.arrivals_for_test() == 0 {
        assert!(
            tokio::time::Instant::now() < bound,
            "the update never reached the store"
        );
        tokio::task::yield_now().await;
    }
    store.set_clock_for_test(Some(at(30)));
    drop(held);
    let refused = queued.await.unwrap();
    assert!(
        matches!(
            refused,
            Ok(ProvideOutcome::Closed(RoundClosed::Continuation(d))) if d == deadline
        ),
        "refused naming the deadline"
    );
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, revision);
}

/// Pin: a round with no stored continuation has no deadline; the TTL alone
/// bounds it. Mutant: `None` read as already expired.
#[tokio::test]
async fn a_round_without_a_deadline_takes_answers_until_the_ttl() {
    let (_dir, store, task) = opened().await;
    parked(&store, &task, &["a", "b"]).await;
    store.set_clock_for_test(Some(at(1) + crate::duration_bound::delta!(hours, 1)));
    let accepted = store
        .provide_input(
            OWNER,
            task.id(),
            answers(json!({ "a": {} })),
            || None,
            at(2),
        )
        .await;
    assert!(matches!(accepted, Ok(ProvideOutcome::Partial(_))));
}

/// An update on a clock before 1970 is refused without closing the
/// round, since a close cancels the task for good. The same update is taken
/// once the clock reads again. Mutant: the round closed on that clock.
#[tokio::test]
async fn a_clock_before_the_epoch_refuses_an_update_and_keeps_the_round() {
    let (_dir, store, task) = opened().await;
    parked(&store, &task, &["a", "b"]).await;
    let update = || answers(json!({ "a": {} }));

    store.set_clock_for_test(Some(
        chrono::DateTime::<chrono::Utc>::from_timestamp(-1, 0).expect("one second before 1970"),
    ));
    let refused = store
        .provide_input(OWNER, task.id(), update(), || None, at(2))
        .await;
    assert!(
        matches!(refused, Err(StoreError::Unavailable)),
        "an unreadable clock took or closed the update"
    );

    store.set_clock_for_test(Some(at(1) + crate::duration_bound::delta!(hours, 1)));
    let accepted = store
        .provide_input(OWNER, task.id(), update(), || None, at(2))
        .await;
    assert!(
        matches!(accepted, Ok(ProvideOutcome::Partial(_))),
        "the round did not survive an unreadable clock"
    );
}

/// Pin: a record written before the field loads as `None`, and a `None`
/// round writes no field. Mutant: `skip_serializing_if` removed.
#[test]
fn the_deadline_field_is_absent_when_none_and_round_trips_when_set() {
    let old = json!({ "requestState": "s", "tool": "t", "arguments": {} });
    let loaded: InputRound = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(loaded.continuation_deadline, None);
    assert_eq!(serde_json::to_value(&loaded).unwrap(), old);
    let set = InputRound {
        continuation_deadline: Some(7),
        ..loaded
    };
    let back: InputRound = serde_json::from_value(serde_json::to_value(&set).unwrap()).unwrap();
    assert_eq!(back, set);
}

/// Mutant: the settlement written without the revision check.
#[tokio::test]
async fn closing_a_round_at_a_stale_revision_writes_nothing() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let stale = store
        .close_round(OWNER, task.id(), revision - 1, "closed".to_owned(), at(31))
        .await;
    assert!(
        matches!(stale, Err(StoreError::RevisionConflict)),
        "{stale:?}"
    );
    let after = store.get(OWNER, task.id()).unwrap();
    assert_eq!(after.task.status(), TaskStatus::InputRequired);
    assert_eq!(after.revision, revision);
}

/// Mutants: two writes; the round kept; the reason dropped.
#[tokio::test]
async fn closing_a_round_cancels_it_with_the_reason_in_one_write() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let closed = store
        .close_round(OWNER, task.id(), revision, "the reason".to_owned(), at(31))
        .await
        .expect("an open round closes");
    assert_eq!(closed.revision, revision + 1);
    assert_eq!(closed.task.status(), TaskStatus::Cancelled);
    let wire = serde_json::to_value(closed.task.wire()).unwrap();
    assert_eq!(wire["statusMessage"], "the reason");
    assert!(store.input_round_for_test(task.id()).0.is_none());
}

/// A close is stamped at the time its caller judged the round
/// closed, never at a second read: with the store's clock stepped before
/// 1970 it still closes, dated by the caller. Mutant: the close reads the
/// clock again, and is refused.
#[tokio::test]
async fn a_close_is_stamped_at_its_callers_time() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    store.set_clock_for_test(Some(
        chrono::DateTime::<chrono::Utc>::from_timestamp(-1, 0).expect("one second before 1970"),
    ));
    let closed = store
        .close_round(OWNER, task.id(), revision, "expired".to_owned(), at(31))
        .await
        .expect("closed at the caller's time");
    assert_eq!(closed.task.status(), TaskStatus::Cancelled);
    assert_eq!(closed.task.last_updated_at(), at(31));
}

/// A readable store clock that disagrees with the caller does not date the
/// close either. Mutant: the close stamped at a second read.
#[tokio::test]
async fn a_close_ignores_a_readable_store_clock_that_disagrees() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    store.set_clock_for_test(Some(at(40)));
    let closed = store
        .close_round(OWNER, task.id(), revision, "expired".to_owned(), at(31))
        .await
        .expect("an open round closes");
    assert_eq!(closed.task.last_updated_at(), at(31));
}

/// Mutant: a settled row closed again (a second terminal write and publish).
#[tokio::test]
async fn closing_an_already_settled_round_writes_nothing() {
    let (_dir, store, task) = opened().await;
    let revision = parked_with(&store, &task, &["confirm"], due(secs(at(30)))).await;
    let closed = store
        .close_round(OWNER, task.id(), revision, "first".to_owned(), at(31))
        .await
        .expect("an open round closes");
    let again = store
        .close_round(
            OWNER,
            task.id(),
            closed.revision,
            "second".to_owned(),
            at(31),
        )
        .await;
    assert!(
        matches!(again, Err(StoreError::InvalidTransition)),
        "{again:?}"
    );
    assert_eq!(
        store.get(OWNER, task.id()).unwrap().revision,
        closed.revision
    );
}
