// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gate's timer rows (G7 deadlines, timer ownership) and two variants
//! (G3 released, G9 panic), split from `store_gate_tests.rs` for the size
//! ceiling. The helpers are the parent's.

use super::*;

// G7: an External submitter still parked on its own attempt at deadline + 1 s
// refuses itself, whether the gate is Paused or Certified.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_external_park_ends_one_second_past_the_deadline() {
    for gate in [paused(), certified()] {
        let refused = within("G7 refusal", gate.admit(Kind::External)).await;
        assert_eq!(
            refused.map(drop),
            Err(Refused::Restarting),
            "{:?}",
            gate.state()
        );
    }
}

// G7: the coordinator's own exit at the deadline wins every tie with the
// parker's timer: polled first, resumed first, or left unpolled past its
// timer, the parker is admitted, never told "restarting".
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_resume_at_the_deadline_always_beats_the_parker_timer() {
    // (a) the parker is polled at the deadline, then the gate resumes.
    let gate = paused();
    let mut parker = std::pin::pin!(gate.admit(Kind::External));
    assert!(futures::poll!(parker.as_mut()).is_pending(), "(a) parked");
    tokio::time::advance(DEADLINE).await;
    assert!(
        futures::poll!(parker.as_mut()).is_pending(),
        "(a) still parked at the deadline"
    );
    gate.resume();
    assert!(within("G7 (a)", parker).await.is_ok(), "(a) admitted");

    // (b) the gate resumes at the deadline before the parker is polled again.
    let gate = paused();
    let mut parker = std::pin::pin!(gate.admit(Kind::External));
    assert!(futures::poll!(parker.as_mut()).is_pending(), "(b) parked");
    tokio::time::advance(DEADLINE).await;
    gate.resume();
    assert!(within("G7 (b)", parker).await.is_ok(), "(b) admitted");

    // (c) resumed at the deadline, the parker is not polled again until its
    // own timer has fired: the timer's re-decision sees the resume.
    let gate = paused();
    let mut parker = std::pin::pin!(gate.admit(Kind::External));
    assert!(futures::poll!(parker.as_mut()).is_pending(), "(c) parked");
    tokio::time::advance(DEADLINE).await;
    gate.resume();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        within("G7 (c)", parker).await.is_ok(),
        "(c) admitted after its timer"
    );
}

// G7: an Internal submitter is never refused by a timer: past the deadline it
// still waits for the coordinator's exit, and lands after resume.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_internal_park_outlasts_the_deadline_until_resume() {
    let gate = paused();
    let mut parker = std::pin::pin!(gate.admit(Kind::Internal));
    assert!(futures::poll!(parker.as_mut()).is_pending(), "parked");
    tokio::time::advance(DEADLINE + Duration::from_secs(2)).await;
    assert!(
        futures::poll!(parker.as_mut()).is_pending(),
        "not refused past the deadline"
    );
    gate.resume();
    assert!(
        within("G7 internal", parker).await.is_ok(),
        "admitted after resume"
    );
}

// G7: with the coordinator's exit withheld, an Internal submitter proceeds at
// the backstop (deadline + stop budget) while the gate is still paused.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_internal_park_proceeds_at_the_backstop() {
    let gate = paused();
    let mut parker = std::pin::pin!(gate.admit(Kind::Internal));
    assert!(futures::poll!(parker.as_mut()).is_pending(), "parked");
    tokio::time::advance((DEADLINE + BUDGET).saturating_sub(Duration::from_secs(1))).await;
    assert!(
        futures::poll!(parker.as_mut()).is_pending(),
        "still parked before the backstop"
    );
    let admitted = within("G7 backstop", parker).await;
    assert!(admitted.is_ok(), "proceeds at the backstop, never refused");
    assert_eq!(
        gate.state(),
        GateState::Paused(1),
        "no exit came: the gate never opened"
    );
}

// G3 variant: a parker held between its decision and its wait is admitted by
// a release (a stop signal won) with no further change.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_held_parker_is_admitted_by_a_release() {
    let gate = paused();
    let hold = GateSeams::arm(&gate.seams().before_wait);
    let parked = tokio::spawn({
        let gate = gate.clone();
        async move { gate.admit(Kind::External).await.map(drop) }
    });
    within("G3r park", hold.reached()).await;
    gate.release();
    hold.release();
    let admitted = within("G3r wake", parked)
        .await
        .expect("the submitter task");
    assert_eq!(admitted, Ok(()), "a release admits the parked submitter");
}

// G7 timer ownership: a ticket's bounds are its attempt's. An External ticket
// still parked when a later attempt pauses takes that attempt's deadline, so
// passing the first attempt's deadline + 1 s does not refuse it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_park_carried_into_a_later_attempt_takes_its_deadline() {
    let gate = paused();
    let log = std::sync::Arc::default();
    let (c_task, c_admitted, c_finish) = park_held(&gate, Kind::Internal, "C", &log).await;
    gate.resume();
    within("G7t C admitted", c_admitted.notified()).await;
    let mut p = std::pin::pin!(gate.admit(Kind::External));
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "P parks behind the drain"
    );
    let _ = c_finish.send(());
    within("G7t C done", c_task).await.expect("C's task");
    // Attempt 2 pauses with a deadline well after attempt 1's.
    let later = Instant::now() + DEADLINE * 3;
    gate.pause(2, later, later + BUDGET);
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "P re-parks in attempt 2"
    );
    tokio::time::advance(DEADLINE + Duration::from_secs(2)).await;
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "attempt 1's deadline does not refuse a ticket now in attempt 2"
    );
    // Past attempt 2's own deadline + 1 s the carried ticket refuses itself.
    tokio::time::advance(DEADLINE * 2).await;
    assert!(
        matches!(
            futures::poll!(p.as_mut()),
            std::task::Poll::Ready(Err(Refused::Restarting))
        ),
        "past attempt 2's deadline + 1 s the carried ticket refuses itself"
    );
}

// G7 timer ownership: while draining a parker has no timer, so an Internal
// parker held past the old backstop does not proceed ahead of the cohort.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_drain_parker_has_no_timer_to_jump_the_cohort() {
    let gate = paused();
    let log = std::sync::Arc::default();
    let (c_task, c_admitted, c_finish) = park_held(&gate, Kind::Internal, "C", &log).await;
    gate.resume();
    within("G7d C admitted", c_admitted.notified()).await;
    let mut p = std::pin::pin!(gate.admit(Kind::Internal));
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "P parks behind the drain"
    );
    let decision = GateSeams::arm(&gate.seams().at_decision);
    tokio::time::advance(DEADLINE + BUDGET + Duration::from_secs(5)).await;
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "past the old backstop P still waits for the cohort"
    );
    assert!(
        decision.reached().now_or_never().is_none(),
        "no timer woke P to decide again while draining"
    );
    *gate
        .seams()
        .at_decision
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    assert_eq!(gate.state(), GateState::Draining { left: 1 });
    let _ = c_finish.send(());
    within("G7d C done", c_task).await.expect("C's task");
    assert!(within("G7d P admitted", p).await.is_ok());
}

// G9 variant: work that ends without an outcome (it panicked, test profile)
// fails the open attempt, even with its caller gone: admitted while open,
// held in its first write stage, the gate pauses, then the write panics.
#[tokio::test(flavor = "current_thread")]
async fn work_that_panics_fails_the_attempt() {
    let (_dir, store) = store().await;
    let gate = store.gate_for_test();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    let hook: super::super::CommitHook = std::sync::Arc::new({
        let entered = std::sync::Arc::clone(&entered);
        move |stage| {
            if matches!(stage, super::super::StoreWriteStage::Write) {
                entered.notify_one();
                let _ = released.lock().map(|rx| rx.recv());
                panic!("the write panics on purpose");
            }
            Ok(())
        }
    });
    store.set_hook(Some(hook)).await;
    let caller = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create(PreparedTask::for_test(&task(), OWNER, 1))
                .await
                .map(drop)
        }
    });
    within("G9p entered", entered.notified()).await;
    caller.abort();
    let _ = caller.await;
    pause(&gate, 1);
    let _ = release.send(());
    within("G9p drained", gate.idle()).await;
    assert!(
        gate.failed(),
        "an admission that ended without an outcome failed the attempt"
    );
}

// G7 x G11: an internal parker admitted at its backstop leaves the parked count
// in the same step. A resume that lands between that admission and the
// parker's return must not count it as a drain member, or the drain waits for
// a member that never reports and the gate stays Draining.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_backstop_admission_is_never_a_drain_member() {
    let gate = paused();
    let mut p = std::pin::pin!(gate.admit(Kind::Internal));
    assert!(futures::poll!(p.as_mut()).is_pending(), "P parks");
    let decision = GateSeams::arm(&gate.seams().at_decision);
    tokio::time::advance(DEADLINE + BUDGET + Duration::from_secs(1)).await;
    assert!(
        futures::poll!(p.as_mut()).is_pending(),
        "P is admitted at its backstop and held at the decision"
    );
    within("G7b decision", decision.reached()).await;
    gate.resume();
    decision.release();
    let admitted = within("G7b P returns", p).await;
    assert!(admitted.is_ok(), "the backstop admits an Internal parker");
    drop(admitted);
    assert_eq!(
        gate.state(),
        GateState::Open,
        "the resume found no parked member, so the gate is open"
    );
}
