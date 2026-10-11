// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8347 edge rows: what a send does when the clock, the row or the store
//! cannot be trusted. Each keeps the cancel recoverable or gives it up loudly,
//! and none loses it silently. T15 delivers it twice on purpose: an outcome
//! the store could not write is sent again after restart, which the design
//! allows because a peer ignores a second cancel of a finished task.

use serde_json::{Value, json};

use super::tests::{
    BACKEND, Fixture, ScriptedPeer, executor_over, fixture, open_service, sends_reach, settle,
};
use crate::gateway::task_service::execution::CancelDelivery::Failed;
use crate::gateway::task_service::store::targets::UpstreamCancelState::{Done, Pending};

const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

/// T13. A clock that reads before 1970 when the send runs sends nothing and
/// keeps the cancel pending; once the clock reads, it is sent.
/// Mutant: "a send with no clock still sends".
#[tokio::test]
async fn a_clock_before_1970_sends_nothing_and_keeps_the_cancel() {
    let f = fixture(Some(DAY_MS)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    // Before any yield: the detached send has not run yet.
    let before_epoch = chrono::DateTime::from_timestamp(-1, 0).expect("a representable instant");
    f.service.store.set_clock_for_test(Some(before_epoch));
    f.executor.cancel_send_idle(&f.id).await;
    assert_eq!(peer.count(), 0, "a send ran with no clock");
    f.service.store.set_clock_for_test(None);
    assert_eq!(f.state(), Some(Pending { attempts: 0 }));
    settle(f.executor.flush_pending_cancels(Some(BACKEND))).await;
    assert_eq!((peer.count(), f.state()), (1, Some(Done)));
}

/// Rewrite the fixture row's pending cancel on disk, the store closed.
fn damage_pending(f: &Fixture) {
    let file = f.dir.path().join("tasks").join(format!("{}.json", f.id));
    let mut record: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let pending = record["upstreamCancelPending"]
        .as_object_mut()
        .expect("a pending cancel on the row");
    pending.remove("backend");
    pending.insert("target".into(), json!(200));
    std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
}

/// T14. A pending cancel whose backend cannot be resolved (its target index
/// names no call) is given up without a send, never retried forever.
/// Mutant: "an unresolvable row stays pending".
#[tokio::test]
async fn a_pending_cancel_naming_no_backend_is_given_up_without_a_send() {
    let f = fixture(Some(DAY_MS)).await;
    let first = ScriptedPeer::new([Failed]);
    assert!(f.executor.install_recovery(first.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 1 }).await;
    f.service.shutdown().await.expect("the first gateway stops");
    damage_pending(&f);
    let service = open_service(f.dir.path()).await;
    let later = service.store.now().expect("a clock after 1970")
        + chrono::Duration::try_hours(1).expect("one hour");
    service.store.set_clock_for_test(Some(later));
    let executor = executor_over(&service);
    let peer = ScriptedPeer::new([]);
    assert!(executor.install_recovery(peer.clone()));
    settle(executor.flush_pending_cancels(None)).await;
    assert_eq!(peer.count(), 0, "a send to no backend");
    assert_eq!(
        service.store.upstream_cancel_state(&f.owner_digest, &f.id),
        Some(Done)
    );
}

/// T15. A store that closes while a send is in flight cannot take its
/// outcome: the cancel stays pending on disk and the next gateway sends it.
/// Mutant: "the outcome is marked done before the write".
#[tokio::test]
async fn a_send_whose_outcome_cannot_be_written_is_sent_again_after_restart() {
    let f = fixture(Some(DAY_MS)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let release = peer.hold_next();
    let parked = peer.parked.notified();
    f.owner_cancels().await;
    parked.await;
    f.service.shutdown().await.expect("the gateway stops");
    let _ = release.send(());
    sends_reach(&peer, 1).await;
    f.executor.cancel_send_idle(&f.id).await;
    let service = open_service(f.dir.path()).await;
    assert_eq!(
        service.store.upstream_cancel_state(&f.owner_digest, &f.id),
        Some(Pending { attempts: 0 }),
        "an unwritten outcome leaves the cancel pending"
    );
    let executor = executor_over(&service);
    let again = ScriptedPeer::new([]);
    assert!(executor.install_recovery(again.clone()));
    settle(executor.flush_pending_cancels(Some(BACKEND))).await;
    assert_eq!(again.count(), 1);
}
