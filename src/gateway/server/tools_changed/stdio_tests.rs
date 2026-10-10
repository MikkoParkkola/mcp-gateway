// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8278 T12: the sender's latch. Decisions made while the sender is not
//! running collapse to one frame; a decision after that frame is another.

use std::sync::Arc;

use tokio::sync::{Notify, broadcast, mpsc};

use super::send_when_ready;

const BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// One frame arrives within [`BOUND`], and no second follows it.
async fn exactly_one(queue: &mut mpsc::Receiver<crate::gateway::outbound::OutboundFrame>) {
    tokio::time::timeout(BOUND, queue.recv())
        .await
        .expect("a frame within the bound")
        .expect("the sender is alive");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), queue.recv())
            .await
            .is_err(),
        "a second frame followed"
    );
}

#[tokio::test]
async fn t12_a_burst_before_the_sender_wakes_is_one_frame() {
    let pending = Arc::new(Notify::new());
    let (writer, mut queue) = mpsc::channel(64);
    let (stop, _) = broadcast::channel(1);
    for _ in 0..50 {
        pending.notify_one();
    }
    let sender = tokio::spawn(send_when_ready(
        (
            Arc::clone(&pending),
            Arc::new(parking_lot::Mutex::new(false)),
        ),
        stop.subscribe(),
        writer,
    ));
    exactly_one(&mut queue).await;
    pending.notify_one();
    exactly_one(&mut queue).await;
    drop(stop.send(()));
    tokio::time::timeout(BOUND, sender)
        .await
        .expect("the sender ends on stop")
        .expect("the sender did not panic");
}

/// The stop lock is held across the final check and the enqueue: while the
/// sender is between them, `stop` cannot take it, so no frame is queued after
/// `stop` returns. Killed by releasing the lock before the enqueue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stop_lock_is_held_across_the_final_send() {
    let pending = Arc::new(Notify::new());
    let stopping = Arc::new(parking_lot::Mutex::new(false));
    let (writer, mut queue) = mpsc::channel(4);
    let (stop, _) = broadcast::channel(1);
    let (reached, release) =
        crate::gateway::server::stdio_seams::arm_final_send_pause(Arc::as_ptr(&stopping) as usize);
    let sender = tokio::spawn(send_when_ready(
        (Arc::clone(&pending), Arc::clone(&stopping)),
        stop.subscribe(),
        writer,
    ));
    pending.notify_one();
    tokio::task::spawn_blocking(move || reached.recv_timeout(BOUND))
        .await
        .expect("the waiter ran")
        .expect("the sender reached its final send");
    assert!(
        stopping.try_lock().is_none(),
        "the stop lock was free between the final check and the enqueue"
    );
    drop(release.send(()));
    tokio::time::timeout(BOUND, queue.recv())
        .await
        .expect("the frame within the bound")
        .expect("the sender is alive");
    *stopping.lock() = true;
    drop(stop.send(()));
    tokio::time::timeout(BOUND, sender)
        .await
        .expect("the sender ends on stop")
        .expect("the sender did not panic");
}
