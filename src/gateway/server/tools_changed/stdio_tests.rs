// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8278 T12: the sender's latch. Decisions made while the sender is not
//! running collapse to one frame; a decision after that frame is another.

use std::sync::Arc;

use tokio::sync::{Notify, broadcast, mpsc};

use super::send_when_ready;

const BOUND: std::time::Duration = std::time::Duration::from_secs(5);

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
