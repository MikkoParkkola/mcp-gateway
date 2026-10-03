// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.LIFE.1: a client may reuse a request id once its answer is out,
//! even while the answered dispatch is not yet joined (review on #2519).
//!
//! Each case holds the old dispatch between queuing its answer and returning,
//! which is the window where the serve loop has not reaped it yet.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use super::super::stdio_dispatches::StdioDispatches;
use crate::gateway::outbound::OutboundFrame;
use crate::protocol::RequestId;

/// The next frame's written value.
async fn recv(stdout: &mut mpsc::Receiver<OutboundFrame>) -> Option<Value> {
    stdout
        .recv()
        .await
        .and_then(|frame| frame.stdio_value().map(std::borrow::Cow::into_owned))
}

const BOUND: Duration = Duration::from_secs(5);

fn id() -> RequestId {
    serde_json::from_value(json!(7)).expect("a request id")
}

/// Spawn the first dispatch for [`id`]: it queues `frame`, then waits on the
/// returned sender before it returns.
async fn answered_but_unreaped(
    dispatches: &mut StdioDispatches,
    writer: &mpsc::Sender<OutboundFrame>,
    frame: Value,
) -> oneshot::Sender<()> {
    let (release, held) = oneshot::channel::<()>();
    let cancelled = dispatches.cancelled();
    let writer = writer.clone();
    let answers = Some(id());
    dispatches.spawn(Some(id()), async move {
        let permit = writer.reserve().await.expect("the writer is open");
        cancelled.send_unless_cancelled(
            answers.as_ref(),
            permit,
            OutboundFrame::gateway_stdio(frame),
        );
        let _ = held.await;
    });
    release
}

/// Cancelling a reused id aborts the new dispatch, not the answered one.
#[tokio::test]
async fn a_reused_id_is_cancellable_before_its_predecessor_is_joined() {
    let mut dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let _release = answered_but_unreaped(&mut dispatches, &writer, json!("first")).await;
    let first = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(first.expect("answered in time"), Some(json!("first")));

    // The client has its answer, so it may send the id again.
    let (alive, dropped) = oneshot::channel::<()>();
    dispatches.spawn(Some(id()), async move {
        let _alive = alive;
        std::future::pending::<()>().await;
    });
    dispatches.cancel(&id());

    let outcome = tokio::time::timeout(BOUND, dropped).await;
    assert!(
        outcome.is_ok(),
        "the cancel aborted the answered dispatch; the reused id's call kept running"
    );
}

/// A cancel that names an id already answered is ignored, and does not
/// silence the next call that reuses the id.
#[tokio::test]
async fn a_late_cancel_does_not_silence_a_reused_id() {
    let mut dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let _release = answered_but_unreaped(&mut dispatches, &writer, json!("first")).await;
    let first = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(first.expect("answered in time"), Some(json!("first")));

    dispatches.cancel(&id());
    let cancelled = dispatches.cancelled();
    let second_writer = writer.clone();
    let answers = Some(id());
    dispatches.spawn(Some(id()), async move {
        let permit = second_writer.reserve().await.expect("the writer is open");
        cancelled.send_unless_cancelled(
            answers.as_ref(),
            permit,
            OutboundFrame::gateway_stdio(json!("second")),
        );
    });

    let second = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(
        second.expect("the reused id was answered, not silenced by the late cancel"),
        Some(json!("second"))
    );
}

/// Joining an answered dispatch clears only its own marks: the call that
/// reused its id keeps its "answered" mark, so a third use of the id is
/// still cancellable.
#[tokio::test]
async fn joining_a_predecessor_keeps_its_successors_marks() {
    let mut dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let first = answered_but_unreaped(&mut dispatches, &writer, json!("first")).await;
    let answered = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(answered.expect("first answered"), Some(json!("first")));
    let _second = answered_but_unreaped(&mut dispatches, &writer, json!("second")).await;
    let answered = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(answered.expect("second answered"), Some(json!("second")));

    // Only the first dispatch can finish, so this joins exactly it.
    drop(first);
    let joined = tokio::time::timeout(BOUND, dispatches.join_next()).await;
    assert!(
        matches!(joined, Ok(Some(Ok(())))),
        "the first dispatch joined"
    );

    let (alive, dropped) = oneshot::channel::<()>();
    dispatches.spawn(Some(id()), async move {
        let _alive = alive;
        std::future::pending::<()>().await;
    });
    dispatches.cancel(&id());
    let outcome = tokio::time::timeout(BOUND, dropped).await;
    assert!(
        outcome.is_ok(),
        "joining the first dispatch cleared the second's marks; the third call kept running"
    );
}

/// An id whose call was cancelled is free to reuse at once, before the
/// aborted dispatch is joined.
#[tokio::test]
async fn a_cancelled_id_is_reusable_before_its_dispatch_is_joined() {
    let mut dispatches = StdioDispatches::default();
    dispatches.spawn(Some(id()), std::future::pending::<()>());
    dispatches.cancel(&id());

    let (alive, dropped) = oneshot::channel::<()>();
    dispatches.spawn(Some(id()), async move {
        let _alive = alive;
        std::future::pending::<()>().await;
    });
    dispatches.cancel(&id());
    let outcome = tokio::time::timeout(BOUND, dropped).await;
    assert!(
        outcome.is_ok(),
        "the second cancel hit the cancelled dispatch; the reused id's call kept running"
    );
}

/// Joining the answered predecessor leaves the reused id mapped to its
/// in-flight successor, which a cancel still reaches.
#[tokio::test]
async fn joining_a_predecessor_keeps_the_reused_ids_mapping() {
    let mut dispatches = StdioDispatches::default();
    let (writer, mut stdout) = mpsc::channel::<OutboundFrame>(4);
    let first = answered_but_unreaped(&mut dispatches, &writer, json!("first")).await;
    let answered = tokio::time::timeout(BOUND, recv(&mut stdout)).await;
    assert_eq!(answered.expect("first answered"), Some(json!("first")));

    let (alive, dropped) = oneshot::channel::<()>();
    dispatches.spawn(Some(id()), async move {
        let _alive = alive;
        std::future::pending::<()>().await;
    });
    drop(first);
    let joined = tokio::time::timeout(BOUND, dispatches.join_next()).await;
    assert!(
        matches!(joined, Ok(Some(Ok(())))),
        "the first dispatch joined"
    );

    dispatches.cancel(&id());
    let outcome = tokio::time::timeout(BOUND, dropped).await;
    assert!(
        outcome.is_ok(),
        "joining the predecessor unmapped the reused id; its call kept running"
    );
}
