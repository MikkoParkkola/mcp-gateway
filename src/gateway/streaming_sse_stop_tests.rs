// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The session stream's stop wait, `next_unless_stopped`, at the two edges the
//! stream rows reach only by timing: the stop and a queued copy ready at once,
//! and a stop signal whose sender is gone.

use std::time::Duration;

use tokio::sync::{broadcast, watch};

use super::super::{CopyAudience, SessionFrame, TaggedNotification};
use super::next_unless_stopped;

/// A bare copy of one notification about `uri`, with no delivery watch.
fn frame(uri: &str) -> SessionFrame {
    SessionFrame {
        note: TaggedNotification {
            source: "alpha".to_string(),
            event_type: "message".to_string(),
            data: serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/resources/updated",
                "params": { "uri": uri },
            }),
            event_id: None,
        },
        mark: None,
        watch: None,
        audience: CopyAudience::Any,
        judged: None,
    }
}

/// The stop and a queued copy are both ready: the stop wins, and the copy is
/// taken off the queue and settled rather than left for a write that will not
/// come.
#[tokio::test]
async fn a_stop_ready_beside_a_queued_copy_wins_and_empties_the_queue() {
    let (tx, mut rx) = broadcast::channel(4);
    let (stop, mut stopped) = watch::channel(false);
    tx.send(frame("rows://tie")).expect("the stream receives");
    stop.send(true).expect("the stream watches");
    let next = tokio::time::timeout(
        Duration::from_secs(10),
        next_unless_stopped(&mut rx, &mut stopped),
    )
    .await
    .expect("the wait answers at once");
    assert!(next.is_none(), "the queued copy won over the stop");
    assert!(
        matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Empty)),
        "the stop left a copy on the queue"
    );
}

/// A stop signal whose sender is gone never fires, so the stream goes on
/// reading its queue instead of ending.
#[tokio::test]
async fn a_dropped_stop_sender_leaves_the_stream_reading() {
    let (tx, mut rx) = broadcast::channel(4);
    let (stop, mut stopped) = watch::channel(false);
    drop(stop);
    tx.send(frame("rows://open")).expect("the stream receives");
    let next = tokio::time::timeout(
        Duration::from_secs(10),
        next_unless_stopped(&mut rx, &mut stopped),
    )
    .await
    .expect("the wait answers at once");
    let uri = next
        .and_then(Result::ok)
        .map(|copy| copy.into_inner().data["params"]["uri"].clone());
    assert_eq!(
        uri,
        Some(serde_json::json!("rows://open")),
        "a dropped stop sender ended the stream"
    );
}
