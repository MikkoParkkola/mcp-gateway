// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use super::Gateway;
use crate::protocol::JsonRpcNotification;
use crate::transport::notification_sink;

/// The read judge of a gateway with the verdict off.
fn plain_reads() -> crate::gateway::outbound::StdioReads {
    crate::gateway::outbound::StdioReads::new(
        None,
        std::sync::Arc::new(crate::gateway::outbound::RejectionAudit::new(None, 1)),
        None,
    )
}

fn progress(token: &str) -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(json!({ "progressToken": token, "progress": 1 })),
    }
}

/// S-02's liveness half: the notification is on the wire before the
/// dispatch it belongs to has produced a response. Asserting only that
/// both appear would pass on a drain-then-emit implementation, which is
/// the design ADR-014 §1 rejects.
#[tokio::test]
async fn a_notification_is_written_before_its_dispatch_returns() {
    let (writer, mut queue) = tokio::sync::mpsc::channel(super::STDOUT_QUEUE_DEPTH);
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let dispatch_gate = std::sync::Arc::clone(&gate);

    let dispatch = tokio::spawn(async move {
        Gateway::dispatch_streaming_notifications(
            async move {
                notification_sink::publish(vec![progress("gw-1")]);
                // Park the dispatch. Reading the notification below can
                // only succeed if it was queued for the single writer while
                // this is pending, so a drain-after-resolve implementation
                // deadlocks here instead of passing.
                let _permit = dispatch_gate.acquire().await.unwrap();
                "result"
            },
            &writer,
            &plain_reads(),
            None,
        )
        .await
        .0
    });

    let first = queue
        .recv()
        .await
        .expect("nothing was queued")
        .stdio_value()
        .map(std::borrow::Cow::into_owned)
        .expect("a notification writes a value");
    assert!(
        first.to_string().contains("notifications/progress"),
        "first frame was not the notification: {first}"
    );

    gate.add_permits(1);
    assert_eq!(dispatch.await.unwrap(), "result");
}

/// The scope is what makes the mint reachable. Without it
/// `mint_progress_token` returns `None` and the client's own token
/// travels to the backend unchanged -- the leak SUB.2b forbids.
#[tokio::test]
async fn a_dispatch_runs_inside_a_notification_scope() {
    let (writer, _queue) = tokio::sync::mpsc::channel(super::STDOUT_QUEUE_DEPTH);
    let minted = Gateway::dispatch_streaming_notifications(
        async { notification_sink::mint_progress_token(&json!(7)) },
        &writer,
        &plain_reads(),
        None,
    )
    .await
    .0;
    assert!(
        minted.is_some(),
        "dispatch ran outside a notification scope"
    );
}

/// A notification published after the dispatch resolves is still the
/// caller's to see; the post-loop drain is what delivers it.
#[tokio::test]
async fn a_late_notification_is_drained_before_the_response() {
    let (writer, mut queue) = tokio::sync::mpsc::channel(super::STDOUT_QUEUE_DEPTH);
    Gateway::dispatch_streaming_notifications(
        async {
            notification_sink::publish(vec![progress("gw-late")]);
        },
        &writer,
        &plain_reads(),
        None,
    )
    .await;
    let late = queue
        .recv()
        .await
        .expect("the late notification was dropped")
        .stdio_value()
        .map(std::borrow::Cow::into_owned)
        .expect("a notification writes a value");
    assert!(late.to_string().contains("gw-late"));
}
