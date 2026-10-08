// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B` on websocket, driven at the outbound queue: the test plays
//! the writer, so it decides whether a request frame was written.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc::{Receiver, channel};
use tokio_tungstenite::tungstenite::Message;

use super::{Outbound, WebSocketTransport};
use crate::protocol::JsonRpcResponse;
use crate::transport::Transport as _;

const ARRIVAL: Duration = Duration::from_secs(2);

/// A transport whose writer is the returned queue, and a request on it.
async fn queued_request(
    method: &'static str,
) -> (
    Arc<WebSocketTransport>,
    Receiver<Outbound>,
    tokio::task::JoinHandle<()>,
    Outbound,
) {
    let transport = WebSocketTransport::new(
        "ws://localhost:9",
        HashMap::new(),
        Duration::from_secs(60),
        None,
    );
    let (tx, mut rx) = channel::<Outbound>(8);
    *transport.inner.outbound_tx.lock().await = Some(tx);
    let caller = Arc::clone(&transport);
    let call = tokio::spawn(async move { drop(caller.request(method, None).await) });
    let request = tokio::time::timeout(ARRIVAL, rx.recv())
        .await
        .expect("queued")
        .expect("open");
    (transport, rx, call, request)
}

fn json_of(message: &Message) -> Value {
    serde_json::from_str(message.to_text().expect("text")).expect("json")
}

#[tokio::test]
async fn a_written_request_dropped_unanswered_is_cancelled_by_its_id() {
    let (_transport, mut rx, call, (frame, claim)) = queued_request("tools/call").await;
    assert!(claim.expect("a request carries a claim").claim_write());
    call.abort();
    let (cancel, _) = tokio::time::timeout(ARRIVAL, rx.recv())
        .await
        .expect("a cancel is queued")
        .expect("open");
    let cancel = json_of(&cancel);
    assert_eq!(cancel["method"], "notifications/cancelled", "{cancel}");
    assert_eq!(
        cancel["params"]["requestId"],
        json_of(&frame)["id"],
        "{cancel}"
    );
}

/// Q1w: a request whose caller gave up while it was queued is never written,
/// so there is nothing to cancel.
#[tokio::test]
async fn a_queued_request_dropped_is_never_written_or_cancelled() {
    let (_transport, mut rx, call, (_, claim)) = queued_request("tools/call").await;
    call.abort();
    drop(call.await);
    assert!(
        !claim.expect("a claim").claim_write(),
        "the writer skips it"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "no cancel follows");
}

#[tokio::test]
async fn an_answered_request_is_never_cancelled() {
    let (transport, mut rx, call, (frame, claim)) = queued_request("tools/call").await;
    assert!(claim.expect("a claim").claim_write());
    let id = json_of(&frame)["id"].to_string();
    let (_, sender) = transport.inner.pending.remove(&id).expect("pending");
    drop(sender.send(JsonRpcResponse::success(
        serde_json::from_str(&id).unwrap(),
        json!({}),
    )));
    drop(call.await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "no cancel after the answer");
}

#[tokio::test]
async fn a_written_initialize_dropped_is_never_cancelled() {
    let (_transport, mut rx, call, (_, claim)) = queued_request("initialize").await;
    assert!(claim.expect("a claim").claim_write());
    call.abort();
    drop(call.await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "initialize is never cancelled");
}
