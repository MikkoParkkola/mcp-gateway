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

/// A hang bound on frames that do arrive, never a window an outcome is timed
/// against: a loaded runner may take seconds (MIK-8222).
const ARRIVAL: Duration = Duration::from_secs(10);

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

/// The answer was routed, but its caller was dropped before reading it: the
/// answer won the race, so no cancel follows. On this single-threaded test
/// runtime the abort lands before the caller is polled again.
#[tokio::test]
async fn a_caller_dropped_after_its_answer_was_routed_sends_no_cancel() {
    let (transport, mut rx, call, (frame, claim)) = queued_request("tools/call").await;
    assert!(claim.expect("a claim").claim_write());
    let id = json_of(&frame)["id"].to_string();
    let (_, sender) = transport.inner.pending.remove(&id).expect("pending");
    drop(sender.send(JsonRpcResponse::success(
        serde_json::from_str(&id).unwrap(),
        json!({}),
    )));
    call.abort();
    drop(call.await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "the routed answer won; no cancel");
}

/// Q1w through the real writer: a request abandoned in the queue never
/// reaches the peer, and the frame behind it still does.
#[tokio::test]
async fn the_writer_skips_a_request_abandoned_in_the_queue() {
    use crate::protocol::{JsonRpcRequest, RequestId};
    use crate::transport::websocket_test_server::{Behaviour, WsPeer};
    use crate::transport::write_claim::WriteClaim;

    let peer = WsPeer::start(Behaviour::Normal).await;
    let transport = WebSocketTransport::new(&peer.url, HashMap::new(), ARRIVAL, None);
    tokio::time::timeout(ARRIVAL, transport.connect())
        .await
        .expect("connects in time")
        .expect("connects");
    let abandoned = WriteClaim::new();
    assert!(!abandoned.abandon(), "precondition: abandoned unwritten");
    for (id, claim) in [(900, Some(abandoned)), (901, None)] {
        let frame = super::McpFrame::Request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(id),
            method: "tools/call".to_string(),
            params: Some(json!({"name": "echo"})),
        })
        .to_ws_message()
        .expect("a frame");
        transport.enqueue((frame, claim)).await.expect("queued");
    }
    let deadline = tokio::time::Instant::now() + ARRIVAL;
    while peer.seen.calls.lock().is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "nothing arrived");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ids: Vec<Value> = peer
        .seen
        .calls
        .lock()
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, [json!(901)], "only the frame nobody abandoned");
}

/// A request still queued when the transport's own timeout fires is never
/// written: nobody is waiting for its answer. No cancel either (design Q1).
#[tokio::test]
async fn a_queued_request_that_timed_out_is_never_written() {
    let transport = WebSocketTransport::new(
        "ws://localhost:9",
        HashMap::new(),
        Duration::from_millis(200),
        None,
    );
    let (tx, mut rx) = channel::<Outbound>(8);
    *transport.inner.outbound_tx.lock().await = Some(tx);
    let result = transport.request("tools/call", None).await;
    assert!(
        matches!(result, Err(crate::Error::BackendTimeout(_))),
        "precondition: it timed out: {result:?}"
    );
    assert!(
        transport.inner.pending.is_empty(),
        "no pending entry is left"
    );
    let (_, claim) = rx.try_recv().expect("the request was queued");
    assert!(
        !claim.expect("a claim").claim_write(),
        "the writer skips it"
    );
    assert!(rx.try_recv().is_err(), "and no cancel follows");
}

/// An `initialize` dropped while queued is never written either, though it is
/// never cancelled.
#[tokio::test]
async fn a_queued_initialize_dropped_is_never_written() {
    let (_transport, mut rx, call, (_, claim)) = queued_request("initialize").await;
    call.abort();
    drop(call.await);
    assert!(
        !claim.expect("a claim").claim_write(),
        "the writer skips it"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "no cancel");
}
