// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `SseChannel` rows (MIK-8835.SSE.2): pairing by id, the waiting bound, a
//! saturated notification sink, a large answer, and the pre-endpoint cap.

use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::sync::mpsc;

use super::{HANDSHAKE_CAP, Sink, SseChannel};
use crate::protocol::RequestId;
use crate::transport::upstream_tap::{TAP_CAPACITY, UpstreamNote};

type Feed = Arc<Mutex<Option<mpsc::UnboundedReceiver<String>>>>;

/// A server whose one GET streams what the row sends on the returned sender.
async fn stream_server() -> (String, mpsc::UnboundedSender<String>) {
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let feed: Feed = Arc::new(Mutex::new(Some(rx)));
    let app = axum::Router::new().route(
        "/sse",
        axum::routing::get(move || {
            let feed = Arc::clone(&feed);
            async move {
                let mut rx = feed.lock().expect("feed").take().expect("one GET");
                let body = async_stream::stream! {
                    while let Some(chunk) = rx.recv().await {
                        yield Ok::<_, std::io::Error>(chunk);
                    }
                };
                axum::body::Body::from_stream(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/sse", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, tx)
}

async fn open(url: &str, sink: Option<Sink>) -> crate::Result<Arc<SseChannel>> {
    open_budgeted(url, sink, None).await
}

async fn open_budgeted(
    url: &str,
    sink: Option<Sink>,
    budget: Option<Arc<super::super::budget::ByteBudget>>,
) -> crate::Result<Arc<SseChannel>> {
    let response = reqwest::get(url).await.expect("GET");
    SseChannel::open(
        response,
        |data| Ok(format!("resolved:{data}")),
        sink,
        budget,
    )
    .await
}

fn event(data: &serde_json::Value) -> String {
    format!("event: message\ndata: {data}\n\n")
}

#[tokio::test]
async fn an_answer_reaches_only_the_request_with_its_id() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /messages?session_id=1\n\n".into())
        .expect("send");
    let channel = open(&url, None).await.expect("open");
    assert_eq!(channel.endpoint(), "resolved:/messages?session_id=1");
    let waiting = channel.register(&RequestId::Number(7)).expect("register");
    // A wrong id, then the string id "7" (not the number), then the answer.
    tx.send(event(
        &json!({"jsonrpc": "2.0", "id": 8, "result": {"no": true}}),
    ))
    .expect("send");
    tx.send(event(
        &json!({"jsonrpc": "2.0", "id": "7", "result": {"no": true}}),
    ))
    .expect("send");
    tx.send(event(
        &json!({"jsonrpc": "2.0", "id": 7, "result": {"yes": true}}),
    ))
    .expect("send");
    let response = waiting.response().await.expect("answered");
    assert_eq!(response.result, Some(json!({"yes": true})));
}

/// X2: at most `TAP_CAPACITY` requests wait; a finished one frees its place.
#[tokio::test]
async fn x2_the_waiting_bound_refuses_then_admits() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let channel = open(&url, None).await.expect("open");
    let mut held: Vec<_> = (0..TAP_CAPACITY)
        .map(|n| {
            channel
                .register(&RequestId::Number(i64::try_from(n).expect("small")))
                .expect("within the bound")
        })
        .collect();
    assert!(
        channel.register(&RequestId::Number(-1)).is_err(),
        "a full map refuses"
    );
    drop(held.pop());
    assert!(
        channel.register(&RequestId::Number(-1)).is_ok(),
        "a freed place is reused"
    );
}

/// X3: a full notification sink is closed, and the answer queued behind the
/// notifications still arrives.
#[tokio::test]
async fn x3_a_saturated_sink_never_holds_an_answer() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let (note_tx, mut note_rx) = mpsc::channel::<UpstreamNote>(1);
    let sink = Sink {
        tx: note_tx,
        map: Box::new(|_| Some(UpstreamNote::End)),
    };
    let channel = open(&url, Some(sink)).await.expect("open");
    let waiting = channel.register(&RequestId::Number(1)).expect("register");
    for _ in 0..10 {
        tx.send(event(
            &json!({"jsonrpc": "2.0", "method": "notifications/message"}),
        ))
        .expect("send");
    }
    tx.send(event(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})))
        .expect("send");
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), waiting.response())
        .await
        .expect("not held behind the notifications");
    assert!(answered.is_ok());
    // The sink took one note and was then closed.
    assert!(note_rx.recv().await.is_some());
    assert!(note_rx.recv().await.is_none(), "the sink is closed");
}

/// K5: an answer far over the 64 KiB handshake line cap is accepted.
#[tokio::test]
async fn k5_a_large_answer_is_accepted() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let channel = open(&url, None).await.expect("open");
    let waiting = channel.register(&RequestId::Number(1)).expect("register");
    let other = channel.register(&RequestId::Number(2)).expect("register");
    let big = "x".repeat(256 * 1024);
    tx.send(event(
        &json!({"jsonrpc": "2.0", "id": 1, "result": {"text": big}}),
    ))
    .expect("send");
    let response = waiting.response().await.expect("answered");
    assert_eq!(
        response.result.expect("result")["text"]
            .as_str()
            .map(str::len),
        Some(256 * 1024)
    );
    assert!(
        !channel.is_closed(),
        "the channel stays up for the other request"
    );
    drop(other);
}

/// Bytes with no `endpoint` past the handshake cap are refused, not buffered.
#[tokio::test]
async fn a_stream_without_an_endpoint_is_capped() {
    let (url, tx) = stream_server().await;
    tx.send(format!("data: {}\n\n", "y".repeat(HANDSHAKE_CAP + 1)))
        .expect("send");
    let refused = open(&url, None).await;
    assert!(refused.is_err(), "refused past the cap");
}

/// The stream ending fails every waiting request with a transport error.
#[tokio::test]
async fn the_stream_ending_fails_what_waits() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let channel = open(&url, None).await.expect("open");
    let waiting = channel.register(&RequestId::Number(1)).expect("register");
    drop(tx);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(10), waiting.response())
        .await
        .expect("prompt");
    assert!(ended.is_err());
    assert!(channel.is_closed());
    assert!(
        channel.register(&RequestId::Number(2)).is_err(),
        "a closed channel refuses"
    );
}

/// What the stream carries that is not an answer is ignored: an event whose
/// data is not JSON, and a result frame with no id. The real answer after
/// them still reaches its request.
#[tokio::test]
async fn non_json_and_id_less_frames_are_ignored() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let channel = open(&url, None).await.expect("open");
    let waiting = channel.register(&RequestId::Number(3)).expect("register");
    tx.send("event: message\ndata: not json at all\n\n".into())
        .expect("send");
    tx.send(event(
        &json!({"jsonrpc": "2.0", "result": {"orphan": true}}),
    ))
    .expect("send");
    tx.send(event(
        &json!({"jsonrpc": "2.0", "id": 3, "result": {"mine": true}}),
    ))
    .expect("send");
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), waiting.response())
        .await
        .expect("answered")
        .expect("paired");
    assert_eq!(response.result, Some(json!({"mine": true})));
    assert!(
        !channel.is_closed(),
        "ignored frames do not end the channel"
    );
}

/// The replacing task's own request, meeting a stream that ended at once,
/// fails rather than wait on the lock its own caller holds.
#[tokio::test]
async fn the_replacing_tasks_own_request_fails_fast() {
    use super::super::sse_send_tests::{peer, wait_closed};
    let (url, _log, streams) = peer().await;
    let transport = super::super::HttpTransport::new(
        &url,
        std::collections::HashMap::new(),
        std::time::Duration::from_secs(10),
        false,
    )
    .expect("transport");
    transport
        .initialize()
        .await
        .expect("handshake on session 1");
    streams.lock().expect("streams").insert(1, None);
    wait_closed(&transport).await;
    let Err(refused) = super::REPLACING
        .scope((), transport.live_sse_channel(&[]))
        .await
    else {
        panic!("the replacing task's own request must fail fast");
    };
    assert!(refused.to_string().contains("being replaced"), "{refused}");
}

/// The preview's byte budget covers the retained stream too: a waiting
/// request learns the budget that ended it, never a bare "stream ended".
#[tokio::test]
async fn a_budgeted_stream_past_its_total_fails_the_waiting_request() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let budget = Arc::new(super::super::budget::ByteBudget::new(1024, 2048));
    let channel = open_budgeted(&url, None, Some(budget)).await.expect("open");
    let waiting = channel.register(&RequestId::Number(1)).expect("register");
    // Notifications under the frame limit, past the total.
    let note = format!(
        "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":\"{}\"}}\n\n",
        "a".repeat(600)
    );
    for _ in 0..4 {
        tx.send(note.clone()).expect("send");
    }
    let error = waiting
        .response()
        .await
        .expect_err("the budget ends the stream");
    assert!(error.to_string().contains("preview is over its"), "{error}");
}

#[tokio::test]
async fn a_budgeted_stream_refuses_a_frame_past_the_response_limit() {
    let (url, tx) = stream_server().await;
    tx.send("event: endpoint\ndata: /m\n\n".into())
        .expect("send");
    let budget = Arc::new(super::super::budget::ByteBudget::new(1024, 1 << 20));
    let channel = open_budgeted(&url, None, Some(budget)).await.expect("open");
    let waiting = channel.register(&RequestId::Number(1)).expect("register");
    tx.send(format!("event: message\ndata: {}", "a".repeat(2000)))
        .expect("send");
    let error = waiting
        .response()
        .await
        .expect_err("the frame limit ends the stream");
    // The budget's own refusal, which the era probe reports instead of
    // reading as silence.
    assert!(error.to_string().contains("over the preview's"), "{error}");
    assert!(crate::transport::is_budget_refusal(&error), "{error}");
}
