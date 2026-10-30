// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K4b (MIK-8835.SSE.2, design B16): a calls-path request takes its place on
//! the stream, and the stream closes before its POST. The request is not sent
//! on the dead stream: it is placed on a replacement and sent there, once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::HttpTransport;
use crate::protocol::{JsonRpcRequest, RequestId};

/// The posts the peer saw: `(session, method)`, in order.
pub(super) type Log = Arc<Mutex<Vec<(u32, String)>>>;
/// Each session's stream sender; `None` once the row ended it.
pub(super) type Streams = Arc<Mutex<HashMap<u32, Option<mpsc::UnboundedSender<String>>>>>;

/// A spec SSE peer: each GET is a new session; every POST is answered 202
/// with its response on that session's stream.
pub(super) async fn peer() -> (String, Log, Streams) {
    let log: Log = Arc::default();
    let streams: Streams = Arc::default();
    let (get_streams, post_streams, post_log) = (streams.clone(), streams.clone(), log.clone());
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::get(move || {
                let streams = get_streams.clone();
                async move {
                    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                    let session = {
                        let mut all = streams.lock().expect("streams");
                        let n = u32::try_from(all.len()).expect("few") + 1;
                        all.insert(n, Some(tx));
                        n
                    };
                    let body = async_stream::stream! {
                        yield Ok::<_, std::io::Error>(format!("event: endpoint\ndata: /messages?session_id={session}\n\n"));
                        while let Some(frame) = rx.recv().await {
                            yield Ok(format!("event: message\ndata: {frame}\n\n"));
                        }
                    };
                    axum::body::Body::from_stream(body)
                }
            }),
        )
        .route(
            "/messages",
            axum::routing::post(
                move |Query(q): Query<HashMap<String, String>>, axum::Json(frame): axum::Json<Value>| {
                    let (streams, log) = (post_streams.clone(), post_log.clone());
                    async move {
                        let session: u32 = q["session_id"].parse().expect("session");
                        let method = frame["method"].as_str().unwrap_or_default().to_owned();
                        log.lock().expect("log").push((session, method.clone()));
                        if let Some(id) = frame.get("id") {
                            let result = if method == "initialize" {
                                json!({"protocolVersion": "2024-11-05", "capabilities": {},
                                       "serverInfo": {"name": "k4b", "version": "1"}})
                            } else {
                                json!({"tools": []})
                            };
                            let answer = json!({"jsonrpc": "2.0", "id": id, "result": result});
                            if let Some(Some(tx)) = streams.lock().expect("streams").get(&session) {
                                let _ = tx.send(answer.to_string());
                            }
                        }
                        (StatusCode::ACCEPTED, "Accepted").into_response()
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/sse", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, log, streams)
}

fn list(id: i64) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: RequestId::Number(id),
        method: "tools/list".to_owned(),
        params: None,
    }
}

#[tokio::test]
async fn k4b_a_stream_closed_before_the_post_sends_on_the_replacement() {
    let (url, log, streams) = peer().await;
    let transport = HttpTransport::new(&url, HashMap::new(), Duration::from_secs(10), false)
        .expect("transport");
    transport
        .initialize()
        .await
        .expect("handshake on session 1");
    let (reached, release) = transport.before_sse_post.arm();
    let sending = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.send_request_as(&list(77), &[]).await })
    };
    crate::test_pause::within("the request took its place", reached.notified()).await;
    // End session 1's stream while the request holds its place on it, and
    // wait until the gateway's reader has seen that.
    streams.lock().expect("streams").insert(1, None);
    let closed = || {
        transport
            .sse_channel
            .read()
            .as_ref()
            .is_some_and(|c| c.is_closed())
    };
    crate::test_pause::within("the channel saw the end", async {
        while !closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    release.notify_one();
    let answered = crate::test_pause::within("the request finished", sending)
        .await
        .expect("task");
    assert!(answered.is_ok(), "sent on the replacement: {answered:?}");
    let lists: Vec<u32> = log
        .lock()
        .expect("log")
        .iter()
        .filter(|(_, m)| m == "tools/list")
        .map(|(s, _)| *s)
        .collect();
    assert_eq!(
        lists,
        [2],
        "posted once, on the new session, never on the dead one"
    );
}

/// The transport's channel once its reader has seen the stream end.
pub(super) async fn wait_closed(transport: &HttpTransport) {
    crate::test_pause::within("the channel saw the end", async {
        while !transport
            .sse_channel
            .read()
            .as_ref()
            .is_some_and(|c| c.is_closed())
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// Before any handshake in SSE mode there is no stream: body mode.
#[tokio::test]
async fn no_stream_before_the_first_handshake_means_body_mode() {
    let (url, _log, _streams) = peer().await;
    let transport = HttpTransport::new(&url, HashMap::new(), Duration::from_secs(10), false)
        .expect("transport");
    assert!(
        transport
            .live_sse_channel(&[])
            .await
            .expect("no error")
            .is_none()
    );
}

/// A caller that waited on `reinit_lock` while another replaced the dead
/// stream uses that replacement: one shared replacement, not a second.
#[tokio::test]
async fn a_caller_that_waited_uses_the_replacement_made_meanwhile() {
    let (url, _log, streams) = peer().await;
    let transport = HttpTransport::new(&url, HashMap::new(), Duration::from_secs(10), false)
        .expect("transport");
    transport
        .initialize()
        .await
        .expect("handshake on session 1");
    streams.lock().expect("streams").insert(1, None);
    wait_closed(&transport).await;
    let held = transport.reinit_lock.lock().await;
    let waiting = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.live_sse_channel(&[]).await })
    };
    // Let the caller reach the lock this row holds.
    // timing: precondition
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The replacement the other caller would make, under the held lock.
    transport.connect_sse(&[]).await.expect("new stream");
    transport
        .legacy_handshake(&[])
        .await
        .expect("handshake on session 2");
    drop(held);
    let got = crate::test_pause::within("the waiting caller", waiting)
        .await
        .expect("task")
        .expect("no error")
        .expect("a channel");
    assert!(!got.is_closed(), "the replacement made while it waited");
    assert_eq!(
        streams.lock().expect("streams").len(),
        2,
        "one replacement, not two"
    );
}
