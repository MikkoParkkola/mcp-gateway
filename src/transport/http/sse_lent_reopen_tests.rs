// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lent-only slot's legacy SSE stream that drops between calls stays closed
//! until the subscriber's next call, which reopens it as that subscriber
//! before its POST.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::HttpTransport;
use super::sse_send_tests::{Streams, wait_closed};
use crate::transport::{Lender, LentCredential, ResendPermission, SlotCredential, Transport};

/// What the peer saw, in order: `(GET or POST, session, Authorization)`.
type Seen = Arc<Mutex<Vec<(&'static str, u32, String)>>>;

fn authorization(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// A spec SSE peer like `sse_send_tests::peer`, recording each request's
/// `Authorization`: each GET is a new session; every POST is answered 202
/// with its response on that session's stream.
async fn recording_peer() -> (String, Seen, Streams) {
    let peer = peer(Expiry::Never).await;
    (peer.url, peer.seen, peer.streams)
}

/// The recording peer and what it saw beyond [`Seen`]: each POST's session
/// and method, in order, and whether any request carried the start marker
/// header, which must never reach the wire.
struct Peer {
    url: String,
    seen: Seen,
    streams: Streams,
    posts: Arc<Mutex<Vec<(u32, String)>>>,
    marker_sent: Arc<std::sync::atomic::AtomicBool>,
}

/// The start call's marker header, which no request may carry.
const START_MARKER: &str = "x-mcp-gateway-slot-start";

/// Whether the peer expires the session under the first call.
#[derive(Clone, Copy)]
enum Expiry {
    Never,
    /// The first `tools/list` is answered "session not found".
    FirstList,
}

/// [`recording_peer`], expiring the session as `expiry` says.
async fn peer(expiry: Expiry) -> Peer {
    let lists = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let posts: Arc<Mutex<Vec<(u32, String)>>> = Arc::default();
    let marker_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (get_marker, post_marker, post_log) = (
        Arc::clone(&marker_sent),
        Arc::clone(&marker_sent),
        Arc::clone(&posts),
    );
    let seen: Seen = Arc::default();
    let streams: Streams = Arc::default();
    let (get_streams, post_streams) = (streams.clone(), streams.clone());
    let (get_seen, post_seen) = (seen.clone(), seen.clone());
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::get(move |headers: HeaderMap| {
                let (streams, seen) = (get_streams.clone(), get_seen.clone());
                if headers.contains_key(START_MARKER) {
                    get_marker.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                async move {
                    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                    let session = {
                        let mut all = streams.lock().expect("streams");
                        let n = u32::try_from(all.len()).expect("few") + 1;
                        all.insert(n, Some(tx));
                        n
                    };
                    seen.lock()
                        .expect("seen")
                        .push(("GET", session, authorization(&headers)));
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
                move |Query(q): Query<HashMap<String, String>>,
                      headers: HeaderMap,
                      axum::Json(frame): axum::Json<Value>| {
                    let (streams, seen) = (post_streams.clone(), post_seen.clone());
                    let lists = Arc::clone(&lists);
                    if headers.contains_key(START_MARKER) {
                        post_marker.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    let post_log = Arc::clone(&post_log);
                    async move {
                        let session: u32 = q["session_id"].parse().expect("session");
                        post_log.lock().expect("posts").push((
                            session,
                            frame["method"].as_str().unwrap_or_default().to_owned(),
                        ));
                        seen.lock()
                            .expect("seen")
                            .push(("POST", session, authorization(&headers)));
                        if let Some(id) = frame.get("id") {
                            let first_list = frame["method"] == "tools/list"
                                && lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                            let answer = if first_list && matches!(expiry, Expiry::FirstList) {
                                json!({"jsonrpc": "2.0", "id": id,
                                       "error": {"code": -32015, "message": "session not found"}})
                            } else if frame["method"] == "initialize" {
                                json!({"jsonrpc": "2.0", "id": id, "result":
                                       {"protocolVersion": "2024-11-05", "capabilities": {},
                                        "serverInfo": {"name": "lent-reopen", "version": "1"}}})
                            } else {
                                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})
                            };
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
    Peer {
        url,
        seen,
        streams,
        posts,
        marker_sent,
    }
}

fn subscriber() -> Vec<(String, String)> {
    vec![("Authorization".to_owned(), "Bearer subscriber".to_owned())]
}

/// The subscriber's credential with a send check that always passes.
fn checked() -> LentCredential {
    LentCredential {
        headers: subscriber().into(),
        check: Some(Arc::new(|| Box::pin(async { Ok(()) }))),
    }
}

#[tokio::test]
async fn a_dropped_legacy_stream_reopens_as_the_next_caller_before_its_post() {
    let (url, seen, streams) = recording_peer().await;
    let mut statics = HashMap::new();
    statics.insert(
        "Authorization".to_owned(),
        "Bearer gateway-owned".to_owned(),
    );
    let transport =
        HttpTransport::new(&url, statics, Duration::from_secs(10), false).expect("transport");
    let lender = Arc::new(Lender::default());
    transport.mark_per_user_slot(SlotCredential::LentOnly, Arc::clone(&lender));
    let _loan = lender.lend(checked());
    let call = |id: &'static str| {
        let transport = Arc::clone(&transport);
        async move {
            transport
                .request_with_headers(
                    "tools/list",
                    None,
                    &subscriber(),
                    None,
                    ResendPermission::Denied,
                )
                .await
                .unwrap_or_else(|e| panic!("call {id}: {e}"))
        }
    };

    transport
        .initialize_as(&subscriber())
        .await
        .expect("start as the subscriber");
    call("first").await;
    streams.lock().expect("streams").insert(1, None);
    wait_closed(&transport).await;
    let before_reopen = seen.lock().expect("seen").len();
    call("after the drop").await;

    let seen = seen.lock().expect("seen").clone();
    assert!(
        seen.iter().all(|(_, _, auth)| auth == "Bearer subscriber"),
        "a request went out other than as the subscriber: {seen:?}"
    );
    let after: Vec<_> = seen[before_reopen..]
        .iter()
        .map(|(kind, session, _)| (*kind, *session))
        .collect();
    assert_eq!(
        after.first(),
        Some(&("GET", 2)),
        "the next call reopens the stream before anything else: {seen:?}"
    );
    assert!(
        after
            .iter()
            .skip(1)
            .all(|&(kind, session)| kind == "POST" && session == 2)
            && after.len() > 1,
        "the call posts on the reopened stream only: {seen:?}"
    );
}

/// A session that expires under a call is healed by a re-handshake inside
/// that call: on a legacy SSE peer the new stream opens as the call's
/// credential, and the call is resent and answered.
#[tokio::test]
async fn a_session_expiry_reopens_the_legacy_stream_as_the_call() {
    let Peer {
        url,
        seen,
        posts,
        marker_sent,
        ..
    } = peer(Expiry::FirstList).await;
    let transport = HttpTransport::new(&url, HashMap::new(), Duration::from_secs(10), false)
        .expect("transport");
    let lender = Arc::new(Lender::default());
    transport.mark_per_user_slot(SlotCredential::LentOnly, Arc::clone(&lender));
    let loan = lender.lend(checked());

    // The slot's own start, as a dispatch's start runs it: its sends carry
    // the start marker, resolved to this loan at each send.
    {
        let _starting = lender.starting(loan.id());
        transport
            .initialize()
            .await
            .expect("start as the subscriber");
    }
    let answered = transport
        .request_with_headers(
            "tools/list",
            None,
            &subscriber(),
            None,
            ResendPermission::Permitted,
        )
        .await;

    let seen = seen.lock().expect("seen").clone();
    assert!(
        answered.as_ref().is_ok_and(|r| r.error.is_none()),
        "the expired call was not healed and answered: {answered:?} {seen:?}"
    );
    assert!(
        seen.contains(&("GET", 2, "Bearer subscriber".to_owned())),
        "the re-handshake did not reopen the stream as the call: {seen:?}"
    );
    assert!(
        seen.iter().all(|(_, _, auth)| auth == "Bearer subscriber"),
        "a request went out other than as the subscriber: {seen:?}"
    );
    let posts = posts.lock().expect("posts").clone();
    let on_second: Vec<&str> = posts
        .iter()
        .filter(|(session, _)| *session == 2)
        .map(|(_, method)| method.as_str())
        .collect();
    assert!(
        on_second.first() == Some(&"initialize") && on_second.last() == Some(&"tools/list"),
        "the call was not re-handshaken and resent on the new session: {posts:?}"
    );
    assert!(
        !marker_sent.load(std::sync::atomic::Ordering::SeqCst),
        "the start marker reached the wire"
    );
}
