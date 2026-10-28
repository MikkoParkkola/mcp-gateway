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
    let seen: Seen = Arc::default();
    let streams: Streams = Arc::default();
    let (get_streams, post_streams) = (streams.clone(), streams.clone());
    let (get_seen, post_seen) = (seen.clone(), seen.clone());
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::get(move |headers: HeaderMap| {
                let (streams, seen) = (get_streams.clone(), get_seen.clone());
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
                    async move {
                        let session: u32 = q["session_id"].parse().expect("session");
                        seen.lock()
                            .expect("seen")
                            .push(("POST", session, authorization(&headers)));
                        if let Some(id) = frame.get("id") {
                            let result = if frame["method"] == "initialize" {
                                json!({"protocolVersion": "2024-11-05", "capabilities": {},
                                       "serverInfo": {"name": "lent-reopen", "version": "1"}})
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
    (url, seen, streams)
}

fn subscriber() -> Vec<(String, String)> {
    vec![("Authorization".to_owned(), "Bearer subscriber".to_owned())]
}

/// The subscriber's credential with a send check that always passes.
fn checked() -> LentCredential {
    LentCredential {
        headers: subscriber(),
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
