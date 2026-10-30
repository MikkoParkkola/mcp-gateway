// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Listener session rows (MIK-8835.SSE.1, SSE.4): the handshake order on a
//! spec-shaped peer (answers on the stream), and the credential seam C1, C2
//! and C5.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::super::HttpTransport;
use crate::transport::upstream_tap::{
    CredentialSource, CredentialedSend, LegacyPin, ListenerCredential, UpstreamListen, Watched,
};

/// What the peer saw: `(request, x-cred header)`, in order.
type Log = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A one-session spec SSE peer: `GET /sse` names `/messages` and keeps the
/// stream; each POST is answered 202 with its response on the stream, except
/// `resources/unsubscribe`, which is refused with HTTP 500.
async fn peer() -> (String, Log) {
    let log: Log = Arc::default();
    let stream: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>> = Arc::default();
    let (get_log, get_stream) = (Arc::clone(&log), Arc::clone(&stream));
    let (post_log, post_stream) = (Arc::clone(&log), Arc::clone(&stream));
    let cred = |h: &HeaderMap| {
        h.get("x-cred")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::get(move |headers: HeaderMap| {
                let (log, stream) = (Arc::clone(&get_log), Arc::clone(&get_stream));
                async move {
                    log.lock().expect("log").push(("GET".to_owned(), cred(&headers)));
                    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                    *stream.lock().expect("stream") = Some(tx);
                    let body = async_stream::stream! {
                        yield Ok::<_, std::io::Error>("event: endpoint\ndata: /messages\n\n".to_owned());
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
            axum::routing::post(move |headers: HeaderMap, axum::Json(frame): axum::Json<Value>| {
                let (log, stream) = (Arc::clone(&post_log), Arc::clone(&post_stream));
                async move {
                    let method = frame["method"].as_str().unwrap_or_default().to_owned();
                    log.lock().expect("log").push((method.clone(), cred(&headers)));
                    // A refusal to answer as an error status (the request row).
                    if method == "resources/unsubscribe" {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    if let Some(id) = frame.get("id") {
                        let answer = json!({"jsonrpc": "2.0", "id": id, "result": {}});
                        if let Some(tx) = stream.lock().expect("stream").as_ref() {
                            let _ = tx.send(answer.to_string());
                        }
                    }
                    StatusCode::ACCEPTED.into_response()
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
    (url, log)
}

/// Lends `x-cred: v<n>` to each send, refusing from the `refuse_from`th on.
struct Counting {
    calls: AtomicUsize,
    refuse_from: usize,
}

impl CredentialSource for Counting {
    fn with_credential<'a>(
        &'a self,
        send: CredentialedSend<'a>,
    ) -> BoxFuture<'a, crate::Result<reqwest::Response>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n >= self.refuse_from {
                return Err(crate::Error::Transport("credential withdrawn".to_owned()));
            }
            send(vec![("x-cred".to_owned(), format!("v{n}"))].into()).await
        })
    }

    fn identity_key(&self) -> Option<&str> {
        None
    }
}

/// The session and the transport it holds weakly, which the row keeps alive.
fn session(
    url: &str,
    refuse_from: Option<usize>,
) -> (Arc<HttpTransport>, Arc<super::SseListenSession>) {
    let transport =
        HttpTransport::new(url, HashMap::new(), Duration::from_secs(5), false).expect("transport");
    let credential = ListenerCredential {
        identity_key: None,
        source: refuse_from.map(|refuse_from| {
            let source: Arc<dyn CredentialSource> = Arc::new(Counting {
                calls: AtomicUsize::new(0),
                refuse_from,
            });
            source
        }),
    };
    let session = Arc::new(transport.sse_listen_session(credential));
    (transport, session)
}

fn methods(log: &Log) -> Vec<String> {
    log.lock()
        .expect("log")
        .iter()
        .map(|(m, _)| m.clone())
        .collect()
}

/// S2 at unit level: GET, initialize (answered only on the stream),
/// initialized; then a subscribe on the same session.
#[tokio::test]
async fn the_handshake_runs_in_order_on_a_spec_peer() {
    let (url, log) = peer().await;
    let (_transport, session) = session(&url, None);
    let _stream = Arc::clone(&session)
        .unsolicited(Watched::default())
        .await
        .map_err(|_| "refused")
        .expect("handshake");
    Arc::clone(&session)
        .legacy_interest(LegacyPin::default(), "file:///a", true)
        .await
        .expect("subscribe answered on the stream");
    assert_eq!(
        methods(&log),
        [
            "GET",
            "initialize",
            "notifications/initialized",
            "resources/subscribe"
        ]
    );
}

/// C1: every request carries the credential, minted per request.
#[tokio::test]
async fn c1_every_request_carries_a_fresh_credential() {
    let (url, log) = peer().await;
    let (_transport, session) = session(&url, Some(usize::MAX));
    let _stream = Arc::clone(&session)
        .unsolicited(Watched::default())
        .await
        .map_err(|_| "refused")
        .expect("handshake");
    Arc::clone(&session)
        .legacy_interest(LegacyPin::default(), "file:///a", true)
        .await
        .expect("subscribe");
    let creds: Vec<Option<String>> = log
        .lock()
        .expect("log")
        .iter()
        .map(|(_, c)| c.clone())
        .collect();
    assert_eq!(
        creds,
        [Some("v0"), Some("v1"), Some("v2"), Some("v3")].map(|c| c.map(str::to_owned))
    );
}

/// C2: a source that refuses sends nothing.
#[tokio::test]
async fn c2_a_refusing_source_sends_nothing() {
    let (url, log) = peer().await;
    let (_transport, session) = session(&url, Some(0));
    assert!(
        Arc::clone(&session)
            .unsolicited(Watched::default())
            .await
            .is_err()
    );
    assert!(
        log.lock().expect("log").is_empty(),
        "no request reached the peer"
    );
}

/// C5: the source lends the GET and the handshake, then refuses: the next
/// POST is not sent and fails, and the stream is unchanged.
#[tokio::test]
async fn c5_a_later_refusal_sends_nothing_more() {
    let (url, log) = peer().await;
    let (_transport, session) = session(&url, Some(3));
    let _stream = Arc::clone(&session)
        .unsolicited(Watched::default())
        .await
        .map_err(|_| "refused")
        .expect("handshake");
    assert!(
        Arc::clone(&session)
            .legacy_interest(LegacyPin::default(), "file:///a", true)
            .await
            .is_err()
    );
    assert_eq!(
        methods(&log),
        ["GET", "initialize", "notifications/initialized"]
    );
    assert!(session.channel().is_ok(), "the stream is still up");
}

/// A listener request the peer refuses with an error status fails with that
/// status named, and nothing waits on the stream for it.
#[tokio::test]
async fn a_refused_listener_request_names_the_status() {
    let (url, _log) = peer().await;
    let (_transport, session) = session(&url, None);
    let _stream = Arc::clone(&session)
        .unsolicited(Watched::default())
        .await
        .map_err(|_| "refused")
        .expect("handshake");
    let refused = Arc::clone(&session)
        .legacy_interest(LegacyPin::default(), "file:///a", false)
        .await
        .expect_err("a 500 is an error");
    assert!(
        refused.to_string().contains("returned HTTP 500"),
        "names the status: {refused}"
    );
}
