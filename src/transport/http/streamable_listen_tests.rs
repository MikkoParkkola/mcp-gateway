// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Streamable HTTP: a per-user listener's own session
//! handshakes, listens and subscribes with its subscriber's credential on
//! its own session bucket, and sends nothing of the gateway's.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures::future::BoxFuture;
use serde_json::{Value, json};

use super::super::HttpTransport;
use crate::transport::upstream_tap::{
    CredentialSource, CredentialedSend, LegacyPin, ListenerCredential, UpstreamListen, Watched,
};

/// What the peer saw: `(request, x-cred, x-static, mcp-session-id)`.
type Seen = (String, Option<String>, Option<String>, Option<String>);
type Log = Arc<Mutex<Vec<Seen>>>;

/// A stateful Streamable HTTP peer at `/mcp`: `initialize` answers JSON and
/// mints session `s-1`; the GET is a held event stream.
async fn peer() -> (String, Log) {
    peer_answering(json!({})).await
}

/// [`peer`], answering every request with `result`.
async fn peer_answering(result: Value) -> (String, Log) {
    let log: Log = Arc::default();
    let header =
        |h: &HeaderMap, name: &str| h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let seen = move |method: &str, h: &HeaderMap| -> Seen {
        (
            method.to_owned(),
            header(h, "x-cred"),
            header(h, "x-static"),
            header(h, "mcp-session-id"),
        )
    };
    let (get_log, post_log) = (Arc::clone(&log), Arc::clone(&log));
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::get(move |headers: HeaderMap| {
            let log = Arc::clone(&get_log);
            async move {
                log.lock().expect("log").push(seen("GET", &headers));
                let body = async_stream::stream! {
                    yield Ok::<_, std::io::Error>(": open\n\n".to_owned());
                    std::future::pending::<()>().await;
                };
                (
                    [("content-type", "text/event-stream")],
                    axum::body::Body::from_stream(body),
                )
                    .into_response()
            }
        })
        .post(
            move |headers: HeaderMap, axum::Json(frame): axum::Json<Value>| {
                let log = Arc::clone(&post_log);
                let result = result.clone();
                async move {
                    let method = frame["method"].as_str().unwrap_or_default().to_owned();
                    log.lock().expect("log").push(seen(&method, &headers));
                    let Some(id) = frame.get("id") else {
                        return StatusCode::ACCEPTED.into_response();
                    };
                    let answer = json!({"jsonrpc": "2.0", "id": id, "result": result});
                    ([("mcp-session-id", "s-1")], axum::Json(answer)).into_response()
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, log)
}

/// Lends `x-cred: v<n>` to each send.
struct Counting(AtomicUsize);

impl CredentialSource for Counting {
    fn with_credential<'a>(
        &'a self,
        send: CredentialedSend<'a>,
    ) -> BoxFuture<'a, crate::Result<reqwest::Response>> {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { send(vec![("x-cred".to_owned(), format!("v{n}"))].into()).await })
    }

    fn identity_key(&self) -> Option<&str> {
        Some("idp:p")
    }
}

fn transport(url: &str) -> Arc<HttpTransport> {
    let statics = HashMap::from([("X-Static".to_owned(), "gateway-key".to_owned())]);
    let t = HttpTransport::new(url, statics, Duration::from_secs(5), false).expect("transport");
    t.set_detected(Some(true));
    t
}

fn lent() -> ListenerCredential {
    let source: Arc<dyn CredentialSource> = Arc::new(Counting(AtomicUsize::new(0)));
    ListenerCredential {
        identity_key: Some("idp:p".to_owned()),
        source: Some(source),
    }
}

#[tokio::test]
async fn d7_a_per_user_listener_gets_its_own_streamable_session() {
    let (url, _log) = peer().await;
    let t = transport(&url);
    assert!(t.per_user_session("b", lent()).await.is_some());
    assert!(
        t.per_user_session("b", ListenerCredential::shared())
            .await
            .is_none(),
        "nothing to lend, no session"
    );
    assert!(
        Arc::clone(&t)
            .own_session(ListenerCredential::shared())
            .is_none(),
        "the shared listener uses the transport itself"
    );
}

/// D7 + C6: the era probe, initialize, initialized, the session GET and a
/// subscribe all carry a fresh lent credential, and all after the handshake
/// the subscriber's own session, never the operator's static header; the
/// shared bucket gets no session. A probe answer naming no modern version is
/// legacy, so the session handshakes.
#[tokio::test]
async fn d7_every_request_is_the_subscribers_on_their_own_session() {
    let (url, log) = peer().await;
    let t = transport(&url);
    let (session, era) = t.per_user_session("b", lent()).await.expect("own session");
    assert_eq!(era, crate::protocol::era::PeerEra::Legacy);
    let _stream = Arc::clone(&session)
        .unsolicited(Watched::default())
        .await
        .map_err(|_| "refused")
        .expect("opened");
    Arc::clone(&session)
        .legacy_interest(LegacyPin::default(), "file:///a", true)
        .await
        .expect("subscribed");
    let seen = log.lock().expect("log").clone();
    let methods: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
    assert_eq!(
        methods,
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "GET",
            "resources/subscribe"
        ]
    );
    for (method, cred, statics, _) in &seen {
        assert!(cred.is_some(), "{method}: the subscriber's credential");
        assert!(statics.is_none(), "{method}: no gateway header");
    }
    for (method, _, _, session) in &seen[2..] {
        assert_eq!(session.as_deref(), Some("s-1"), "{method}: their session");
    }
    let sessions = t.sessions.read();
    assert_eq!(
        sessions
            .get(HttpTransport::bucket_key(Some("idp:p")))
            .map(String::as_str),
        Some("s-1")
    );
    assert!(
        !sessions.contains_key(HttpTransport::bucket_key(None)),
        "the shared bucket is untouched"
    );
}

/// A backend configured for the SSE handshake gets a legacy SSE session: no
/// era probe is sent, and nothing reaches the peer until the session opens.
#[tokio::test]
async fn a_per_user_listener_on_an_sse_backend_is_legacy_and_sends_nothing_yet() {
    let (url, log) = peer().await;
    let statics = HashMap::from([("X-Static".to_owned(), "gateway-key".to_owned())]);
    let t = HttpTransport::new(&url, statics, Duration::from_secs(5), false).expect("transport");
    let (session, era) = t.per_user_session("b", lent()).await.expect("own session");
    assert_eq!(era, crate::protocol::era::PeerEra::Legacy);
    assert_eq!(
        session.detected_streamable(),
        Some(false),
        "the SSE session"
    );
    assert!(log.lock().expect("log").is_empty(), "no probe on SSE");
}

/// A handshake whose selected version is refused leaves no session behind:
/// the next call sends `initialize` again instead of speaking on the
/// session that answer minted.
#[tokio::test]
async fn a_refused_version_selection_is_not_reused_by_the_next_call() {
    let (url, log) = peer_answering(json!({"protocolVersion": "1999-01-01"})).await;
    let t = transport(&url);
    let (session, _) = t.per_user_session("b", lent()).await.expect("own session");
    for _ in 0..2 {
        assert!(
            Arc::clone(&session)
                .legacy_interest(LegacyPin::default(), "file:///a", true)
                .await
                .is_err(),
            "a refused selection fails the call"
        );
    }
    let seen = log.lock().expect("log").clone();
    let methods: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
    assert_eq!(
        methods,
        ["server/discover", "initialize", "initialize"],
        "{seen:?}"
    );
    assert!(
        !t.sessions
            .read()
            .contains_key(HttpTransport::bucket_key(Some("idp:p"))),
        "no session kept"
    );
}
