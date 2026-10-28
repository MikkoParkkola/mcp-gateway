// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lease replace on a listener that is already running: the session open
//! under the old token closes and reopens under the new one, and nothing read
//! under the old token is delivered as observed under the new.

use super::*;

/// A stream a two-token peer opened or saw closed, by the index of the token
/// it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Opened(usize),
    Closed(usize),
}

/// Reports its stream closed when the peer drops the response body, which it
/// does when the client goes away.
struct OnClose(tokio::sync::mpsc::UnboundedSender<Stream>, usize);

impl Drop for OnClose {
    fn drop(&mut self) {
        let _ = self.0.send(Stream::Closed(self.1));
    }
}

/// A legacy Streamable HTTP peer at `/mcp` serving either of two tokens and
/// nothing else: it reports each session stream it opens and sees closed,
/// and lets a test push a frame down the open stream of either token.
struct TwoTokenPeer {
    url: String,
    streams: tokio::sync::mpsc::UnboundedReceiver<Stream>,
    pushes: Arc<std::sync::Mutex<[Option<tokio::sync::mpsc::UnboundedSender<String>>; 2]>>,
}

impl TwoTokenPeer {
    /// The next stream report, or `None` once the hang guard runs out.
    async fn next(&mut self) -> Option<Stream> {
        tokio::time::timeout(std::time::Duration::from_secs(30), self.streams.recv())
            .await
            .ok()
            .flatten()
    }

    /// Push a `tools/list_changed` notice down token `index`'s open stream:
    /// `false` when that stream is closed.
    fn push_tools_changed(&self, index: usize) -> bool {
        let frame =
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";
        self.pushes.lock().expect("pushes")[index]
            .as_ref()
            .is_some_and(|push| push.send(frame.to_owned()).is_ok())
    }
}

async fn two_token_peer(tokens: [String; 2]) -> TwoTokenPeer {
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    let (report, streams) = tokio::sync::mpsc::unbounded_channel();
    let pushes: TwoTokenPeer = TwoTokenPeer {
        url: String::new(),
        streams,
        pushes: Arc::default(),
    };
    let tokens = Arc::new(tokens);
    let which = move |h: &HeaderMap| {
        let presented = h.get("authorization").and_then(|v| v.to_str().ok());
        tokens.iter().position(|t| Some(t.as_str()) == presented)
    };
    let get_which = which.clone();
    let get_pushes = Arc::clone(&pushes.pushes);
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::get(move |headers: HeaderMap| async move {
            let Some(index) = get_which(&headers) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
            let (push, mut frames) = tokio::sync::mpsc::unbounded_channel::<String>();
            get_pushes.lock().expect("pushes")[index] = Some(push);
            let _ = report.send(Stream::Opened(index));
            let closed = OnClose(report.clone(), index);
            let body = async_stream::stream! {
                let _closed = closed;
                yield Ok::<_, std::io::Error>(": open\n\n".to_owned());
                while let Some(frame) = frames.recv().await {
                    yield Ok(frame);
                }
            };
            (
                [("content-type", "text/event-stream")],
                axum::body::Body::from_stream(body),
            )
                .into_response()
        })
        .post(
            move |headers: HeaderMap, axum::Json(frame): axum::Json<serde_json::Value>| async move {
                if which(&headers).is_none() {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let method = frame["method"].as_str().unwrap_or_default().to_owned();
                let Some(id) = frame.get("id") else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let answer = if method == "server/discover" {
                    json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": "not found"}})
                } else {
                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                };
                ([("mcp-session-id", "s-1")], axum::Json(answer)).into_response()
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
    TwoTokenPeer { url, ..pushes }
}

/// The lease stamp of every record in `f`'s outbox.
fn outbox_stamps(f: &Fixture) -> Vec<Option<String>> {
    std::fs::read_dir(f._dir.path().join("outbox"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| {
                    let record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(e.path()).expect("read"))
                            .expect("record");
                    record["observed"]["lease"].as_str().map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Wait until `f`'s outbox holds `count` records, or the hang guard runs out.
async fn outbox_reaches(f: &Fixture, count: usize) -> Vec<Option<String>> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let stamps = outbox_stamps(f);
        if stamps.len() >= count || tokio::time::Instant::now() >= deadline {
            return stamps;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// `p`'s current lease generation on `pt`, as a record stamps it.
fn stamp_now(f: &Fixture) -> String {
    let generation = f
        .hub
        .leases
        .held_generation(&lease_key(f, "p"))
        .expect("held");
    format!("{generation:032x}")
}

/// A per-user passthrough listener on `peer`, leased with `first`.
async fn leased_listener(
    peer: &mut TwoTokenPeer,
    first: Zeroizing<String>,
) -> (Fixture, String, ListenersAndBackend) {
    let f = fixture_with(&format!(
        "backends:\n  pt:\n    http_url: {}\n    streamable_http: true\n    \
         identity_propagation:\n      \
         strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n",
        peer.url
    ));
    let handle = subscribe(&f, "p", "pt", "p");
    let listening = parked_listener(&f).await;
    lease_as(&f, &handle, first).await;
    assert_eq!(
        peer.next().await,
        Some(Stream::Opened(0)),
        "premise: the listener opened its stream under the first token"
    );
    (f, handle, listening)
}

async fn lease_as(f: &Fixture, handle: &str, token: Zeroizing<String>) {
    f.hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token),
        )
        .await
        .expect("leased");
}

/// LEASE-T2b (design §3.5): a replace closes the session the listener opened
/// under the old token, and opens a new one under the new token, before
/// anything is emitted. Its notice, debounce and coalescer state live in the
/// session, so they go with the old one.
#[tokio::test]
async fn lease_t2b_a_replace_reopens_the_session_under_the_new_token() {
    let (first, second) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    assert_ne!(*first, *second, "premise: two different tokens");
    let mut peer = two_token_peer([first.to_string(), second.to_string()]).await;
    let (f, handle, _listening) = leased_listener(&mut peer, first).await;
    lease_as(&f, &handle, second).await;
    let after = [peer.next().await, peer.next().await];
    assert_eq!(
        after,
        [Some(Stream::Closed(0)), Some(Stream::Opened(1))],
        "the replace closes the old session, then reopens under the new token"
    );
}

/// LEASE-T2b, scope: a replace may narrow what the subscriber granted (a
/// token with fewer scopes, or one replacing a compromised token). A notice
/// read on the old token's stream after the replace is never delivered as
/// observed under the new token's generation.
#[tokio::test]
async fn lease_t2b_a_notice_read_under_the_old_token_is_never_stamped_with_the_new() {
    let (wide, narrow) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    assert_ne!(*wide, *narrow, "premise: two different tokens");
    let mut peer = two_token_peer([wide.to_string(), narrow.to_string()]).await;
    let (f, handle, _listening) = leased_listener(&mut peer, wide).await;
    // Premise: a notice on this stream produces a record, stamped with the
    // lease it was read under.
    let wide_stamp = stamp_now(&f);
    assert!(
        peer.push_tools_changed(0),
        "premise: the wide stream is open"
    );
    assert_eq!(
        outbox_reaches(&f, 1).await,
        [Some(wide_stamp.clone())],
        "premise: the notice became one record, stamped as read"
    );
    lease_as(&f, &handle, narrow).await;
    let narrow_stamp = stamp_now(&f);
    assert_ne!(
        narrow_stamp, wide_stamp,
        "premise: the replace moved the generation"
    );
    if peer.push_tools_changed(0) {
        // The old stream is still open: whatever it now yields must not
        // carry the narrow token's generation.
        let stamps = outbox_reaches(&f, 2).await;
        assert!(
            !stamps.contains(&Some(narrow_stamp)),
            "a notice read under the wide token was stamped with the narrow one: {stamps:?}"
        );
    }
}
