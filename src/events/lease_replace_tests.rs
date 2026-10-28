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
    std::fs::read_dir(f.dir.path().join("outbox"))
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

/// Fan out the next occurrence the listener queued, as the hub's dispatcher
/// does (the fixture starts none): `false` once the hang guard runs out.
async fn fan_out_next(
    f: &Fixture,
    intake: &mut tokio::sync::mpsc::Receiver<crate::events::fanout::SourceEvent>,
) -> bool {
    let Ok(Some(event)) =
        tokio::time::timeout(std::time::Duration::from_secs(30), intake.recv()).await
    else {
        return false;
    };
    let services = Arc::clone(f.hub.runtime.services.get().expect("services"));
    f.hub.fan_out(&services, &event).await;
    true
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
    // Two connections, so the peer may see the close and the open in either
    // order; the listener ends the old session before it opens the new.
    let mut after = vec![peer.next().await, peer.next().await];
    after.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        after,
        [Some(Stream::Closed(0)), Some(Stream::Opened(1))],
        "the replace closes the old session and reopens under the new token"
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
    let mut intake = f.hub.take_intake();
    // Premise: a notice on this stream becomes one record, stamped with the
    // lease it was read under.
    let wide_stamp = stamp_now(&f);
    assert!(
        peer.push_tools_changed(0),
        "premise: the wide stream is open"
    );
    assert!(
        fan_out_next(&f, &mut intake).await,
        "premise: the notice was queued"
    );
    assert_eq!(
        outbox_stamps(&f),
        [Some(wide_stamp.clone())],
        "premise: the notice became one record, stamped as read"
    );
    lease_as(&f, &handle, narrow).await;
    let narrow_stamp = stamp_now(&f);
    assert_ne!(
        narrow_stamp, wide_stamp,
        "premise: the replace moved the generation"
    );
    // Whatever the old stream still yields must not carry the narrow token's
    // generation. A replace that closed it leaves nothing to read.
    // Either the replace closed the old stream (a push to it fails, as its
    // body is gone), or it is still open and what it yields must be read and
    // checked: a push that reached nothing would make this row prove nothing.
    if peer.push_tools_changed(0) {
        assert!(
            fan_out_next(&f, &mut intake).await,
            "the old stream took the notice but nothing was read from it"
        );
    }
    let stamps = outbox_stamps(&f);
    assert!(
        !stamps.contains(&Some(narrow_stamp)),
        "a notice read under the wide token was stamped with the narrow one: {stamps:?}"
    );
}

/// LEASE-T2b, the stamp at fan-out: a notice read under the wide token and
/// still queued when the lease is replaced keeps the wide token's stamp, so
/// delivery, which reads the narrow lease, never sends it as the narrow's.
/// Independent of when the old stream closes.
#[tokio::test]
async fn lease_t2b_a_queued_notice_keeps_the_stamp_it_was_read_under() {
    let (wide, narrow) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([wide.to_string(), narrow.to_string()]).await;
    let (f, handle, _listening) = leased_listener(&mut peer, wide).await;
    let mut intake = f.hub.take_intake();
    let wide_stamp = stamp_now(&f);
    assert!(
        peer.push_tools_changed(0),
        "premise: the wide stream is open"
    );
    let read = tokio::time::timeout(std::time::Duration::from_secs(30), intake.recv())
        .await
        .ok()
        .flatten()
        .expect("premise: the notice was queued");
    lease_as(&f, &handle, narrow).await;
    assert_ne!(
        stamp_now(&f),
        wide_stamp,
        "premise: the replace moved the generation"
    );
    let services = Arc::clone(f.hub.runtime.services.get().expect("services"));
    f.hub.fan_out(&services, &read).await;
    assert_eq!(
        outbox_stamps(&f),
        [Some(wide_stamp)],
        "stamped as read, never as the narrow lease"
    );
}

/// A passthrough row's stamp at fan-out comes only from a fence marked as a
/// leased run's; any other fence stamps no lease, so delivery buries it. Only
/// no fence (delivery, replay) reads the lease held now.
#[tokio::test]
async fn a_passthrough_stamp_comes_only_from_a_leased_runs_fence() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    lease_as(&f, &handle, token(Some(in_an_hour()))).await;
    let row = f
        .hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name.starts_with("backend.pt."))
        .expect("row");
    let lease_of = |fence: Option<&str>| {
        f.hub
            .observed_now(&row, &f.config, fence)
            .expect("observable")
            .expect("per-user")
            .lease
    };
    assert_eq!(
        lease_of(None),
        Some(stamp_now(&f)),
        "no fence: the lease held now"
    );
    let stamp = "0123456789abcdef0123456789abcdef";
    assert_eq!(
        lease_of(Some(format!("lease:{stamp}").as_str())),
        Some(stamp.to_owned()),
        "a leased run's own generation"
    );
    for malformed in [
        "lease:00ab",
        "lease:0123456789ABCDEF0123456789ABCDEF",
        "lease:",
    ] {
        assert_eq!(
            lease_of(Some(malformed)),
            None,
            "{malformed}: not a generation"
        );
    }
    assert_eq!(
        lease_of(Some("binding-7")),
        None,
        "an unmarked fence names no lease"
    );
}
