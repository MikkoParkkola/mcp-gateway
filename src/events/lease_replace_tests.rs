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
    /// A stream the peer refused, per [`TwoTokenPeer::refuse_stream`].
    Refused(usize),
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
    wire: Wire,
    streams: tokio::sync::mpsc::UnboundedReceiver<Stream>,
    pushes: Arc<std::sync::Mutex<[Option<tokio::sync::mpsc::UnboundedSender<String>>; 2]>>,
    /// A status the legacy `GET` stream of each token is refused with; `0`
    /// serves it.
    refuse_stream: Arc<[std::sync::atomic::AtomicU16; 2]>,
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

/// How a two-token peer talks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    /// Legacy Streamable HTTP: `initialize`, then a session `GET` stream.
    Legacy,
    /// Modern Streamable HTTP: `server/discover`, then a
    /// `subscriptions/listen` stream.
    Modern,
    /// The HTTP+SSE handshake: a `GET` stream that names where to post, and
    /// carries every answer.
    SseHandshake,
}

async fn two_token_peer(tokens: [String; 2]) -> TwoTokenPeer {
    two_token_peer_in(Wire::Legacy, tokens).await
}

/// The peer's half of an open stream for token `index`: registers its push
/// sender, reports it opened, and reports it closed once the body drops.
/// `first` is written before any pushed frame.
fn open_stream(
    report: &tokio::sync::mpsc::UnboundedSender<Stream>,
    pushes: &std::sync::Mutex<[Option<tokio::sync::mpsc::UnboundedSender<String>>; 2]>,
    index: usize,
    first: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (push, mut frames) = tokio::sync::mpsc::unbounded_channel::<String>();
    pushes.lock().expect("pushes")[index] = Some(push);
    let _ = report.send(Stream::Opened(index));
    let closed = OnClose(report.clone(), index);
    let body = async_stream::stream! {
        let _closed = closed;
        yield Ok::<_, std::io::Error>(first);
        while let Some(frame) = frames.recv().await {
            yield Ok(frame);
        }
    };
    (
        [("content-type", "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

async fn two_token_peer_in(wire: Wire, tokens: [String; 2]) -> TwoTokenPeer {
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    let (report, streams) = tokio::sync::mpsc::unbounded_channel();
    let pushes: TwoTokenPeer = TwoTokenPeer {
        url: String::new(),
        wire,
        streams,
        pushes: Arc::default(),
        refuse_stream: Arc::default(),
    };
    let tokens = Arc::new(tokens);
    let which = move |h: &HeaderMap| {
        let presented = h.get("authorization").and_then(|v| v.to_str().ok());
        tokens.iter().position(|t| Some(t.as_str()) == presented)
    };
    let get_which = which.clone();
    let (get_report, get_pushes) = (report.clone(), Arc::clone(&pushes.pushes));
    let get_refuse = Arc::clone(&pushes.refuse_stream);
    let post_pushes = Arc::clone(&pushes.pushes);
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::get(move |headers: HeaderMap| async move {
            let Some(index) = get_which(&headers) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
            if wire == Wire::Modern {
                // A modern peer has no session GET stream: an open reported
                // here can only come from `subscriptions/listen`.
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            let refused = get_refuse[index].load(std::sync::atomic::Ordering::SeqCst);
            if refused != 0 {
                let _ = get_report.send(Stream::Refused(index));
                return StatusCode::from_u16(refused)
                    .expect("status")
                    .into_response();
            }
            let first = if wire == Wire::SseHandshake {
                "event: endpoint\ndata: /mcp\n\n"
            } else {
                ": open\n\n"
            };
            open_stream(&get_report, &get_pushes, index, first.to_owned())
        })
        .post(
            move |headers: HeaderMap, axum::Json(frame): axum::Json<serde_json::Value>| async move {
                let Some(index) = which(&headers) else {
                    return StatusCode::UNAUTHORIZED.into_response();
                };
                let method = frame["method"].as_str().unwrap_or_default().to_owned();
                let Some(id) = frame.get("id") else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let answer = match (wire, method.as_str()) {
                    (Wire::Modern, "server/discover") => json!({"jsonrpc": "2.0", "id": id,
                        "result": {"resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {"tools": {"listChanged": true}},
                            "serverInfo": {"name": "peer", "version": "0"}}}),
                    (Wire::Modern, "subscriptions/listen") => {
                        let ack = json!({"jsonrpc": "2.0",
                            "method": "notifications/subscriptions/acknowledged",
                            "params": {"notifications": frame["params"]["notifications"],
                                "_meta": {"io.modelcontextprotocol/subscriptionId": id}}});
                        let first = format!("event: message\ndata: {ack}\n\n");
                        return open_stream(&report, &post_pushes, index, first);
                    }
                    (_, "server/discover") => json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": "not found"}}),
                    _ => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                };
                if wire == Wire::SseHandshake {
                    // Answered on the token's handshake stream, never inline.
                    let frame = format!("event: message\ndata: {answer}\n\n");
                    let sent = post_pushes.lock().expect("pushes")[index]
                        .as_ref()
                        .is_some_and(|push| push.send(frame).is_ok());
                    return if sent {
                        StatusCode::ACCEPTED
                    } else {
                        StatusCode::NOT_FOUND
                    }
                    .into_response();
                }
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

/// The subscription and lease stamp of every record in `f`'s outbox.
fn outbox_rows(f: &Fixture) -> Vec<(String, Option<String>)> {
    std::fs::read_dir(f.dir.path().join("outbox"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| {
                    let record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(e.path()).expect("read"))
                            .expect("record");
                    (
                        record["subscription_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        record["observed"]["lease"].as_str().map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The lease stamp of every record in `f`'s outbox.
fn outbox_stamps(f: &Fixture) -> Vec<Option<String>> {
    outbox_rows(f).into_iter().map(|(_, stamp)| stamp).collect()
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
    let f = listener_fixture(peer);
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

/// A hub whose `pt` is a per-user passthrough backend at `peer`.
fn listener_fixture(peer: &TwoTokenPeer) -> Fixture {
    fixture_with(&format!(
        "backends:\n  pt:\n    http_url: {}\n    streamable_http: {}\n    \
         identity_propagation:\n      \
         strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n",
        peer.url,
        peer.wire != Wire::SseHandshake,
    ))
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
    a_replace_reopens_under_the_new_token_on(Wire::Legacy).await;
}

/// The replace on a peer that talks `wire`: the old token's stream closes
/// and one opens under the new token.
async fn a_replace_reopens_under_the_new_token_on(wire: Wire) {
    let (first, second) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    assert_ne!(*first, *second, "premise: two different tokens");
    let mut peer = two_token_peer_in(wire, [first.to_string(), second.to_string()]).await;
    let (f, handle, _listening) = leased_listener(&mut peer, first).await;
    lease_as(&f, &handle, second).await;
    // Two connections, so the peer may see the close and the open in either
    // order; the listener ends the old session before it opens the new.
    let mut after = vec![peer.next().await, peer.next().await];
    after.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        after,
        [Some(Stream::Closed(0)), Some(Stream::Opened(1))],
        "{wire:?}: the replace closes the old session and reopens under the new token"
    );
}

/// The same replace on modern Streamable HTTP and on the HTTP+SSE
/// handshake, the other two ways a listener reaches its backend.
#[tokio::test]
async fn a_replace_reopens_a_modern_listen_stream_under_the_new_token() {
    a_replace_reopens_under_the_new_token_on(Wire::Modern).await;
}

#[tokio::test]
async fn a_replace_reopens_an_sse_handshake_under_the_new_token() {
    a_replace_reopens_under_the_new_token_on(Wire::SseHandshake).await;
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
    // The replace ends the session read under the wide token and reopens
    // under the narrow one; the peer sees both, in either order.
    let mut after = vec![peer.next().await, peer.next().await];
    after.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        after,
        [Some(Stream::Closed(0)), Some(Stream::Opened(1))],
        "premise: the replace reopened under the narrow token"
    );
    assert!(
        !peer.push_tools_changed(0),
        "the wide stream is gone: nothing more is read under the wide token"
    );
    // Control: a notice read under the narrow token is stamped as read.
    assert!(
        peer.push_tools_changed(1),
        "premise: the narrow stream is open"
    );
    assert!(
        fan_out_next(&f, &mut intake).await,
        "the narrow notice was read"
    );
    // The outbox is a directory, read in no set order.
    let mut stamps = outbox_stamps(&f);
    stamps.sort();
    let mut want = vec![Some(wide_stamp), Some(narrow_stamp)];
    want.sort();
    assert_eq!(
        stamps, want,
        "each notice carries the lease it was read under"
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

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// LEASE-T5: a lease is memory only. After a restart the subscription row is
/// still there and waits in "credential needed", and no file the store
/// wrote holds the token or its claims.
#[tokio::test]
async fn lease_t5_after_a_restart_the_row_needs_a_credential_and_no_file_holds_the_token() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let leased = token(Some(in_an_hour()));
    let secret = leased.to_string();
    let claims = secret.split('.').nth(1).expect("a JWT payload").to_owned();
    lease_as(&f, &handle, leased).await;
    let key = lease_key(&f, "p");
    assert!(
        f.hub.leases.held_generation(&key).is_some(),
        "premise: leased"
    );
    let Fixture { hub, dir, .. } = f;
    drop(hub);
    let reopened = EventsHub::open(&crate::config::EventsConfig::default(), dir.path())
        .expect("the store reopens");
    assert!(
        reopened
            .store
            .subscriptions()
            .iter()
            .any(|s| s.name == "backend.pt.tools_changed"),
        "premise: the row survives the restart"
    );
    assert_eq!(reopened.leases.held_generation(&key), None);
    assert_eq!(
        reopened.leases.state(&key).await,
        crate::events::lease::LeaseState::CredentialNeeded
    );
    let files = files_under(dir.path());
    assert!(
        !files.is_empty(),
        "premise: the scan reads the store's files"
    );
    for file in files {
        let bytes = std::fs::read(&file).expect("readable");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&secret) && !text.contains(&claims),
            "{} holds the leased token",
            file.display()
        );
    }
}

/// LEASE-T4 end to end: a backend that answers the leased token with 401
/// wipes the lease at once, through the listener's own send (not a direct
/// call), and the admin view shows the row's credential as rejected.
#[tokio::test]
async fn lease_t4_a_401_from_the_backend_wipes_the_lease_and_shows_it_rejected() {
    let (a, b) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([a.to_string(), b.to_string()]).await;
    let f = fixture_with(&format!(
        "backends:\n  pt:\n    http_url: {}\n    streamable_http: true\n    \
         identity_propagation:\n      \
         strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n",
        peer.url
    ));
    let handle = subscribe(&f, "p", "pt", "p");
    let _listening = parked_listener(&f).await;
    // A token the backend does not accept: its first request is refused.
    lease_as(&f, &handle, token(Some(in_an_hour() + 120))).await;
    let key = lease_key(&f, "p");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while f.hub.leases.state(&key).await != LeaseState::CredentialRejected
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        f.hub.leases.state(&key).await,
        LeaseState::CredentialRejected,
        "the backend's 401 wiped the lease"
    );
    assert_eq!(f.hub.leases.held_generation(&key), None);
    let listed = f.hub.list_leases().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["state"], "credential_rejected");
    assert!(
        peer.streams.try_recv().is_err(),
        "no stream opened under it"
    );
}

/// LEASE-T2, held lease: another principal's lease call on P's row is
/// refused and leaves P's held lease exactly as it was, the same generation.
#[tokio::test]
async fn lease_t2_another_principals_call_leaves_a_held_lease_untouched() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    lease_as(&f, &handle, token(Some(in_an_hour()))).await;
    let key = lease_key(&f, "p");
    let before = f
        .hub
        .leases
        .held_generation(&key)
        .expect("premise: p holds a lease");
    let refused = f
        .hub
        .lease(
            Some("q"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour() + 60))),
        )
        .await
        .expect_err("not q's row");
    assert_eq!(refused.code, -32012);
    assert_eq!(
        f.hub.leases.held_generation(&key),
        Some(before),
        "p's lease is untouched: same generation"
    );
}

/// LEASE-T2, listener half: two principals lease their own tokens on one
/// backend. Each listener presents only its own principal's token (the peer
/// tells the streams apart by the token they carry), and a notice read on
/// Q's stream reaches Q's row alone, stamped with Q's lease.
#[tokio::test]
async fn lease_t2_each_principals_listener_reads_with_its_own_token_only() {
    let (p_token, q_token) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([p_token.to_string(), q_token.to_string()]).await;
    let (f, _p_handle, _listening) = leased_listener(&mut peer, p_token).await;
    let q_handle = subscribe(&f, "q", "pt", "q");
    let q_key = lease_key(&f, "q");
    // Started as the hub starts a stored row, as `parked_listener` starts p.
    f.hub.replay_starts().await;
    f.hub
        .lease(
            Some("q"),
            "pt",
            Some(&json!({ "subscription": q_handle })),
            Some(q_token),
        )
        .await
        .expect("leased");
    assert_eq!(
        peer.next().await,
        Some(Stream::Opened(1)),
        "q's listener opened under q's token, never p's"
    );
    let mut intake = f.hub.take_intake();
    assert!(peer.push_tools_changed(1), "premise: q's stream is open");
    assert!(fan_out_next(&f, &mut intake).await, "q's notice was read");
    let q_stamp = crate::events::observation::lease_stamp(
        f.hub
            .leases
            .held_generation(&q_key)
            .expect("q holds a lease"),
    );
    assert_eq!(
        outbox_rows(&f),
        [("sub_q_pt".to_owned(), Some(q_stamp))],
        "q's notice reached q's row alone, under q's lease"
    );
}

/// ISO-T6 end to end: a subscriber who loses access is revoked by the sweep's
/// admission pass, and its listener's session on the backend closes though
/// the backend never sends a byte; nothing is read for it after.
#[tokio::test]
async fn iso_t6_a_revoked_subscribers_listener_closes_on_a_silent_backend() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let p_token = token(Some(in_an_hour()));
    let mut peer =
        two_token_peer([p_token.to_string(), token(Some(in_an_hour())).to_string()]).await;
    let (f, _handle, (listeners, _backend)) = leased_listener(&mut peer, p_token).await;
    let mut intake = f.hub.take_intake();
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    f.hub.revoke_inadmissible(None).await;
    assert!(f.hub.store.subscriptions().is_empty(), "premise: revoked");
    assert_eq!(
        peer.next().await,
        Some(Stream::Closed(0)),
        "the silent backend's session closed"
    );
    assert!(!peer.push_tools_changed(0), "no stream is left to read on");
    assert!(intake.try_recv().is_err(), "nothing was read for p");
    assert!(outbox_rows(&f).is_empty(), "nothing queued for p");
    assert!(
        listeners
            .entry_for(&crate::events::upstream_listener::ListenerKey {
                backend: "pt".into(),
                obs: Some(lease_key(&f, "p").obs),
            })
            .is_none(),
        "no listener is left for p to reconnect with"
    );
}

/// ISO-T6, pushed: a reconcile of the backend (the path a reload or a
/// credential change takes) revokes a subscriber who lost admission at once.
/// The fixture starts no worker, so no sweep can run: the listener's session
/// closes on the push alone, and nothing is read for it after.
#[tokio::test]
async fn iso_t6_a_pushed_revocation_closes_the_listener_without_the_sweep() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let p_token = token(Some(in_an_hour()));
    let mut peer =
        two_token_peer([p_token.to_string(), token(Some(in_an_hour())).to_string()]).await;
    let (f, _handle, (listeners, _backend)) = leased_listener(&mut peer, p_token).await;
    let mut intake = f.hub.take_intake();
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    f.hub.reconcile_backend("pt");
    assert_eq!(
        peer.next().await,
        Some(Stream::Closed(0)),
        "the push closed the session with no sweep running"
    );
    assert!(f.hub.store.subscriptions().is_empty(), "p's row is revoked");
    assert!(!peer.push_tools_changed(0), "no stream is left to read on");
    assert!(intake.try_recv().is_err(), "nothing was read for p");
    assert!(
        listeners
            .entry_for(&crate::events::upstream_listener::ListenerKey {
                backend: "pt".into(),
                obs: Some(lease_key(&f, "p").obs),
            })
            .is_none(),
        "no listener is left for p"
    );
}

/// A lease replaced after the backend refused the old token's stream with
/// `status`: the next stream opens under the new token. The rows go by the
/// peer's reports, not by timing: the replace follows the refusal, and
/// refusals of the old token that arrive in between are skipped.
async fn a_replace_after_a_refused_stream_reopens_under_the_new_token(status: u16) {
    let (old, new) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([old.to_string(), new.to_string()]).await;
    peer.refuse_stream[0].store(status, std::sync::atomic::Ordering::SeqCst);
    let f = listener_fixture(&peer);
    let handle = subscribe(&f, "p", "pt", "p");
    let (listeners, _backend) = parked_listener(&f).await;
    lease_as(&f, &handle, old).await;
    assert_eq!(
        peer.next().await,
        Some(Stream::Refused(0)),
        "premise: HTTP {status} refused the old token's stream"
    );
    // A parked key runs nothing before its lease (LEASE-T8), so the first
    // backoff this listener begins is the one the refused run ended in: the
    // replace lands during it, never before the run has judged the refusal.
    let shared = listeners
        .entry_for(&crate::events::upstream_listener::ListenerKey {
            backend: "pt".into(),
            obs: Some(lease_key(&f, "p").obs),
        })
        .expect("p's listener entry");
    crate::test_pause::within("the refused run's backoff", shared.waits.began.notified()).await;
    lease_as(&f, &handle, new).await;
    // One deadline for the whole wait, however many refusals arrive first.
    let reopened = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match peer.streams.recv().await {
                Some(Stream::Refused(0)) => {}
                other => return other,
            }
        }
    })
    .await
    .ok()
    .flatten();
    assert_eq!(
        reopened,
        Some(Stream::Opened(1)),
        "HTTP {status}: the next stream opened under the new token"
    );
}

/// A failed open, then a lease change.
#[tokio::test]
async fn a_replace_after_a_failed_open_reopens_under_the_new_token() {
    a_replace_after_a_refused_stream_reopens_under_the_new_token(500).await;
}

/// A terminal exit (the backend offers no stream, so the task waits out the
/// five-minute cap), then a lease change: the move cuts that wait, so the
/// reopen lands inside the 30 s hang guard.
#[tokio::test]
async fn a_replace_after_a_terminal_exit_cuts_its_backoff() {
    a_replace_after_a_refused_stream_reopens_under_the_new_token(405).await;
}
#[path = "lease_replace_push_tests.rs"]
mod push;
