// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a streamed listen body ends: an oversized frame, a body that breaks
//! off, and an answer to another request (`MIK-7324.COV.3` rows
//! `read_stream`, `next_events`).

use super::tests::{peer, req, transport};
use super::*;

/// A streamed frame over `FRAME_CAP` ends the listen: nothing after it is
/// read, not even this listen's own end.
#[tokio::test]
async fn a_streamed_frame_over_the_cap_ends_the_listen() {
    let url = peer(|id| {
        let big = json!({"jsonrpc": "2.0", "method": "notifications/message",
            "params": {"data": "x".repeat(FRAME_CAP)}});
        let end = json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "complete"}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {big}\n\ndata: {end}\n\n"
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(20), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, None);
}

/// A stream whose body breaks off mid-chunk is a read error: the listen
/// ends without a note. A complete frame still waiting for its closing blank
/// line is not delivered either, as it would be at a clean end of the body.
#[tokio::test]
async fn a_stream_that_breaks_off_ends_the_listen() {
    let url = peer(|id| {
        let end = json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "complete"}});
        let pending = format!("data: {end}\n");
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
             transfer-encoding: chunked\r\n\r\n{:x}\r\n{pending}\r\n40\r\ndata:",
            pending.len()
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(20), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, None);
}

/// A streamed answer to another request is skipped, not the listen's end:
/// the listen's own end after it still arrives.
#[tokio::test]
async fn a_streamed_answer_for_another_id_is_skipped() {
    let url = peer(|id| {
        let other = json!({"jsonrpc": "2.0", "id": "another-listen", "result": {}});
        let end = json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "complete"}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {other}\n\ndata: {end}\n\n"
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(20), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, Some(UpstreamNote::End));
}

/// MIK-8195 W1 (`open_session_stream`): a session stream whose session cannot
/// heal is refused as 404 before any GET is sent.
#[tokio::test]
async fn a_session_stream_that_cannot_heal_is_a_404() {
    let t = transport("http://127.0.0.1:1/mcp");
    t.reinit_needed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let opened = t
        .open_session_stream(Watched::default())
        .await
        .expect("no request is sent");
    assert!(matches!(opened, Err(404)));
}

/// MIK-8195 W1 (`open_session_stream`): the session stream delivers an
/// admitted notification, and ends when the body ends.
#[tokio::test]
async fn a_session_stream_delivers_its_notes_and_ends_with_the_body() {
    let url = peer(|_| {
        let note = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {note}\n\n"
        )
    })
    .await;
    let t = transport(&url);
    let mut rx = t
        .open_session_stream(Watched::default())
        .await
        .expect("sent")
        .expect("opened");
    let first = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("a note arrives");
    assert!(first.is_some(), "the notification was not delivered");
    let end = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(end, None);
}

/// MIK-8195 W1 (`open_session_stream`): a session stream whose body breaks
/// off mid-chunk ends without a note.
#[tokio::test]
async fn a_session_stream_that_breaks_off_ends() {
    let url = peer(|_| {
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
         transfer-encoding: chunked\r\n\r\n40\r\ndata:"
            .to_owned()
    })
    .await;
    let t = transport(&url);
    let mut rx = t
        .open_session_stream(Watched::default())
        .await
        .expect("sent")
        .expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, None);
}

/// MIK-8195 W1 (`open_session_stream`): a note the watch admits crosses the
/// channel and one it does not admit is dropped, on the same stream.
#[tokio::test]
async fn a_session_stream_drops_a_note_the_watch_does_not_admit() {
    let url = peer(|_| {
        let watched = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
            "params": {"uri": "file:///watched"}});
        let unwatched = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
            "params": {"uri": "file:///unwatched"}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {unwatched}\n\ndata: {watched}\n\n"
        )
    })
    .await;
    let t = transport(&url);
    let mut rx = t
        .open_session_stream(Watched::by(|uri| uri == "file:///watched"))
        .await
        .expect("sent")
        .expect("opened");
    let first = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the watched note arrives");
    let Some(UpstreamNote::Notice { uri, .. }) = first else {
        panic!("not the watched notice: {first:?}");
    };
    assert_eq!(uri.as_deref(), Some("file:///watched"));
    let end = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(end, None, "an unwatched note crossed the channel");
}

/// MIK-9035 T1.27 (DELTA-9): the listener reads the backend's LIVE value set.
/// A value that joins the set after the set was attached is still removed
/// from a change notice's URI before the note leaves the transport.
#[tokio::test]
async fn a_listen_notice_uri_is_scrubbed_with_the_live_set() {
    const NEEDLE: &str = "listen-secret-77d1";
    let url = peer(|id| {
        let notice = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
            "params": {"uri": format!("file:///x?k={NEEDLE}"),
                       "_meta": {"io.modelcontextprotocol/subscriptionId": id}}});
        let end = json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "complete"}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {notice}\n\ndata: {end}\n\n"
        )
    })
    .await;
    let t = transport(&url);
    let needles = std::sync::Arc::new(crate::security::needles::NeedleSet::with_grace(
        Duration::from_secs(3_600),
    ));
    t.attach_needles(std::sync::Arc::clone(&needles));
    // Joins after the attach: a snapshot taken at the attach would miss it.
    needles.insert("b", NEEDLE);
    let mut stream = t.listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(20), stream.rx.recv())
        .await
        .expect("the notice arrives");
    let Some(UpstreamNote::Notice { uri: Some(uri), .. }) = note else {
        panic!("not the notice: {note:?}");
    };
    assert!(
        uri.starts_with("file:///x?k="),
        "premise: the notice routed: {uri}"
    );
    assert!(
        !uri.contains(NEEDLE),
        "the notice carried the secret: {uri}"
    );
}
