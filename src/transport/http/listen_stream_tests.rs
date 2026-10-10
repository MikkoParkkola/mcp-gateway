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
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
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
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
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
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
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
    let first = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a note arrives");
    assert!(first.is_some(), "the notification was not delivered");
    let end = tokio::time::timeout(Duration::from_secs(10), rx.recv())
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
    let note = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, None);
}
