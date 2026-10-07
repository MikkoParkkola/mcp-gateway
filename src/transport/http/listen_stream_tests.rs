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
/// ends without a note, and a frame cut short is not delivered.
#[tokio::test]
async fn a_stream_that_breaks_off_ends_the_listen() {
    let url = peer(|_| {
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
         transfer-encoding: chunked\r\n\r\n40\r\ndata: {\"jsonrpc\""
            .to_owned()
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
