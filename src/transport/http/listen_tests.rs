// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::transport::upstream_tap::{KindSet, NoteKind, SUBSCRIPTION_ID};

pub(super) fn req() -> Requested {
    Requested {
        kinds: KindSet {
            resources_changed: true,
            prompts_changed: true,
            tools_changed: false,
        },
        uris: vec!["file:///a".into()],
    }
}

/// T11 (MIK-7969): the detected transport is read live, so a session
/// recovery that switched it in place is seen at the next read.
#[test]
fn the_detected_transport_is_read_live() {
    let transport = HttpTransport::new(
        "http://127.0.0.1:9/mcp",
        std::collections::HashMap::new(),
        std::time::Duration::from_secs(1),
        true,
    )
    .expect("transport");
    for flavour in [Some(false), Some(true), None] {
        transport.set_detected(flavour);
        assert_eq!(transport.detected_streamable(), flavour);
    }
}

/// A refused connection to a URL that carries credentials (userinfo, query): neither listen
/// error may repeat them (MIK-7895; a `reqwest` error's text embeds the URL).
#[tokio::test]
async fn a_listen_error_does_not_carry_url_credentials() {
    let url = "http://user:hunter2@127.0.0.1:1/mcp?token=hunter3";
    let transport = HttpTransport::new(
        url,
        std::collections::HashMap::new(),
        Duration::from_secs(2),
        true,
    )
    .expect("transport");
    let listen = transport
        .open_listen(Requested::default())
        .await
        .expect_err("nothing listens on port 1");
    let session = transport
        .open_session_stream(Watched::default())
        .await
        .expect_err("nothing listens on port 1");
    for error in [listen.to_string(), session.to_string()] {
        assert!(!error.contains("hunter2"), "password leaked: {error}");
        assert!(!error.contains("hunter3"), "query token leaked: {error}");
    }
}

#[test]
fn frames_of_the_listen_are_projected() {
    let id = RequestId::Number(4);
    let v = json!(4);
    let r = req();
    let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
        "params": {"notifications": {"promptsListChanged": true},
                   "_meta": {SUBSCRIPTION_ID: 4}}});
    assert!(matches!(
        frame(&ack.to_string(), &id, &v, &r, true),
        Frame::Note(UpstreamNote::Ack { .. })
    ));
    let upd = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
        "params": {"uri": "file:///a", "_meta": {SUBSCRIPTION_ID: 4}}});
    assert!(matches!(
        frame(&upd.to_string(), &id, &v, &r, false),
        Frame::Note(UpstreamNote::Notice {
            kind: NoteKind::ResourceUpdated,
            ..
        })
    ));
    let untagged = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
        "params": {"uri": "file:///a"}});
    assert!(matches!(
        frame(&untagged.to_string(), &id, &v, &r, false),
        Frame::Ignore
    ));
    let end = json!({"jsonrpc": "2.0", "id": 4, "result": {"resultType": "complete"}});
    assert!(matches!(
        frame(&end.to_string(), &id, &v, &r, false),
        Frame::Note(UpstreamNote::End)
    ));
    let other = json!({"jsonrpc": "2.0", "id": 5, "result": {}});
    assert!(matches!(
        frame(&other.to_string(), &id, &v, &r, false),
        Frame::Skip
    ));
    assert!(matches!(
        frame("not json", &id, &v, &r, false),
        Frame::Ignore
    ));
}

#[test]
fn the_legacy_stream_keeps_only_the_four_notifications() {
    let upd = json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
        "params": {"uri": "file:///a"}});
    assert!(unsolicited_frame(&upd.to_string()).is_some());
    let tools = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    assert!(unsolicited_frame(&tools.to_string()).is_some());
    let other = json!({"jsonrpc": "2.0", "method": "notifications/message"});
    assert!(unsolicited_frame(&other.to_string()).is_none());
    let resp = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
    assert!(unsolicited_frame(&resp.to_string()).is_none());
    assert!(unsolicited_frame(": keep-alive").is_none());
}

/// MIK-7899 CLASS.1: a `-32601` answer to the listen says the peer has no
/// listen; it is not the listen's graceful end.
#[test]
fn a_method_not_found_answer_is_not_a_graceful_end() {
    let (id, v, r) = (RequestId::Number(4), json!(4), req());
    let refused = json!({"jsonrpc": "2.0", "id": 4,
        "error": {"code": -32601, "message": "Method not found"}});
    let Frame::Note(note) = frame(&refused.to_string(), &id, &v, &r, true) else {
        panic!("the listen's own answer is a note");
    };
    assert_eq!(note, UpstreamNote::Unsupported);
}

/// MIK-7899 CLASS.2: an acknowledgement counts only as the listen's first
/// frame; a later one is skipped.
#[test]
fn an_acknowledgement_after_another_frame_is_skipped() {
    let (id, v, r) = (RequestId::Number(4), json!(4), req());
    let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
        "params": {"notifications": {"promptsListChanged": true},
                   "_meta": {SUBSCRIPTION_ID: 4}}});
    assert!(matches!(
        frame(&ack.to_string(), &id, &v, &r, false),
        Frame::Skip
    ));
}

/// A one-shot HTTP peer on loopback: it answers the first request with
/// `reply(id)`, `id` being that request's JSON-RPC id, then closes.
pub(super) async fn peer(reply: impl Fn(&Value) -> String + Send + 'static) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let (mut seen, mut chunk) = (Vec::new(), [0u8; 4096]);
        let body = loop {
            let n = stream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            seen.extend_from_slice(&chunk[..n]);
            let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|l| l.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if seen.len() >= end + 4 + length {
                break seen[end + 4..end + 4 + length].to_vec();
            }
        };
        let id = serde_json::from_slice::<Value>(&body).map_or(Value::Null, |b| b["id"].clone());
        let _ = stream.write_all(reply(&id).as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    url
}

pub(super) fn transport(url: &str) -> std::sync::Arc<HttpTransport> {
    HttpTransport::new(
        url,
        std::collections::HashMap::new(),
        Duration::from_secs(5),
        true,
    )
    .expect("transport")
}

/// MIK-7899 CLASS.1: a peer that answers the listen POST with HTTP 405
/// offers no listen: `Unsupported`, not a failure to retry fast.
#[tokio::test]
async fn a_405_listen_is_unsupported() {
    let url = peer(|_| {
        "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_owned()
    })
    .await;
    let refused = transport(&url).listen(req()).await.err();
    assert!(matches!(refused, Some(Refused::Unsupported)), "{refused:?}");
}

/// MIK-7899 CLASS.1: a plain JSON `-32601` answer to the listen POST
/// reaches the session as a note that is not the graceful end.
#[tokio::test]
async fn a_json_method_not_found_answer_reaches_the_session() {
    let url = peer(|id| {
        let body = json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}})
        .to_string();
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, Some(UpstreamNote::Unsupported));
}

/// MIK-7899 CLASS.2: a frame the body ends on without its closing blank
/// line is still decoded, not lost at EOF.
#[tokio::test]
async fn the_last_frame_before_eof_is_decoded() {
    let url = peer(|id| {
        let ack = json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
            "params": {"notifications": {"promptsListChanged": true},
                       "_meta": {SUBSCRIPTION_ID: id}}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {ack}"
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert!(matches!(note, Some(UpstreamNote::Ack { .. })), "{note:?}");
}

/// MIK-7899 CLASS.1: a `-32601` answer inside the listen's SSE stream is
/// `Unsupported`, as a plain JSON one is.
#[tokio::test]
async fn an_sse_method_not_found_answer_is_unsupported() {
    let url = peer(|id| {
        let answer = json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}});
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n\
             data: {answer}\n\n"
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, Some(UpstreamNote::Unsupported));
}

/// A 404 on the listen POST is an expired session, retried as such; the
/// media type of a JSON answer matches whatever its case and parameters.
#[tokio::test]
async fn a_404_listen_is_expired_and_json_is_matched_loosely() {
    let url = peer(|_| {
        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned()
    })
    .await;
    let refused = transport(&url).listen(req()).await.err();
    assert!(matches!(refused, Some(Refused::Expired)), "{refused:?}");

    let url = peer(|id| {
        let body = json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}})
        .to_string();
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: Application/JSON; charset=utf-8\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, Some(UpstreamNote::Unsupported));
}

/// A frame of no listen, with a method the tap does not know, is not this
/// listen's first frame: the acknowledgement after it still counts.
#[test]
fn an_untagged_frame_of_any_method_is_not_the_first() {
    let (id, v, r) = (RequestId::Number(4), json!(4), req());
    let message = json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"level": "info"}});
    assert!(matches!(
        frame(&message.to_string(), &id, &v, &r, true),
        Frame::Ignore
    ));
}

/// A JSON answer cut short (a closed connection before its declared
/// length) is not classified, though its bytes so far parse.
#[tokio::test]
async fn a_truncated_json_answer_is_not_classified() {
    let url = peer(|id| {
        let body = json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}})
        .to_string();
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len() + 100
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    let note = tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends");
    assert_eq!(note, None);
}

/// The note a listen answered with one complete JSON body delivers.
async fn note_for_json_answer(
    body: impl Fn(&Value) -> String + Send + 'static,
) -> Option<UpstreamNote> {
    let url = peer(move |id| {
        let body = body(id);
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    })
    .await;
    let mut stream = transport(&url).listen(req()).await.expect("opened");
    tokio::time::timeout(Duration::from_secs(5), stream.rx.recv())
        .await
        .expect("the stream ends")
}

/// An untrusted upstream's single answer is capped at `FRAME_CAP`: the
/// answer that reaches the session as `Unsupported` at exactly the cap is
/// dropped unread one byte over it.
#[tokio::test]
async fn a_json_answer_over_the_frame_cap_is_not_classified() {
    fn sized(id: &Value, size: usize) -> String {
        let answer = |message: &str| {
            json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": message}})
            .to_string()
        };
        let body = answer(&"x".repeat(size - answer("").len()));
        assert_eq!(body.len(), size);
        body
    }
    let at_cap = note_for_json_answer(|id| sized(id, FRAME_CAP)).await;
    assert_eq!(at_cap, Some(UpstreamNote::Unsupported));
    let over = note_for_json_answer(|id| sized(id, FRAME_CAP + 1)).await;
    assert_eq!(over, None);
}

/// A single answer carrying another request's id is not this listen's.
#[tokio::test]
async fn a_json_answer_for_another_id_is_not_classified() {
    let note = note_for_json_answer(|_| {
        json!({"jsonrpc": "2.0", "id": "another-listen",
            "error": {"code": -32601, "message": "Method not found"}})
        .to_string()
    })
    .await;
    assert_eq!(note, None);
}

/// MIK-8019.SAME.1: a null-method frame carrying this listen's id is not a
/// response of the listen, so it is not projected into a note.
#[test]
fn a_null_method_frame_is_not_projected() {
    let id = RequestId::Number(4);
    let frame_text = json!({"jsonrpc": "2.0", "id": 4, "method": null, "result": {}});
    assert!(matches!(
        frame(&frame_text.to_string(), &id, &json!(4), &req(), true),
        Frame::Ignore
    ));
}
