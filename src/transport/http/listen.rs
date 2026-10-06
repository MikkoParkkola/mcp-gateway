// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `subscriptions/listen` over streamable HTTP (MIK-7630 I5 design §3-§4):
//! one POST whose SSE body is read until it ends, each frame projected to an
//! [`UpstreamNote`] before it crosses the channel.
//!
//! The body is read on a spawned task that holds no `Arc` of the transport,
//! only a clone of its `reqwest::Client` response and the transport's listen
//! cancellation token, which `close()` cancels: a restart or stop ends the
//! stream at once. Dropping the receiver ends it too.

use std::time::Duration;

use reqwest::header;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::debug;

use super::sse_decoder::SseDecoder;
use super::{HeaderMode, HttpTransport, finalise_modern_headers, with_modern_meta};
use crate::protocol::{JsonRpcMessage, RequestId};
use crate::security::http_diagnostics::safe_request_error;
use crate::transport::upstream_tap::{
    FrameStream, Refused, Requested, TAP_CAPACITY, UpstreamListen, UpstreamNote, classify_response,
    listen_filter, project,
};
use crate::{Error, Result};

/// A notification is small; a frame over this ends the stream (§4). Twice
/// the URI budget, so an acknowledgement echoing the whole filter fits.
const FRAME_CAP: usize = 64 * 1024;
/// The stream is recycled hourly (§4): the client's total timeout would
/// otherwise cut it at an arbitrary point.
const STREAM_TIMEOUT: Duration = Duration::from_secs(3600);
const METHOD: &str = "subscriptions/listen";

impl HttpTransport {
    /// Open a modern listen for `requested` on the shared session bucket.
    /// Notes arrive on the receiver until the stream ends, which the
    /// receiver sees as `Closed` (after an `End` for a graceful end).
    ///
    /// # Errors
    /// The request could not be built or sent, or the peer refused it.
    pub(crate) async fn open_listen(
        &self,
        requested: Requested,
    ) -> Result<mpsc::Receiver<UpstreamNote>> {
        let id = self.next_id();
        let id_value = serde_json::to_value(&id).map_err(|e| Error::Protocol(e.to_string()))?;
        let params = with_modern_meta(
            METHOD,
            Some(listen_filter(requested.kinds, &requested.uris)),
        )?;
        let mut headers = self
            .build_mcp_headers(HeaderMode::Request { method: METHOD }, None)
            .await?;
        finalise_modern_headers(&mut headers, METHOD, params.as_ref())?;
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("text/event-stream"),
        );
        let body = json!({"jsonrpc": "2.0", "id": id, "method": METHOD, "params": params});
        let response = self
            .client
            .post(self.get_message_url())
            .headers(headers)
            .json(&body)
            .timeout(STREAM_TIMEOUT)
            .send()
            .await
            .map_err(|e| safe_request_error("listen", &e))?;
        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "listen refused: HTTP {}",
                response.status().as_u16()
            )));
        }
        let (tx, rx) = mpsc::channel(TAP_CAPACITY);
        let cancel = self.listen_cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = read_stream(response, &id, &id_value, &requested, &tx) => {}
                () = cancel.cancelled() => {}
                () = tx.closed() => {}
            }
        });
        Ok(rx)
    }
}

impl HttpTransport {
    /// Open the legacy session GET (§3): the backend's out-of-request
    /// notifications on the shared bucket's session, or sessionless when the
    /// backend assigned none. One at a time per backend: a legacy server
    /// sends each message on one stream only.
    ///
    /// `Ok(Err(status))` is the peer's refusal: 405 means the backend offers
    /// no stream, 404 that the session expired.
    ///
    /// # Errors
    /// The request could not be built or sent.
    pub(crate) async fn open_session_stream(
        &self,
    ) -> Result<std::result::Result<mpsc::Receiver<UpstreamNote>, u16>> {
        let headers = self
            .build_mcp_headers(HeaderMode::SessionStream, None)
            .await?;
        let mut response = self
            .client
            .get(self.get_message_url())
            .headers(headers)
            .timeout(STREAM_TIMEOUT)
            .send()
            .await
            .map_err(|e| safe_request_error("session stream", &e))?;
        if !response.status().is_success() {
            return Ok(Err(response.status().as_u16()));
        }
        let (tx, rx) = mpsc::channel(TAP_CAPACITY);
        let cancel = self.listen_cancel.clone();
        tokio::spawn(async move {
            let read = async {
                let mut decoder = SseDecoder::new(FRAME_CAP);
                while let Ok(Some(chunk)) = response.chunk().await {
                    let Ok(events) = decoder.push(&chunk) else {
                        return;
                    };
                    for event in events {
                        if let Some(note) = unsolicited_frame(&event.data)
                            && tx.send(note).await.is_err()
                        {
                            return;
                        }
                    }
                }
            };
            tokio::select! {
                () = read => {}
                () = cancel.cancelled() => {}
                () = tx.closed() => {}
            }
        });
        Ok(Ok(rx))
    }
}

#[async_trait::async_trait]
impl UpstreamListen for HttpTransport {
    async fn listen(
        self: std::sync::Arc<Self>,
        requested: Requested,
    ) -> std::result::Result<FrameStream, Refused> {
        Ok(FrameStream::new(self.open_listen(requested).await?))
    }

    async fn unsolicited(self: std::sync::Arc<Self>) -> std::result::Result<FrameStream, Refused> {
        match self.open_session_stream().await? {
            Ok(rx) => Ok(FrameStream::new(rx)),
            Err(405) => Err(Refused::Unsupported),
            Err(404) => Err(Refused::Expired),
            Err(status) => Err(Refused::Failed(Error::Transport(format!(
                "session stream refused: HTTP {status}"
            )))),
        }
    }
}

/// One legacy stream payload as a note: only the three notifications.
fn unsolicited_frame(data: &str) -> Option<UpstreamNote> {
    match serde_json::from_str::<JsonRpcMessage>(data) {
        Ok(JsonRpcMessage::Notification(n)) => project(&n.method, n.params.as_ref(), None).ok(),
        _ => None,
    }
}

/// Read the listen body until it ends, sending each projected frame. A
/// plain JSON body is a single response: the end, or the compatible ack.
async fn read_stream(
    mut response: reqwest::Response,
    id: &RequestId,
    id_value: &Value,
    requested: &Requested,
    tx: &mpsc::Sender<UpstreamNote>,
) {
    let mut decoder = SseDecoder::new(FRAME_CAP);
    let mut first = true;
    loop {
        let Ok(Some(chunk)) = response.chunk().await else {
            return;
        };
        let Ok(events) = decoder.push(&chunk) else {
            debug!("listen frame over the cap; ending the stream");
            return;
        };
        for event in events {
            match frame(&event.data, id, id_value, requested, first) {
                Frame::Note(note) => {
                    first = false;
                    let end = note == UpstreamNote::End;
                    // Waiting here only stops reading the socket: TCP flow
                    // control pushes back on the backend (§8).
                    if tx.send(note).await.is_err() || end {
                        return;
                    }
                }
                Frame::Skip => first = false,
                Frame::Ignore => {}
            }
        }
    }
}

enum Frame {
    Note(UpstreamNote),
    /// A frame of this listen that carries nothing for the hub.
    Skip,
    /// Not a JSON-RPC message (a comment, a keep-alive).
    Ignore,
}

/// Classify one SSE `data` payload of listen `id`.
fn frame(
    data: &str,
    id: &RequestId,
    id_value: &Value,
    requested: &Requested,
    first: bool,
) -> Frame {
    match serde_json::from_str::<JsonRpcMessage>(data) {
        Ok(JsonRpcMessage::Notification(n)) => {
            project(&n.method, n.params.as_ref(), Some((id_value, requested)))
                .map_or(Frame::Skip, Frame::Note)
        }
        Ok(JsonRpcMessage::Response(r)) if r.id.as_ref() == Some(id) => Frame::Note(
            classify_response(first, id_value, r.result.as_ref(), requested),
        ),
        Ok(_) => Frame::Skip,
        Err(_) => Frame::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::upstream_tap::{KindSet, NoteKind, SUBSCRIPTION_ID};

    fn req() -> Requested {
        Requested {
            kinds: KindSet {
                resources_changed: true,
                prompts_changed: true,
                tools_changed: false,
            },
            uris: vec!["file:///a".into()],
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
            .open_session_stream()
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
            Frame::Skip
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
        assert_ne!(note, UpstreamNote::End);
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
    async fn peer(reply: impl Fn(&Value) -> String + Send + 'static) -> String {
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
            let id =
                serde_json::from_slice::<Value>(&body).map_or(Value::Null, |b| b["id"].clone());
            let _ = stream.write_all(reply(&id).as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        url
    }

    fn transport(url: &str) -> std::sync::Arc<HttpTransport> {
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
        assert!(
            note.as_ref().is_some_and(|n| *n != UpstreamNote::End),
            "{note:?}"
        );
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
}
