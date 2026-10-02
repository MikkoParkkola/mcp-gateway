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
use crate::transport::upstream_tap::{
    Requested, TAP_CAPACITY, UpstreamNote, classify_response, listen_filter, project,
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
            .map_err(|e| Error::Transport(format!("listen: {e}")))?;
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
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => return,
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
            },
            uris: vec!["file:///a".into()],
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
}
