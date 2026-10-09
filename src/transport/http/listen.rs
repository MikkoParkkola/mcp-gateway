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
    Dropped, FrameStream, LegacyPin, Refused, Requested, TAP_CAPACITY, UpstreamListen,
    UpstreamNote, Watched, classify_response, interest_method, listen_filter, project,
    project_listen,
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
    /// `Ok(Err(status))` is the peer's refusal, as for the session GET.
    ///
    /// # Errors
    /// The request could not be built or sent.
    pub(crate) async fn open_listen(
        &self,
        requested: Requested,
    ) -> Result<std::result::Result<mpsc::Receiver<UpstreamNote>, u16>> {
        if !self.reinit_if_needed().await {
            return Ok(Err(404));
        }
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
        let carried = carried_session(&headers);
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
            return Ok(Err(self.refused(response.status().as_u16(), carried).await));
        }
        // A peer may answer the POST with one JSON response instead of a
        // stream: the end, the compatible acknowledgement or a `-32601`.
        let single = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
        let (tx, rx) = mpsc::channel(TAP_CAPACITY);
        let cancel = self.listen_cancel.clone();
        tokio::spawn(async move {
            let read = async {
                if single {
                    read_single(response, &id, &id_value, &requested, &tx).await;
                } else {
                    read_stream(response, &id, &id_value, &requested, &tx).await;
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

/// The session id an outgoing stream open carries, read from its headers.
fn carried_session(headers: &header::HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

impl HttpTransport {
    /// A stream open was refused with `status`. A 404 says the session it
    /// carried expired: that id is dropped only if it is still current (a
    /// late 404 from an older session leaves a newer one alone) and the
    /// session is re-handshaken. A sessionless 404 changes nothing.
    async fn refused(&self, status: u16, carried: Option<String>) -> u16 {
        if status == 404
            && let Some(carried) = carried
        {
            self.session_expired(&carried).await;
        }
        status
    }

    /// The shared session `carried` expired: drop it if it is still current
    /// (a newer one is left alone) and re-handshake. Dropping and marking run
    /// under the recovery lock, so they never interleave a re-handshake.
    pub(super) async fn session_expired(&self, carried: &str) -> bool {
        {
            let _held = self.reinit_lock.lock().await;
            let mut sessions = self.sessions.write();
            let bucket = Self::bucket_key(None);
            if sessions.get(bucket).map(String::as_str) != Some(carried) {
                return false;
            }
            sessions.remove(bucket);
            self.reinit_needed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.reinit_if_needed().await
    }

    /// Re-handshake while an earlier 404 left the shared session dropped;
    /// `false` while that still fails. One caller at a time; the flag is read
    /// again under the lock, so concurrent callers share one `initialize`.
    pub(super) async fn reinit_if_needed(&self) -> bool {
        use std::sync::atomic::Ordering;
        if !self.reinit_needed.load(Ordering::SeqCst) {
            return true;
        }
        let _held = self.reinit_lock.lock().await;
        if !self.reinit_needed.load(Ordering::SeqCst) {
            return true;
        }
        let healed = self.initialize().await.is_ok();
        if healed {
            self.reinit_needed.store(false, Ordering::SeqCst);
        }
        healed
    }

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
        watched: Watched,
    ) -> Result<std::result::Result<mpsc::Receiver<UpstreamNote>, u16>> {
        if !self.reinit_if_needed().await {
            return Ok(Err(404));
        }
        let headers = self
            .build_mcp_headers(HeaderMode::SessionStream, None)
            .await?;
        let carried = carried_session(&headers);
        let mut response = self
            .client
            .get(self.get_message_url())
            .headers(headers)
            .timeout(STREAM_TIMEOUT)
            .send()
            .await
            .map_err(|e| safe_request_error("session stream", &e))?;
        if !response.status().is_success() {
            return Ok(Err(self.refused(response.status().as_u16(), carried).await));
        }
        let (tx, rx) = mpsc::channel(TAP_CAPACITY);
        let cancel = self.listen_cancel.clone();
        tokio::spawn(async move {
            let read = async {
                let mut decoder = SseDecoder::new(FRAME_CAP);
                loop {
                    let (events, eof) = next_events(&mut response, &mut decoder).await;
                    let Some(events) = events else {
                        return;
                    };
                    for event in events {
                        if let Some(note) = unsolicited_frame(&event.data)
                            && watched.admits(&note)
                            && tx.send(note).await.is_err()
                        {
                            return;
                        }
                    }
                    if eof {
                        return;
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

#[cfg(test)]
impl HttpTransport {
    /// Stand in for a connect or a session recovery that detected `flavour`.
    pub(crate) fn set_detected(&self, flavour: Option<bool>) {
        *self.streamable_http.write() = flavour;
    }
}

#[async_trait::async_trait]
impl UpstreamListen for HttpTransport {
    /// The shared-bucket session: the peer keeps subscription state per
    /// session, so the call carries this one and the ledger its hash.
    fn legacy_pin(&self) -> LegacyPin {
        use std::hash::{Hash, Hasher};
        let session = self.sessions.read().get(Self::bucket_key(None)).cloned();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.hash(&mut hasher);
        LegacyPin {
            holder: hasher.finish(),
            session,
        }
    }

    /// Sent without the request path's session heal (which would move the
    /// call to a new session) and with the pinned session id, or none: a
    /// header value that does not parse makes the merge remove the bucket's.
    async fn legacy_interest(
        self: std::sync::Arc<Self>,
        pin: LegacyPin,
        uri: &str,
        subscribe: bool,
    ) -> Result<crate::protocol::JsonRpcResponse> {
        let request = crate::protocol::JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: self.next_id(),
            method: interest_method(subscribe).to_owned(),
            params: Some(json!({ "uri": uri })),
        };
        let pinned = (
            "mcp-session-id".to_owned(),
            pin.session.unwrap_or_else(|| "\n".to_owned()),
        );
        self.send_request_with_headers(&request, &[pinned], None, None)
            .await
    }

    async fn listen(
        self: std::sync::Arc<Self>,
        requested: Requested,
    ) -> std::result::Result<FrameStream, Refused> {
        let opened = self.open_listen(requested).await?;
        refused_as("listen", opened.map(FrameStream::new))
    }

    async fn unsolicited(
        self: std::sync::Arc<Self>,
        watched: Watched,
    ) -> std::result::Result<FrameStream, Refused> {
        let opened = self.open_session_stream(watched).await?;
        refused_as("session stream", opened.map(FrameStream::new))
    }

    fn detected_streamable(&self) -> Option<bool> {
        self.streamable()
    }
}

/// A refused open by its status: 405 means the backend offers no such
/// stream, 404 that the session expired (MIK-7899).
fn refused_as(
    what: &str,
    opened: std::result::Result<FrameStream, u16>,
) -> std::result::Result<FrameStream, Refused> {
    match opened {
        Ok(stream) => Ok(stream),
        Err(405) => Err(Refused::Unsupported),
        Err(404) => Err(Refused::Expired),
        Err(status) => Err(Refused::Failed(Error::Transport(format!(
            "{what} refused: HTTP {status}"
        )))),
    }
}

/// The next decoded events of `response`, and whether its body ended. At
/// the end the decoder is flushed, so a last frame without its closing
/// blank line still counts (MIK-7899). `None`: a frame over the cap or a
/// read error, which end the stream.
async fn next_events(
    response: &mut reqwest::Response,
    decoder: &mut SseDecoder,
) -> (Option<Vec<super::sse_decoder::SseEvent>>, bool) {
    match response.chunk().await {
        Ok(Some(chunk)) => (decoder.push(&chunk).ok(), false),
        Ok(None) => (decoder.finish().ok(), true),
        Err(_) => (None, true),
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
        let (events, eof) = next_events(&mut response, &mut decoder).await;
        let Some(events) = events else {
            debug!("listen frame over the cap or unreadable; ending the stream");
            return;
        };
        for event in events {
            match frame(&event.data, id, id_value, requested, first) {
                Frame::Note(note) => {
                    first = false;
                    let end = note.ends();
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
        if eof {
            return;
        }
    }
}

/// A listen answered with one JSON body (at most a frame's size): its single
/// response, as the stream's first frame.
async fn read_single(
    mut response: reqwest::Response,
    id: &RequestId,
    id_value: &Value,
    requested: &Requested,
    tx: &mpsc::Sender<UpstreamNote>,
) {
    let mut body = Vec::new();
    // Only a body read to its end is classified: a read error can cut a
    // longer answer down to a shorter valid one.
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => return,
        }
        if body.len() > FRAME_CAP {
            debug!("listen answer over the cap; ending the stream");
            return;
        }
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return;
    };
    if let Frame::Note(note) = frame(text, id, id_value, requested, true) {
        let _ = tx.send(note).await;
    }
}

enum Frame {
    Note(UpstreamNote),
    /// A frame of this listen that carries nothing for the hub.
    Skip,
    /// Not a JSON-RPC message (a comment, a keep-alive), or a frame of
    /// another listen: neither counts as this listen's first frame.
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
            project_listen(&n.method, n.params.as_ref(), id_value, requested, first).map_or_else(
                // A frame of another listen is not this one's first, as on
                // the tap, where it never reaches the listen.
                |dropped| {
                    if dropped == Dropped::Untagged {
                        Frame::Ignore
                    } else {
                        Frame::Skip
                    }
                },
                Frame::Note,
            )
        }
        Ok(JsonRpcMessage::Response(r)) if r.id.as_ref() == Some(id) => {
            Frame::Note(classify_response(
                first,
                id_value,
                r.result.as_ref(),
                r.error.as_ref().map(|e| e.code),
                requested,
            ))
        }
        Ok(_) => Frame::Skip,
        Err(_) => Frame::Ignore,
    }
}

#[cfg(test)]
#[path = "listen_stream_tests.rs"]
mod stream_tests;

#[cfg(test)]
#[path = "listen_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_heal_tests.rs"]
mod session_heal_tests;

#[cfg(test)]
#[path = "legacy_pin_tests.rs"]
mod legacy_pin_tests;
