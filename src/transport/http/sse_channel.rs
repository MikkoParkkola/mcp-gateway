// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The retained GET stream of a 2024-11-05 HTTP+SSE session (MIK-8835.SSE.2).
//! The spec transport answers each POST 202 and puts its JSON-RPC response on
//! the session's stream, so the stream is kept after `endpoint` and every
//! response is paired with its request by id.
//!
//! An instance holds no credential: its owner builds every request's headers
//! at send time (design B1a). One instance per owner: the calls transport and
//! each listener session have their own, never shared.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::sse_decoder::{MAX_PENDING_SSE_BYTES, SseDecoder, SseEvent};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::http_diagnostics::safe_request_error;
use crate::transport::upstream_tap::{TAP_CAPACITY, UpstreamNote};
use crate::{Error, Result};

/// Bytes read before the `endpoint` event, at most. The event is one short
/// line, so a peer streaming more without it is refused rather than buffered
/// (the handshake's bound before the stream was kept).
const HANDSHAKE_CAP: usize = 64 * 1024;

/// How a notification on the stream becomes a listener note, and where it goes.
pub(super) struct Sink {
    pub tx: mpsc::Sender<UpstreamNote>,
    pub map: Box<dyn Fn(&str) -> Option<UpstreamNote> + Send + Sync>,
}

/// A live session stream: its message endpoint and the requests waiting on it.
pub(crate) struct SseChannel {
    endpoint: String,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>,
    closed: CancellationToken,
}

impl Drop for SseChannel {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

/// A request's place on a channel. Dropping it (an answer in the body, a failed
/// POST, a timeout, a cancelled caller) frees the slot.
pub(super) struct Waiting {
    key: String,
    rx: Option<oneshot::Receiver<JsonRpcResponse>>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>>,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.pending.lock().remove(&self.key);
    }
}

impl Waiting {
    /// The response, or a transport error once the stream ended without it.
    pub(super) async fn response(mut self) -> Result<JsonRpcResponse> {
        let Some(rx) = self.rx.take() else {
            return Err(Error::Transport("SSE response already taken".to_owned()));
        };
        rx.await
            .map_err(|_| Error::Transport("SSE stream ended before the response".to_owned()))
    }
}

/// The pairing key of a JSON-RPC id: its JSON text, so `1` and `"1"` differ.
fn key_of(id: &Value) -> String {
    id.to_string()
}

impl SseChannel {
    /// Read `response` (the session GET) up to its `endpoint` event, resolve
    /// that with `resolve`, then keep reading in the background: responses to
    /// their waiting requests, notifications to `sink`. A frame over the
    /// response bound (`MAX_PENDING_SSE_BYTES`, the limit a call answer has
    /// in a body) or a read error ends the channel.
    pub(super) async fn open(
        mut response: reqwest::Response,
        resolve: impl FnOnce(&str) -> Result<String>,
        sink: Option<Sink>,
    ) -> Result<Arc<Self>> {
        let mut decoder = SseDecoder::new(MAX_PENDING_SSE_BYTES);
        let mut early: Vec<SseEvent> = Vec::new();
        let mut read = 0usize;
        let endpoint = loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| safe_request_error("Failed to read SSE chunk", &e))?;
            let Some(chunk) = chunk else {
                return Err(Error::Transport(
                    "SSE stream ended without endpoint event".to_owned(),
                ));
            };
            read += chunk.len();
            if read > HANDSHAKE_CAP {
                return Err(Error::Transport(format!(
                    "SSE handshake exceeded {HANDSHAKE_CAP}-byte buffer without an endpoint event"
                )));
            }
            let mut events = decoder.push(&chunk)?.into_iter();
            if let Some(found) = events
                .by_ref()
                .find(|e| e.event.as_deref() == Some("endpoint"))
            {
                early.extend(events);
                break resolve(found.data.trim())?;
            }
        };
        let channel = Arc::new(Self {
            endpoint,
            pending: Arc::default(),
            closed: CancellationToken::new(),
        });
        let (pending, closed) = (Arc::clone(&channel.pending), channel.closed.clone());
        tokio::spawn(async move {
            let mut sink = sink;
            let read = async {
                route(&pending, &mut sink, early);
                loop {
                    let next = match response.chunk().await {
                        Ok(Some(chunk)) => decoder.push(&chunk),
                        Ok(None) => {
                            if let Ok(events) = decoder.finish() {
                                route(&pending, &mut sink, events);
                            }
                            return;
                        }
                        Err(_) => return,
                    };
                    let Ok(events) = next else {
                        return;
                    };
                    route(&pending, &mut sink, events);
                }
            };
            tokio::select! {
                () = read => {}
                () = closed.cancelled() => {}
            }
            closed.cancel();
            // Every request still waiting learns the stream is gone.
            pending.lock().clear();
        });
        Ok(channel)
    }

    /// The session's message URL.
    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Take a place for request `id` before its POST is sent. Refused when the
    /// channel has ended or `TAP_CAPACITY` requests already wait.
    pub(super) fn register(&self, id: &RequestId) -> Result<Waiting> {
        let id = serde_json::to_value(id).map_err(|e| Error::Protocol(e.to_string()))?;
        let key = key_of(&id);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock();
            if self.is_closed() {
                return Err(Error::Transport("SSE stream ended".to_owned()));
            }
            if pending.len() >= TAP_CAPACITY {
                return Err(Error::Transport(
                    "too many requests waiting on the SSE stream".to_owned(),
                ));
            }
            pending.insert(key.clone(), tx);
        }
        Ok(Waiting {
            key,
            rx: Some(rx),
            pending: Arc::clone(&self.pending),
        })
    }
}

/// Hand each event to its waiting request or the sink. A response for no
/// waiting request (another reader's, or a late one) is dropped. A full sink
/// is closed rather than awaited, so a burst of notifications never holds a
/// response back; the listener sees its stream end and reconnects.
fn route(
    pending: &Mutex<HashMap<String, oneshot::Sender<JsonRpcResponse>>>,
    sink: &mut Option<Sink>,
    events: Vec<SseEvent>,
) {
    for event in events {
        let Ok(value) = serde_json::from_str::<Value>(&event.data) else {
            continue;
        };
        let is_response = value.get("method").is_none()
            && (value.get("result").is_some() || value.get("error").is_some());
        if is_response {
            let Some(id) = value.get("id") else {
                continue;
            };
            let Some(waiter) = pending.lock().remove(&key_of(id)) else {
                continue;
            };
            if let Ok(response) = serde_json::from_value::<JsonRpcResponse>(value) {
                let _ = waiter.send(response);
            }
            continue;
        }
        let Some(open) = sink.as_ref() else {
            continue;
        };
        if let Some(note) = (open.map)(&event.data)
            && open.tx.try_send(note).is_err()
        {
            *sink = None;
        }
    }
}

impl super::HttpTransport {
    /// The calls session's live SSE stream, or `None` outside SSE mode (and
    /// before the first handshake made one). A stream that ended is replaced
    /// first, by a new handshake under `reinit_lock`, so concurrent callers
    /// share one replacement and a death after it is just a closed stream at
    /// the next request (design B7'). Nothing is resent: the requests the old
    /// stream failed have already returned their error.
    ///
    /// # Errors
    /// The replacement failed; the caller's request is not sent.
    pub(super) async fn live_sse_channel(&self) -> Result<Option<Arc<SseChannel>>> {
        if *self.streamable_http.read() != Some(false) {
            return Ok(None);
        }
        let Some(current) = self.sse_channel.read().clone() else {
            return Ok(None);
        };
        if !current.is_closed() {
            return Ok(Some(current));
        }
        // The replacement's own handshake requests land here when its new
        // stream ended at once: they fail rather than wait on the lock their
        // caller holds.
        if self.sse_reconnecting.load(Ordering::SeqCst) {
            return Err(Error::Transport(
                "SSE stream ended while it was being replaced".to_owned(),
            ));
        }
        let _held = self.reinit_lock.lock().await;
        if let Some(now) = self.sse_channel.read().clone()
            && !now.is_closed()
        {
            return Ok(Some(now));
        }
        self.sse_reconnecting.store(true, Ordering::SeqCst);
        // Boxed: the handshake sends requests, which come back here (E0733).
        let replaced: futures::future::BoxFuture<'_, Result<()>> = Box::pin(async {
            self.sessions.write().remove(Self::bucket_key(None));
            self.connect_sse().await?;
            self.legacy_handshake().await
        });
        let replaced = replaced.await;
        self.sse_reconnecting.store(false, Ordering::SeqCst);
        replaced?;
        let now = self.sse_channel.read().clone().filter(|c| !c.is_closed());
        now.map(Some)
            .ok_or_else(|| Error::Transport("the replacement SSE stream ended at once".to_owned()))
    }
}

#[cfg(test)]
#[path = "sse_channel_tests.rs"]
mod tests;
