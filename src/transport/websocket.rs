// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WebSocket transport implementation for full-duplex MCP communication.
//!
//! Implements the [`Transport`] trait over a persistent WebSocket connection.
//!
//! # Design
//!
//! - A bounded outbound channel (`OUTBOUND_QUEUE_DEPTH`) provides backpressure:
//!   senders block when the queue is full rather than growing without limit.
//! - A background tokio task drives both reading (inbound frames) and writing
//!   (outbound frames) using `tokio::select!`.
//! - Pending requests are stored in a [`dashmap::DashMap`] keyed by request-id,
//!   mirroring the stdio and HTTP transport patterns.
//! - There is no reconnect here: on close the transport reports itself
//!   disconnected and fails its in-flight calls, and the backend lifecycle
//!   builds a fresh transport on the next call.
//!
//! # Frame model
//!
//! All JSON-RPC messages are carried as WebSocket *text* frames.  The
//! [`McpFrame`] enum classifies them as Request / Response / Notification /
//! Ping / Pong.  Ping and Pong use a small application-level JSON wrapper
//! (`{"type":"ping"}` / `{"type":"pong"}`) so they are distinguishable from
//! transport-level WebSocket ping/pong frames.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc::{Sender, channel};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};
use uuid::Uuid;

use super::notification_sink::DeliveryHandle;
use super::write_claim::WriteClaim;
use super::{Transport, sanitize_url_for_diagnostics};
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId, Selectable,
    checked_selection, initialize_params, is_version_mismatch_error, negotiate_best_version,
    parse_supported_versions_from_error,
};
use crate::security::ssrf::{DestinationPolicy, SystemResolver};
use crate::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Bounded outbound queue depth.  Callers experience backpressure beyond this.
const OUTBOUND_QUEUE_DEPTH: usize = 256;

// ── Frame types ──────────────────────────────────────────────────────────────

/// Logical MCP frame carried over a WebSocket text message.
#[derive(Debug, Clone)]
pub enum McpFrame {
    /// JSON-RPC request (has an `id` and a `method`).
    Request(JsonRpcRequest),
    /// JSON-RPC response (has an `id` and either `result` or `error`).
    Response(JsonRpcResponse),
    /// JSON-RPC notification (has `method`, no `id`).
    Notification {
        /// Method name.
        method: String,
        /// Optional parameters.
        params: Option<Value>,
    },
    /// Application-level ping (`{"type":"ping"}`).
    Ping,
    /// Application-level pong (`{"type":"pong"}`).
    Pong,
}

impl McpFrame {
    /// Serialise this frame to a WebSocket text [`Message`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if serialisation fails.
    pub fn to_ws_message(&self) -> Result<Message> {
        let json = match self {
            McpFrame::Request(req) => serde_json::to_string(req)?,
            McpFrame::Response(res) => serde_json::to_string(res)?,
            McpFrame::Notification { method, params } => {
                serde_json::to_string(&JsonRpcNotification {
                    jsonrpc: "2.0".to_string(),
                    method: method.clone(),
                    params: params.clone(),
                })?
            }
            McpFrame::Ping => r#"{"type":"ping"}"#.to_string(),
            McpFrame::Pong => r#"{"type":"pong"}"#.to_string(),
        };
        Ok(Message::Text(json.into()))
    }

    /// Parse a text payload into an [`McpFrame`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] for invalid JSON, or [`Error::Protocol`] when
    /// the JSON does not match a known frame shape.
    pub fn from_text(text: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(text)?;

        // Application-level ping / pong shortcut.
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            match t {
                "ping" => return Ok(McpFrame::Ping),
                "pong" => return Ok(McpFrame::Pong),
                _ => {}
            }
        }

        // All remaining frames must be JSON-RPC 2.0.
        let version = v.get("jsonrpc").and_then(Value::as_str).unwrap_or("");
        // No error below quotes the frame: it is backend text, and can hold
        // an injected value.
        if version != "2.0" {
            return Err(Error::Protocol(
                "Unexpected WebSocket frame: jsonrpc is not \"2.0\"".to_string(),
            ));
        }
        let malformed =
            |kind: &str| Error::Protocol(format!("WebSocket {kind} frame is malformed"));

        let has_id = v.get("id").is_some();
        let has_method = v.get("method").is_some();
        let has_result_or_error = v.get("result").is_some() || v.get("error").is_some();

        if has_id && has_method {
            let req: JsonRpcRequest =
                serde_json::from_value(v).map_err(|_| malformed("request"))?;
            Ok(McpFrame::Request(req))
        } else if has_id && has_result_or_error {
            let res: JsonRpcResponse =
                serde_json::from_value(v).map_err(|_| malformed("response"))?;
            Ok(McpFrame::Response(res))
        } else if !has_id && has_method {
            let method = v["method"]
                .as_str()
                .ok_or_else(|| Error::Protocol("Notification method is not a string".to_string()))?
                .to_string();
            let params = v.get("params").cloned();
            Ok(McpFrame::Notification { method, params })
        } else {
            Err(Error::Protocol(format!(
                "Cannot classify WebSocket frame ({} bytes)",
                text.len()
            )))
        }
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Per-connection state for a WebSocket session.
#[derive(Debug)]
pub struct WebSocketSession {
    /// Unique session identifier (UUID v4).
    pub session_id: String,
    /// Number of frames received on this session.
    pub messages_received: u64,
    /// Number of frames sent on this session.
    pub messages_sent: u64,
}

impl WebSocketSession {
    /// Create a new session with a randomly-generated UUID v4 identifier.
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            messages_received: 0,
            messages_sent: 0,
        }
    }

    /// Return the session ID.
    pub fn id(&self) -> &str {
        &self.session_id
    }
}

impl Default for WebSocketSession {
    fn default() -> Self {
        Self::new()
    }
}

/// A frame for the writer, with the write claim of a request frame.
type Outbound = (Message, Option<Arc<WriteClaim>>);

// ── Inner (shared state) ──────────────────────────────────────────────────────

/// Shared mutable state accessed by both the public API and the I/O task.
struct Inner {
    /// Pending requests: request-id string → response oneshot sender.
    pending: dashmap::DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// Sender side of the outbound channel. Taken on close, which ends the
    /// I/O task.
    outbound_tx: Mutex<Option<Sender<Outbound>>>,
    /// Session metadata.
    session: Mutex<WebSocketSession>,
    /// Connected flag (set to true after MCP initialisation, false on close).
    connected: AtomicBool,
    /// Monotonically-increasing request ID counter.
    request_id: AtomicU64,
    /// Handle to the background I/O task (reader + writer loop). A sync lock
    /// so `Drop` can abort it.
    task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    /// Where to deliver a progress notification, keyed by the token the call
    /// supplied. One socket carries every call, so -- as on stdio's stdout --
    /// the token is the whole correlation. See `StdioTransport`'s field of the
    /// same name for why this holds destinations rather than payloads.
    progress_destinations: dashmap::DashMap<String, DeliveryHandle>,
    /// Upstream-notification taps of the events listener (MIK-7630 I5).
    pub(crate) taps: super::upstream_tap::Taps,
    /// The values the backend's rules injected; every frame this transport
    /// reads is scrubbed of them before it is routed. Set before
    /// the connect, so the handshake is scrubbed too.
    needles: std::sync::OnceLock<Arc<crate::security::needles::NeedleSet>>,
}

impl Inner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: dashmap::DashMap::new(),
            outbound_tx: Mutex::new(None),
            session: Mutex::new(WebSocketSession::new()),
            connected: AtomicBool::new(false),
            request_id: AtomicU64::new(1),
            task: parking_lot::Mutex::new(None),
            progress_destinations: dashmap::DashMap::new(),
            taps: super::upstream_tap::Taps::default(),
            needles: std::sync::OnceLock::new(),
        })
    }
}

// ── Transport ─────────────────────────────────────────────────────────────────

/// WebSocket transport for MCP servers.
///
/// A single instance manages one persistent WebSocket connection.  Call
/// [`connect`] after construction to establish the connection and run the MCP
/// handshake.  The transport is ready for use once `connect` returns `Ok(())`.
///
/// ## Backpressure
///
/// Outbound messages are placed on a bounded channel of size
/// [`OUTBOUND_QUEUE_DEPTH`].  `send` awaits when the channel is full, providing
/// natural flow-control.
///
/// ## Teardown
///
/// A failed `connect`, `close`, and `Drop` all stop the I/O task, so no socket
/// outlives the transport that opened it.
///
/// [`connect`]: WebSocketTransport::connect
pub struct WebSocketTransport {
    /// WebSocket endpoint URL (`ws://` or `wss://`).
    url: String,
    /// Static headers sent once, on the upgrade request.
    headers: HashMap<String, String>,
    /// Bounds the upgrade and every request.
    timeout: Duration,
    /// `initialize` protocol version; `None` sends [`PROTOCOL_VERSION`].
    protocol_version: Option<String>,
    /// Shared inner state (also held by the I/O task).
    inner: Arc<Inner>,
    /// Where the upgrade may connect (`hardened` pins it; see `websocket_pinned.rs`).
    destination: DestinationPolicy,
}

impl WebSocketTransport {
    /// Create a new, unconnected transport.
    ///
    /// Call [`connect`] to establish the WebSocket connection and perform the
    /// MCP initialisation handshake.
    ///
    /// [`connect`]: WebSocketTransport::connect
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        protocol_version: Option<String>,
    ) -> Arc<Self> {
        Self::build(
            url,
            headers,
            timeout,
            protocol_version,
            DestinationPolicy::Configured,
        )
    }

    /// Build and connect a backend transport (the `ws_url` arm of
    /// `Backend::start_entry`).
    ///
    /// # Errors
    ///
    /// As [`WebSocketTransport::connect`].
    pub async fn start(
        url: &str,
        headers: &HashMap<String, String>,
        timeout: Duration,
        protocol_version: Option<String>,
    ) -> Result<Arc<dyn Transport>> {
        let started = Self::start_with_destination(
            url,
            headers,
            timeout,
            protocol_version,
            DestinationPolicy::Configured,
            None,
        )
        .await?;
        Ok(started)
    }

    /// Connect to the WebSocket server and initialise the MCP session.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP/TLS connection or WebSocket upgrade fails
    /// or outlasts the configured timeout, or if the MCP `initialize` request
    /// is rejected or unanswered. A failed `initialize` closes the socket the
    /// upgrade opened before the error is returned.
    pub async fn connect(self: &Arc<Self>) -> Result<()> {
        self.do_connect().await?;
        if let Err(e) = self.initialize().await {
            let _ = self.close().await;
            return Err(e);
        }
        Ok(())
    }

    // ── private ──────────────────────────────────────────────────────────────

    /// Open the WebSocket, spawn the I/O task, wire up the outbound channel.
    ///
    /// The static `headers` go on the upgrade request, once. The upgrade is
    /// bounded by the configured timeout. No log line or error carries more
    /// of the URL than its origin: it may hold userinfo or a query token.
    async fn do_connect(self: &Arc<Self>) -> Result<()> {
        let origin = sanitize_url_for_diagnostics(&self.url);
        debug!(url = %origin, "WebSocket connecting");

        let request = Self::upgrade_request(&self.url, &self.headers)?;

        // The timeout bounds the whole connect: lookup, TCP, TLS and upgrade.
        let connecting = pinned::connect(request, self.destination, &SystemResolver);
        let (ws_stream, _response) = tokio::time::timeout(self.timeout, connecting)
            .await
            .map_err(|_| {
                // The configured value, not the measured one: this text is
                // also the breaker's `reason` label, so it must stay constant.
                Error::Transport(format!(
                    "WebSocket connect timed out after {:?}",
                    self.timeout
                ))
            })??;

        debug!(url = %origin, "WebSocket handshake complete");

        let (outbound_tx, outbound_rx) = channel::<Outbound>(OUTBOUND_QUEUE_DEPTH);

        // Store the sender so `send_message` can use it.
        *self.inner.outbound_tx.lock().await = Some(outbound_tx);

        let inner = Arc::clone(&self.inner);

        let task = tokio::spawn(async move {
            run_io_loop(inner, ws_stream, outbound_rx).await;
        });

        *self.inner.task.lock() = Some(task);

        Ok(())
    }

    /// Perform the MCP `initialize` / `notifications/initialized` handshake.
    ///
    /// A version rejection is retried once, on this socket, at the highest
    /// revision both sides speak (GH #517, as on HTTP and stdio), and the
    /// revision the backend selects must be one this gateway speaks. Nothing
    /// after the handshake states a revision, so the selection is not kept.
    async fn initialize(&self) -> Result<()> {
        let proposed = self.protocol_version.as_deref().unwrap_or(PROTOCOL_VERSION);
        let mut response = self
            .request("initialize", Some(initialize_params(proposed)))
            .await?;
        if let Some(fallback) = response
            .error
            .as_ref()
            .filter(|error| is_version_mismatch_error(&error.message))
            .and_then(|error| parse_supported_versions_from_error(&error.message))
            .as_deref()
            .and_then(negotiate_best_version)
        {
            warn!(
                url = %sanitize_url_for_diagnostics(&self.url),
                rejected = %proposed,
                negotiated = %fallback,
                "Retrying initialize with negotiated protocol version"
            );
            response = self
                .request("initialize", Some(initialize_params(fallback)))
                .await?;
        }

        if response.error.is_some() {
            return Err(Error::Protocol(
                "WebSocket MCP initialize failed".to_string(),
            ));
        }
        checked_selection(response.result.as_ref(), Selectable::LegacyOrModern)?;

        tokio::task::yield_now().await;
        self.notify("notifications/initialized", None).await?;
        tokio::task::yield_now().await;

        self.inner.connected.store(true, Ordering::Relaxed);
        debug!(url = %sanitize_url_for_diagnostics(&self.url), "WebSocket transport initialized");
        Ok(())
    }

    /// Enqueue a message for the I/O task to write, applying backpressure.
    async fn send_message(&self, msg: Message) -> Result<()> {
        self.enqueue((msg, None)).await
    }

    /// Enqueue a frame with its write claim, if it is a request's.
    async fn enqueue(&self, out: Outbound) -> Result<()> {
        // Clone the sender out and release the slot before awaiting: a full
        // queue must not keep `close()` waiting on the slot's mutex.
        let tx = self
            .inner
            .outbound_tx
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::Transport("WebSocket not connected".to_string()))?;

        tx.send(out)
            .await
            .map_err(|_| Error::Transport("WebSocket outbound channel closed".to_string()))
    }

    /// Dispatch an inbound text frame to a pending request or log it.
    fn dispatch_inbound(inner: &Arc<Inner>, text: &str) -> Result<()> {
        debug!(len = text.len(), "Dispatching inbound WebSocket frame");
        let mut frame = McpFrame::from_text(text)?;
        // Routing keys (a progress token, a subscription tag) are read from
        // the frame as sent; only the delivered copy is scrubbed (DELTA-5).
        let keys = match &frame {
            McpFrame::Notification { params, .. } if inner.needles.get().is_some() => {
                params.clone()
            }
            _ => None,
        };
        // A listen's own answer is classified as sent (lead ruling G9): an
        // acknowledgement's URIs are the listen's requested ones. A listen is
        // never a pending request (I5 design §4).
        if let McpFrame::Response(response) = &frame
            && let Some(ref id) = response.id
            && inner
                .taps
                .response_to(id, response.result.as_ref(), response.error.as_ref())
        {
            return Ok(());
        }
        if let Some(needles) = inner.needles.get()
            && !scrub_frame(needles, &mut frame)
        {
            return Ok(());
        }

        match frame {
            McpFrame::Response(response) => {
                if let Some(ref id) = response.id {
                    let key = id.to_string();
                    if let Some((_, tx)) = inner.pending.remove(&key) {
                        let _ = tx.send(response);
                    } else {
                        // The id is backend text: its length only.
                        warn!(
                            id_len = key.len(),
                            "Received WebSocket response for unknown request"
                        );
                    }
                }
            }
            McpFrame::Ping => {
                debug!("Received application-level ping");
            }
            McpFrame::Pong => {
                debug!("Received application-level pong");
            }
            McpFrame::Notification { method, params } => {
                let keys = keys.as_ref().or(params.as_ref());
                if inner.taps.notification_keyed(
                    &method,
                    keys,
                    inner.needles.get().map(AsRef::as_ref),
                ) {
                    return Ok(());
                }
                let token = progress_key(&method, keys);
                route_progress(
                    inner,
                    JsonRpcNotification {
                        jsonrpc: "2.0".to_string(),
                        method,
                        params,
                    },
                    token,
                );
            }
            // Not relayed mid-call; the 2026 input bridge (`gateway::input_bridge`) is the path.
            McpFrame::Request(_) => {
                warn!("Received unexpected server-initiated request over WebSocket");
            }
        }

        Ok(())
    }

    /// Return the next request ID.
    #[allow(clippy::cast_possible_wrap)]
    fn next_id(&self) -> RequestId {
        RequestId::Number(self.inner.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }

    /// Return a snapshot of the current session metadata.
    pub async fn session(&self) -> WebSocketSession {
        let s = self.inner.session.lock().await;
        WebSocketSession {
            session_id: s.session_id.clone(),
            messages_received: s.messages_received,
            messages_sent: s.messages_sent,
        }
    }
}

// ── I/O loop (runs inside the spawned task) ───────────────────────────────────

// ── Transport impl ────────────────────────────────────────────────────────────

/// A transport dropped without `close()` (a lifecycle that discards it, a
/// start that was cancelled) must not orphan its I/O task: the task holds the
/// socket, which the handshake credential authenticated.
impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        if let Some(h) = self.inner.task.lock().take() {
            h.abort();
        }
    }
}

/// Render a connect failure without the request URI, which carries the query.
fn connect_error(error: &tokio_tungstenite::tungstenite::Error) -> String {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match error {
        WsError::Url(_) => "invalid ws_url".to_string(),
        WsError::Http(response) => format!("upgrade refused with HTTP {}", response.status()),
        other => other.to_string(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[path = "websocket_calls.rs"]
mod calls;
#[path = "websocket_cancel.rs"]
mod cancel;
#[path = "websocket_io.rs"]
mod io;
#[path = "websocket_listen.rs"]
mod listen;
#[path = "websocket_progress.rs"]
mod progress;
#[path = "websocket_scrub.rs"]
mod scrub;
use io::run_io_loop;
use progress::{ProgressRegistration, progress_key, route_progress};
use scrub::{log_close, scrub_frame};

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "websocket_cancel_tests.rs"]
mod cancel_tests;

#[path = "websocket_pinned.rs"]
mod pinned;

#[cfg(test)]
#[path = "websocket_backend_tests.rs"]
mod backend_tests;

#[cfg(test)]
#[path = "websocket_negotiation_tests.rs"]
mod negotiation_tests;

#[cfg(test)]
#[path = "websocket_scrub_tests.rs"]
mod scrub_tests;
