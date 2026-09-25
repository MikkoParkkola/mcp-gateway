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

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, warn};
use uuid::Uuid;

use super::{PendingRequestGuard, Transport, sanitize_url_for_diagnostics};
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId,
};
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
        if version != "2.0" {
            return Err(Error::Protocol(format!(
                "Unexpected WebSocket frame: jsonrpc='{version}'"
            )));
        }

        let has_id = v.get("id").is_some();
        let has_method = v.get("method").is_some();
        let has_result_or_error = v.get("result").is_some() || v.get("error").is_some();

        if has_id && has_method {
            let req: JsonRpcRequest = serde_json::from_value(v)?;
            Ok(McpFrame::Request(req))
        } else if has_id && has_result_or_error {
            let res: JsonRpcResponse = serde_json::from_value(v)?;
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
                "Cannot classify WebSocket frame: {v}"
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

// ── Inner (shared state) ──────────────────────────────────────────────────────

/// Shared mutable state accessed by both the public API and the I/O task.
struct Inner {
    /// Pending requests: request-id string → response oneshot sender.
    pending: dashmap::DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// Sender side of the outbound channel. Taken on close, which ends the
    /// I/O task.
    outbound_tx: Mutex<Option<Sender<Message>>>,
    /// Session metadata.
    session: Mutex<WebSocketSession>,
    /// Connected flag (set to true after MCP initialisation, false on close).
    connected: AtomicBool,
    /// Monotonically-increasing request ID counter.
    request_id: AtomicU64,
    /// Handle to the background I/O task (reader + writer loop). A sync lock
    /// so `Drop` can abort it.
    task: parking_lot::Mutex<Option<JoinHandle<()>>>,
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
        Arc::new(Self {
            url: url.to_string(),
            headers,
            timeout,
            protocol_version,
            inner: Inner::new(),
        })
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
        let transport = Self::new(url, headers.clone(), timeout, protocol_version);
        // Boxed: the TLS upgrade future is large, and inlining it would grow
        // every future that can start a backend (clippy::large_futures).
        Box::pin(transport.connect()).await?;
        Ok(transport)
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
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

        let origin = sanitize_url_for_diagnostics(&self.url);
        debug!(url = %origin, "WebSocket connecting");

        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| Error::Transport("WebSocket connect failed: invalid ws_url".into()))?;
        for (name, value) in &self.headers {
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                // The value is a credential; name the header only.
                return Err(Error::Transport(format!(
                    "WebSocket connect failed: header `{name}` is not a valid HTTP header"
                )));
            };
            request.headers_mut().insert(name, value);
        }

        let (ws_stream, _response) = tokio::time::timeout(self.timeout, connect_async(request))
            .await
            .map_err(|_| {
                // The configured value, not the measured one: this text is
                // also the breaker's `reason` label, so it must stay constant.
                Error::Transport(format!(
                    "WebSocket connect timed out after {:?}",
                    self.timeout
                ))
            })?
            .map_err(|e| {
                Error::Transport(format!("WebSocket connect failed: {}", connect_error(&e)))
            })?;

        debug!(url = %origin, "WebSocket handshake complete");

        let (outbound_tx, outbound_rx) = channel::<Message>(OUTBOUND_QUEUE_DEPTH);

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
    async fn initialize(&self) -> Result<()> {
        let response = self
            .request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": self.protocol_version.as_deref().unwrap_or(PROTOCOL_VERSION),
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;

        if response.error.is_some() {
            return Err(Error::Protocol(
                "WebSocket MCP initialize failed".to_string(),
            ));
        }

        tokio::task::yield_now().await;
        self.notify("notifications/initialized", None).await?;
        tokio::task::yield_now().await;

        self.inner.connected.store(true, Ordering::Relaxed);
        debug!(url = %sanitize_url_for_diagnostics(&self.url), "WebSocket transport initialized");
        Ok(())
    }

    /// Enqueue a message for the I/O task to write, applying backpressure.
    async fn send_message(&self, msg: Message) -> Result<()> {
        let guard = self.inner.outbound_tx.lock().await;
        let tx = guard
            .as_ref()
            .ok_or_else(|| Error::Transport("WebSocket not connected".to_string()))?;

        tx.send(msg)
            .await
            .map_err(|_| Error::Transport("WebSocket outbound channel closed".to_string()))
    }

    /// Dispatch an inbound text frame to a pending request or log it.
    fn dispatch_inbound(inner: &Arc<Inner>, text: &str) -> Result<()> {
        debug!(len = text.len(), "Dispatching inbound WebSocket frame");
        let frame = McpFrame::from_text(text)?;

        match frame {
            McpFrame::Response(response) => {
                if let Some(ref id) = response.id {
                    let key = id.to_string();
                    if let Some((_, tx)) = inner.pending.remove(&key) {
                        let _ = tx.send(response);
                    } else {
                        warn!(id = %key, "Received WebSocket response for unknown request");
                    }
                }
            }
            McpFrame::Ping => {
                debug!("Received application-level ping");
            }
            McpFrame::Pong => {
                debug!("Received application-level pong");
            }
            McpFrame::Notification { method, .. } => {
                debug!(method = %method, "Received WebSocket notification");
            }
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

/// Drive reads from the WebSocket stream and writes from the outbound channel
/// using `tokio::select!`.  Exits when the connection closes or the outbound
/// channel is dropped.
async fn run_io_loop(
    inner: Arc<Inner>,
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    mut outbound_rx: Receiver<Message>,
) {
    use futures::{SinkExt, StreamExt};

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    loop {
        tokio::select! {
            // Inbound frame from the server.
            maybe_msg = ws_source.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => {
                        inner.session.lock().await.messages_received += 1;
                        let text_str: &str = &text;
                        if let Err(e) = WebSocketTransport::dispatch_inbound(&inner, text_str) {
                            error!(error = %e, "Failed to dispatch inbound WebSocket frame");
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        debug!("Received transport-level WebSocket ping, replying with pong");
                        let _ = ws_sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        debug!("Received transport-level WebSocket pong");
                    }
                    Some(Ok(Message::Close(frame))) => {
                        debug!(frame = ?frame, "WebSocket close frame received");
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                    Some(Ok(_)) => {
                        // Binary / continuation frames — not used by MCP.
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "WebSocket read error");
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                    None => {
                        debug!("WebSocket stream ended");
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }

            // Outbound frame from the application.
            maybe_out = outbound_rx.recv() => {
                if let Some(msg) = maybe_out {
                    if let Err(e) = ws_sink.send(msg).await {
                        error!(error = %e, "WebSocket write error");
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                    inner.session.lock().await.messages_sent += 1;
                } else {
                    // Channel dropped — application is closing the transport.
                    debug!("WebSocket outbound channel closed; sending close frame");
                    let _ = ws_sink.send(Message::Close(None)).await;
                    inner.connected.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    // Fail in-flight calls now: their senders drop, so each caller sees
    // "connection closed before the response arrived" instead of waiting out
    // its timeout.
    inner.pending.clear();
}

// ── Transport impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Transport for WebSocketTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: id.clone(),
            method: method.to_string(),
            params,
        };

        let (tx, rx) = oneshot::channel();
        self.inner.pending.insert(id.to_string(), tx);
        // See StdioTransport::request: removing the entry is the guard's job
        // so a request future dropped by an OUTER timeout or task abort does
        // not strand its `pending` entry.
        let _cleanup = PendingRequestGuard::new(&self.inner.pending, &id.to_string());

        let msg = McpFrame::Request(request).to_ws_message()?;
        self.send_message(msg).await?;

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport(
                "WebSocket connection closed before the response arrived".to_string(),
            )),
            Err(_) => Err(Error::BackendTimeout(
                "WebSocket request timed out".to_string(),
            )),
        }
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let msg = McpFrame::Notification {
            method: method.to_string(),
            params,
        }
        .to_ws_message()?;
        self.send_message(msg).await
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.inner.connected.store(false, Ordering::Relaxed);

        // Dropping the sender closes the outbound channel, which causes the I/O
        // task to send a WebSocket close frame and exit cleanly.
        self.inner.outbound_tx.lock().await.take();

        // Abort the task (safe to call even after it has already exited).
        if let Some(h) = self.inner.task.lock().take() {
            h.abort();
        }

        Ok(())
    }
}

/// A transport dropped without `close()` (a lifecycle that discards it, a
/// start that was cancelled) must not orphan its I/O task: the task holds the
/// socket, which the handshake credential authenticated.
impl Drop for WebSocketTransport {
    fn drop(&mut self) {
        if false {
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

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "websocket_backend_tests.rs"]
mod backend_tests;
