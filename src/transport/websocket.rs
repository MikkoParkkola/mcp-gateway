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
//! - [`WebSocketTransport::reconnect`] tears down the existing connection and
//!   re-establishes it to the same URL.
//!
//! # Frame model
//!
//! All JSON-RPC messages are carried as WebSocket *text* frames.  The
//! [`McpFrame`] enum classifies them as Request / Response / Notification /
//! Ping / Pong.  Ping and Pong use a small application-level JSON wrapper
//! (`{"type":"ping"}` / `{"type":"pong"}`) so they are distinguishable from
//! transport-level WebSocket ping/pong frames.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, warn};
use uuid::Uuid;

use super::Transport;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId};
use crate::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Bounded outbound queue depth.  Callers experience backpressure beyond this.
const OUTBOUND_QUEUE_DEPTH: usize = 256;

/// Default request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
                serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                }))?
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
    /// Sender side of the outbound channel.  Wrapped in a Mutex so it can be
    /// replaced on reconnect without rebuilding the Arc.
    outbound_tx: Mutex<Option<Sender<Message>>>,
    /// Session metadata.
    session: Mutex<WebSocketSession>,
    /// Connected flag (set to true after MCP initialisation, false on close).
    connected: AtomicBool,
    /// Monotonically-increasing request ID counter.
    request_id: AtomicU64,
    /// Handle to the background I/O task (reader + writer loop).
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Inner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: dashmap::DashMap::new(),
            outbound_tx: Mutex::new(None),
            session: Mutex::new(WebSocketSession::new()),
            connected: AtomicBool::new(false),
            request_id: AtomicU64::new(1),
            task: Mutex::new(None),
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
/// ## Reconnection
///
/// [`reconnect`] aborts the I/O task, clears pending state, resets the session,
/// and calls `connect` again against the same URL.
///
/// [`connect`]: WebSocketTransport::connect
/// [`reconnect`]: WebSocketTransport::reconnect
pub struct WebSocketTransport {
    /// WebSocket endpoint URL (`ws://` or `wss://`).
    url: String,
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
    pub fn new(url: &str) -> Arc<Self> {
        Arc::new(Self {
            url: url.to_string(),
            inner: Inner::new(),
        })
    }

    /// Connect to the WebSocket server and initialise the MCP session.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP/TLS connection or WebSocket upgrade fails,
    /// or if the MCP `initialize` request is rejected by the server.
    pub async fn connect(self: &Arc<Self>) -> Result<()> {
        self.do_connect().await?;
        self.initialize().await
    }

    /// Reconnect: tear down the existing connection then call [`connect`] again.
    ///
    /// Any pending requests are silently dropped (callers will receive a
    /// channel-closed error on their `oneshot::Receiver`).
    ///
    /// [`connect`]: WebSocketTransport::connect
    pub async fn reconnect(self: &Arc<Self>) -> Result<()> {
        debug!(url = %self.url, "WebSocket reconnecting");

        // Abort and drop the old I/O task.
        if let Some(h) = self.inner.task.lock().await.take() {
            h.abort();
        }

        // Drain the outbound channel (close it).
        self.inner.outbound_tx.lock().await.take();

        // Drop all pending request senders — callers will see channel-closed.
        self.inner.pending.clear();

        self.inner.connected.store(false, Ordering::Relaxed);

        // Fresh session metadata.
        *self.inner.session.lock().await = WebSocketSession::new();

        self.connect().await
    }

    // ── private ──────────────────────────────────────────────────────────────

    /// Open the WebSocket, spawn the I/O task, wire up the outbound channel.
    async fn do_connect(self: &Arc<Self>) -> Result<()> {
        use tokio_tungstenite::connect_async;

        debug!(url = %self.url, "WebSocket connecting");

        let (ws_stream, _response) = connect_async(&self.url)
            .await
            .map_err(|e| Error::Transport(format!("WebSocket connect failed: {e}")))?;

        debug!(url = %self.url, "WebSocket handshake complete");

        let (outbound_tx, outbound_rx) = channel::<Message>(OUTBOUND_QUEUE_DEPTH);

        // Store the sender so `send_message` can use it.
        *self.inner.outbound_tx.lock().await = Some(outbound_tx);

        let inner = Arc::clone(&self.inner);

        let task = tokio::spawn(async move {
            run_io_loop(inner, ws_stream, outbound_rx).await;
        });

        *self.inner.task.lock().await = Some(task);

        Ok(())
    }

    /// Perform the MCP `initialize` / `notifications/initialized` handshake.
    async fn initialize(&self) -> Result<()> {
        let response = self
            .request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;

        if response.error.is_some() {
            return Err(Error::Protocol("WebSocket MCP initialize failed".to_string()));
        }

        tokio::task::yield_now().await;
        self.notify("notifications/initialized", None).await?;
        tokio::task::yield_now().await;

        self.inner.connected.store(true, Ordering::Relaxed);
        debug!(url = %self.url, "WebSocket transport initialized");
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
                match maybe_out {
                    Some(msg) => {
                        if let Err(e) = ws_sink.send(msg).await {
                            error!(error = %e, "WebSocket write error");
                            inner.connected.store(false, Ordering::Relaxed);
                            break;
                        }
                        inner.session.lock().await.messages_sent += 1;
                    }
                    None => {
                        // Channel dropped — application is closing the transport.
                        debug!("WebSocket outbound channel closed; sending close frame");
                        let _ = ws_sink.send(Message::Close(None)).await;
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
    }
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

        let msg = McpFrame::Request(request).to_ws_message()?;
        if let Err(e) = self.send_message(msg).await {
            self.inner.pending.remove(&id.to_string());
            return Err(e);
        }

        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport(
                "WebSocket response channel closed".to_string(),
            )),
            Err(_) => {
                self.inner.pending.remove(&id.to_string());
                Err(Error::BackendTimeout(
                    "WebSocket request timed out".to_string(),
                ))
            }
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
        if let Some(h) = self.inner.task.lock().await.take() {
            h.abort();
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
