// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-process WebSocket MCP peer for tests (F17, reused by F16).
//!
//! Binds 127.0.0.1:0 and records what a backend transport did to it: TCP
//! accepts, upgrade headers, `initialize` params, and when a socket closed.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};

/// How the peer answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Behaviour {
    /// Answer `initialize`, `tools/list` and `tools/call`.
    Normal,
    /// Answer `initialize` with a JSON-RPC error.
    RejectInitialize,
    /// Never answer `initialize`.
    SilentInitialize,
    /// Accept TCP and never read the upgrade request.
    StallUpgrade,
    /// Refuse the upgrade with HTTP 401.
    RefuseUpgrade,
    /// Close the first connection when its first `tools/call` arrives; later
    /// connections behave as `Normal`.
    CloseFirstCall,
    /// Answer `initialize`, then never answer anything.
    SilentRequests,
}

/// What the peer observed.
#[derive(Default)]
pub(crate) struct Seen {
    /// TCP connections accepted.
    pub(crate) accepts: AtomicUsize,
    /// Headers of every upgrade request, lower-cased names.
    pub(crate) upgrade_headers: Mutex<Vec<HashMap<String, String>>>,
    /// `params` of every `initialize` request.
    pub(crate) initialize_params: Mutex<Vec<Value>>,
    /// Sockets that ended (close frame or EOF) after a completed upgrade.
    pub(crate) closed: AtomicUsize,
    /// Signalled whenever `closed` grows.
    pub(crate) closed_notify: Notify,
    /// `tools/call` requests received, in arrival order.
    pub(crate) calls: Mutex<Vec<Value>>,
}

/// A running peer. `url` is `ws://127.0.0.1:<port>/mcp`.
pub(crate) struct WsPeer {
    pub(crate) url: String,
    pub(crate) port: u16,
    pub(crate) seen: Arc<Seen>,
}

impl WsPeer {
    /// Start a peer with `behaviour`.
    pub(crate) async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Seen::default());
        let accept_seen = Arc::clone(&seen);
        tokio::spawn(async move {
            // Stalled streams are held here so they stay open.
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let n = accept_seen.accepts.fetch_add(1, Ordering::SeqCst);
                if behaviour == Behaviour::StallUpgrade {
                    held.push(stream);
                    continue;
                }
                let behaviour = match behaviour {
                    Behaviour::CloseFirstCall if n > 0 => Behaviour::Normal,
                    other => other,
                };
                tokio::spawn(serve(stream, behaviour, Arc::clone(&accept_seen)));
            }
        });
        Self {
            url: format!("ws://127.0.0.1:{port}/mcp"),
            port,
            seen,
        }
    }

    /// Wait until at least `n` upgraded sockets have ended.
    pub(crate) async fn wait_closed(&self, n: usize) {
        loop {
            let notified = self.seen.closed_notify.notified();
            if self.seen.closed.load(Ordering::SeqCst) >= n {
                return;
            }
            notified.await;
        }
    }
}

async fn serve(stream: TcpStream, behaviour: Behaviour, seen: Arc<Seen>) {
    let header_seen = Arc::clone(&seen);
    let callback = move |request: &Request, response: Response| {
        let headers = request
            .headers()
            .iter()
            .map(|(k, v)| {
                let value = v.to_str().unwrap_or_default().to_string();
                (k.as_str().to_ascii_lowercase(), value)
            })
            .collect();
        header_seen.upgrade_headers.lock().push(headers);
        if behaviour == Behaviour::RefuseUpgrade {
            let mut refused = ErrorResponse::new(Some("unauthorized".to_string()));
            *refused.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED;
            return Err(refused);
        }
        Ok(response)
    };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    let (mut write, mut read) = ws.split();
    while let Some(Ok(message)) = read.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let frame: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let Some(reply) = answer(&frame, behaviour, &seen) else {
            if behaviour == Behaviour::CloseFirstCall && frame["method"] == "tools/call" {
                break;
            }
            continue;
        };
        for reply in reply {
            if write.send(Message::Text(reply.to_string().into())).await.is_err() {
                break;
            }
        }
    }
    let _ = write.close().await;
    seen.closed.fetch_add(1, Ordering::SeqCst);
    seen.closed_notify.notify_waiters();
}

/// The frames to send for `frame`, or `None` to stay silent.
fn answer(frame: &Value, behaviour: Behaviour, seen: &Seen) -> Option<Vec<Value>> {
    let id = frame.get("id")?.clone();
    let method = frame["method"].as_str().unwrap_or_default();
    let result = match method {
        "initialize" => {
            seen.initialize_params
                .lock()
                .push(frame.get("params").cloned().unwrap_or(Value::Null));
            match behaviour {
                Behaviour::SilentInitialize => return None,
                Behaviour::RejectInitialize => {
                    let error = json!({ "code": -32600, "message": "no legacy handshake" });
                    return Some(vec![json!({ "jsonrpc": "2.0", "id": id, "error": error })]);
                }
                _ => json!({
                    "protocolVersion": frame["params"]["protocolVersion"],
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ws-peer", "version": "0" }
                }),
            }
        }
        _ if behaviour == Behaviour::SilentRequests => return None,
        "tools/list" => json!({ "tools": [{
            "name": "echo",
            "description": "echoes its wire id and progress token",
            "inputSchema": { "type": "object" }
        }] }),
        "tools/call" => {
            seen.calls.lock().push(frame.clone());
            if behaviour == Behaviour::CloseFirstCall {
                return None;
            }
            let token = frame["params"]["_meta"]["progressToken"].clone();
            let echo = json!({ "wire_id": id, "token": token, "arguments": frame["params"]["arguments"] });
            let mut frames = Vec::new();
            if !token.is_null() {
                frames.push(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": { "progressToken": token, "progress": 1 }
                }));
            }
            let content = json!([{ "type": "text", "text": echo.to_string() }]);
            frames.push(json!({ "jsonrpc": "2.0", "id": id, "result": { "content": content } }));
            return Some(frames);
        }
        "ping" => json!({}),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return Some(vec![json!({ "jsonrpc": "2.0", "id": id, "error": error })]);
        }
    };
    Some(vec![json!({ "jsonrpc": "2.0", "id": id, "result": result })])
}
