// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The loopback peer the baseline rows send to: it takes a census inside
//! every request, checks the credential each request carries, and counts its
//! open connections so a teardown row knows when the client has let go.

use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::gateway::alloc_meter::take_census;

/// How the peer treats `tools/call`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Peer {
    /// Answers every call.
    Answers,
    /// Answers the first measured request, of any method, with HTTP 503,
    /// then answers.
    FailsOnce,
    /// Never answers a call: the gateway's call is dropped mid-send.
    Hangs,
}

/// What a `Hangs` peer reports: the hung call arrived, and its handler
/// ended because the gateway dropped the call.
#[derive(Default)]
pub(super) struct Hang {
    pub(super) arrived: tokio::sync::Notify,
    pub(super) released: tokio::sync::Notify,
}

/// Wakes `released` when the hung handler is dropped.
struct Released(Arc<Hang>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.released.notify_one();
    }
}

/// What a peer reports, and the switch that arms `FailsOnce` and `Hangs`
/// (off for the warm-up).
pub(super) struct Wire {
    pub(super) url: String,
    /// Requests that reached the peer.
    pub(super) sends: Arc<std::sync::atomic::AtomicUsize>,
    /// Requests that carried `Bearer <token>` as their `Authorization`.
    pub(super) carried: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) armed: Arc<std::sync::atomic::AtomicBool>,
    pub(super) hang: Arc<Hang>,
    /// Connections open now, and a wake-up each time the last one closes.
    open: Arc<std::sync::atomic::AtomicUsize>,
    closed: Arc<tokio::sync::Notify>,
}

/// The peer's listener: every accepted connection is counted open until its
/// stream drops, which happens only once the client has closed it.
struct Counted {
    inner: tokio::net::TcpListener,
    open: Arc<std::sync::atomic::AtomicUsize>,
    closed: Arc<tokio::sync::Notify>,
}

/// One accepted connection; dropping it closes the count.
struct CountedStream {
    inner: tokio::net::TcpStream,
    open: Arc<std::sync::atomic::AtomicUsize>,
    closed: Arc<tokio::sync::Notify>,
}

impl Drop for CountedStream {
    fn drop(&mut self) {
        if self.open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            self.closed.notify_one();
        }
    }
}

impl axum::serve::Listener for Counted {
    type Io = CountedStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Ok((inner, addr)) = self.inner.accept().await {
                self.open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let stream = CountedStream {
                    inner,
                    open: Arc::clone(&self.open),
                    closed: Arc::clone(&self.closed),
                };
                return (stream, addr);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl tokio::io::AsyncRead for CountedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for CountedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Wire {
    /// Wait until every connection to the peer has closed.
    pub(super) async fn all_closed(&self) {
        while self.open.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            self.closed.notified().await;
        }
    }
}

/// A streamable HTTP MCP peer on loopback that takes a census on every
/// request it serves, notes whether the request carried `token`, then
/// answers as `behaviour` says.
pub(super) async fn peer(behaviour: Peer, token: &'static str) -> Wire {
    use axum::response::IntoResponse as _;
    let wire = Wire {
        url: String::new(),
        sends: Arc::default(),
        carried: Arc::default(),
        armed: Arc::default(),
        hang: Arc::default(),
        open: Arc::default(),
        closed: Arc::default(),
    };
    let counted = Arc::clone(&wire.sends);
    let carried = Arc::clone(&wire.carried);
    let switch = Arc::clone(&wire.armed);
    let holder = Arc::clone(&wire.hang);
    let app = axum::Router::new().fallback(
        move |headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let carried = Arc::clone(&carried);
            let switch = Arc::clone(&switch);
            let holder = Arc::clone(&holder);
            async move {
                take_census();
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Compared in place: a copy here would be one more block
                // holding the token.
                let authorization = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "));
                if authorization == Some(token.as_bytes()) {
                    carried.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let method = message["method"].as_str().unwrap_or_default().to_owned();
                if switch.load(std::sync::atomic::Ordering::SeqCst) {
                    match behaviour {
                        Peer::FailsOnce => {
                            switch.store(false, std::sync::atomic::Ordering::SeqCst);
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        Peer::Hangs if method == "tools/call" => {
                            let _released = Released(Arc::clone(&holder));
                            holder.arrived.notify_one();
                            std::future::pending::<()>().await;
                        }
                        Peer::Answers | Peer::Hangs => {}
                    }
                }
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let result = match method.as_str() {
                    "server/discover" => json!({
                        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                        "capabilities": {"tools": {}}
                    }),
                    "tools/list" => json!({"tools": [{
                        "name": super::TOOL,
                        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                    }]}),
                    "tools/call" => json!({"content": [{"type": "text", "text": "ok"}]}),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
            }
        },
    );
    let listener = Counted {
        inner: tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind"),
        open: Arc::clone(&wire.open),
        closed: Arc::clone(&wire.closed),
    };
    let url = format!("http://{}/mcp", listener.inner.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    Wire { url, ..wire }
}
