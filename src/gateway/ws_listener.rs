//! Optional WebSocket transport listener.
//!
//! Binds a TCP listener and upgrades each accepted connection to a WebSocket
//! using tokio-tungstenite. Each peer runs in its own task and echoes text
//! messages back as a trivial loopback until the connection is closed or the
//! gateway-wide shutdown signal fires.
//!
//! Intentionally kept separate from the main Axum HTTP server so the two can
//! run on different ports without coupling.

use tracing::{debug, info, warn};

/// Accept loop for the optional WebSocket transport listener.
///
/// Binds a TCP listener on `addr` and upgrades each accepted connection to a
/// WebSocket using tokio-tungstenite.  Each peer runs in its own task and
/// echoes [`McpFrame`] text messages back as a trivial loopback until the
/// connection is closed or the gateway-wide shutdown signal fires.
///
/// This is intentionally kept separate from the main Axum HTTP server so the
/// two can run on different ports without coupling.
pub(crate) async fn run_websocket_listener(
    addr: std::net::SocketAddr,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %addr, error = %e, "WebSocket listener failed to bind");
            return;
        }
    };

    info!(addr = %addr, "WebSocket transport listening");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        debug!(peer = %peer, "WebSocket connection accepted");
                        tokio::spawn(handle_ws_peer(stream, peer));
                    }
                    Err(e) => {
                        warn!(error = %e, "WebSocket accept error");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("WebSocket listener shutting down");
                break;
            }
        }
    }
}

/// Handle a single WebSocket peer connection.
///
/// Upgrades the raw TCP stream and then drives a read loop.  Each incoming
/// text frame is echoed back verbatim (loopback behaviour).  Ping frames are
/// answered with a Pong.  The loop exits when the peer closes or an error
/// occurs.
async fn handle_ws_peer(stream: tokio::net::TcpStream, peer: std::net::SocketAddr) {
    use futures::SinkExt as _;
    use futures::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!(peer = %peer, error = %e, "WebSocket handshake failed");
            return;
        }
    };

    debug!(peer = %peer, "WebSocket handshake complete");

    let (mut write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                debug!(peer = %peer, bytes = text.len(), "WS text frame received");
                if write.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Ping(data)) => {
                if write.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }

    debug!(peer = %peer, "WebSocket connection closed");
}
