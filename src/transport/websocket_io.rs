// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The WebSocket transport's I/O loop: one task reads inbound frames and
//! writes the outbound queue, then fails in-flight calls when the connection
//! ends (moved from `websocket.rs`).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::mpsc::Receiver;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error};

use super::{Inner, Outbound, WebSocketTransport, log_close};

/// Frame counters, taken outside the `select!` below: inside a macro body the
/// log-under-lock scan sees only tokens, and a lock there reads as held over
/// the arm's log lines. The guard is a temporary released at once either way.
async fn count_received(inner: &Inner) {
    inner.session.lock().await.messages_received += 1;
}

async fn count_sent(inner: &Inner) {
    inner.session.lock().await.messages_sent += 1;
}

/// Drive reads from the WebSocket stream and writes from the outbound channel
/// using `tokio::select!`.  Exits when the connection closes or the outbound
/// channel is dropped.
pub(super) async fn run_io_loop(
    inner: Arc<Inner>,
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    mut outbound_rx: Receiver<Outbound>,
) {
    use futures::{SinkExt, StreamExt};

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    loop {
        tokio::select! {
            // Inbound frame from the server.
            maybe_msg = ws_source.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => {
                        count_received(&inner).await;
                        let text_str: &str = &text;
                        if let Err(e) = WebSocketTransport::dispatch_inbound(&inner, text_str) {
                            // `from_text` errors quote no frame text.
                            error!(
                                error = %e,
                                len = text_str.len(),
                                "Failed to dispatch inbound WebSocket frame"
                            );
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
                        log_close(frame.as_ref());
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
                if let Some((msg, claim)) = maybe_out {
                    // A request whose caller gave up while it was queued is
                    // never written.
                    if claim.is_some_and(|claim| !claim.claim_write()) {
                        continue;
                    }
                    if let Err(e) = ws_sink.send(msg).await {
                        error!(error = %e, "WebSocket write error");
                        inner.connected.store(false, Ordering::Relaxed);
                        break;
                    }
                    count_sent(&inner).await;
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
    inner.taps.clear();
}
