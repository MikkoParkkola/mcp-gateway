// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's HTTP listener, plain or mTLS, and how it stops (#2147).

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;

use crate::config::Config;
use crate::{Error, Result};

/// Serve `app` on the already bound `listener` until `shutdown` resolves.
///
/// Both transports stop the same way (#2147): after the signal the listener
/// refuses new connections and gives open requests `server.shutdown_timeout`.
/// At the deadline `axum_server` returns and signals every open connection to
/// drop; each drops its request, and the request's in-flight permit, shortly
/// after, so the drain that follows in `run` does not wait a second timeout.
pub(super) async fn serve(
    app: Router,
    listener: std::net::TcpListener,
    addr: SocketAddr,
    config: &Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let handle = axum_server::Handle::<SocketAddr>::new();
    let bridge = handle.clone();
    let grace = config.server.shutdown_timeout;
    tokio::spawn(async move {
        shutdown.await;
        bridge.graceful_shutdown(Some(grace));
    });
    if config.mtls.enabled {
        return super::support::serve_tls(app, listener, addr, &config.mtls, handle).await;
    }
    // Unlike `axum::serve`, this does not enable HTTP/2 extended CONNECT
    // (RFC 8441). Nothing here serves WebSockets; a WebSocket route would need
    // `http_builder().http2().enable_connect_protocol()`.
    axum_server::from_tcp(listener)
        .map_err(|e| Error::Tls(format!("listener setup failed: {e}")))?
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| Error::Tls(e.to_string()))
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
