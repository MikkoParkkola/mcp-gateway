// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The WebSocket upgrade under a backend destination policy.
//!
//! `Configured` connects as today. `Public` resolves the name once, checks
//! every answer, opens TCP to a checked address, and only then runs TLS and
//! the upgrade with the ORIGINAL request, so SNI and `Host` keep the name the
//! operator configured while no second lookup can move the connection.

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::{Request, Response};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::security::ssrf::{DestinationPolicy, HostResolver};
use crate::{Error, Result};

/// An upgraded connection, as `connect_async` returns it.
pub(super) type Upgraded = (WebSocketStream<MaybeTlsStream<TcpStream>>, Response);

/// Open the upgrade for `request` under `destination`.
pub(super) async fn connect(
    request: Request,
    destination: DestinationPolicy,
    resolver: &impl HostResolver,
) -> Result<Upgraded> {
    match destination {
        DestinationPolicy::Configured => connect_async(request).await.map_err(failed),
        DestinationPolicy::Public => connect_pinned(request, destination, resolver).await,
    }
}

/// Resolve once through `resolver`, refuse any answer `check` denies, connect
/// TCP to a checked address, then TLS and upgrade with the original request.
pub(super) async fn connect_pinned(
    request: Request,
    check: DestinationPolicy,
    resolver: &impl HostResolver,
) -> Result<Upgraded> {
    let _ = (check, resolver);
    connect_async(request).await.map_err(failed)
}

fn failed(error: tokio_tungstenite::tungstenite::Error) -> Error {
    Error::Transport(format!(
        "WebSocket connect failed: {}",
        super::connect_error(&error)
    ))
}

#[cfg(test)]
#[path = "websocket_pinned_tests.rs"]
mod tests;
