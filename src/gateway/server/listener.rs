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
/// At the deadline `axum_server` cancels what is still running, which also
/// releases each request's in-flight permit, so the drain that follows in
/// `run` does not wait for them a second time.
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
    axum_server::from_tcp(listener)?
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| Error::Tls(e.to_string()))
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
