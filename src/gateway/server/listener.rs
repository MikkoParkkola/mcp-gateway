//! The gateway's HTTP listener, plain or mTLS, and how it stops (#2147).

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;

use crate::config::Config;
use crate::{Error, Result};

/// Serve `app` on the already bound `listener` until `shutdown` resolves.
#[allow(dead_code, reason = "red-first stub")]
pub(super) async fn serve(
    app: Router,
    listener: std::net::TcpListener,
    addr: SocketAddr,
    config: &Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    if config.mtls.enabled {
        return super::support::serve_tls(app, listener, addr, &config.mtls, shutdown).await;
    }
    axum::serve(
        tokio::net::TcpListener::from_std(listener)?,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|e| Error::Tls(e.to_string()))
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
