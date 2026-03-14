//! Support functions for the gateway server.
//!
//! Contains free functions used during server startup and shutdown:
//! - [`log_startup_banner`]: emits the startup info block to the tracing log.
//! - [`serve_tls`]: starts the mTLS HTTPS listener via `axum-server`.
//! - [`shutdown_signal`]: awaits Ctrl+C / SIGTERM and broadcasts shutdown.
//! - [`build_persisted_costs`]: converts an enforcer snapshot to the
//!   persistence format (cost-governance feature only).

use std::net::SocketAddr;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use tokio::signal;
use tracing::{info, warn};

use crate::backend::BackendRegistry;
use crate::config::Config;

/// Emit the startup banner to the tracing log.
///
/// Logs version, listen address, backend count, auth status,
/// Meta-MCP URLs, streaming URLs, and per-backend direct access paths.
pub(super) fn log_startup_banner(config: &Config, backends: &BackendRegistry) {
    info!("============================================================");
    info!("MCP GATEWAY v{}", env!("CARGO_PKG_VERSION"));
    info!("============================================================");
    info!(host = %config.server.host, port = %config.server.port, "Listening");
    info!(backends = backends.all().len(), "Backends registered");

    if config.auth.enabled {
        let key_count = config.auth.api_keys.len();
        let has_bearer = config.auth.bearer_token.is_some();
        info!(
            "AUTHENTICATION enabled (bearer={}, api_keys={})",
            has_bearer, key_count
        );
    } else {
        warn!("AUTHENTICATION disabled - gateway is open to all requests");
    }

    if config.meta_mcp.enabled {
        info!("META-MCP (saves ~95% context tokens):");
        info!(
            "  POST http://{}:{}/mcp  (requests)",
            config.server.host, config.server.port
        );
    }

    if config.streaming.enabled {
        info!("STREAMING (real-time notifications):");
        info!(
            "  GET  http://{}:{}/mcp  (SSE stream)",
            config.server.host, config.server.port
        );
        if !config.streaming.auto_subscribe.is_empty() {
            info!(
                "  Auto-subscribe backends: {:?}",
                config.streaming.auto_subscribe
            );
        }
    }

    info!("Direct backend access:");
    for backend in backends.all() {
        info!("  /mcp/{}", backend.name);
    }
    info!("============================================================");
}

/// Start the HTTPS (mTLS) server using `axum-server`.
///
/// Builds a `rustls::ServerConfig` from `mtls_config`, wraps it in
/// `axum-server`'s `RustlsConfig`, and runs until the `shutdown_fut` resolves.
pub(super) async fn serve_tls(
    app: axum::Router,
    addr: SocketAddr,
    mtls_config: &crate::mtls::MtlsConfig,
    shutdown_fut: impl std::future::Future<Output = ()> + Send + 'static,
) -> crate::Result<()> {
    use crate::mtls::cert_manager::build_tls_config;

    let rustls_cfg = build_tls_config(mtls_config)?;
    let rustls_config = RustlsConfig::from_config(Arc::new(rustls_cfg));

    info!(
        addr = %addr,
        require_client_cert = mtls_config.require_client_cert,
        "mTLS listener starting"
    );

    let handle = axum_server::Handle::new();
    let handle_for_shutdown = handle.clone();

    // Bridge our broadcast-based shutdown signal to the axum-server handle
    tokio::spawn(async move {
        shutdown_fut.await;
        handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| crate::Error::Tls(format!("TLS server error: {e}")))
}

/// Shutdown signal handler.
///
/// Resolves on Ctrl+C (all platforms) or SIGTERM (Unix only), then broadcasts
/// the shutdown signal to all subscriber tasks.
pub(super) async fn shutdown_signal(shutdown_tx: tokio::sync::broadcast::Sender<()>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("Shutdown signal received");
    let _ = shutdown_tx.send(());
}

/// Build a `PersistedCosts` snapshot from the current enforcer state.
#[cfg(feature = "cost-governance")]
pub(super) fn build_persisted_costs(
    snap: &crate::cost_accounting::enforcer::EnforcerSnapshot,
) -> crate::cost_accounting::persistence::PersistedCosts {
    use crate::cost_accounting::persistence::ToolTotal;

    let tool_totals = snap
        .tool_daily
        .iter()
        .map(|(name, &daily_usd)| {
            (
                name.clone(),
                ToolTotal {
                    call_count: 0,
                    total_cost_usd: daily_usd,
                    avg_cost_usd: 0.0,
                },
            )
        })
        .collect();

    crate::cost_accounting::persistence::PersistedCosts {
        saved_at: crate::cost_accounting::persistence::now_secs(),
        tool_totals,
        key_totals: snap.key_daily.clone(),
    }
}
