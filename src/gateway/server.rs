//! Gateway server

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn};

use super::meta_mcp::MetaMcp;
use super::router::{AppState, create_router};
use crate::backend::{Backend, BackendRegistry};
use crate::config::Config;
use crate::{Error, Result};

/// MCP Gateway server
pub struct Gateway {
    /// Configuration
    config: Config,
    /// Backend registry
    backends: Arc<BackendRegistry>,
    /// Shutdown flag
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
}

impl Gateway {
    /// Create a new gateway
    pub async fn new(config: Config) -> Result<Self> {
        let backends = Arc::new(BackendRegistry::new());

        // Register backends
        for (name, backend_config) in config.enabled_backends() {
            let backend = Backend::new(
                name,
                backend_config.clone(),
                &config.failsafe,
                config.meta_mcp.cache_ttl,
            );
            backends.register(Arc::new(backend));
            info!(backend = %name, transport = %backend_config.transport.transport_type(), "Registered backend");
        }

        Ok(Self {
            config,
            backends,
            shutdown_tx: None,
        })
    }

    /// Run the gateway
    pub async fn run(mut self) -> Result<()> {
        let addr = SocketAddr::new(
            self.config
                .server
                .host
                .parse()
                .map_err(|e| Error::Config(format!("Invalid host: {e}")))?,
            self.config.server.port,
        );

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Create app state
        let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&self.backends)));
        let state = Arc::new(AppState {
            backends: Arc::clone(&self.backends),
            meta_mcp,
            meta_mcp_enabled: self.config.meta_mcp.enabled,
        });

        // Create router
        let app = create_router(state);

        // Bind listener
        let listener = TcpListener::bind(addr).await?;

        info!("============================================================");
        info!("MCP GATEWAY v{}", env!("CARGO_PKG_VERSION"));
        info!("============================================================");
        info!(host = %self.config.server.host, port = %self.config.server.port, "Listening");
        info!(backends = self.backends.all().len(), "Backends registered");

        if self.config.meta_mcp.enabled {
            info!("META-MCP (saves ~95% context tokens):");
            info!(
                "  http://{}:{}/mcp",
                self.config.server.host, self.config.server.port
            );
        }

        info!("Direct backend access:");
        for backend in self.backends.all() {
            info!("  /mcp/{}", backend.name);
        }
        info!("============================================================");

        // Start health check task
        let backends_clone = Arc::clone(&self.backends);
        let health_config = self.config.failsafe.health_check.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            if !health_config.enabled {
                return;
            }

            let mut interval = tokio::time::interval(health_config.interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        for backend in backends_clone.all() {
                            if backend.is_running() {
                                // Send ping
                                if let Err(e) = backend.request("ping", None).await {
                                    warn!(backend = %backend.name, error = %e, "Health check failed");
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // Start idle checker task
        let _backends_clone = Arc::clone(&self.backends);
        let mut shutdown_rx2 = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check for idle backends to hibernate
                        // (Implementation would check last_used timestamps)
                    }
                    _ = shutdown_rx2.recv() => {
                        break;
                    }
                }
            }
        });

        // Run server with graceful shutdown
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(shutdown_tx))
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Stop all backends
        info!("Shutting down backends...");
        self.backends.stop_all().await;

        Ok(())
    }
}

/// Shutdown signal handler
async fn shutdown_signal(shutdown_tx: tokio::sync::broadcast::Sender<()>) {
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
