//! Gateway server

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{debug, info, warn};

use super::auth::ResolvedAuthConfig;
use super::meta_mcp::MetaMcp;
use super::router::{AppState, create_router};
use super::streaming::NotificationMultiplexer;
use crate::backend::{Backend, BackendRegistry};
use crate::capability::{CapabilityBackend, CapabilityExecutor, CapabilityWatcher};
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

        // Load capabilities if enabled
        let _capability_watcher: Option<CapabilityWatcher> = if self.config.capabilities.enabled {
            let executor = Arc::new(CapabilityExecutor::new());
            let cap_backend = Arc::new(
                CapabilityBackend::new(&self.config.capabilities.name, executor)
            );

            let mut total_caps = 0;
            for dir in &self.config.capabilities.directories {
                match cap_backend.load_from_directory(dir).await {
                    Ok(count) => {
                        total_caps += count;
                        debug!(directory = %dir, count = count, "Loaded capabilities");
                    }
                    Err(e) => {
                        // Don't fail startup if capability dir doesn't exist
                        debug!(directory = %dir, error = %e, "Failed to load capabilities");
                    }
                }
            }

            if total_caps > 0 {
                info!(
                    capabilities = total_caps,
                    name = %self.config.capabilities.name,
                    "Capability backend ready"
                );
            }

            // Start file watcher for hot-reload
            let watcher = match CapabilityWatcher::start(
                Arc::clone(&cap_backend),
                shutdown_tx.subscribe(),
            ) {
                Ok(w) => {
                    info!("Capability hot-reload enabled");
                    Some(w)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start capability watcher, hot-reload disabled");
                    None
                }
            };

            meta_mcp.set_capabilities(cap_backend);
            watcher
        } else {
            None
        };

        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&self.backends),
            self.config.streaming.clone(),
        ));
        let auth_config = Arc::new(ResolvedAuthConfig::from_config(&self.config.auth));
        let state = Arc::new(AppState {
            backends: Arc::clone(&self.backends),
            meta_mcp,
            meta_mcp_enabled: self.config.meta_mcp.enabled,
            multiplexer,
            streaming_config: self.config.streaming.clone(),
            auth_config,
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

        if self.config.auth.enabled {
            let key_count = self.config.auth.api_keys.len();
            let has_bearer = self.config.auth.bearer_token.is_some();
            info!(
                "AUTHENTICATION enabled (bearer={}, api_keys={})",
                has_bearer, key_count
            );
        } else {
            warn!("AUTHENTICATION disabled - gateway is open to all requests");
        }

        if self.config.meta_mcp.enabled {
            info!("META-MCP (saves ~95% context tokens):");
            info!(
                "  POST http://{}:{}/mcp  (requests)",
                self.config.server.host, self.config.server.port
            );
        }

        if self.config.streaming.enabled {
            info!("STREAMING (real-time notifications):");
            info!(
                "  GET  http://{}:{}/mcp  (SSE stream)",
                self.config.server.host, self.config.server.port
            );
            if !self.config.streaming.auto_subscribe.is_empty() {
                info!("  Auto-subscribe backends: {:?}", self.config.streaming.auto_subscribe);
            }
        }

        info!("Direct backend access:");
        for backend in self.backends.all() {
            info!("  /mcp/{}", backend.name);
        }
        info!("============================================================");

        // Warm-start specified backends
        if !self.config.meta_mcp.warm_start.is_empty() {
            info!("Warm-starting backends: {:?}", self.config.meta_mcp.warm_start);
            let backends_clone = Arc::clone(&self.backends);
            let warm_start_list = self.config.meta_mcp.warm_start.clone();

            tokio::spawn(async move {
                for name in warm_start_list {
                    if let Some(backend) = backends_clone.get(&name) {
                        match backend.start().await {
                            Ok(()) => info!(backend = %name, "Warm-started successfully"),
                            Err(e) => warn!(backend = %name, error = %e, "Warm-start failed"),
                        }
                    } else {
                        warn!(backend = %name, "Backend not found for warm-start");
                    }
                }
            });
        }

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
