//! Gateway server

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{debug, info, warn};

use super::auth::ResolvedAuthConfig;
use super::meta_mcp::MetaMcp;
use super::proxy::ProxyManager;
use super::router::{AppState, create_router};
use super::streaming::NotificationMultiplexer;
use super::webhooks::WebhookRegistry;
use crate::backend::{Backend, BackendRegistry};
use crate::cache::ResponseCache;
use crate::capability::{CapabilityBackend, CapabilityExecutor, CapabilityWatcher};
use crate::config::Config;
use crate::playbook::PlaybookEngine;
use crate::ranking::SearchRanker;
use crate::security::ToolPolicy;
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;
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
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration fails.
    #[allow(clippy::unused_async)] // async for future initialization needs
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
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot bind to the configured address
    /// or if an unrecoverable runtime error occurs.
    #[allow(clippy::too_many_lines)]
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

        // Create cache if enabled (with bounded max-size eviction)
        let cache = if self.config.cache.enabled {
            let cache = if self.config.cache.max_entries > 0 {
                Arc::new(ResponseCache::with_max_entries(
                    self.config.cache.max_entries,
                ))
            } else {
                Arc::new(ResponseCache::new())
            };
            info!(
                enabled = true,
                default_ttl = ?self.config.cache.default_ttl,
                max_entries = self.config.cache.max_entries,
                "Response cache initialized"
            );
            Some(cache)
        } else {
            None
        };

        // Compile tool policy
        let tool_policy = Arc::new(ToolPolicy::from_config(&self.config.security.tool_policy));
        if self.config.security.tool_policy.enabled {
            info!("Tool security policy enabled");
        }

        // Create usage stats (always enabled for now)
        let usage_stats = Some(Arc::new(UsageStats::new()));
        if usage_stats.is_some() {
            info!("Usage statistics tracking enabled");
        }

        // Create search ranker with persistence
        let ranker_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".mcp-gateway")
            .join("usage.json");

        let ranker = Arc::new(SearchRanker::new());
        if let Some(parent) = ranker_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if ranker_path.exists() {
            if let Err(e) = ranker.load(&ranker_path) {
                warn!(error = %e, "Failed to load search ranker usage data");
            } else {
                info!("Loaded search ranking usage data");
            }
        }
        let ranker_for_shutdown = Arc::clone(&ranker);

        // Create transition tracker with persistence
        let transition_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".mcp-gateway")
            .join("transitions.json");

        let transition_tracker = Arc::new(TransitionTracker::new());
        if transition_path.exists() {
            if let Err(e) = transition_tracker.load(&transition_path) {
                warn!(error = %e, "Failed to load transition tracking data");
            } else {
                info!("Loaded transition tracking data");
            }
        }
        let tracker_for_shutdown = Arc::clone(&transition_tracker);

        // Create app state with cache, stats, and ranking support
        let meta_mcp = Arc::new(MetaMcp::with_features(
            Arc::clone(&self.backends),
            cache,
            usage_stats,
            Some(ranker),
            self.config.cache.default_ttl,
        ));

        // Attach transition tracker for predictive tool prefetch
        meta_mcp.set_transition_tracker(transition_tracker);

        // Create webhook registry
        let webhook_registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
            self.config.webhooks.clone(),
        )));

        // Load capabilities if enabled
        let _capability_watcher: Option<CapabilityWatcher> = if self.config.capabilities.enabled {
            let executor = Arc::new(CapabilityExecutor::new());
            let cap_backend = Arc::new(CapabilityBackend::new(
                &self.config.capabilities.name,
                executor,
            ));

            let mut total_caps = 0;
            for dir in &self.config.capabilities.directories {
                match cap_backend.load_from_directory(dir).await {
                    Ok(count) => {
                        total_caps += count;
                        debug!(directory = %dir, count = count, "Loaded capabilities");

                        // Register webhooks from capabilities
                        if self.config.webhooks.enabled {
                            for cap in cap_backend.list_capabilities() {
                                if !cap.webhooks.is_empty() {
                                    webhook_registry.write().register_capability(&cap);
                                }
                            }
                        }
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

        // Load playbooks if enabled
        if self.config.playbooks.enabled {
            let mut engine = PlaybookEngine::new();
            let mut total_playbooks = 0;
            for dir in &self.config.playbooks.directories {
                match engine.load_from_directory(dir) {
                    Ok(count) => {
                        total_playbooks += count;
                        debug!(directory = %dir, count, "Loaded playbooks");
                    }
                    Err(e) => {
                        debug!(directory = %dir, error = %e, "Failed to load playbooks");
                    }
                }
            }
            if total_playbooks > 0 {
                info!(playbooks = total_playbooks, "Playbook engine ready");
            }
            meta_mcp.set_playbook_engine(engine);
        }

        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&self.backends),
            self.config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let auth_config = Arc::new(ResolvedAuthConfig::from_config(&self.config.auth));

        // Wire webhook registry into MetaMcp for gateway_webhook_status.
        if self.config.webhooks.enabled {
            meta_mcp.set_webhook_registry(Arc::clone(&webhook_registry));
        }

        // In-flight request tracker: large initial permits, drain waits for
        // all permits to be returned (i.e., all in-flight requests complete).
        let inflight = Arc::new(tokio::sync::Semaphore::new(10_000));

        let state = Arc::new(AppState {
            backends: Arc::clone(&self.backends),
            meta_mcp,
            meta_mcp_enabled: self.config.meta_mcp.enabled,
            multiplexer: Arc::clone(&multiplexer),
            proxy_manager,
            streaming_config: self.config.streaming.clone(),
            auth_config,
            tool_policy,
            sanitize_input: self.config.security.sanitize_input,
            ssrf_protection: self.config.security.ssrf_protection,
            inflight: Arc::clone(&inflight),
        });

        // Create router
        let mut app = create_router(state);

        // Add webhook routes if enabled
        if self.config.webhooks.enabled {
            let webhook_routes = webhook_registry
                .read()
                .create_routes(Arc::clone(&multiplexer));
            app = app.merge(webhook_routes);
            info!(
                enabled = true,
                base_path = %self.config.webhooks.base_path,
                "Webhook receiver enabled"
            );
        }

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
                info!(
                    "  Auto-subscribe backends: {:?}",
                    self.config.streaming.auto_subscribe
                );
            }
        }

        info!("Direct backend access:");
        for backend in self.backends.all() {
            info!("  /mcp/{}", backend.name);
        }
        info!("============================================================");

        // Warm-start backends: connect + prefetch tools into cache
        // If warm_start list is empty, warm ALL backends (makes list/search fast)
        {
            let warm_start_list = if self.config.meta_mcp.warm_start.is_empty() {
                let all_names: Vec<String> =
                    self.backends.all().iter().map(|b| b.name.clone()).collect();
                info!("Warm-starting ALL {} backends (tool prefetch)", all_names.len());
                all_names
            } else {
                info!(
                    "Warm-starting backends: {:?}",
                    self.config.meta_mcp.warm_start
                );
                self.config.meta_mcp.warm_start.clone()
            };

            let backends_clone = Arc::clone(&self.backends);

            tokio::spawn(async move {
                for name in warm_start_list {
                    if let Some(backend) = backends_clone.get(&name) {
                        match backend.start().await {
                            Ok(()) => {
                                // Prefetch tools into cache after successful start
                                match backend.get_tools().await {
                                    Ok(tools) => info!(
                                        backend = %name,
                                        tools = tools.len(),
                                        "Warm-started + tools cached"
                                    ),
                                    Err(e) => warn!(
                                        backend = %name,
                                        error = %e,
                                        "Warm-started but tool prefetch failed"
                                    ),
                                }
                            }
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

        // Save search ranker usage data
        if let Err(e) = ranker_for_shutdown.save(&ranker_path) {
            warn!(error = %e, "Failed to save search ranker usage data");
        } else {
            info!("Saved search ranking usage data");
        }

        // Save transition tracking data
        if let Err(e) = tracker_for_shutdown.save(&transition_path) {
            warn!(error = %e, "Failed to save transition tracking data");
        } else {
            info!("Saved transition tracking data");
        }

        // Graceful drain: wait for in-flight requests to complete.
        // The semaphore has 10,000 permits; each in-flight request holds one.
        // We try to acquire all 10,000 (meaning all requests finished) with a timeout.
        let drain_timeout = self.config.server.shutdown_timeout;
        info!(timeout = ?drain_timeout, "Draining in-flight requests...");

        let drain_result = tokio::time::timeout(drain_timeout, inflight.acquire_many(10_000)).await;

        match drain_result {
            Ok(Ok(_permits)) => {
                info!("All in-flight requests completed");
            }
            Ok(Err(_)) => {
                warn!("Inflight semaphore closed unexpectedly during drain");
            }
            Err(_) => {
                let available = inflight.available_permits();
                let remaining = 10_000_usize.saturating_sub(available);
                warn!(
                    remaining_requests = remaining,
                    "Drain timeout reached, proceeding with shutdown"
                );
            }
        }

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
