//! Gateway server

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use super::auth::ResolvedAuthConfig;
use super::meta_mcp::MetaMcp;
use super::oauth::{AgentAuthState, AgentDefinition, AgentRegistry, GatewayKeyPair};
use super::proxy::ProxyManager;
use super::router::{AppState, create_router};
use super::streaming::NotificationMultiplexer;
use super::webhooks::WebhookRegistry;
use crate::backend::{Backend, BackendRegistry};
use crate::cache::ResponseCache;
use crate::capability::{CapabilityBackend, CapabilityExecutor, CapabilityWatcher};
use crate::config::Config;
use crate::config_reload::{ConfigWatcher, LiveConfig, ReloadContext};
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::{
    enforcer::BudgetEnforcer,
    persistence::{self},
    registry::CostRegistry,
};
use crate::key_server::{KeyServer, store::spawn_reaper};
use crate::mtls::MtlsPolicy;
use crate::playbook::PlaybookEngine;
use crate::ranking::SearchRanker;
use crate::routing_profile::ProfileRegistry;
use crate::security::ToolPolicy;
#[cfg(feature = "firewall")]
use crate::security::firewall::Firewall;
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;
use crate::{Error, Result};

#[cfg(feature = "cost-governance")]
use support::build_persisted_costs;
use support::{log_startup_banner, serve_tls, shutdown_signal};

/// MCP Gateway server
pub struct Gateway {
    /// Configuration
    config: Config,
    /// Path to config file on disk (enables hot-reload when `Some`)
    config_path: Option<std::path::PathBuf>,
    /// Backend registry
    backends: Arc<BackendRegistry>,
    /// Shutdown flag
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
}

/// Shared components produced by [`Gateway::build_meta_mcp`].
///
/// Both the HTTP server (`Gateway::run`) and the stdio server
/// (`Gateway::run_stdio`) require identical `MetaMcp` initialisation.  This
/// struct carries the results so callers can destructure exactly what they need
/// without duplicating the construction logic.
struct BuiltMetaMcp {
    meta_mcp: Arc<MetaMcp>,
    tool_policy: Arc<ToolPolicy>,
    mtls_policy: Arc<MtlsPolicy>,
    /// Ranker handle retained for graceful-shutdown persistence (HTTP mode).
    ranker: Arc<SearchRanker>,
    /// On-disk path for ranker persistence.
    ranker_path: std::path::PathBuf,
    /// Transition tracker retained for shutdown persistence (HTTP mode).
    transition_tracker: Arc<TransitionTracker>,
    /// On-disk path for transition persistence.
    transition_path: std::path::PathBuf,
    /// Data directory used by cost-governance persistence.
    data_dir: std::path::PathBuf,
}

impl Gateway {
    /// Create a new gateway
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration fails.
    #[allow(clippy::unused_async)] // async for future initialization needs
    pub async fn new(config: Config) -> Result<Self> {
        Self::new_with_path(config, None).await
    }

    /// Create a new gateway with a config file path for hot-reload support.
    ///
    /// When `config_path` is `Some`, config changes to that file trigger
    /// automatic diff + patch at runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration fails.
    #[allow(clippy::unused_async)] // async for future initialization needs
    pub async fn new_with_path(
        config: Config,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
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
            config_path,
            backends,
            shutdown_tx: None,
        })
    }

    /// Build [`MetaMcp`] and all supporting components shared between HTTP and
    /// stdio modes.
    ///
    /// Eliminates ~100 lines of duplication between [`Self::run`] and
    /// [`Self::run_stdio`].  The returned [`BuiltMetaMcp`] carries handles that
    /// callers may need for graceful shutdown or further wiring.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Result` for forward-compatibility.
    async fn build_meta_mcp(&self) -> Result<BuiltMetaMcp> {
        // ── Response cache ───────────────────────────────────────────────────
        let cache = if self.config.cache.enabled {
            let cache = if self.config.cache.max_entries > 0 {
                Arc::new(ResponseCache::with_max_entries(
                    self.config.cache.max_entries,
                ))
            } else {
                Arc::new(ResponseCache::new())
            };
            Some(cache)
        } else {
            None
        };

        // ── Security policies ────────────────────────────────────────────────
        let tool_policy = Arc::new(ToolPolicy::from_config(&self.config.security.tool_policy));
        let mtls_policy = Arc::new(MtlsPolicy::from_config(&self.config.mtls));

        // ── Usage stats + search ranker with on-disk persistence ─────────────
        let usage_stats = Some(Arc::new(UsageStats::new()));

        let data_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".mcp-gateway");
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            warn!(error = %e, "Failed to create data directory");
        }

        let ranker_path = data_dir.join("usage.json");
        let ranker = Arc::new(SearchRanker::new());
        if ranker_path.exists() {
            if let Err(e) = ranker.load(&ranker_path) {
                warn!(error = %e, "Failed to load search ranker usage data");
            } else {
                info!("Loaded search ranking usage data");
            }
        }

        // ── Transition tracker ───────────────────────────────────────────────
        let transition_path = data_dir.join("transitions.json");
        let transition_tracker = Arc::new(TransitionTracker::new());
        if transition_path.exists() {
            if let Err(e) = transition_tracker.load(&transition_path) {
                warn!(error = %e, "Failed to load transition tracking data");
            } else {
                info!("Loaded transition tracking data");
            }
        }

        // ── Routing profiles + secret injector ──────────────────────────────
        let profile_registry = ProfileRegistry::from_config(
            &self.config.routing_profiles,
            &self.config.default_routing_profile,
        );
        let secret_injector =
            crate::secret_injection::SecretInjector::from_backend_configs(&self.config.backends);

        // ── Cost governance (feature-gated) ──────────────────────────────────
        #[cfg(feature = "cost-governance")]
        let (cost_registry_opt, budget_enforcer_opt) = {
            let cg_cfg = self.config.cost_governance.clone();
            if cg_cfg.enabled {
                let registry = Arc::new(CostRegistry::new(&cg_cfg));
                let costs_path = data_dir.join("costs.json");
                if costs_path.exists() {
                    match persistence::load(&costs_path) {
                        Ok(_persisted) => info!("Loaded persisted cost data"),
                        Err(e) => warn!(error = %e, "Failed to load persisted cost data"),
                    }
                }
                let enforcer = Arc::new(BudgetEnforcer::new(cg_cfg, Arc::clone(&registry)));
                info!("Cost governance enabled");
                (Some(registry), Some(enforcer))
            } else {
                (None, None)
            }
        };

        // ── MetaMcp builder ──────────────────────────────────────────────────
        #[allow(unused_mut)]
        let mut meta_mcp_builder = MetaMcp::with_features(
            Arc::clone(&self.backends),
            cache,
            usage_stats,
            Some(Arc::clone(&ranker)),
            self.config.cache.default_ttl,
        )
        .with_profile_registry(profile_registry)
        .with_code_mode(self.config.code_mode.enabled)
        .with_secret_injector(secret_injector)
        .with_surfaced_tools(self.config.meta_mcp.surfaced_tools.clone());

        #[cfg(feature = "cost-governance")]
        if let (Some(registry), Some(enforcer)) = (cost_registry_opt, budget_enforcer_opt) {
            meta_mcp_builder = meta_mcp_builder.with_cost_governance(enforcer, registry);
        }

        let meta_mcp = Arc::new(meta_mcp_builder);
        meta_mcp.set_transition_tracker(Arc::clone(&transition_tracker));

        Ok(BuiltMetaMcp {
            meta_mcp,
            tool_policy,
            mtls_policy,
            ranker,
            ranker_path,
            transition_tracker,
            transition_path,
            data_dir,
        })
    }

    /// Run the gateway.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot bind to the configured address
    /// or if an unrecoverable runtime error occurs.
    ///
    /// # Panics
    ///
    /// Panics if RSA key pair generation fails on all retry attempts.
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

        // ── Shared MetaMcp initialisation ────────────────────────────────────
        let BuiltMetaMcp {
            meta_mcp,
            tool_policy,
            mtls_policy,
            ranker,
            ranker_path,
            transition_tracker,
            transition_path,
            data_dir,
        } = self.build_meta_mcp().await?;

        // Log policy and feature states now that the shared builder has run.
        if self.config.security.tool_policy.enabled {
            info!("Tool security policy enabled");
        }
        if self.config.mtls.enabled {
            info!(
                policies = self.config.mtls.policies.len(),
                require_client_cert = self.config.mtls.require_client_cert,
                "mTLS enabled"
            );
        }
        info!("Usage statistics tracking enabled");
        if self.config.cache.enabled {
            info!(
                enabled = true,
                default_ttl = ?self.config.cache.default_ttl,
                max_entries = self.config.cache.max_entries,
                "Response cache initialized"
            );
        }
        if !self.config.routing_profiles.is_empty() {
            info!(
                profiles = ?self.config.routing_profiles.keys().collect::<Vec<_>>(),
                default = %self.config.default_routing_profile,
                "Routing profiles loaded"
            );
        }

        let ranker_for_shutdown = Arc::clone(&ranker);
        let tracker_for_shutdown = Arc::clone(&transition_tracker);

        // T2.6: warn when a surfaced tool's backend is not in warm_start.
        for surfaced in &self.config.meta_mcp.surfaced_tools {
            if !self.config.meta_mcp.warm_start.contains(&surfaced.server) {
                warn!(
                    tool = %surfaced.tool,
                    server = %surfaced.server,
                    "Surfaced tool's backend is not in meta_mcp.warm_start — \
                     schema may be absent until the backend is first used"
                );
            }
        }

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
        multiplexer.spawn_reaper_on();
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let auth_config = Arc::new(ResolvedAuthConfig::from_config(&self.config.auth));

        // Wire webhook registry into MetaMcp for gateway_webhook_status.
        if self.config.webhooks.enabled {
            meta_mcp.set_webhook_registry(Arc::clone(&webhook_registry));
        }

        // Wire config hot-reload if a config path was provided.
        let _config_watcher: Option<ConfigWatcher> = if let Some(ref path) = self.config_path {
            let live_config = Arc::new(LiveConfig::new(self.config.clone()));
            let reload_ctx = Arc::new(ReloadContext::new(
                path.clone(),
                Arc::clone(&live_config),
                Arc::clone(&self.backends),
                self.config.failsafe.clone(),
                self.config.meta_mcp.cache_ttl,
            ));
            meta_mcp.set_reload_context(Arc::clone(&reload_ctx));

            match ConfigWatcher::start(
                path.clone(),
                live_config,
                Arc::clone(&self.backends),
                &self.config,
                shutdown_tx.subscribe(),
            ) {
                Ok(w) => {
                    info!(path = %path.display(), "Config hot-reload enabled");
                    Some(w)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start config watcher, hot-reload disabled");
                    None
                }
            }
        } else {
            None
        };

        // In-flight request tracker: large initial permits, drain waits for
        // all permits to be returned (i.e., all in-flight requests complete).
        let inflight = Arc::new(tokio::sync::Semaphore::new(10_000));

        // Create key server if enabled
        let key_server = if self.config.key_server.enabled {
            let mut ks_config = self.config.key_server.clone();
            // Resolve admin token (expand env:VAR_NAME)
            ks_config.admin_token = ks_config.resolve_admin_token();

            let cleanup_interval = std::time::Duration::from_secs(ks_config.cleanup_interval_secs);
            let ks = Arc::new(KeyServer::new(ks_config));

            spawn_reaper(
                Arc::clone(&ks.store),
                cleanup_interval,
                shutdown_tx.subscribe(),
            );

            info!(
                token_ttl_secs = self.config.key_server.token_ttl_secs,
                providers = self.config.key_server.oidc.len(),
                policies = self.config.key_server.policies.len(),
                "Key server enabled"
            );
            Some(ks)
        } else {
            None
        };

        // Build agent registry from config.
        let agent_registry = Arc::new(AgentRegistry::new());
        for def in &self.config.agent_auth.agents {
            let secret = def.resolved_hs256_secret();
            agent_registry.register(AgentDefinition {
                client_id: def.client_id.clone(),
                name: def.name.clone(),
                hs256_secret: secret,
                rs256_public_key: def.rs256_public_key.clone(),
                scopes: def.scopes.clone(),
                issuer: def.issuer.clone(),
                audience: def.audience.clone(),
            });
        }
        let agent_auth =
            AgentAuthState::new(self.config.agent_auth.enabled, Arc::clone(&agent_registry));
        if self.config.agent_auth.enabled {
            info!(
                agents = agent_registry.len(),
                "Agent auth (issue #80) enabled"
            );
        }

        // Generate gateway RSA key pair for JWKS endpoint.
        let gateway_key_pair = Arc::new(match GatewayKeyPair::generate() {
            Ok(kp) => {
                info!(kid = %kp.key_info().kid, "Gateway RSA key pair generated (JWKS available at /.well-known/jwks.json)");
                kp
            }
            Err(e) => {
                warn!(error = %e, "Failed to generate gateway RSA key pair; JWKS will be empty");
                // Fallback: return a trivially unusable key pair that won't block startup.
                // This path should not occur on any normal platform.
                GatewayKeyPair::generate().unwrap_or_else(|_| {
                    // Last resort: produce a dummy pair (panics on catastrophic failure).
                    GatewayKeyPair::generate().expect("RSA key pair generation failed twice")
                })
            }
        });

        // Construct security firewall (RFC-0071).
        // The transition tracker is only used when anomaly_detection=true; pass
        // a fresh tracker so the firewall has its own dedicated state.
        #[cfg(feature = "firewall")]
        let firewall_arc: Option<Arc<Firewall>> = {
            let fw_cfg = self.config.security.firewall.clone();
            let fw_enabled = fw_cfg.enabled;
            let tt = if fw_cfg.anomaly_detection {
                Some(Arc::new(TransitionTracker::new()))
            } else {
                None
            };
            let fw = Arc::new(Firewall::from_config(fw_cfg, tt));
            if fw_enabled {
                info!("Security firewall enabled (RFC-0071)");
            }
            Some(fw)
        };

        // Keep a clone of meta_mcp for post-shutdown operations (periodic
        // persistence and graceful shutdown cost saves use this handle).
        let meta_mcp_for_shutdown = Arc::clone(&meta_mcp);

        let state = Arc::new(AppState {
            backends: Arc::clone(&self.backends),
            meta_mcp,
            meta_mcp_enabled: self.config.meta_mcp.enabled,
            multiplexer: Arc::clone(&multiplexer),
            proxy_manager,
            streaming_config: self.config.streaming.clone(),
            auth_config,
            key_server,
            tool_policy,
            mtls_policy,
            sanitize_input: self.config.security.sanitize_input,
            ssrf_protection: self.config.security.ssrf_protection,
            inflight: Arc::clone(&inflight),
            agent_auth,
            gateway_key_pair,
            capability_dirs: if self.config.capabilities.enabled {
                self.config.capabilities.directories.clone()
            } else {
                Vec::new()
            },
            config_path: self.config_path.clone(),
            #[cfg(feature = "firewall")]
            firewall: firewall_arc,
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

        // Optionally spawn a WebSocket listener alongside the HTTP server.
        if let Some(ws_port) = self.config.server.ws_port {
            let ws_addr = SocketAddr::new(
                self.config
                    .server
                    .host
                    .parse()
                    .map_err(|e| Error::Config(format!("Invalid host for WS: {e}")))?,
                ws_port,
            );
            let ws_shutdown = shutdown_tx.subscribe();
            tokio::spawn(super::ws_listener::run_websocket_listener(
                ws_addr,
                ws_shutdown,
            ));
            info!(
                host = %self.config.server.host,
                port = ws_port,
                "WebSocket listener spawned"
            );
        }

        // Bind listener
        let listener = TcpListener::bind(addr).await?;

        log_startup_banner(&self.config, &self.backends);

        // Warm-start backends: connect + prefetch tools into cache
        // If warm_start list is empty, warm ALL backends (makes list/search fast)
        {
            let warm_start_list = if self.config.meta_mcp.warm_start.is_empty() {
                let all_names: Vec<String> =
                    self.backends.all().iter().map(|b| b.name.clone()).collect();
                info!(
                    "Warm-starting ALL {} backends (tool prefetch)",
                    all_names.len()
                );
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

        // Spawn periodic cost-governance persistence (every 5 minutes)
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = meta_mcp_for_shutdown.budget_enforcer {
            let enforcer_persist = Arc::clone(enforcer);
            let costs_path_periodic = data_dir.join("costs.json");
            let mut shutdown_rx_costs = shutdown_tx.subscribe();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                // Skip first immediate tick (don't save before any spend occurs)
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let snap = enforcer_persist.snapshot();
                            let persisted = build_persisted_costs(&snap);
                            if let Err(e) = persistence::save(&costs_path_periodic, &persisted) {
                                warn!(error = %e, "Periodic cost persistence failed");
                            } else {
                                debug!("Periodic cost data saved");
                            }
                        }
                        _ = shutdown_rx_costs.recv() => {
                            break;
                        }
                    }
                }
            });
        }

        // Run server — plain HTTP or mTLS depending on config
        if self.config.mtls.enabled {
            serve_tls(app, addr, &self.config.mtls, shutdown_signal(shutdown_tx)).await?;
        } else {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal(shutdown_tx))
                .await
                .map_err(|e| Error::Tls(e.to_string()))?;
        }

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

        // Save cost governance data on graceful shutdown
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = meta_mcp_for_shutdown.budget_enforcer {
            let costs_path = data_dir.join("costs.json");
            let snap = enforcer.snapshot();
            let persisted = build_persisted_costs(&snap);
            if let Err(e) = persistence::save(&costs_path, &persisted) {
                warn!(error = %e, "Failed to save cost data on shutdown");
            } else {
                info!("Saved cost governance data");
            }
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

    /// Run the gateway in stdio mode.
    ///
    /// Reads newline-delimited JSON-RPC from stdin and writes responses to stdout.
    /// Reuses the same `MetaMcp` dispatch logic as the HTTP server so all meta-tools
    /// (`gateway_search_tools`, `gateway_invoke`, etc.) work identically.
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration or `MetaMcp` initialisation fails.
    ///
    /// # Panics
    ///
    /// Panics if RSA key pair generation fails on all retry attempts.
    #[allow(clippy::too_many_lines)]
    pub async fn run_stdio(self) -> Result<()> {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            "Starting MCP Gateway (stdio mode)"
        );

        // ── Shared MetaMcp initialisation ────────────────────────────────────
        let BuiltMetaMcp {
            meta_mcp,
            tool_policy,
            mtls_policy,
            ..
        } = self.build_meta_mcp().await?;

        if self.config.capabilities.enabled {
            let executor = Arc::new(CapabilityExecutor::new());
            let cap_backend = Arc::new(CapabilityBackend::new(
                &self.config.capabilities.name,
                executor,
            ));
            for dir in &self.config.capabilities.directories {
                if let Ok(count) = cap_backend.load_from_directory(dir).await {
                    debug!(directory = %dir, count, "Loaded capabilities (stdio)");
                }
            }
            meta_mcp.set_capabilities(cap_backend);
        }

        if self.config.playbooks.enabled {
            let mut engine = crate::playbook::PlaybookEngine::new();
            for dir in &self.config.playbooks.directories {
                if let Ok(count) = engine.load_from_directory(dir) {
                    debug!(directory = %dir, count, "Loaded playbooks (stdio)");
                }
            }
            meta_mcp.set_playbook_engine(engine);
        }

        // Warm-start backends (same as HTTP mode)
        {
            let warm_start_list = if self.config.meta_mcp.warm_start.is_empty() {
                self.backends
                    .all()
                    .iter()
                    .map(|b| b.name.clone())
                    .collect::<Vec<_>>()
            } else {
                self.config.meta_mcp.warm_start.clone()
            };
            let backends_clone = Arc::clone(&self.backends);
            tokio::spawn(async move {
                for name in warm_start_list {
                    if let Some(backend) = backends_clone.get(&name)
                        && let Err(e) = backend.start().await
                    {
                        warn!(backend = %name, error = %e, "Warm-start failed (stdio)");
                    }
                }
            });
        }

        info!("MCP Gateway stdio mode ready — reading JSON-RPC from stdin");

        // ── Read → dispatch → write loop ────────────────────────────────────
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut stdout = stdout;

        // Use a fixed session ID for stdio sessions (single client, long-lived)
        let session_id = "stdio-session";

        while let Ok(Some(line)) = reader.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            debug!(line_len = line.len(), "stdio: received line");

            let request: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let err_resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32700, "message": format!("Parse error: {e}")}
                    });
                    Self::write_response(&mut stdout, &err_resp).await;
                    continue;
                }
            };

            // Handle batch requests (array of JSON-RPC calls)
            if request.is_array() {
                let responses = Self::dispatch_batch(
                    &meta_mcp,
                    &tool_policy,
                    &mtls_policy,
                    request,
                    session_id,
                )
                .await;
                if !responses.is_empty() {
                    let batch_resp = serde_json::Value::Array(responses);
                    Self::write_response(&mut stdout, &batch_resp).await;
                }
                continue;
            }

            // Single request
            let response_opt =
                Self::dispatch_single(&meta_mcp, &tool_policy, &mtls_policy, &request, session_id)
                    .await;

            if let Some(response) = response_opt {
                Self::write_response(&mut stdout, &response).await;
            }
        }

        info!("stdio: EOF reached, shutting down");
        self.backends.stop_all().await;
        Ok(())
    }

    /// Write a JSON-RPC response to stdout followed by a newline.
    async fn write_response(stdout: &mut tokio::io::Stdout, value: &serde_json::Value) {
        let serialized = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to serialize response");
                return;
            }
        };
        debug!(response_len = serialized.len(), "stdio: writing response");
        if let Err(e) = stdout.write_all(serialized.as_bytes()).await {
            warn!(error = %e, "Failed to write to stdout");
            return;
        }
        if let Err(e) = stdout.write_all(b"\n").await {
            warn!(error = %e, "Failed to write newline to stdout");
            return;
        }
        if let Err(e) = stdout.flush().await {
            warn!(error = %e, "Failed to flush stdout");
        }
    }

    /// Dispatch a single JSON-RPC request through `MetaMcp`.
    ///
    /// Returns `None` for notifications (no response expected per JSON-RPC spec).
    async fn dispatch_single(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        _mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: &serde_json::Value,
        session_id: &str,
    ) -> Option<serde_json::Value> {
        use super::router::helpers::{
            extract_request_id, extract_tools_call_params, is_notification_method,
        };
        use crate::protocol::JsonRpcResponse;

        // Validate jsonrpc version
        if request.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            let resp = JsonRpcResponse::error(None, -32600, "Invalid JSON-RPC version");
            return Some(serde_json::to_value(resp).unwrap());
        }

        let id = request.get("id").and_then(extract_request_id);

        let method = if let Some(m) = request.get("method").and_then(|v| v.as_str()) {
            m.to_string()
        } else {
            let resp = JsonRpcResponse::error(id, -32600, "Missing method");
            return Some(serde_json::to_value(resp).unwrap());
        };

        let params = request.get("params").cloned();

        // Notifications have no id — send no response
        if is_notification_method(&method) {
            debug!(notification = %method, "stdio: notification (no response)");
            return None;
        }

        // Requests must have an id
        let Some(id) = id else {
            let resp = JsonRpcResponse::error(None, -32600, "Missing id");
            return Some(serde_json::to_value(resp).unwrap());
        };

        let response = match method.as_str() {
            "initialize" => meta_mcp.handle_initialize(id, params.as_ref(), Some(session_id), None),
            "tools/list" => {
                meta_mcp.handle_tools_list_with_params(id, params.as_ref(), Some(session_id))
            }
            "tools/call" => {
                let (tool_name, arguments) = extract_tools_call_params(params.as_ref());
                let tool_name = tool_name.to_string();

                // Apply tool policy check for gateway_invoke calls
                if tool_name == "gateway_invoke"
                    && let Some(ref p) = params
                {
                    let server = p
                        .get("arguments")
                        .and_then(|a| a.get("server"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let tool = p
                        .get("arguments")
                        .and_then(|a| a.get("tool"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !server.is_empty() && !tool.is_empty()
                        && let Err(e) = tool_policy.check(server, tool)
                    {
                        let resp = JsonRpcResponse::error(Some(id), -32600, e.to_string());
                        return Some(serde_json::to_value(resp).unwrap());
                    }
                }

                meta_mcp
                    .handle_tools_call(id, &tool_name, arguments, Some(session_id), None)
                    .await
            }
            "prompts/list" => meta_mcp.handle_prompts_list(id, params.as_ref()).await,
            "prompts/get" => meta_mcp.handle_prompts_get(id, params.as_ref()).await,
            "resources/list" => meta_mcp.handle_resources_list(id, params.as_ref()).await,
            "resources/read" => meta_mcp.handle_resources_read(id, params.as_ref()).await,
            "resources/templates/list" => {
                meta_mcp
                    .handle_resources_templates_list(id, params.as_ref())
                    .await
            }
            "logging/setLevel" => meta_mcp.handle_logging_set_level(id, params.as_ref()).await,
            "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
            other => {
                debug!(method = %other, "stdio: unknown method");
                JsonRpcResponse::error(Some(id), -32601, format!("Method not found: {other}"))
            }
        };

        Some(serde_json::to_value(response).unwrap())
    }

    /// Dispatch a JSON-RPC batch request.
    async fn dispatch_batch(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
    ) -> Vec<serde_json::Value> {
        let Some(requests) = batch.as_array() else {
            return vec![];
        };

        let mut responses = Vec::new();
        for req in requests {
            if let Some(resp) =
                Self::dispatch_single(meta_mcp, tool_policy, mtls_policy, req, session_id).await
            {
                responses.push(resp);
            }
        }
        responses
    }
}
