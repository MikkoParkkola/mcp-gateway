//! Backend management

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::{BackendConfig, TransportConfig};
use crate::failsafe::{Failsafe, with_retry};
use crate::oauth::{OAuthClient, TokenStorage};
use crate::protocol::{JsonRpcResponse, Tool, ToolsListResult};
use crate::transport::{HttpTransport, StdioTransport, Transport};
use crate::{Error, Result};

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// Configuration
    config: BackendConfig,
    /// Transport
    transport: RwLock<Option<Arc<dyn Transport>>>,
    /// Failsafe mechanisms
    failsafe: Failsafe,
    /// Cached tools
    tools_cache: RwLock<Option<Vec<Tool>>>,
    /// Cache timestamp
    cache_time: RwLock<Option<Instant>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Last used timestamp
    last_used: AtomicU64,
    /// Concurrency limiter
    semaphore: Semaphore,
    /// Request counter
    request_count: AtomicU64,
}

impl Backend {
    /// Create a new backend
    #[must_use]
    pub fn new(
        name: &str,
        config: BackendConfig,
        failsafe_config: &crate::config::FailsafeConfig,
        cache_ttl: Duration,
    ) -> Self {
        // Use per-backend circuit breaker config if provided, otherwise use global
        let cb_config = config.circuit_breaker.clone().unwrap_or_else(|| failsafe_config.circuit_breaker.clone());

        Self {
            name: name.to_string(),
            config,
            transport: RwLock::new(None),
            failsafe: Failsafe::new_with_cb(name, failsafe_config, &cb_config),
            tools_cache: RwLock::new(None),
            cache_time: RwLock::new(None),
            cache_ttl,
            last_used: AtomicU64::new(0),
            semaphore: Semaphore::new(100), // Max concurrent requests
            request_count: AtomicU64::new(0),
        }
    }

    /// Ensure backend is started
    pub async fn ensure_started(&self) -> Result<()> {
        // Update last used
        self.last_used.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );

        // Check if already connected
        {
            let transport = self.transport.read();
            if transport.as_ref().is_some_and(|t| t.is_connected()) {
                return Ok(());
            }
        }

        // Start transport
        self.start().await
    }

    /// Start the backend
    pub async fn start(&self) -> Result<()> {
        info!(backend = %self.name, "Starting backend");

        let transport: Arc<dyn Transport> = match &self.config.transport {
            TransportConfig::Stdio { command, cwd } => {
                let transport = StdioTransport::new(command, self.config.env.clone(), cwd.clone());
                transport.start().await?;
                transport
            }
            TransportConfig::Http {
                http_url,
                streamable_http,
            } => {
                // Create OAuth client if configured
                let oauth_client = self.create_oauth_client(http_url)?;

                let transport = HttpTransport::new_with_oauth(
                    http_url,
                    self.config.headers.clone(),
                    self.config.timeout,
                    *streamable_http,
                    oauth_client,
                )?;
                transport.initialize().await?;
                transport
            }
        };

        *self.transport.write() = Some(transport);

        // Note: Tools are fetched lazily on first get_tools() call
        // We can't pre-cache here because get_tools() -> ensure_started() -> start()
        // would create infinite async recursion

        Ok(())
    }

    /// Create OAuth client if OAuth is configured for this backend
    fn create_oauth_client(&self, resource_url: &str) -> Result<Option<OAuthClient>> {
        let oauth_config = match &self.config.oauth {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        info!(backend = %self.name, "Initializing OAuth client");

        // Create HTTP client for OAuth requests
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Internal(format!("Failed to create OAuth HTTP client: {e}")))?;

        // Get or create token storage
        let storage = Arc::new(
            TokenStorage::default_location()
                .map_err(|e| Error::Internal(format!("Failed to create token storage: {e}")))?,
        );

        // Create OAuth client
        let oauth = OAuthClient::new(
            http_client,
            self.name.clone(),
            resource_url.to_string(),
            oauth_config.scopes.clone(),
            storage,
        );

        Ok(Some(oauth))
    }

    /// Stop the backend
    pub async fn stop(&self) -> Result<()> {
        info!(backend = %self.name, "Stopping backend");

        let transport = self.transport.write().take();
        if let Some(t) = transport {
            t.close().await?;
        }

        Ok(())
    }

    /// Check if backend is running
    pub fn is_running(&self) -> bool {
        self.transport
            .read()
            .as_ref()
            .is_some_and(|t| t.is_connected())
    }

    /// Get cached tools (or fetch if needed)
    pub async fn get_tools(&self) -> Result<Vec<Tool>> {
        // Check cache
        {
            let cache = self.tools_cache.read();
            let cache_time = self.cache_time.read();

            if let (Some(tools), Some(time)) = (cache.as_ref(), cache_time.as_ref()) {
                if time.elapsed() < self.cache_ttl {
                    return Ok(tools.clone());
                }
            }
        }

        // Ensure backend is started before fetching tools
        // Note: start() also calls get_tools() at the end, but by then
        // the transport is set so ensure_started() returns immediately
        self.ensure_started().await?;

        // Fetch tools - use request_internal to avoid recursion
        let response = self.request_internal("tools/list", None).await?;

        if let Some(result) = response.result {
            let tools_result: ToolsListResult = serde_json::from_value(result)?;
            let tools = tools_result.tools;

            // Update cache
            *self.tools_cache.write() = Some(tools.clone());
            *self.cache_time.write() = Some(Instant::now());

            debug!(backend = %self.name, count = tools.len(), "Tools cached");

            return Ok(tools);
        }

        Ok(vec![])
    }

    /// Internal request without `ensure_started` (to avoid recursion)
    async fn request_internal(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        // Get transport
        let transport = {
            let t = self.transport.read();
            t.clone()
        };

        let transport = transport.ok_or_else(|| Error::BackendUnavailable(self.name.clone()))?;

        transport.request(method, params).await
    }

    /// Send a request to the backend
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        // Check failsafe
        if !self.failsafe.can_proceed() {
            let status = self.failsafe.circuit_breaker.status_message();
            return Err(Error::BackendUnavailable(status));
        }

        // Acquire semaphore
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| Error::BackendUnavailable("Concurrency limit reached".to_string()))?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Get transport
        self.ensure_started().await?;

        let transport = {
            let t = self.transport.read();
            t.clone()
        };

        let transport = transport.ok_or_else(|| Error::BackendUnavailable(self.name.clone()))?;

        // Execute with retry
        let name = self.name.clone();
        let result = with_retry(&self.failsafe.retry_policy, &name, || {
            let transport = Arc::clone(&transport);
            let method = method.to_string();
            let params = params.clone();
            async move { transport.request(&method, params).await }
        })
        .await;

        // Record success/failure
        match &result {
            Ok(_) => self.failsafe.record_success(),
            Err(_) => self.failsafe.record_failure(),
        }

        result
    }

    /// Get backend status
    pub fn status(&self) -> BackendStatus {
        BackendStatus {
            name: self.name.clone(),
            running: self.is_running(),
            transport: self.config.transport.transport_type().to_string(),
            tools_cached: self
                .tools_cache
                .read()
                .as_ref()
                .map_or(0, std::vec::Vec::len),
            circuit_state: format!("{:?}", self.failsafe.circuit_breaker.state()),
            request_count: self.request_count.load(Ordering::Relaxed),
        }
    }
}

/// Backend status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendStatus {
    /// Backend name
    pub name: String,
    /// Whether backend is running
    pub running: bool,
    /// Transport type
    pub transport: String,
    /// Number of cached tools
    pub tools_cached: usize,
    /// Circuit breaker state
    pub circuit_state: String,
    /// Total request count
    pub request_count: u64,
}

/// Backend registry - manages all backends
pub struct BackendRegistry {
    /// Backends by name
    backends: DashMap<String, Arc<Backend>>,
}

impl BackendRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: DashMap::new(),
        }
    }

    /// Register a backend
    pub fn register(&self, backend: Arc<Backend>) {
        self.backends.insert(backend.name.clone(), backend);
    }

    /// Get a backend by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<Backend>> {
        self.backends.get(name).map(|b| Arc::clone(&*b))
    }

    /// Get all backends
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Backend>> {
        self.backends.iter().map(|b| Arc::clone(&*b)).collect()
    }

    /// Get all backend statuses
    #[must_use]
    pub fn statuses(&self) -> HashMap<String, BackendStatus> {
        self.backends
            .iter()
            .map(|b| (b.name.clone(), b.status()))
            .collect()
    }

    /// Stop all backends
    pub async fn stop_all(&self) {
        for backend in &self.backends {
            if let Err(e) = backend.stop().await {
                warn!(backend = %backend.name, error = %e, "Failed to stop backend");
            }
        }
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}
