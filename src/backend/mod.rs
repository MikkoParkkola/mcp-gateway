//! Backend management

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{debug, info, warn};

use crate::config::{BackendConfig, TransportConfig};
use crate::failsafe::{Failsafe, with_retry};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::protocol::{
    JsonRpcResponse, Prompt, PromptsListResult, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult, Tool, ToolAnnotations, ToolsListResult,
};
use crate::transport::{HttpTransport, StdioTransport, Transport};
use crate::{Error, Result};

struct CachedMetadata<T> {
    state: RwLock<CachedMetadataState<T>>,
}

struct CachedMetadataState<T> {
    value: Option<Arc<T>>,
    cached_at: Option<Instant>,
    in_flight: Option<watch::Sender<()>>,
}

impl<T> Default for CachedMetadataState<T> {
    fn default() -> Self {
        Self {
            value: None,
            cached_at: None,
            in_flight: None,
        }
    }
}

enum CacheFetchState<'a, T> {
    Cached(Arc<T>),
    Wait(watch::Receiver<()>),
    Fetch(FetchPermit<'a, T>),
}

struct FetchPermit<'a, T> {
    cache: &'a CachedMetadata<T>,
    sender: watch::Sender<()>,
}

impl<T> Drop for FetchPermit<'_, T> {
    fn drop(&mut self) {
        self.cache.state.write().in_flight = None;
        let _ = self.sender.send(());
    }
}

impl<T> CachedMetadata<T> {
    fn new() -> Self {
        Self {
            state: RwLock::new(CachedMetadataState::default()),
        }
    }

    fn with_cached<R>(&self, map: impl FnOnce(Option<&Arc<T>>) -> R) -> R {
        let state = self.state.read();
        map(state.value.as_ref())
    }

    fn is_fresh(&self, ttl: Duration) -> bool {
        let state = self.state.read();
        matches!(
            (&state.value, state.cached_at),
            (Some(_), Some(cached_at)) if cached_at.elapsed() < ttl
        )
    }

    fn snapshot_shared(&self) -> Option<Arc<T>> {
        let state = self.state.read();
        state.value.clone()
    }

    fn store_shared(&self, value: Arc<T>) {
        let mut state = self.state.write();
        state.value = Some(value);
        state.cached_at = Some(Instant::now());
    }

    fn acquire(&self, ttl: Duration) -> CacheFetchState<'_, T> {
        {
            let state = self.state.read();
            if let Some(value) = Self::fresh_value(&state, ttl) {
                return CacheFetchState::Cached(value);
            }
            if let Some(sender) = state.in_flight.as_ref() {
                return CacheFetchState::Wait(sender.subscribe());
            }
        }

        let mut state = self.state.write();
        if let Some(value) = Self::fresh_value(&state, ttl) {
            return CacheFetchState::Cached(value);
        }
        if let Some(sender) = state.in_flight.as_ref() {
            return CacheFetchState::Wait(sender.subscribe());
        }

        let (sender, _receiver) = watch::channel(());
        state.in_flight = Some(sender.clone());
        CacheFetchState::Fetch(FetchPermit {
            cache: self,
            sender,
        })
    }

    async fn get_or_fetch_shared<F, Fut>(&self, ttl: Duration, fetch: F) -> Result<Arc<T>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        loop {
            match self.acquire(ttl) {
                CacheFetchState::Cached(value) => return Ok(value),
                CacheFetchState::Wait(mut receiver) => {
                    let _ = receiver.changed().await;
                }
                CacheFetchState::Fetch(permit) => {
                    let result = fetch().await.map(Arc::new);
                    if let Ok(value) = &result {
                        self.store_shared(Arc::clone(value));
                    }
                    drop(permit);
                    return result;
                }
            }
        }
    }

    fn fresh_value(state: &CachedMetadataState<T>, ttl: Duration) -> Option<Arc<T>> {
        if let (Some(value), Some(cached_at)) = (&state.value, state.cached_at)
            && cached_at.elapsed() < ttl
        {
            return Some(Arc::clone(value));
        }

        None
    }
}

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// Configuration
    config: BackendConfig,
    /// Transport
    transport: RwLock<Option<Arc<dyn Transport>>>,
    /// Serializes backend startup so concurrent warm-start/client requests do
    /// not spawn duplicate stdio processes for the same backend.
    start_lock: Mutex<()>,
    /// Failsafe mechanisms
    failsafe: Failsafe,
    /// Cached tools
    tools_cache: CachedMetadata<Vec<Tool>>,
    /// Cached resources
    resources_cache: CachedMetadata<Vec<Resource>>,
    /// Cached resource templates
    resource_templates_cache: CachedMetadata<Vec<ResourceTemplate>>,
    /// Cached prompts
    prompts_cache: CachedMetadata<Vec<Prompt>>,
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
        Self {
            name: name.to_string(),
            config,
            transport: RwLock::new(None),
            start_lock: Mutex::new(()),
            failsafe: Failsafe::new(name, failsafe_config),
            tools_cache: CachedMetadata::new(),
            resources_cache: CachedMetadata::new(),
            resource_templates_cache: CachedMetadata::new(),
            prompts_cache: CachedMetadata::new(),
            cache_ttl,
            last_used: AtomicU64::new(0),
            semaphore: Semaphore::new(100), // Max concurrent requests
            request_count: AtomicU64::new(0),
        }
    }

    /// Ensure backend is started
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to start.
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

        let _start_guard = self.start_lock.lock().await;

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
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    pub async fn start(&self) -> Result<()> {
        info!(backend = %self.name, "Starting backend");

        let transport: Arc<dyn Transport> = match &self.config.transport {
            TransportConfig::Stdio {
                command,
                cwd,
                protocol_version,
            } => {
                let transport = StdioTransport::new(
                    command,
                    self.config.env.clone(),
                    cwd.clone(),
                    self.config.timeout,
                    protocol_version.clone(),
                );
                transport.start().await?;
                transport
            }
            TransportConfig::Http {
                http_url,
                streamable_http,
                protocol_version,
            } => {
                // Create OAuth client if configured
                let oauth_client = self.create_oauth_client(http_url)?;

                let transport = HttpTransport::new_with_oauth(
                    http_url,
                    self.config.headers.clone(),
                    self.config.timeout,
                    *streamable_http,
                    oauth_client,
                    protocol_version.clone(),
                )?;
                transport.initialize().await?;
                transport
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => {
                // A2A backends are managed by A2aProvider, not the legacy
                // Backend/Transport stack.  Reaching this branch means an A2A
                // backend was incorrectly started through the legacy path.
                return Err(crate::Error::Config(format!(
                    "A2A backend '{name}' (url: {a2a_url}) must be started via A2aProvider, \
                     not the legacy Backend::start() path",
                    name = self.name,
                )));
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
            .map_err(|e| Error::OAuth(format!("Failed to create OAuth HTTP client: {e}")))?;

        // Get or create token storage
        let storage = Arc::new(
            TokenStorage::default_location()
                .map_err(|e| Error::OAuth(format!("Failed to create token storage: {e}")))?,
        );

        // Create OAuth client
        let oauth = OAuthClient::new(
            http_client,
            self.name.clone(),
            resource_url.to_string(),
            oauth_config.scopes.clone(),
            storage,
            OAuthClientConfig {
                client_id: oauth_config.client_id.clone(),
                client_secret: oauth_config.client_secret.clone(),
                callback_host: oauth_config.callback_host.clone(),
                callback_port: oauth_config.callback_port,
                callback_path: oauth_config.callback_path.clone(),
                token_refresh_buffer_secs: oauth_config.token_refresh_buffer_secs,
            },
        );

        Ok(Some(oauth))
    }

    /// Stop the backend
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to close cleanly.
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
    ///
    /// Check if this backend has cached tools (non-blocking).
    ///
    /// Returns `true` if tools are cached and the cache hasn't expired.
    /// Used by `search_tools` to skip unstarted backends.
    #[must_use]
    pub fn has_cached_tools(&self) -> bool {
        self.tools_cache.is_fresh(self.cache_ttl)
    }

    /// Return the number of tools in the cache (non-blocking, no network I/O).
    ///
    /// Returns `0` when the cache is empty or has never been populated.
    /// This is intentionally best-effort: it reads whatever is in the cache
    /// without triggering a refresh, so the count may be stale.
    #[must_use]
    pub fn cached_tools_count(&self) -> usize {
        self.tools_cache
            .with_cached(|tools| tools.map_or(0, |tools| tools.len()))
    }

    /// Return the names of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty `Vec` when the cache is empty or has never been populated.
    /// Intended for producing "did you mean?" suggestions on unknown tool names.
    #[must_use]
    pub fn get_cached_tool_names(&self) -> Vec<String> {
        self.tools_cache.with_cached(|tools| {
            tools
                .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
                .unwrap_or_default()
        })
    }

    /// Return a single tool by exact name from the cache (non-blocking, no network I/O).
    ///
    /// Returns `None` when the cache is empty, has never been populated, or does
    /// not contain a tool with the given name.  Intended for resolving surfaced
    /// tool schemas at `tools/list` time.
    #[must_use]
    pub fn get_cached_tool(&self, name: &str) -> Option<Tool> {
        self.tools_cache.with_cached(|tools| {
            tools.and_then(|tools| tools.iter().find(|t| t.name == name).cloned())
        })
    }

    /// Return a snapshot of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty shared vector when the cache is empty or has never been
    /// populated. Used by the `spec-preview` filtered `tools/list`
    /// implementation to avoid cloning the full tool list on every cache hit.
    #[must_use]
    pub fn get_cached_tools_snapshot(&self) -> Arc<Vec<Tool>> {
        self.tools_cache
            .snapshot_shared()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    async fn get_cached_list_shared<T, F>(
        &self,
        cache: &CachedMetadata<Vec<T>>,
        method: &str,
        kind: &'static str,
        parse: F,
    ) -> Result<Arc<Vec<T>>>
    where
        F: Fn(Value) -> Result<Vec<T>>,
    {
        cache
            .get_or_fetch_shared(self.cache_ttl, || async {
                self.ensure_started().await?;

                let response = self.request_internal(method, None).await?;
                if let Some(error) = response.error {
                    return Err(Error::json_rpc(error.code, error.message));
                }
                let items = if let Some(result) = response.result {
                    parse(result)?
                } else {
                    Vec::new()
                };

                debug!(backend = %self.name, kind, count = items.len(), "Backend metadata cached");

                Ok(items)
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_shared(&self) -> Result<Arc<Vec<Tool>>> {
        self.get_cached_list_shared(&self.tools_cache, "tools/list", "tools", |result| {
            let mut tools = serde_json::from_value::<ToolsListResult>(result)?.tools;
            normalize_tool_annotations(&self.name, &mut tools);
            Ok(tools)
        })
        .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools(&self) -> Result<Vec<Tool>> {
        self.get_tools_shared()
            .await
            .map(|tools| tools.as_ref().clone())
    }

    /// Get cached resources (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_shared(&self) -> Result<Arc<Vec<Resource>>> {
        self.get_cached_list_shared(
            &self.resources_cache,
            "resources/list",
            "resources",
            |result| Ok(serde_json::from_value::<ResourcesListResult>(result)?.resources),
        )
        .await
    }

    /// Get cached resources (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources(&self) -> Result<Vec<Resource>> {
        self.get_resources_shared()
            .await
            .map(|resources| resources.as_ref().clone())
    }

    /// Get cached resource templates (or fetch if needed) without cloning the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_shared(&self) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_cached_list_shared(
            &self.resource_templates_cache,
            "resources/templates/list",
            "resource_templates",
            |result| {
                Ok(
                    serde_json::from_value::<ResourcesTemplatesListResult>(result)?
                        .resource_templates,
                )
            },
        )
        .await
    }

    /// Get cached resource templates (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates(&self) -> Result<Vec<ResourceTemplate>> {
        self.get_resource_templates_shared()
            .await
            .map(|templates| templates.as_ref().clone())
    }

    /// Get cached prompts (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_shared(&self) -> Result<Arc<Vec<Prompt>>> {
        self.get_cached_list_shared(&self.prompts_cache, "prompts/list", "prompts", |result| {
            Ok(serde_json::from_value::<PromptsListResult>(result)?.prompts)
        })
        .await
    }

    /// Get cached prompts (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts(&self) -> Result<Vec<Prompt>> {
        self.get_prompts_shared()
            .await
            .map(|prompts| prompts.as_ref().clone())
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

    /// Internal notification send without `ensure_started` (to avoid recursion)
    async fn notify_internal(&self, method: &str, params: Option<Value>) -> Result<()> {
        let transport = {
            let t = self.transport.read();
            t.clone()
        };

        let transport = transport.ok_or_else(|| Error::BackendUnavailable(self.name.clone()))?;

        transport.notify(method, params).await
    }

    /// Send a request to the backend
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let start_time = std::time::Instant::now();

        // Check failsafe
        if !self.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, "Request rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        // Acquire semaphore
        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Get transport
        self.ensure_started().await?;

        let transport = {
            let t = self.transport.read();
            t.clone()
        };

        let transport = transport.ok_or_else(|| {
            tracing::error!("Transport not available");
            Error::BackendUnavailable(self.name.clone())
        })?;

        // Execute with retry
        let name = self.name.clone();
        let result = with_retry(&self.failsafe.retry_policy, &name, || {
            let transport = Arc::clone(&transport);
            let method = method.to_string();
            let params = params.clone();
            async move { transport.request(&method, params).await }
        })
        .await;

        // Calculate latency
        let latency = start_time.elapsed();

        // Record success/failure with metrics
        match &result {
            Ok(_) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Request completed successfully"
                );
                self.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Request failed");
                self.failsafe.record_failure();
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    /// Send a notification to the backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let start_time = std::time::Instant::now();

        if !self.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, "Notification rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        self.ensure_started().await?;

        let result = self.notify_internal(method, params).await;
        let latency = start_time.elapsed();

        match &result {
            Ok(()) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Notification sent successfully"
                );
                self.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Notification failed");
                self.failsafe.record_failure();
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    #[cfg(test)]
    pub(crate) fn set_transport_for_test(&self, transport: Arc<dyn Transport>) {
        *self.transport.write() = Some(transport);
    }

    /// Return `true` if this backend is configured for pass-through mode.
    ///
    /// When `true`, the direct `/mcp/{name}` endpoint skips tool policy
    /// enforcement and input sanitization for `tools/call` requests.
    /// This must only be enabled for fully-trusted internal backends.
    #[must_use]
    pub fn passthrough(&self) -> bool {
        self.config.passthrough
    }

    /// Return the HTTP URL if this backend uses an HTTP-based transport.
    ///
    /// Returns `None` for stdio backends.
    #[must_use]
    pub fn transport_url(&self) -> Option<&str> {
        match &self.config.transport {
            TransportConfig::Http { http_url, .. } => Some(http_url.as_str()),
            TransportConfig::Stdio { .. } => None,
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => Some(a2a_url.as_str()),
        }
    }

    /// Get backend status
    pub fn status(&self) -> BackendStatus {
        BackendStatus {
            name: self.name.clone(),
            running: self.is_running(),
            transport: self.config.transport.transport_type().to_string(),
            tools_cached: self.cached_tools_count(),
            circuit_state: self.failsafe.circuit_breaker.state().as_str().to_string(),
            request_count: self.request_count.load(Ordering::Relaxed),
        }
    }

    /// Get circuit breaker stats for this backend.
    pub fn circuit_breaker_stats(&self) -> crate::failsafe::CircuitBreakerStats {
        self.failsafe.circuit_breaker.stats()
    }

    /// Get health metrics for this backend.
    pub fn health_metrics(&self) -> crate::failsafe::HealthMetrics {
        self.failsafe.health_metrics()
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

    /// Remove a backend by name (deregister without stopping).
    ///
    /// If the backend must be stopped before removal, call `backend.stop()`
    /// first.  Returns `true` when the backend was present and removed.
    pub fn remove(&self, name: &str) -> bool {
        self.backends.remove(name).is_some()
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

pub(crate) fn normalize_tool_annotations(server: &str, tools: &mut [Tool]) {
    for tool in tools {
        let inferred_read_only = infer_read_only_tool(&tool.name);
        let annotations = tool
            .annotations
            .get_or_insert_with(ToolAnnotations::default);
        let read_only = annotations.read_only_hint.unwrap_or(inferred_read_only);
        let destructive = annotations
            .destructive_hint
            .unwrap_or_else(|| infer_destructive_tool(&tool.name, read_only));

        annotations.read_only_hint = Some(read_only);
        annotations.destructive_hint = Some(destructive);
        annotations.idempotent_hint = Some(
            annotations
                .idempotent_hint
                .unwrap_or_else(|| infer_idempotent_tool(&tool.name, read_only, destructive)),
        );
        annotations.open_world_hint = Some(
            annotations
                .open_world_hint
                .unwrap_or_else(|| infer_open_world_tool(server, &tool.name)),
        );
    }
}

fn infer_read_only_tool(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let read_prefixes = [
        "analyze",
        "auth_lookup",
        "benchmark",
        "calculate",
        "check",
        "classify",
        "count",
        "describe",
        "detect",
        "estimate",
        "fetch",
        "find",
        "fingerprint",
        "get",
        "health",
        "info",
        "list",
        "lookup",
        "preview",
        "query",
        "read",
        "recall",
        "search",
        "status",
        "suggest",
        "validate",
        "verify",
    ];
    read_prefixes
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}_")))
}

fn infer_destructive_tool(name: &str, read_only: bool) -> bool {
    if read_only {
        return false;
    }

    let name = name.to_ascii_lowercase();
    let destructive_words = [
        "archive", "bash", "clear", "delete", "forget", "kill", "login", "post", "remove", "run",
        "send", "submit", "type", "write",
    ];
    destructive_words.iter().any(|word| name.contains(word))
}

fn infer_idempotent_tool(name: &str, read_only: bool, destructive: bool) -> bool {
    if read_only {
        return true;
    }
    if destructive {
        return false;
    }

    let name = name.to_ascii_lowercase();
    name.starts_with("set_")
        || name.starts_with("clear_")
        || name.starts_with("focus_")
        || name.starts_with("connect")
}

fn infer_open_world_tool(server: &str, name: &str) -> bool {
    let server = server.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();

    if matches!(
        server.as_str(),
        "hebb" | "metacognition" | "pithy" | "cached-grep" | "haiku-file-reader"
    ) {
        return false;
    }

    if name.contains("validate") || name.contains("fingerprint") || name.contains("auth_lookup") {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;
    use tokio::sync::Barrier;
    use tokio::time::sleep;

    use super::*;
    use crate::protocol::{RequestId, ToolsListResult};

    struct MockTransport {
        response: JsonRpcResponse,
        delay: Duration,
        connected: AtomicBool,
        requests: AtomicUsize,
    }

    impl MockTransport {
        fn new(response: JsonRpcResponse, delay: Duration) -> Self {
            Self {
                response,
                delay,
                connected: AtomicBool::new(true),
                requests: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            assert_eq!(method, "tools/list");
            self.requests.fetch_add(1, Ordering::SeqCst);
            sleep(self.delay).await;
            Ok(self.response.clone())
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        async fn close(&self) -> Result<()> {
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        }
    }

    fn sample_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(format!("{name} tool")),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn normalize_tool_annotations_fills_missing_hints() {
        let mut tools = vec![sample_tool("search_messages"), sample_tool("send_message")];

        normalize_tool_annotations("beeper", &mut tools);

        let search = tools[0].annotations.as_ref().unwrap();
        assert_eq!(search.read_only_hint, Some(true));
        assert_eq!(search.destructive_hint, Some(false));
        assert_eq!(search.idempotent_hint, Some(true));
        assert_eq!(search.open_world_hint, Some(true));

        let send = tools[1].annotations.as_ref().unwrap();
        assert_eq!(send.read_only_hint, Some(false));
        assert_eq!(send.destructive_hint, Some(true));
        assert_eq!(send.idempotent_hint, Some(false));
        assert_eq!(send.open_world_hint, Some(true));
    }

    #[test]
    fn normalize_tool_annotations_preserves_existing_true_hints_and_adds_false_hints() {
        let mut tool = sample_tool("recall");
        tool.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: None,
            title: None,
        });
        let mut tools = vec![tool];

        normalize_tool_annotations("hebb", &mut tools);

        let annotations = tools[0].annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(true));
        assert_eq!(annotations.open_world_hint, Some(false));
    }

    #[test]
    fn cached_metadata_tracks_freshness() {
        let cache = CachedMetadata::new();
        assert!(!cache.is_fresh(Duration::from_secs(60)));

        cache.store_shared(Arc::new(vec![1, 2, 3]));

        assert!(cache.is_fresh(Duration::from_secs(60)));
        let snapshot = cache.snapshot_shared().unwrap();
        assert_eq!(snapshot.as_ref(), &vec![1, 2, 3]);
        assert_eq!(snapshot.len(), 3);
    }

    #[tokio::test]
    async fn cached_metadata_shared_reads_reuse_arc() {
        let cache = CachedMetadata::new();

        let first = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async { Ok(vec![1, 2, 3]) })
            .await
            .unwrap();
        let second = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                panic!("fresh cache hit should not refetch")
            })
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn cached_metadata_retries_after_fetch_error() {
        let cache = CachedMetadata::new();
        let attempts = AtomicUsize::new(0);

        let first = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(Error::BackendUnavailable("boom".to_string()))
                } else {
                    Ok(vec![7])
                }
            })
            .await;
        assert!(first.is_err());

        let second = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(Error::BackendUnavailable("boom".to_string()))
                } else {
                    Ok(vec![7])
                }
            })
            .await;

        assert_eq!(second.unwrap().as_ref(), &vec![7]);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn get_tools_singleflight_coalesces_concurrent_requests() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let response = JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![sample_tool("echo")],
                next_cursor: None,
            },
        );
        let transport = Arc::new(MockTransport::new(response, Duration::from_millis(25)));
        let transport_dyn: Arc<dyn Transport> = transport.clone();
        *backend.transport.write() = Some(transport_dyn);

        let barrier = Arc::new(Barrier::new(6));
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                backend.get_tools().await.unwrap()
            }));
        }

        barrier.wait().await;

        for task in tasks {
            let tools = task.await.unwrap();
            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].name, "echo");
        }

        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        assert!(backend.has_cached_tools());
        assert_eq!(backend.cached_tools_count(), 1);
        assert_eq!(
            backend.get_cached_tool("echo").map(|tool| tool.name),
            Some("echo".to_string())
        );
    }

    #[tokio::test]
    async fn get_tools_does_not_cache_json_rpc_error_response() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend down");
        let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
        let transport_dyn: Arc<dyn Transport> = transport.clone();
        *backend.transport.write() = Some(transport_dyn);

        let result = backend.get_tools().await;

        assert!(result.is_err());
        assert!(!backend.has_cached_tools());
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    }
}
