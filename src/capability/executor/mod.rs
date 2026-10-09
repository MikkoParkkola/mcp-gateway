// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability executor - REST API execution with credential injection
//!
//! # Security
//!
//! This executor handles credentials securely:
//! - Credentials are fetched from secure storage at execution time
//! - Credentials are NEVER logged or included in error messages
//! - Credentials are NEVER returned in responses
//!
//! # Credential Sources
//!
//! - `env:VAR_NAME` - Environment variable
//! - `keychain:name` - macOS Keychain
//! - `oauth:provider` - OAuth token from vault (with auto-refresh)
//! - `file:/path/to/file.json:field` - JSON file with dot-path field extraction
//! - `{env.VAR}` - Template format for environment variables

mod cli;
mod cli_argv;
mod cli_run;
mod client;
mod credentials;
pub mod graphql;
pub mod jsonrpc;
mod mcp;
mod params;
mod process;
mod readiness;
pub mod rest;
mod save_file;
pub(crate) use cli_argv::check_cli_templates;
pub use save_file::SaveFileSpec;
mod xml;

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;

use super::response_cache::ResponseCache;
use super::{
    CapabilityDefinition, CapabilityExecutionContext, ProviderConfig, RestConfig,
    validate_capability_url_for_context, validate_personal_capability_identity,
};
use crate::oauth::{TokenInfo, TokenStorage};
use crate::secrets::SecretResolver;
use crate::transform::TransformPipeline;
use crate::{Error, Result};
use client::send_with_retry;

/// Executor for capability REST calls
pub struct CapabilityExecutor {
    pub(super) client: Client,
    /// The client provider OAuth refreshes go through (MIK-8020).
    refresh: client::RefreshClient,
    pub(super) cache: ResponseCache,
    /// OAuth token storage
    pub(super) token_storage: Option<Arc<TokenStorage>>,
    /// Cached OAuth tokens by provider name
    pub(super) oauth_tokens: RwLock<DashMap<String, TokenInfo>>,
    /// Secret resolver for keychain integration
    pub(super) secret_resolver: Arc<SecretResolver>,
    /// Health tracker for outbound transport. Recorded at the transport
    /// boundary (in `send_with_retry`) so it reflects upstream liveness only:
    /// cache hits never touch it, and an HTTP error *status* (4xx/5xx) still
    /// counts as a live backend. Surfaced via the capability backend in
    /// `/health` (MIK-5080).
    pub(super) health: crate::failsafe::HealthTracker,
    /// The environment a credential name resolves against.
    ///
    /// Capability credentials resolve lazily, per call, so this is the reader
    /// that a rotated env file has to reach. Defaults to the process
    /// environment; the gateway replaces it with the overlay startup published
    /// (`with_env`), which a reload republishes.
    pub(super) env: Arc<crate::config::LiveEnv>,
    /// Shared authorization-policy generation. Bumpers clone this Arc;
    /// readers use the `u64` snapshot on [`CapabilityExecutionContext`].
    pub(super) policy_epoch: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// The gateway's per-descriptor account strategies, when this executor
    /// belongs to a gateway.
    ///
    /// `None` for a standalone executor: there is then no account catalogue,
    /// and a capability naming one fails CLOSED at execution rather than
    /// resolving the gateway-held `oauth:<provider>` token. This is a handle on
    /// the ONE registry the shared installer wrote to — not a second store.
    pub(super) account_strategies:
        Option<Arc<crate::identity_propagation::AccountStrategyRegistry>>,
    /// What `service: cli`/`mcp` capabilities may run (MIK-7782).
    pub(super) process_policy: process::ProcessPolicy,
    /// Per-capability bound on simultaneous CLI children.
    pub(super) process_slots: DashMap<String, Arc<tokio::sync::Semaphore>>,
    /// Per-caller MCP capability children (MIK-7782).
    pub(super) mcp_children: Arc<mcp::McpChildren>,
    /// Mirrors the capability backend's multi-user flag.
    pub(super) multi_user: std::sync::atomic::AtomicBool,
}

impl CapabilityExecutor {
    /// Create a new executor.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    pub fn new() -> Self {
        let token_storage = TokenStorage::default_location().ok().map(Arc::new);

        Self {
            client: client::build(None),
            refresh: client::build_refresh(None),
            cache: ResponseCache::new(),
            token_storage,
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("capabilities"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
            process_policy: process::ProcessPolicy::default(),
            process_slots: DashMap::new(),
            mcp_children: Arc::default(),
            multi_user: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A new executor whose calls go through `capabilities.egress_proxy` when
    /// it is set, and direct and pinned otherwise (#1881). A value the load
    /// check would refuse is ignored here, which only ever means direct.
    // Public for the gateway server and the egress tests under tests/; not
    // documented API.
    #[doc(hidden)]
    #[must_use]
    pub fn for_config(config: &crate::config::CapabilityConfig) -> Self {
        let mut executor = Self::new();
        executor.process_policy = process::ProcessPolicy::from_config(config);
        if let Ok(Some(proxy)) = config.egress_proxy_url() {
            tracing::warn!(
                proxy = %crate::config::CapabilityConfig::egress_proxy_for_log(&proxy),
                "capability calls go through capabilities.egress_proxy; the proxy, not the \
                 gateway, resolves their destinations"
            );
            executor.client = client::build(Some(&proxy));
            executor.refresh = client::build_refresh(Some(&proxy));
        }
        executor
    }

    /// Whether several callers share this gateway (set with the capability
    /// backend's flag): an MCP capability then needs an identified caller.
    pub fn set_multi_user(&self, multi_user: bool) {
        self.multi_user
            .store(multi_user, std::sync::atomic::Ordering::Release);
    }

    /// Stop the MCP children of every capability `loaded` rejects.
    pub(crate) fn stop_unloaded_mcp(&self, loaded: &dyn Fn(&str) -> bool) {
        self.mcp_children.evict(std::time::Duration::MAX, loaded);
    }

    /// Share the gateway policy epoch so capability reload can bump it.
    #[must_use]
    pub fn with_policy_epoch(mut self, epoch: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.policy_epoch = Some(epoch);
        self
    }

    /// The MCP revocation generation of one capability.
    pub(crate) fn mcp_generation(&self, capability: &str) -> u64 {
        self.mcp_children.generation(capability)
    }

    /// Revoke the calls of one capability that read an earlier generation
    /// (unload, removal or edit on reload, quarantine).
    pub(crate) fn bump_mcp_generation(&self, capability: &str) {
        self.mcp_children.bump_generation(capability);
    }

    /// Advance the shared epoch after a capability-registry mutation is visible.
    pub(crate) fn bump_policy_epoch(&self) {
        if let Some(epoch) = &self.policy_epoch {
            let prev = epoch.fetch_add(1, std::sync::atomic::Ordering::Release);
            debug_assert!(
                epoch.load(std::sync::atomic::Ordering::Relaxed) > prev,
                "policy epoch must be monotonic"
            );
        }
    }

    /// Resolve credential names against `env` instead of the process
    /// environment.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.secret_resolver = Arc::new(SecretResolver::new().with_env(Arc::clone(&env)));
        self.env = env;
        self
    }

    /// Resolve `auth.account` references against the gateway's per-descriptor
    /// account strategies.
    ///
    /// The SAME registry the shared installer wrote to, so a REST capability
    /// and an MCP backend naming one descriptor reach one strategy instance.
    #[must_use]
    pub(crate) fn with_account_strategies(
        mut self,
        registry: Arc<crate::identity_propagation::AccountStrategyRegistry>,
    ) -> Self {
        self.account_strategies = Some(registry);
        self
    }

    /// TEST SEAM: swap the outbound HTTP client.
    ///
    /// The production client pins DNS, which a fixture's `localhost` endpoint
    /// cannot satisfy. Swapping the CLIENT — the same thing the existing
    /// `cacheable_counting_executor` fixture does by writing the field directly
    /// — is what lets a warm-cache test run WITHOUT `allow_loopback_egress`,
    /// which disables caching outright. This relaxes no SSRF check: the URL
    /// still goes through `validate_capability_url_for_context`, and the flag
    /// that opens IP-literal egress is untouched. `cfg(test)` only, so no
    /// production path can reach it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_test_http_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// The account catalogue this executor validates and resolves against.
    pub(crate) fn account_strategies(
        &self,
    ) -> Option<&crate::identity_propagation::AccountStrategyRegistry> {
        self.account_strategies.as_deref()
    }

    /// Whether outbound transport is currently considered healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    /// Snapshot of outbound transport health metrics.
    #[must_use]
    pub fn health_metrics(&self) -> crate::failsafe::HealthMetrics {
        self.health.metrics()
    }

    /// Create an executor with a custom OAuth token storage.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    #[must_use]
    pub fn with_token_storage(token_storage: Arc<TokenStorage>) -> Self {
        Self {
            client: client::build(None),
            refresh: client::build_refresh(None),
            cache: ResponseCache::new(),
            token_storage: Some(token_storage),
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("capabilities"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
            process_policy: process::ProcessPolicy::default(),
            process_slots: DashMap::new(),
            mcp_children: Arc::default(),
            multi_user: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Store an OAuth token for a provider.
    pub fn set_oauth_token(&self, provider: &str, token: TokenInfo) {
        let tokens = self.oauth_tokens.read();
        tokens.insert(provider.to_string(), token);
    }

    /// Execute a capability with the given parameters.
    ///
    /// Routes through the [`ProtocolExecutor`](rest::ProtocolExecutor) trait:
    /// the provider's `service` field selects the protocol adapter, and the
    /// adapter handles the actual network call. Phase 1 supports REST only;
    /// future protocols are added by implementing the trait and registering
    /// the executor.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or
    /// credentials cannot be resolved.
    #[tracing::instrument(
        skip(self, params),
        fields(
            capability = %capability.name,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn execute(&self, capability: &CapabilityDefinition, params: Value) -> Result<Value> {
        self.execute_with_context(capability, params, CapabilityExecutionContext::default())
            .await
    }

    /// Execute a capability with request-scoped identity context.
    ///
    /// # Errors
    ///
    /// Returns an error if identity validation, request execution, response
    /// handling, or response transformation fails.
    #[tracing::instrument(
        skip(self, params, context),
        fields(
            capability = %capability.name,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn execute_with_context(
        &self,
        capability: &CapabilityDefinition,
        params: Value,
        context: CapabilityExecutionContext,
    ) -> Result<Value> {
        validate_personal_capability_identity(capability, &context)?;

        let start_time = std::time::Instant::now();

        let provider = capability
            .primary_provider()
            .ok_or_else(|| Error::Config("No primary provider configured".to_string()))?;

        // THE ACCOUNT IS RESOLVED BEFORE ANY CACHE IS CONSULTED.
        //
        // A cache key built before the account is known cannot name the account
        // holder, so the first caller's cached result would be handed to the
        // next one. This resolves the capability's PRIMARY `auth.account`
        // reference — carrying the credential the invoke path already resolved
        // when there is one, and rechecking it against the same registry either
        // way — and publishes its opaque binding onto the context the key below
        // is built from. A capability with no account reference, and an explicit
        // `shared` descriptor, are untouched: both keep the existing key and the
        // existing static credential path. Every other refusal returns HERE,
        // before a lookup, so a request that may not have this account can
        // neither be served from cache nor reach the wire.
        let context = self.prepare_account_context(capability, context).await?;

        if let Some(process) = process::spawned_process(capability) {
            process::admit(&self.process_policy, capability, process)?;
        }

        // Check cache first. Loopback-relaxed fetches never enter the store.
        // The key uses the invoke-path snapshot on `context` (revision, profile,
        // epoch, already-resolved cache_binding), never a reload of the Arcs.
        let cache_key = if capability.is_cacheable() && !context.allow_loopback_egress {
            self.build_cache_key(capability, &params, &context)
        } else {
            None
        };
        if let Some(ref cache_key) = cache_key
            && let Some(cached) = self.cache.get(cache_key)
        {
            tracing::debug!("Cache hit");
            return Ok(cached);
        }

        // A process-running provider (MIK-7782) has its own executor; every
        // other provider routes through the protocol executor trait.
        let (response, protocol) = if let Some(process) = process::spawned_process(capability) {
            let response = self
                .execute_process(capability, process, &params, &context)
                .await?;
            (response, provider.service.as_str())
        } else {
            let protocol_config = provider.protocol_config();
            let response = self
                .dispatch_protocol(capability, provider, &protocol_config, &params, &context)
                .await?;
            (response, protocol_config.protocol_name())
        };
        let read = crate::security::tenant_reads::note_read(&response);

        // Apply response transform pipeline if configured
        let response = {
            let pipeline = TransformPipeline::compile(&capability.transform);
            if pipeline.is_noop() {
                response
            } else {
                tracing::debug!(capability = %capability.name, "Applying response transform");
                pipeline.apply(response)
            }
        };

        let latency = start_time.elapsed();
        tracing::info!(
            latency_ms = latency.as_millis(),
            provider = %provider.service,
            protocol = %protocol,
            "Capability executed successfully"
        );

        if let Some(key) = &cache_key {
            self.cache.set(key, &response, read, capability.cache.ttl);
        }

        Ok(response)
    }

    /// Dispatch to the appropriate protocol executor based on
    /// [`ProtocolConfig::protocol_name()`].
    ///
    /// Phase 1: only REST is supported. Future protocols will be looked up
    /// from a `HashMap<&'static str, Arc<dyn ProtocolExecutor>>` registered
    /// at construction time.
    async fn dispatch_protocol(
        &self,
        capability: &CapabilityDefinition,
        provider: &ProviderConfig,
        protocol_config: &super::definition::ProtocolConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        use rest::{ExecutionContext, ProtocolExecutor as _};

        let ctx = ExecutionContext {
            capability,
            timeout_secs: provider.timeout,
            context: context.clone(),
        };

        match protocol_config.protocol_name() {
            "rest" => {
                let executor = rest::RestExecutor { executor: self };
                executor
                    .execute(protocol_config, params.clone(), &ctx)
                    .await
            }
            "graphql" => {
                let executor = graphql::GraphqlExecutor { executor: self };
                executor
                    .execute(protocol_config, params.clone(), &ctx)
                    .await
            }
            "jsonrpc" => {
                let executor = jsonrpc::JsonRpcExecutor { executor: self };
                executor
                    .execute(protocol_config, params.clone(), &ctx)
                    .await
            }
            other => Err(Error::Config(format!(
                "Unsupported protocol '{other}'. Available: rest, graphql, jsonrpc"
            ))),
        }
    }

    /// Execute a request using a provider configuration.
    ///
    /// This is the core REST execution method. It is `pub(crate)` so the
    /// [`RestExecutor`](rest::RestExecutor) adapter can delegate to it.
    #[tracing::instrument(
        skip(self, params),
        fields(
            capability = %capability.name,
            provider = %provider.service
        )
    )]
    pub(crate) async fn execute_provider_with_context(
        &self,
        capability: &CapabilityDefinition,
        provider: &ProviderConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        validate_personal_capability_identity(capability, context)?;

        let config = &provider.config;

        // Merge static_params (capability-defined fixed values) with caller params.
        // Caller-supplied values always win on key collision.
        let body_nulls = params::admitted_nulls(&capability.schema.input, params);
        let merged = config.merge_with_static_params(params);
        let effective_params =
            params::with_path_defaults(config, &capability.schema.input, merged.as_ref());
        let params = effective_params.as_ref();

        let url = self.build_url(config, params)?;
        super::require_tls_for_rest(&url, &capability.auth, config)?;
        validate_capability_url_for_context(&url, context)?;
        tracing::debug!(url = %url, method = %config.method, "Executing REST request");

        let method = config.method.parse::<Method>().map_err(|e| {
            Error::Config(format!("Invalid HTTP method '{}': {}", config.method, e))
        })?;

        let mut request = self.client.request(method, &url);

        // Add headers; skip Authorization when auth.param is set (credential
        // goes as a query param instead of a header).
        let headers = self
            .build_headers(config, &capability.auth, params, context)
            .await?;
        request = request.headers(headers);

        // Inject auth credential as a query parameter when auth.param is specified
        // (e.g., Spoonacular uses ?apiKey=..., Google Maps uses ?key=...)
        if let Some(ref param_name) = capability.auth.param
            && capability.auth.required
        {
            let credential = self.fetch_credential(&capability.auth, context).await?;
            request = request.query(&[(param_name.as_str(), credential.as_str())]);
        }

        // Add query parameters (from config.params with substitution)
        if !config.params.is_empty() {
            let query_params = self.substitute_params(&config.params, params)?;
            request = request.query(&query_params);
        }

        // Add query parameters from param_map
        if !config.param_map.is_empty() {
            let mapped_params = self.map_params(&config.param_map, params)?;
            if !mapped_params.is_empty() {
                request = request.query(&mapped_params);
            }
        }

        // For GET requests, append static_params not already covered by
        // config.params or config.param_map templates.
        if config.method.eq_ignore_ascii_case("GET") && !config.static_params.is_empty() {
            let extra = self.build_extra_static_params(config, params);
            if !extra.is_empty() {
                request = request.query(&extra);
            }
        }

        // Add body for POST/PUT/PATCH
        let method_upper = config.method.to_uppercase();
        if matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH") {
            request = self.attach_request_body(request, config, params, &body_nulls)?;
        }

        let timeout = Duration::from_secs(provider.timeout);
        // Retry timeouts only for idempotent HTTP methods; a timeout on a
        // mutating method may have already been processed upstream.
        let idempotent = matches!(method_upper.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
        let response = send_with_retry(
            request.timeout(timeout),
            "Request",
            idempotent,
            &self.health,
        )
        .await?;

        let body = self.handle_response(response, config).await?;
        match &config.save_file {
            Some(spec) => {
                Box::pin(save_file::save(
                    spec,
                    &body,
                    params,
                    &self.process_policy.files,
                ))
                .await
            }
            None => Ok(body),
        }
    }

    /// Build URL with path parameter substitution.
    #[allow(clippy::unused_self)]
    fn build_url(&self, config: &RestConfig, params: &Value) -> Result<String> {
        let url = if config.uses_endpoint() {
            config.endpoint.clone()
        } else {
            let path = if let Some(selector) = &config.path_selector {
                let selected = match params.get(&selector.parameter) {
                    None | Some(Value::Null) => selector.default.as_str(),
                    Some(Value::String(value)) => value.as_str(),
                    Some(_) => {
                        return Err(Error::Config(format!(
                            "REST path selector parameter '{}' must be a string",
                            selector.parameter
                        )));
                    }
                };

                let path = selector.paths.get(selected).ok_or_else(|| {
                    Error::Config(format!(
                        "No path is configured for REST path selector parameter '{}'",
                        selector.parameter
                    ))
                })?;
                path.replace(&format!("{{{}}}", selector.parameter), selected)
            } else {
                config.path.clone()
            };

            format!("{}{path}", config.base_url)
        };

        // One pass, caller parameters only: a value holding `{other}` is sent
        // as written, and the URL never resolves a secret (MIK-7888).
        crate::secrets::fill_placeholders(&url, |key| {
            Ok(params.get(key).map(|value| match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => serde_json::to_string(value).unwrap_or_default(),
            }))
        })
    }

    /// Build headers with credential injection.
    async fn build_headers(
        &self,
        config: &RestConfig,
        auth: &super::AuthConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        for (name, value_template) in &config.headers {
            let value = self.substitute_string(value_template, params)?;

            // Skip an Authorization header whose TEMPLATE names {access_token}
            // with no access_token parameter to fill it; inject_auth handles
            // auth from the credential key. The value is not consulted: a
            // resolved secret may contain that text (MIK-7888).
            if name.eq_ignore_ascii_case("authorization")
                && value_template.contains("{access_token}")
                && params.get("access_token").is_none()
            {
                continue;
            }

            if let Ok(header_name) = name.parse::<HeaderName>()
                && let Ok(header_value) = value.parse::<HeaderValue>()
            {
                headers.insert(header_name, header_value);
            }
        }

        // Skip header injection when auth.param is set (credential goes as query param).
        if auth.required && auth.param.is_none() {
            self.inject_auth(&mut headers, auth, context).await?;
        }

        Ok(headers)
    }

    /// Inject authentication into headers.
    ///
    /// # Security
    ///
    /// Credentials are fetched from secure storage and injected at runtime.
    /// They are NEVER logged or stored in memory longer than necessary.
    pub(super) async fn inject_auth(
        &self,
        headers: &mut HeaderMap,
        auth: &super::AuthConfig,
        context: &CapabilityExecutionContext,
    ) -> Result<()> {
        // A recognized `auth.account` is resolved through the SHARED identity
        // resolver — the same strategy instance an MCP backend bound to that
        // descriptor holds — and its headers go on the wire VERBATIM: the
        // provider's own `token_type` is authority this executor must not
        // reformat, and a strategy may mint more than one header. `Ok(None)`
        // means either no account reference or an explicit `shared` descriptor,
        // both of which continue on the existing static path below. Any refusal
        // returns here and never reaches it.
        if let Some(account_headers) = self.resolve_account_headers(auth, context).await? {
            for (name, value) in account_headers {
                let header_name: HeaderName = name.parse().map_err(|_| {
                    Error::Config("Invalid account credential header name".to_string())
                })?;
                let header_value: HeaderValue = value
                    .parse()
                    .map_err(|_| Error::Config("Invalid credential format".to_string()))?;
                headers.insert(header_name, header_value);
            }
            return Ok(());
        }

        let credential = self.fetch_credential(auth, context).await?;

        let header_name: HeaderName = auth
            .header
            .as_deref()
            .unwrap_or("Authorization")
            .parse()
            .map_err(|_| Error::Config("Invalid auth header name".to_string()))?;

        let prefix = auth
            .prefix
            .as_deref()
            .unwrap_or(match auth.auth_type.as_str() {
                "basic" => "Basic",
                "api_key" => "",
                _ => "Bearer",
            });

        let header_value = if prefix.is_empty() {
            credential
        } else {
            format!("{prefix} {credential}")
        };

        let header_val: HeaderValue = header_value
            .parse()
            .map_err(|_| Error::Config("Invalid credential format".to_string()))?;
        headers.insert(header_name, header_val);

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Collect `static_params` that are not already covered by `config.params`
    /// or `config.param_map` templates (GET requests only).
    #[allow(clippy::unused_self)] // method interface kept for future use
    fn build_extra_static_params(
        &self,
        config: &RestConfig,
        _params: &Value,
    ) -> Vec<(String, String)> {
        let covered_keys: std::collections::HashSet<&str> = config
            .params
            .keys()
            .chain(config.param_map.keys())
            .map(String::as_str)
            .collect();

        config
            .static_params
            .iter()
            .filter(|(k, _)| !covered_keys.contains(k.as_str()))
            .map(|(k, v)| {
                let v_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => serde_json::to_string(v).unwrap_or_default(),
                };
                (k.clone(), v_str)
            })
            .collect()
    }
}

impl Default for CapabilityExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod ssrf_denial_tests;

#[cfg(test)]
#[path = "gws_real_tests.rs"]
mod gws_real_tests;
#[cfg(test)]
#[path = "../executor_tests.rs"]
mod tests;
