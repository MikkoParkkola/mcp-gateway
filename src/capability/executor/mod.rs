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

mod credentials;
mod params;
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
use super::{CapabilityDefinition, ProviderConfig, RestConfig};
use crate::oauth::{TokenInfo, TokenStorage};
use crate::secrets::SecretResolver;
use crate::transform::TransformPipeline;
use crate::{Error, Result};

/// Executor for capability REST calls
pub struct CapabilityExecutor {
    pub(super) client: Client,
    pub(super) cache: ResponseCache,
    /// OAuth token storage
    pub(super) token_storage: Option<Arc<TokenStorage>>,
    /// Cached OAuth tokens by provider name
    pub(super) oauth_tokens: RwLock<DashMap<String, TokenInfo>>,
    /// Secret resolver for keychain integration
    pub(super) secret_resolver: Arc<SecretResolver>,
}

impl CapabilityExecutor {
    /// Build a pooled HTTP client suitable for capability execution.
    ///
    /// Matches the pooling parameters used by [`HttpTransport`] so all
    /// outbound HTTP shares the same connection-management strategy and avoids
    /// per-request FD creation.
    ///
    /// # Panics
    ///
    /// Panics if the reqwest client cannot be created (invalid TLS config, etc.).
    fn build_http_client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client")
    }

    /// Create a new executor.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    pub fn new() -> Self {
        let token_storage = TokenStorage::default_location().ok().map(Arc::new);

        Self {
            client: Self::build_http_client(),
            cache: ResponseCache::new(),
            token_storage,
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
        }
    }

    /// Create an executor with a custom OAuth token storage.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created.
    #[must_use]
    pub fn with_token_storage(token_storage: Arc<TokenStorage>) -> Self {
        Self {
            client: Self::build_http_client(),
            cache: ResponseCache::new(),
            token_storage: Some(token_storage),
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
        }
    }

    /// Store an OAuth token for a provider.
    pub fn set_oauth_token(&self, provider: &str, token: TokenInfo) {
        let tokens = self.oauth_tokens.read();
        tokens.insert(provider.to_string(), token);
    }

    /// Execute a capability with the given parameters.
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
        let start_time = std::time::Instant::now();

        let provider = capability
            .primary_provider()
            .ok_or_else(|| Error::Config("No primary provider configured".to_string()))?;

        // Check cache first
        if capability.is_cacheable() {
            let cache_key = self.build_cache_key(capability, &params);
            if let Some(cached) = self.cache.get(&cache_key) {
                tracing::debug!("Cache hit");
                return Ok(cached);
            }
        }

        let response = self.execute_provider(capability, provider, &params).await?;

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
            "Capability executed successfully"
        );

        if capability.is_cacheable() {
            let cache_key = self.build_cache_key(capability, &params);
            self.cache.set(&cache_key, &response, capability.cache.ttl);
        }

        Ok(response)
    }

    /// Execute a request using a provider configuration.
    #[tracing::instrument(
        skip(self, params),
        fields(
            capability = %capability.name,
            provider = %provider.service
        )
    )]
    async fn execute_provider(
        &self,
        capability: &CapabilityDefinition,
        provider: &ProviderConfig,
        params: &Value,
    ) -> Result<Value> {
        let config = &provider.config;

        // Merge static_params (capability-defined fixed values) with caller params.
        // Caller-supplied values always win on key collision.
        let effective_params = config.merge_with_static_params(params);
        let params = effective_params.as_ref();

        let url = self.build_url(config, params)?;
        tracing::debug!(url = %url, method = %config.method, "Executing REST request");

        let method = config.method.parse::<Method>().map_err(|e| {
            Error::Config(format!("Invalid HTTP method '{}': {}", config.method, e))
        })?;

        let mut request = self.client.request(method, &url);

        // Add headers; skip Authorization when auth.param is set (credential
        // goes as a query param instead of a header).
        let headers = self.build_headers(config, &capability.auth, params).await?;
        request = request.headers(headers);

        // Inject auth credential as a query parameter when auth.param is specified
        // (e.g., Spoonacular uses ?apiKey=..., Google Maps uses ?key=...)
        if let Some(ref param_name) = capability.auth.param
            && capability.auth.required
        {
            let credential = self.fetch_credential(&capability.auth).await?;
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
            request = self.attach_request_body(request, config, params)?;
        }

        let timeout = Duration::from_secs(provider.timeout);
        let response = request
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Request failed: {e}")))?;

        self.handle_response(response, config).await
    }

    /// Build URL with path parameter substitution.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn build_url(&self, config: &RestConfig, params: &Value) -> Result<String> {
        let mut url = if config.uses_endpoint() {
            config.endpoint.clone()
        } else {
            format!("{}{}", config.base_url, config.path)
        };

        if let Value::Object(map) = params {
            for (key, value) in map {
                let placeholder = format!("{{{key}}}");
                if url.contains(&placeholder) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    url = url.replace(&placeholder, &value_str);
                }
            }
        }

        Ok(url)
    }

    /// Build headers with credential injection.
    async fn build_headers(
        &self,
        config: &RestConfig,
        auth: &super::AuthConfig,
        params: &Value,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        for (name, value_template) in &config.headers {
            let value = self.substitute_string(value_template, params)?;

            // Skip Authorization headers with unresolved {access_token} —
            // inject_auth will handle auth from the credential key.
            if name.eq_ignore_ascii_case("authorization") && value.contains("{access_token}") {
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
            self.inject_auth(&mut headers, auth).await?;
        }

        Ok(headers)
    }

    /// Inject authentication into headers.
    ///
    /// # Security
    ///
    /// Credentials are fetched from secure storage and injected at runtime.
    /// They are NEVER logged or stored in memory longer than necessary.
    async fn inject_auth(&self, headers: &mut HeaderMap, auth: &super::AuthConfig) -> Result<()> {
        let credential = self.fetch_credential(auth).await?;

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

    /// Attach the request body for POST/PUT/PATCH methods.
    fn attach_request_body(
        &self,
        mut request: reqwest::RequestBuilder,
        config: &RestConfig,
        params: &Value,
    ) -> Result<reqwest::RequestBuilder> {
        if let Some(ref body_template) = config.body {
            let body = self.substitute_value(body_template, params)?;
            request = request.json(&body);
        } else if !params.is_null() && params.as_object().is_some_and(|o| !o.is_empty()) {
            // No body template — use input params directly as body.
            // Enables LLM APIs where the input IS the request body.
            request = request.json(params);
        }
        Ok(request)
    }
}

impl Default for CapabilityExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../executor_tests.rs"]
mod tests;
