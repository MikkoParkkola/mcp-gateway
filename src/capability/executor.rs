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
//! - `{env.VAR}` - Template format for environment variables

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use reqwest::{
    Client, Method, Response,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;
use tracing::debug;

use super::{CapabilityDefinition, ProviderConfig, RestConfig};
use crate::oauth::{TokenInfo, TokenStorage};
use crate::{Error, Result};

/// Executor for capability REST calls
pub struct CapabilityExecutor {
    client: Client,
    cache: ResponseCache,
    /// OAuth token storage
    token_storage: Option<Arc<TokenStorage>>,
    /// Cached OAuth tokens by provider name
    oauth_tokens: RwLock<DashMap<String, TokenInfo>>,
}

impl CapabilityExecutor {
    /// Create a new executor
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        // Try to initialize OAuth token storage
        let token_storage = TokenStorage::default_location().ok().map(Arc::new);

        Self {
            client,
            cache: ResponseCache::new(),
            token_storage,
            oauth_tokens: RwLock::new(DashMap::new()),
        }
    }

    /// Create executor with custom OAuth token storage
    pub fn with_token_storage(token_storage: Arc<TokenStorage>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            cache: ResponseCache::new(),
            token_storage: Some(token_storage),
            oauth_tokens: RwLock::new(DashMap::new()),
        }
    }

    /// Store an OAuth token for a provider
    pub fn set_oauth_token(&self, provider: &str, token: TokenInfo) {
        let tokens = self.oauth_tokens.read();
        tokens.insert(provider.to_string(), token);
    }

    /// Execute a capability with the given parameters
    pub async fn execute(&self, capability: &CapabilityDefinition, params: Value) -> Result<Value> {
        let provider = capability
            .primary_provider()
            .ok_or_else(|| Error::Config("No primary provider configured".to_string()))?;

        // Check cache first
        if capability.is_cacheable() {
            let cache_key = self.build_cache_key(capability, &params);
            if let Some(cached) = self.cache.get(&cache_key) {
                debug!(capability = %capability.name, "Cache hit");
                return Ok(cached);
            }
        }

        // Build and execute request
        let response = self.execute_provider(capability, provider, &params).await?;

        // Cache response if configured
        if capability.is_cacheable() {
            let cache_key = self.build_cache_key(capability, &params);
            self.cache.set(&cache_key, &response, capability.cache.ttl);
        }

        Ok(response)
    }

    /// Execute a request using a provider configuration
    async fn execute_provider(
        &self,
        capability: &CapabilityDefinition,
        provider: &ProviderConfig,
        params: &Value,
    ) -> Result<Value> {
        let config = &provider.config;

        // Build URL
        let url = self.build_url(config, params)?;

        // Build request
        let method = config.method.parse::<Method>().map_err(|e| {
            Error::Config(format!("Invalid HTTP method '{}': {}", config.method, e))
        })?;

        let mut request = self.client.request(method, &url);

        // Add headers with parameter substitution
        let headers = self.build_headers(config, &capability.auth, params).await?;
        request = request.headers(headers);

        // Add query parameters (from config.params with substitution)
        if !config.params.is_empty() {
            let query_params = self.substitute_params(&config.params, params)?;
            request = request.query(&query_params);
        }

        // Add query parameters from param_map (maps input params to API params)
        // e.g., param_map: { query: q } means input "query" becomes API param "q"
        if !config.param_map.is_empty() {
            let mapped_params = self.map_params(&config.param_map, params)?;
            if !mapped_params.is_empty() {
                request = request.query(&mapped_params);
            }
        }

        // Add body for POST/PUT/PATCH
        let method_upper = config.method.to_uppercase();
        if method_upper == "POST" || method_upper == "PUT" || method_upper == "PATCH" {
            if let Some(ref body_template) = config.body {
                // Use explicit body template
                let body = self.substitute_value(body_template, params)?;
                request = request.json(&body);
            } else if !params.is_null() && params.as_object().is_some_and(|o| !o.is_empty()) {
                // No body template - use input params directly as body
                // This enables LLM APIs where input IS the request body
                request = request.json(params);
            }
        }

        // Execute with timeout
        let timeout = Duration::from_secs(provider.timeout);
        let response = request
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Request failed: {e}")))?;

        // Handle response
        self.handle_response(response, config).await
    }

    /// Build URL with path parameter substitution
    fn build_url(&self, config: &RestConfig, params: &Value) -> Result<String> {
        // Use endpoint if set, otherwise combine base_url + path
        let mut url = if config.uses_endpoint() {
            config.endpoint.clone()
        } else {
            format!("{}{}", config.base_url, config.path)
        };

        // Substitute path parameters like {id}
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

    /// Build headers with credential injection
    async fn build_headers(
        &self,
        config: &RestConfig,
        auth: &super::AuthConfig,
        params: &Value,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        // Add configured headers with substitution
        for (name, value_template) in &config.headers {
            let value = self.substitute_string(value_template, params)?;

            // Skip auth header if it references credentials (we'll add it below)
            if name.eq_ignore_ascii_case("authorization") && value.contains("{access_token}") {
                continue;
            }

            if let Ok(header_name) = name.parse::<HeaderName>() {
                if let Ok(header_value) = value.parse::<HeaderValue>() {
                    headers.insert(header_name, header_value);
                }
            }
        }

        // Inject authentication
        if auth.required {
            self.inject_auth(&mut headers, auth).await?;
        }

        Ok(headers)
    }

    /// Inject authentication into headers
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
                "oauth" | "bearer" => "Bearer",
                "basic" => "Basic",
                "api_key" => "",
                _ => "Bearer",
            });

        let header_value = if prefix.is_empty() {
            credential
        } else {
            format!("{prefix} {credential}")
        };

        let header_val: HeaderValue = header_value.parse().map_err(|_| {
            // Don't include credential in error message
            Error::Config("Invalid credential format".to_string())
        })?;
        headers.insert(header_name, header_val);

        Ok(())
    }

    /// Fetch credential from secure storage
    ///
    /// # Security
    ///
    /// This method resolves credential references to actual values.
    /// Supported formats:
    /// - `keychain:name` - macOS Keychain
    /// - `env:VAR_NAME` - Environment variable (explicit)
    /// - `oauth:provider` - OAuth token from vault
    /// - `{env.VAR_NAME}` - Template format
    /// - `VAR_NAME` - Implicit env var (fulcrum compatibility)
    async fn fetch_credential(&self, auth: &super::AuthConfig) -> Result<String> {
        let key = &auth.key;

        if let Some(var_name) = key.strip_prefix("env:") {
            // Explicit environment variable
            std::env::var(var_name).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{}' not set (required for {})",
                    var_name, auth.description
                ))
            })
        } else if let Some(keychain_key) = key.strip_prefix("keychain:") {
            // macOS Keychain
            self.fetch_from_keychain(keychain_key).await
        } else if let Some(provider) = key.strip_prefix("oauth:") {
            // OAuth token from vault
            self.fetch_oauth_token(provider).await
        } else if key.starts_with("{env.") && key.ends_with('}') {
            // Template format: {env.VAR_NAME}
            let var_name = &key[5..key.len() - 1];
            std::env::var(var_name)
                .map_err(|_| Error::Config(format!("Environment variable '{var_name}' not set")))
        } else if key.is_empty() {
            Err(Error::Config("No credential key configured".to_string()))
        } else if Self::looks_like_env_var_name(key) {
            // Fulcrum compatibility: bare name like BRAVE_API_KEY is treated as env var
            std::env::var(key).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{key}' not set. Set it with: export {key}=your_key"
                ))
            })
        } else {
            Err(Error::Config(format!(
                "Unknown credential format: {}. Use keychain:, env:, oauth:, or set environment variable",
                key.chars().take(20).collect::<String>()
            )))
        }
    }

    /// Check if a string looks like an environment variable name
    /// (uppercase letters, digits, underscores, starts with letter)
    fn looks_like_env_var_name(s: &str) -> bool {
        !s.is_empty()
            && s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Fetch OAuth token from vault
    ///
    /// # Token Resolution Order
    ///
    /// 1. Check in-memory cache for valid token
    /// 2. Load from disk storage if available
    /// 3. Return error with instructions if not found
    async fn fetch_oauth_token(&self, provider: &str) -> Result<String> {
        // Check in-memory cache first
        {
            let tokens = self.oauth_tokens.read();
            if let Some(token) = tokens.get(provider) {
                if !token.is_expired() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Try to load from disk storage
        if let Some(ref storage) = self.token_storage {
            // The storage key is based on backend name and resource URL
            // For capabilities, we use a convention: provider name maps to storage key
            if let Some(token) = storage.load(provider, provider) {
                if !token.is_expired() {
                    // Cache it in memory
                    let tokens = self.oauth_tokens.read();
                    tokens.insert(provider.to_string(), token.clone());
                    return Ok(token.access_token);
                }
                // Token exists but is expired - we need a refresh mechanism
                // For now, just report the issue
                return Err(Error::Config(format!(
                    "OAuth token for '{provider}' is expired. Re-authenticate using the gateway OAuth flow or refresh the token."
                )));
            }
        }

        // Not found - provide helpful instructions
        Err(Error::Config(format!(
            "OAuth token for '{provider}' not found. \
            To authorize, use the gateway's OAuth flow: \
            1. Configure an OAuth-enabled backend named '{provider}' in gateway config \
            2. Make a request to trigger authorization \
            3. Complete browser-based authorization \
            Or manually set the token via set_oauth_token()"
        )))
    }

    /// Fetch credential from macOS Keychain
    #[cfg(target_os = "macos")]
    async fn fetch_from_keychain(&self, key: &str) -> Result<String> {
        use std::process::Command;

        // Use security command to fetch from keychain
        // Format: security find-generic-password -s "service" -w
        let output = Command::new("security")
            .args(["find-generic-password", "-s", key, "-w"])
            .output()
            .map_err(|e| Error::Config(format!("Failed to access keychain: {e}")))?;

        if output.status.success() {
            let credential = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(credential)
        } else {
            Err(Error::Config(format!(
                "Keychain entry '{key}' not found. Add it with: security add-generic-password -s '{key}' -a 'mcp-gateway' -w 'YOUR_SECRET'"
            )))
        }
    }

    #[cfg(not(target_os = "macos"))]
    async fn fetch_from_keychain(&self, _key: &str) -> Result<String> {
        Err(Error::Config(
            "Keychain access only supported on macOS. Use env: instead.".to_string(),
        ))
    }

    /// Handle API response
    async fn handle_response(&self, response: Response, config: &RestConfig) -> Result<Value> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Protocol(format!(
                "API returned {}: {}",
                status,
                // Truncate error to avoid leaking sensitive data
                error_text.chars().take(500).collect::<String>()
            )));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| Error::Protocol(format!("Failed to parse response: {e}")))?;

        // Apply response path transformation if configured
        if let Some(ref path) = config.response_path {
            self.extract_path(&body, path)
        } else {
            Ok(body)
        }
    }

    /// Extract a path from JSON response (simple jq-like)
    fn extract_path(&self, value: &Value, path: &str) -> Result<Value> {
        let mut current = value;

        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }

            current = match current {
                Value::Object(map) => map.get(segment).unwrap_or(&Value::Null),
                Value::Array(arr) => {
                    if let Ok(index) = segment.parse::<usize>() {
                        arr.get(index).unwrap_or(&Value::Null)
                    } else {
                        &Value::Null
                    }
                }
                _ => &Value::Null,
            };
        }

        Ok(current.clone())
    }

    /// Substitute parameters in a string template
    fn substitute_string(&self, template: &str, params: &Value) -> Result<String> {
        let mut result = template.to_string();

        // Substitute {param} references
        if let Value::Object(map) = params {
            for (key, value) in map {
                let placeholder = format!("{{{key}}}");
                if result.contains(&placeholder) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => String::new(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    result = result.replace(&placeholder, &value_str);
                }
            }
        }

        // Substitute {env.VAR} references
        let env_pattern = regex::Regex::new(r"\{env\.([^}]+)\}").unwrap();
        let result = env_pattern
            .replace_all(&result, |caps: &regex::Captures| {
                let var_name = &caps[1];
                std::env::var(var_name).unwrap_or_default()
            })
            .to_string();

        Ok(result)
    }

    /// Substitute parameters in a map
    fn substitute_params(
        &self,
        template: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        for (key, value_template) in template {
            let value = self.substitute_string(value_template, params)?;
            // Skip empty values
            if !value.is_empty() && value != "null" {
                result.push((key.clone(), value));
            }
        }

        Ok(result)
    }

    /// Map input parameters to API parameters using `param_map`
    /// e.g., `param_map`: { query: q } maps input "query" to API param "q"
    fn map_params(
        &self,
        param_map: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        if let Value::Object(map) = params {
            for (input_name, api_name) in param_map {
                if let Some(value) = map.get(input_name) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => continue, // Skip null values
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    if !value_str.is_empty() {
                        result.push((api_name.clone(), value_str));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Substitute parameters in a JSON value
    fn substitute_value(&self, template: &Value, params: &Value) -> Result<Value> {
        match template {
            Value::String(s) => {
                let substituted = self.substitute_string(s, params)?;
                // Try to parse as JSON if it looks like JSON
                if (substituted.starts_with('{') && substituted.ends_with('}'))
                    || (substituted.starts_with('[') && substituted.ends_with(']'))
                {
                    Ok(serde_json::from_str(&substituted).unwrap_or(Value::String(substituted)))
                } else {
                    Ok(Value::String(substituted))
                }
            }
            Value::Object(map) => {
                let mut result = serde_json::Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), self.substitute_value(v, params)?);
                }
                Ok(Value::Object(result))
            }
            Value::Array(arr) => {
                let result: Result<Vec<Value>> = arr
                    .iter()
                    .map(|v| self.substitute_value(v, params))
                    .collect();
                Ok(Value::Array(result?))
            }
            _ => Ok(template.clone()),
        }
    }

    /// Build cache key for a request
    fn build_cache_key(&self, capability: &CapabilityDefinition, params: &Value) -> String {
        let params_hash = {
            let json = serde_json::to_string(params).unwrap_or_default();
            format!("{:x}", md5::compute(json.as_bytes()))
        };
        format!("{}:{}", capability.name, params_hash)
    }
}

impl Default for CapabilityExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple response cache with TTL
struct ResponseCache {
    entries: DashMap<String, CacheEntry>,
}

struct CacheEntry {
    value: Value,
    expires_at: Instant,
}

impl ResponseCache {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    fn get(&self, key: &str) -> Option<Value> {
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.value.clone());
            }
            // Entry expired, remove it
            drop(entry);
            self.entries.remove(key);
        }
        None
    }

    fn set(&self, key: &str, value: &Value, ttl_seconds: u64) {
        let entry = CacheEntry {
            value: value.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
        };
        self.entries.insert(key.to_string(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let executor = CapabilityExecutor::new();
        let config = RestConfig {
            base_url: "https://api.example.com".to_string(),
            path: "/users/{id}/posts/{post_id}".to_string(),
            ..Default::default()
        };

        let params = serde_json::json!({
            "id": "123",
            "post_id": 456
        });

        let url = executor.build_url(&config, &params).unwrap();
        assert_eq!(url, "https://api.example.com/users/123/posts/456");
    }

    #[test]
    fn test_substitute_string() {
        let executor = CapabilityExecutor::new();
        let template = "Hello {name}, your score is {score}";
        let params = serde_json::json!({
            "name": "World",
            "score": 100
        });

        let result = executor.substitute_string(template, &params).unwrap();
        assert_eq!(result, "Hello World, your score is 100");
    }

    #[test]
    fn test_extract_path() {
        let executor = CapabilityExecutor::new();
        let value = serde_json::json!({
            "data": {
                "users": [
                    {"name": "Alice"},
                    {"name": "Bob"}
                ]
            }
        });

        let result = executor.extract_path(&value, "data.users").unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 2);

        let result = executor.extract_path(&value, "data.users.0.name").unwrap();
        assert_eq!(result, "Alice");
    }

    #[test]
    fn test_cache() {
        let cache = ResponseCache::new();
        let value = serde_json::json!({"test": true});

        cache.set("key1", &value, 60);
        assert_eq!(cache.get("key1"), Some(value));

        assert_eq!(cache.get("nonexistent"), None);
    }
}
