//! Capability executor - REST API execution with credential injection
//!
//! # Security
//!
//! This executor handles credentials securely:
//! - Credentials are fetched from secure storage at execution time
//! - Credentials are NEVER logged or included in error messages
//! - Credentials are NEVER returned in responses

use super::{CapabilityDefinition, ProviderConfig, RestConfig};
use crate::{Error, Result};
use dashmap::DashMap;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Response,
};
use serde_json::Value;
use std::time::{Duration, Instant};
use tracing::debug;

/// Executor for capability REST calls
pub struct CapabilityExecutor {
    client: Client,
    cache: ResponseCache,
}

impl CapabilityExecutor {
    /// Create a new executor
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            cache: ResponseCache::new(),
        }
    }

    /// Execute a capability with the given parameters
    pub async fn execute(
        &self,
        capability: &CapabilityDefinition,
        params: Value,
    ) -> Result<Value> {
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
        let response = self
            .execute_provider(capability, provider, &params)
            .await?;

        // Cache response if configured
        if capability.is_cacheable() {
            let cache_key = self.build_cache_key(capability, &params);
            self.cache
                .set(&cache_key, &response, capability.cache.ttl);
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

        // Add query parameters
        if !config.params.is_empty() {
            let query_params = self.substitute_params(&config.params, params)?;
            request = request.query(&query_params);
        }

        // Add body for POST/PUT
        if let Some(ref body_template) = config.body {
            let body = self.substitute_value(body_template, params)?;
            request = request.json(&body);
        }

        // Execute with timeout
        let timeout = Duration::from_secs(provider.timeout);
        let response = request
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Request failed: {}", e)))?;

        // Handle response
        self.handle_response(response, config).await
    }

    /// Build URL with path parameter substitution
    fn build_url(&self, config: &RestConfig, params: &Value) -> Result<String> {
        let mut path = config.path.clone();

        // Substitute path parameters like {id}
        if let Value::Object(map) = params {
            for (key, value) in map {
                let placeholder = format!("{{{}}}", key);
                if path.contains(&placeholder) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    path = path.replace(&placeholder, &value_str);
                }
            }
        }

        Ok(format!("{}{}", config.base_url, path))
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

        let prefix = auth.prefix.as_deref().unwrap_or(match auth.auth_type.as_str() {
            "oauth" | "bearer" => "Bearer",
            "basic" => "Basic",
            "api_key" => "",
            _ => "Bearer",
        });

        let header_value = if prefix.is_empty() {
            credential
        } else {
            format!("{} {}", prefix, credential)
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
    /// - `env:VAR_NAME` - Environment variable
    /// - `oauth:provider` - OAuth token from vault
    async fn fetch_credential(&self, auth: &super::AuthConfig) -> Result<String> {
        let key = &auth.key;

        if key.starts_with("env:") {
            // Environment variable
            let var_name = &key[4..];
            std::env::var(var_name).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{}' not set (required for {})",
                    var_name, auth.description
                ))
            })
        } else if key.starts_with("keychain:") {
            // macOS Keychain
            let keychain_key = &key[9..];
            self.fetch_from_keychain(keychain_key).await
        } else if key.starts_with("oauth:") {
            // OAuth token from vault (TODO: implement OAuth vault)
            let _provider = &key[6..];
            Err(Error::Config(
                "OAuth vault not yet implemented - use env: or keychain: instead".to_string(),
            ))
        } else if key.starts_with("{env.") && key.ends_with('}') {
            // Template format: {env.VAR_NAME}
            let var_name = &key[5..key.len() - 1];
            std::env::var(var_name).map_err(|_| {
                Error::Config(format!(
                    "Environment variable '{}' not set",
                    var_name
                ))
            })
        } else if key.is_empty() {
            Err(Error::Config("No credential key configured".to_string()))
        } else {
            Err(Error::Config(format!(
                "Unknown credential format: {}. Use keychain:, env:, or oauth:",
                key.chars().take(10).collect::<String>()
            )))
        }
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
            .map_err(|e| Error::Config(format!("Failed to access keychain: {}", e)))?;

        if output.status.success() {
            let credential = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string();
            Ok(credential)
        } else {
            Err(Error::Config(format!(
                "Keychain entry '{}' not found. Add it with: security add-generic-password -s '{}' -a 'mcp-gateway' -w 'YOUR_SECRET'",
                key, key
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
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
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
            .map_err(|e| Error::Protocol(format!("Failed to parse response: {}", e)))?;

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
                let placeholder = format!("{{{}}}", key);
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
                let result: Result<Vec<Value>> =
                    arr.iter().map(|v| self.substitute_value(v, params)).collect();
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
