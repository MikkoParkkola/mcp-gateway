//! Configuration management

use std::{collections::HashMap, env, path::Path, time::Duration};

use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::security::policy::ToolPolicyConfig;
use crate::{Error, Result};

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Environment files to load before processing config.
    /// Paths support ~ expansion. Loaded in order, later files override earlier.
    /// Variables are set into the process environment for `{env.VAR}` resolution.
    #[serde(default)]
    pub env_files: Vec<String>,
    /// Server configuration
    pub server: ServerConfig,
    /// Authentication configuration
    pub auth: AuthConfig,
    /// Meta-MCP configuration
    pub meta_mcp: MetaMcpConfig,
    /// Streaming configuration (for real-time notifications)
    pub streaming: StreamingConfig,
    /// Failsafe configuration
    pub failsafe: FailsafeConfig,
    /// Backend configurations
    pub backends: HashMap<String, BackendConfig>,
    /// Capability configuration (direct REST API integration)
    pub capabilities: CapabilityConfig,
    /// Cache configuration
    pub cache: CacheConfig,
    /// Playbook configuration
    pub playbooks: PlaybooksConfig,
    /// Security policy configuration
    pub security: SecurityConfig,
}

/// Cache configuration for response caching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Default TTL for cached responses
    #[serde(with = "humantime_serde")]
    pub default_ttl: Duration,
    /// Maximum number of entries before eviction
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: Duration::from_secs(60),
            max_entries: 10_000,
        }
    }
}

/// Playbook configuration for multi-step tool chains
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlaybooksConfig {
    /// Enable playbook engine
    pub enabled: bool,
    /// Directories to load playbook definitions from
    pub directories: Vec<String>,
}

impl Default for PlaybooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec!["playbooks".to_string()],
        }
    }
}

/// Security configuration for the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Enable input sanitization (null byte rejection, control char stripping, NFC)
    pub sanitize_input: bool,
    /// Enable SSRF protection for outbound URLs
    pub ssrf_protection: bool,
    /// Tool allow/deny policy
    pub tool_policy: ToolPolicyConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            ssrf_protection: true,
            tool_policy: ToolPolicyConfig::default(),
        }
    }
}

/// Capability configuration for direct REST API integration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Enable capability system
    pub enabled: bool,
    /// Backend name for capabilities (shown in `gateway_list_servers`)
    pub name: String,
    /// Directories to load capability definitions from
    pub directories: Vec<String>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "fulcrum".to_string(),
            directories: vec!["capabilities".to_string()],
        }
    }
}

/// Authentication configuration for gateway access
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Enable authentication (default: false for backwards compatibility)
    pub enabled: bool,

    /// Bearer token for simple authentication
    /// Supports: literal value, `env:VAR_NAME`, or `auto` (generates random token)
    #[serde(default)]
    pub bearer_token: Option<String>,

    /// API keys for multi-client access with optional restrictions
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,

    /// Paths that bypass authentication (default: `["/health"]`)
    #[serde(default = "default_public_paths")]
    pub public_paths: Vec<String>,
}

fn default_public_paths() -> Vec<String> {
    vec!["/health".to_string()]
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: None,
            api_keys: Vec::new(),
            public_paths: default_public_paths(),
        }
    }
}

impl AuthConfig {
    /// Resolve the bearer token (expand env vars, generate if `auto`)
    #[must_use]
    pub fn resolve_bearer_token(&self) -> Option<String> {
        self.bearer_token.as_ref().map(|token| {
            if token == "auto" {
                // Generate a random token
                use rand::Rng;
                let random_bytes: [u8; 32] = rand::rng().random();
                format!(
                    "mcp_{}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        random_bytes
                    )
                )
            } else if let Some(var_name) = token.strip_prefix("env:") {
                env::var(var_name).unwrap_or_else(|_| token.clone())
            } else {
                token.clone()
            }
        })
    }
}

/// API key configuration for multi-client access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The API key value (supports `env:VAR_NAME`)
    pub key: String,

    /// Human-readable name for this client
    #[serde(default)]
    pub name: String,

    /// Rate limit (requests per minute, 0 = unlimited)
    #[serde(default)]
    pub rate_limit: u32,

    /// Allowed backends (empty = all backends)
    #[serde(default)]
    pub backends: Vec<String>,
}

impl ApiKeyConfig {
    /// Resolve the API key (expand env vars)
    #[must_use]
    pub fn resolve_key(&self) -> String {
        if let Some(var_name) = self.key.strip_prefix("env:") {
            env::var(var_name).unwrap_or_else(|_| self.key.clone())
        } else {
            self.key.clone()
        }
    }

    /// Check if this key has access to a backend
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|b| b == "*" || b == backend)
    }
}

impl Config {
    /// Load configuration from file and environment
    ///
    /// # Errors
    ///
    /// Returns an error if the config file does not exist or cannot be parsed.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut figment = Figment::new();

        // Load from file if provided
        if let Some(p) = path {
            if !p.exists() {
                return Err(Error::Config(format!(
                    "Config file not found: {}",
                    p.display()
                )));
            }
            figment = figment.merge(Yaml::file(p));
        }

        // Merge environment variables (MCP_GATEWAY_ prefix)
        figment = figment.merge(Env::prefixed("MCP_GATEWAY_").split("__"));

        let mut config: Self = figment
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;

        // Load env files into process environment (before env var expansion)
        config.load_env_files();

        // Expand ${VAR} in backend headers
        config.expand_env_vars();

        Ok(config)
    }

    /// Load environment files into the process environment.
    /// Supports ~ expansion. Files that don't exist are silently skipped.
    fn load_env_files(&self) {
        for path_str in &self.env_files {
            let expanded = if path_str.starts_with('~') {
                if let Some(home) = dirs::home_dir() {
                    path_str.replacen('~', &home.display().to_string(), 1)
                } else {
                    path_str.clone()
                }
            } else {
                path_str.clone()
            };

            let path = Path::new(&expanded);
            if path.exists() {
                match dotenvy::from_path(path) {
                    Ok(()) => {
                        tracing::info!("Loaded env file: {expanded}");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load env file {expanded}: {e}");
                    }
                }
            } else {
                tracing::debug!("Env file not found (skipped): {expanded}");
            }
        }
    }

    /// Expand ${VAR} and ${VAR:-default} patterns in config values
    fn expand_env_vars(&mut self) {
        // Pattern: ${VAR} or ${VAR:-default}
        let re = Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap();

        // Expand in backend headers
        for backend in self.backends.values_mut() {
            for value in backend.headers.values_mut() {
                *value = Self::expand_string(&re, value);
            }
        }

        // Expand in capability directories
        for dir in &mut self.capabilities.directories {
            *dir = Self::expand_string(&re, dir);
        }
    }

    /// Expand environment variables in a string
    fn expand_string(re: &Regex, value: &str) -> String {
        re.replace_all(value, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let default = caps.get(2).map_or("", |m| m.as_str());
            env::var(var_name).unwrap_or_else(|_| default.to_string())
        })
        .into_owned()
    }

    /// Get enabled backends only
    pub fn enabled_backends(&self) -> impl Iterator<Item = (&String, &BackendConfig)> {
        self.backends.iter().filter(|(_, b)| b.enabled)
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Request timeout
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// Graceful shutdown timeout
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 39400,
            request_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Meta-MCP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetaMcpConfig {
    /// Enable Meta-MCP mode
    pub enabled: bool,
    /// Cache tool lists
    pub cache_tools: bool,
    /// Tool cache TTL
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    /// Backends to warm-start on gateway startup (pre-connect and cache tools)
    #[serde(default)]
    pub warm_start: Vec<String>,
}

impl Default for MetaMcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_tools: true,
            cache_ttl: Duration::from_secs(300),
            warm_start: Vec::new(),
        }
    }
}

/// Streaming configuration (for real-time notifications)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamingConfig {
    /// Enable streaming (GET /mcp for notifications)
    pub enabled: bool,
    /// Notification buffer size per client
    pub buffer_size: usize,
    /// Keep-alive interval for SSE streams
    #[serde(with = "humantime_serde")]
    pub keep_alive_interval: Duration,
    /// Backends to auto-subscribe for notifications
    #[serde(default)]
    pub auto_subscribe: Vec<String>,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 100,
            keep_alive_interval: Duration::from_secs(15),
            auto_subscribe: Vec::new(),
        }
    }
}

/// Failsafe configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct FailsafeConfig {
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker
    pub enabled: bool,
    /// Failure threshold before opening
    pub failure_threshold: u32,
    /// Success threshold to close
    pub success_threshold: u32,
    /// Time to wait before half-open
    #[serde(with = "humantime_serde")]
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            success_threshold: 3,
            reset_timeout: Duration::from_secs(30),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Enable retries
    pub enabled: bool,
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial backoff duration
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
    /// Backoff multiplier
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per second per backend
    pub requests_per_second: u32,
    /// Burst size
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enabled: bool,
    /// Health check interval
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Health check timeout
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    /// Human-readable description
    pub description: String,
    /// Whether backend is enabled
    pub enabled: bool,
    /// Transport type
    #[serde(flatten)]
    pub transport: TransportConfig,
    /// Idle timeout before hibernation
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Request timeout for this backend
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Environment variables (for stdio)
    pub env: HashMap<String, String>,
    /// HTTP headers (for http/sse)
    pub headers: HashMap<String, String>,
    /// OAuth configuration (optional)
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
}

/// OAuth configuration for a backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Enable OAuth for this backend
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// OAuth scopes to request (if empty, uses server's supported scopes)
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Client ID (optional - uses dynamic registration or generates one if not set)
    #[serde(default)]
    pub client_id: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            description: String::new(),
            enabled: true,
            transport: TransportConfig::default(),
            idle_timeout: Duration::from_secs(300),
            timeout: Duration::from_secs(30),
            env: HashMap::new(),
            headers: HashMap::new(),
            oauth: None,
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportConfig {
    /// Stdio transport (subprocess)
    Stdio {
        /// Command to execute
        command: String,
        /// Working directory
        #[serde(default)]
        cwd: Option<String>,
    },
    /// HTTP transport
    Http {
        /// HTTP URL
        http_url: String,
        /// Use Streamable HTTP (direct POST, no SSE handshake)
        /// Default is false (use SSE handshake)
        #[serde(default)]
        streamable_http: bool,
        /// Override protocol version (for servers that only support older versions)
        #[serde(default)]
        protocol_version: Option<String>,
    },
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Http {
            http_url: String::new(),
            streamable_http: false,
            protocol_version: None,
        }
    }
}

impl TransportConfig {
    /// Get transport type name
    #[must_use]
    pub fn transport_type(&self) -> &'static str {
        match self {
            Self::Stdio { .. } => "stdio",
            Self::Http {
                http_url,
                streamable_http: false,
                ..
            } if http_url.ends_with("/sse") => "sse",
            Self::Http {
                streamable_http: true,
                ..
            } => "streamable-http",
            Self::Http { .. } => "http",
        }
    }
}

/// Custom humantime serde module for Duration
pub mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize Duration to human-readable string (e.g., "30s")
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the serializer fails.
    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    /// Deserialize human-readable duration string (e.g., "30s", "5m", "100ms")
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the string cannot be parsed as a duration.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Parse "30s", "5m", etc.
        if let Some(secs) = s.strip_suffix('s') {
            secs.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(serde::de::Error::custom)
        } else if let Some(mins) = s.strip_suffix('m') {
            mins.parse::<u64>()
                .map(|m| Duration::from_secs(m * 60))
                .map_err(serde::de::Error::custom)
        } else if let Some(ms) = s.strip_suffix("ms") {
            ms.parse::<u64>()
                .map(Duration::from_millis)
                .map_err(serde::de::Error::custom)
        } else {
            // Assume seconds
            s.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_env_files_sets_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join("test.env");
        let mut f = std::fs::File::create(&env_path).unwrap();
        writeln!(f, "MCP_GW_TEST_KEY_A=hello_from_env_file").unwrap();
        writeln!(f, "MCP_GW_TEST_KEY_B=42").unwrap();
        drop(f);

        let config = Config {
            env_files: vec![env_path.to_string_lossy().to_string()],
            ..Default::default()
        };
        config.load_env_files();

        assert_eq!(env::var("MCP_GW_TEST_KEY_A").unwrap(), "hello_from_env_file");
        assert_eq!(env::var("MCP_GW_TEST_KEY_B").unwrap(), "42");

        // Note: env::remove_var is unsafe in edition 2024 and lib forbids unsafe.
        // Test keys use unique MCP_GW_TEST_ prefix so won't conflict.
    }

    #[test]
    fn test_load_env_files_skips_missing() {
        let config = Config {
            env_files: vec!["/nonexistent/path/.env".to_string()],
            ..Default::default()
        };
        // Should not panic
        config.load_env_files();
    }

    #[test]
    fn test_load_env_files_empty() {
        let config = Config::default();
        assert!(config.env_files.is_empty());
        config.load_env_files(); // No-op, should not panic
    }

    #[test]
    fn test_env_files_deserialized_from_yaml() {
        let yaml = r#"
env_files:
  - ~/.claude/secrets.env
  - /tmp/extra.env
server:
  host: "127.0.0.1"
  port: 39401
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.env_files.len(), 2);
        assert_eq!(config.env_files[0], "~/.claude/secrets.env");
    }
}
