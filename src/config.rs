//! Configuration management

use std::{collections::HashMap, env, path::Path, time::Duration};

use figment::{
    providers::{Env, Format, Yaml},
    Figment,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Meta-MCP configuration
    pub meta_mcp: MetaMcpConfig,
    /// Streaming configuration (for real-time notifications)
    pub streaming: StreamingConfig,
    /// Failsafe configuration
    pub failsafe: FailsafeConfig,
    /// Backend configurations
    pub backends: HashMap<String, BackendConfig>,
}

impl Config {
    /// Load configuration from file and environment
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

        // Expand ${VAR} in backend headers
        config.expand_env_vars();

        Ok(config)
    }

    /// Expand ${VAR} patterns in header values
    fn expand_env_vars(&mut self) {
        let re = Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}").unwrap();

        for backend in self.backends.values_mut() {
            for value in backend.headers.values_mut() {
                let expanded = re.replace_all(value, |caps: &regex::Captures| {
                    let var_name = &caps[1];
                    env::var(var_name).unwrap_or_default()
                });
                *value = expanded.into_owned();
            }
        }
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
    },
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Http {
            http_url: String::new(),
            streamable_http: false,
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
    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    /// Deserialize human-readable duration string (e.g., "30s", "5m", "100ms")
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
