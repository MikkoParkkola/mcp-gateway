//! Configuration management.
//!
//! The top-level [`Config`] struct is loaded via figment (YAML + env vars).
//! Feature-specific types live in the [`features`] sub-module and are
//! re-exported here so callers use `crate::config::KeyServerConfig`, etc.

mod features;

use std::{collections::HashMap, env, path::{Path, PathBuf}, time::Duration};

use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::mtls::MtlsConfig;
use crate::routing_profile::RoutingProfileConfig;
use crate::{Error, Result};

// Re-export all feature config types so external code needs only `crate::config::Foo`.
pub use features::{
    AgentAuthConfig, AgentDefinitionConfig, ApiKeyConfig, AuthConfig, CacheConfig,
    CapabilityConfig, CircuitBreakerConfig, CodeModeConfig, FailsafeConfig, HealthCheckConfig,
    KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PlaybooksConfig, PolicyMatchConfig, PolicyScopesConfig, RateLimitConfig, RetryConfig,
    SecurityConfig, StreamingConfig, WebhookConfig,
};

// ── Root config ───────────────────────────────────────────────────────────────

/// Top-level gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Environment files to load before processing config.
    /// Paths support ~ expansion. Loaded in order, later files override earlier.
    #[serde(default)]
    pub env_files: Vec<String>,
    /// Server configuration.
    pub server: ServerConfig,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Meta-MCP configuration.
    pub meta_mcp: MetaMcpConfig,
    /// Streaming configuration (for real-time notifications).
    pub streaming: StreamingConfig,
    /// Failsafe configuration.
    pub failsafe: FailsafeConfig,
    /// Backend configurations.
    pub backends: HashMap<String, BackendConfig>,
    /// Capability configuration (direct REST API integration).
    pub capabilities: CapabilityConfig,
    /// Cache configuration.
    pub cache: CacheConfig,
    /// Playbook configuration.
    pub playbooks: PlaybooksConfig,
    /// Security policy configuration.
    pub security: SecurityConfig,
    /// Webhook receiver configuration.
    pub webhooks: WebhookConfig,
    /// Routing profiles for session-scoped tool access control.
    #[serde(default)]
    pub routing_profiles: HashMap<String, RoutingProfileConfig>,
    /// Name of the routing profile applied to new sessions.
    #[serde(default = "default_routing_profile")]
    pub default_routing_profile: String,
    /// Code Mode configuration (search+execute pattern).
    #[serde(default)]
    pub code_mode: CodeModeConfig,
    /// Mutual TLS configuration for transport-layer certificate authentication.
    #[serde(default)]
    pub mtls: MtlsConfig,
    /// Key Server — OIDC identity to temporary scoped API keys.
    #[serde(default)]
    pub key_server: KeyServerConfig,
    /// Agent Auth — OAuth 2.0 agent-scoped tool permissions.
    #[serde(default)]
    pub agent_auth: AgentAuthConfig,
    /// Plugin marketplace and local plugin directory.
    #[serde(default)]
    pub marketplace: MarketplaceConfig,
    /// Cost governance — per-tool budget enforcement and alerting.
    #[cfg(feature = "cost-governance")]
    #[serde(default)]
    pub cost_governance: crate::cost_accounting::config::CostGovernanceConfig,
}

fn default_routing_profile() -> String {
    "default".to_string()
}

impl Config {
    /// Candidate config file locations searched when `--config` is not specified.
    ///
    /// Checked in order; the first existing file wins.
    const FALLBACK_PATHS: &'static [&'static str] = &[
        "gateway.yaml",
        "config.yaml",
        // XDG / home-relative entries are generated at runtime by
        // [`Config::fallback_config_path`].
    ];

    /// Discover the config file to load when none is explicitly provided.
    ///
    /// Search order:
    /// 1. `./gateway.yaml`
    /// 2. `./config.yaml`
    /// 3. `~/.config/mcp-gateway/gateway.yaml`
    /// 4. `/etc/mcp-gateway/gateway.yaml`
    ///
    /// Returns `None` if none of the candidates exist (caller uses defaults).
    #[must_use]
    pub fn fallback_config_path() -> Option<PathBuf> {
        // Static relative candidates
        for candidate in Self::FALLBACK_PATHS {
            let p = PathBuf::from(candidate);
            if p.exists() {
                tracing::debug!("Auto-discovered config: {}", p.display());
                return Some(p);
            }
        }

        // Home-relative candidate
        if let Some(home) = dirs::home_dir() {
            let p = home.join(".config/mcp-gateway/gateway.yaml");
            if p.exists() {
                tracing::debug!("Auto-discovered config: {}", p.display());
                return Some(p);
            }
        }

        // System-wide candidate
        let system = PathBuf::from("/etc/mcp-gateway/gateway.yaml");
        if system.exists() {
            tracing::debug!("Auto-discovered config: {}", system.display());
            return Some(system);
        }

        None
    }

    /// Load configuration from file and environment.
    ///
    /// When `path` is `None`, the loader checks common locations in order
    /// (see [`Config::fallback_config_path`]).  If no file is found anywhere,
    /// it falls back to compiled-in defaults plus environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if an explicit `path` is supplied but does not exist,
    /// or if the config file cannot be parsed.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut figment = Figment::new();

        // Resolve the config file: explicit path takes priority; otherwise
        // search well-known fallback locations.
        let resolved: Option<PathBuf> = match path {
            Some(p) => {
                if !p.exists() {
                    return Err(Error::Config(format!(
                        "Config file not found: {}",
                        p.display()
                    )));
                }
                Some(p.to_path_buf())
            }
            None => Self::fallback_config_path(),
        };

        if let Some(ref p) = resolved {
            figment = figment.merge(Yaml::file(p));
        }

        figment = figment.merge(Env::prefixed("MCP_GATEWAY_").split("__"));

        let mut config: Self = figment
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;

        config.load_env_files();
        config.expand_env_vars();

        Ok(config)
    }

    /// Load environment files into the process environment.
    /// Supports ~ expansion. Files that don't exist are silently skipped.
    pub(crate) fn load_env_files(&self) {
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
                    Ok(()) => tracing::info!("Loaded env file: {expanded}"),
                    Err(e) => tracing::warn!("Failed to load env file {expanded}: {e}"),
                }
            } else {
                tracing::debug!("Env file not found (skipped): {expanded}");
            }
        }
    }

    /// Expand `${VAR}` and `${VAR:-default}` patterns in config values.
    fn expand_env_vars(&mut self) {
        let re = Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap();

        for backend in self.backends.values_mut() {
            for value in backend.headers.values_mut() {
                *value = Self::expand_string(&re, value);
            }
            for value in backend.env.values_mut() {
                *value = Self::expand_string(&re, value);
            }
        }

        for dir in &mut self.capabilities.directories {
            *dir = Self::expand_string(&re, dir);
        }
    }

    fn expand_string(re: &Regex, value: &str) -> String {
        re.replace_all(value, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let default = caps.get(2).map_or("", |m| m.as_str());
            env::var(var_name).unwrap_or_else(|_| default.to_string())
        })
        .into_owned()
    }

    /// Get enabled backends only.
    pub fn enabled_backends(&self) -> impl Iterator<Item = (&String, &BackendConfig)> {
        self.backends.iter().filter(|(_, b)| b.enabled)
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Host to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Optional WebSocket transport port.  When `Some`, a WebSocket listener is
    /// spawned alongside the HTTP server on this port.  When `None` (default),
    /// the gateway runs in HTTP-only mode.
    #[serde(default)]
    pub ws_port: Option<u16>,
    /// Request timeout.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    /// Graceful shutdown timeout.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Maximum request body size (bytes).
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 39400,
            ws_port: None,
            request_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024,
        }
    }
}

// ── Marketplace / plugin config ───────────────────────────────────────────────

/// Plugin marketplace and local plugin directory configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MarketplaceConfig {
    /// Base URL of the remote plugin marketplace API.
    pub marketplace_url: String,
    /// Local directory where plugins are installed.
    /// Supports `~` expansion at load time.
    pub plugin_dir: String,
}

impl Default for MarketplaceConfig {
    fn default() -> Self {
        Self {
            marketplace_url: "https://plugins.mcpgateway.io".to_string(),
            plugin_dir: "~/.mcp-gateway/plugins".to_string(),
        }
    }
}

// ── Meta-MCP ──────────────────────────────────────────────────────────────────

/// Meta-MCP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetaMcpConfig {
    /// Enable Meta-MCP mode.
    pub enabled: bool,
    /// Cache tool lists.
    pub cache_tools: bool,
    /// Tool cache TTL.
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    /// Backends to warm-start on gateway startup.
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

// ── Backend ───────────────────────────────────────────────────────────────────

/// Backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    /// Human-readable description.
    pub description: String,
    /// Whether backend is enabled.
    pub enabled: bool,
    /// Transport type.
    #[serde(flatten)]
    pub transport: TransportConfig,
    /// Idle timeout before hibernation.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Request timeout for this backend.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Environment variables (for stdio).
    pub env: HashMap<String, String>,
    /// HTTP headers (for http/sse).
    pub headers: HashMap<String, String>,
    /// OAuth configuration (optional).
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
    /// Secret injection rules.
    #[serde(default)]
    pub secrets: Vec<crate::secret_injection::CredentialRule>,
    /// Pass-through mode: skip gateway tool policy and input sanitization.
    ///
    /// **Security warning**: enabling this bypasses `tool_policy.check()`,
    /// `validate_tool_name()`, and `sanitize_json_value()`. Only set this for
    /// fully-trusted internal backends. Default: `false`.
    #[serde(default)]
    pub passthrough: bool,
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
            secrets: Vec::new(),
            passthrough: false,
        }
    }
}

/// OAuth configuration for a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Enable OAuth for this backend.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// OAuth scopes to request (if empty, uses server's supported scopes).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Client ID (optional — uses dynamic registration or generates one if not set).
    #[serde(default)]
    pub client_id: Option<String>,
    /// Seconds before expiry to proactively refresh the token (default: 300).
    #[serde(default = "default_token_refresh_buffer")]
    pub token_refresh_buffer_secs: u64,
}

fn default_token_refresh_buffer() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

// ── Transport ─────────────────────────────────────────────────────────────────

/// Transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportConfig {
    /// Stdio transport (subprocess).
    Stdio {
        /// Command to execute.
        command: String,
        /// Working directory.
        #[serde(default)]
        cwd: Option<String>,
        /// Override protocol version (auto-negotiated if `None`).
        #[serde(default)]
        protocol_version: Option<String>,
    },
    /// HTTP transport.
    Http {
        /// HTTP URL.
        http_url: String,
        /// Use Streamable HTTP (direct POST, no SSE handshake).
        #[serde(default)]
        streamable_http: bool,
        /// Override protocol version.
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
    /// Get transport type name.
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

// ── humantime_serde ───────────────────────────────────────────────────────────

/// Custom humantime serde module for `Duration`.
pub mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize `Duration` to a human-readable string (e.g., `"30s"`).
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

    /// Deserialize a human-readable duration string (e.g., `"30s"`, `"5m"`, `"100ms"`).
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the string cannot be parsed as a duration.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

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
            s.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(serde::de::Error::custom)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
