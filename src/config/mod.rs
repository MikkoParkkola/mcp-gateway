//! Configuration management.
//!
//! The top-level [`Config`] struct is loaded via figment (YAML + env vars).
//! Feature-specific types live in the [`features`] sub-module and are
//! re-exported here so callers use `crate::config::KeyServerConfig`, etc.

mod features;

use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::mtls::MtlsConfig;
use crate::routing_profile::RoutingProfileConfig;
use crate::security::verify_remote_server_provenance;
use crate::{Error, Result};

// Re-export all feature config types so external code needs only `crate::config::Foo`.
pub use features::{
    AgentAuthConfig, AgentDefinitionConfig, AgentIdentityConfig, ApiKeyConfig, AuthConfig,
    CacheConfig, CapabilityConfig, CircuitBreakerConfig, CodeModeConfig, ContextIntegrityConfig,
    ContextIntegrityPresetConfig, FailsafeConfig, HealthCheckConfig, IdentityGrantsConfig,
    KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PlaybooksConfig, PolicyMatchConfig, PolicyScopesConfig, RateLimitConfig,
    RemoteServerSigningConfig, ResponseContractConfig, RetryConfig, RuntimeAvailabilityConfig,
    RuntimeConfig, RuntimeProfileConfig, SecurityConfig, StreamingConfig, ToolContractConfig,
    WebhookConfig,
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
    /// `RuntimeProvider` planning and isolation profiles.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Plugin marketplace and local plugin directory.
    #[serde(default)]
    pub marketplace: MarketplaceConfig,
    /// Enterprise control-plane governance (identity-to-role mapping, MIK-6688).
    #[serde(default)]
    pub control_plane: crate::control_plane::ControlPlaneConfig,
    /// Cost governance — per-tool budget enforcement and alerting.
    #[cfg(feature = "cost-governance")]
    #[serde(default)]
    pub cost_governance: crate::cost_accounting::config::CostGovernanceConfig,
}

fn default_routing_profile() -> String {
    "default".to_string()
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct EnvFileConfig {
    env_files: Vec<String>,
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

        let env_file_config: EnvFileConfig = Self::figment(resolved.as_deref())
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;

        Self::load_env_files_from_paths(&env_file_config.env_files);

        let mut config: Self = Self::figment(resolved.as_deref())
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;
        config.expand_env_vars();
        config.validate()?;

        Ok(config)
    }

    /// Load environment files into the process environment.
    /// Supports `~` expansion. Files are processed in order, and later files
    /// override earlier values. Files that don't exist are silently skipped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn load_env_files(&self) {
        Self::load_env_files_from_paths(&self.env_files);
    }

    fn figment(path: Option<&Path>) -> Figment {
        let mut figment = Figment::new();
        if let Some(path) = path {
            figment = figment.merge(Yaml::file(path));
        }

        figment.merge(Env::prefixed("MCP_GATEWAY_").split("__"))
    }

    fn load_env_files_from_paths(env_files: &[String]) {
        for path_str in env_files {
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
                match dotenvy::from_path_override(path) {
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

    /// Validate the configuration for common misconfigurations.
    ///
    /// Checks performed:
    /// - No backend names are empty or contain invalid characters (`/`, `\`, `:`)
    /// - No duplicate backend names (guaranteed by `HashMap`, but checked for
    ///   completeness in case the config is reconstructed from another source)
    /// - Server port is within the valid range (1–65535; 0 means OS-assigned)
    /// - Backend URLs (for HTTP transports) are syntactically valid
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] describing the first violation found.
    pub fn validate(&self) -> Result<()> {
        // Port 0 is technically valid (OS assigns an ephemeral port).
        // No upper bound needed — u16 already caps at 65535.
        if self.server.port == 0 {
            tracing::warn!("Server port is 0; OS will assign an ephemeral port");
        }
        self.validate_backend_names()?;
        self.validate_backend_urls()?;
        self.validate_remote_backend_provenance()?;
        self.validate_required_env_references()?;
        self.runtime.validate()?;
        self.validate_backend_runtime_profiles()?;
        self.control_plane.role_mapping.validate()?;
        self.validate_identity_propagation()?;
        Ok(())
    }

    /// Validate per-backend identity-propagation config (MIK-6704 / ADR-007),
    /// failing closed at load so a misconfigured propagation backend never
    /// starts. Also rejects `SessionMode::PerUser` until the per-user transport
    /// pool ships (a required `PerUser` backend would otherwise reuse one shared
    /// MCP session across users — IDP.7); `Stateless` is supported now.
    fn validate_identity_propagation(&self) -> Result<()> {
        use crate::identity_propagation::SessionMode;
        for (name, backend) in &self.backends {
            let Some(idp) = backend.identity_propagation.as_ref() else {
                continue;
            };
            idp.validate().map_err(|e| {
                Error::ConfigValidation(format!("backend '{name}' identity_propagation: {e}"))
            })?;
            // Only HTTP transports can carry the per-request credential header;
            // stdio/websocket would silently drop it (their transport ignores
            // extra headers), so a propagation-configured non-HTTP backend must
            // fail closed at load rather than dispatch without the credential
            // (MIK-6734 review).
            if !matches!(backend.transport, TransportConfig::Http { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' identity_propagation requires an http transport; \
                     stdio/websocket cannot carry the credential header (IDP.2)"
                )));
            }
            if idp.session_mode == SessionMode::PerUser {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' identity_propagation.session_mode=per_user is not yet \
                     supported (needs the per-user transport pool, MIK-6728 slice 2c); use \
                     stateless for a backend that keeps no per-session state, or wait for the \
                     pool. Refusing to start rather than reuse a shared session (IDP.7)."
                )));
            }
            // A backend running the gateway's own OAuth client authorizes and
            // persists a gateway-held token during initialize(), authenticating
            // the transport session as the gateway *before* the per-request
            // credential override is applied. Combined with identity_propagation
            // that silently defeats per-user propagation: the session is already
            // gateway-authenticated, so the per-user credential rides on top of a
            // channel that no longer represents the end user. Refuse the pairing
            // at load rather than dispatch under a contradictory trust model (F3).
            if backend.oauth.as_ref().is_some_and(|o| o.enabled) {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' cannot combine identity_propagation with its own enabled \
                     oauth client: the backend oauth authorizes and persists a gateway-held token \
                     during initialize(), authenticating the transport session as the gateway \
                     before the per-request credential override — silently defeating per-user \
                     propagation. Set oauth.enabled=false on this backend or remove \
                     identity_propagation (F3)."
                )));
            }
        }
        Ok(())
    }

    fn validate_backend_names(&self) -> Result<()> {
        const INVALID_CHARS: &[char] = &['/', '\\', ':'];
        for name in self.backends.keys() {
            if name.is_empty() {
                return Err(Error::ConfigValidation(
                    "Backend name must not be empty".to_string(),
                ));
            }
            if let Some(bad) = INVALID_CHARS.iter().find(|&&c| name.contains(c)) {
                return Err(Error::ConfigValidation(format!(
                    "Backend name '{name}' contains invalid character '{bad}'"
                )));
            }
        }
        Ok(())
    }

    fn validate_remote_backend_provenance(&self) -> Result<()> {
        let policy = &self.security.remote_server_signing;

        for (name, backend) in &self.backends {
            if !backend.enabled {
                continue;
            }
            let Some((transport, url)) = remote_transport_identity(&backend.transport) else {
                continue;
            };

            let metadata = policy.backends.get(name);
            if policy.require_for_remote_backends || metadata.is_some() {
                let metadata = metadata.ok_or_else(|| {
                    Error::ConfigValidation(format!(
                        "remote backend '{name}' requires signed provenance metadata"
                    ))
                })?;
                verify_remote_server_provenance(name, transport, url, metadata, policy)?;
            }
        }

        Ok(())
    }

    fn validate_backend_urls(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            match &backend.transport {
                TransportConfig::Http { http_url, .. } => {
                    if http_url.is_empty() {
                        return Err(Error::ConfigValidation(format!(
                            "Backend '{name}' has an empty http_url"
                        )));
                    }
                    url::Url::parse(http_url).map_err(|e| {
                        Error::ConfigValidation(format!(
                            "Backend '{name}' has an invalid http_url '{http_url}': {e}"
                        ))
                    })?;
                }
                #[cfg(feature = "a2a")]
                TransportConfig::A2a { a2a_url, .. } => {
                    if a2a_url.is_empty() {
                        return Err(Error::ConfigValidation(format!(
                            "Backend '{name}' has an empty a2a_url"
                        )));
                    }
                    url::Url::parse(a2a_url).map_err(|e| {
                        Error::ConfigValidation(format!(
                            "Backend '{name}' has an invalid a2a_url '{a2a_url}': {e}"
                        ))
                    })?;
                }
                TransportConfig::Stdio { .. } => {}
            }
        }
        Ok(())
    }

    fn validate_required_env_references(&self) -> Result<()> {
        if self.auth.enabled {
            if let Some(token) = self.auth.bearer_token.as_deref() {
                Self::validate_env_reference("auth.bearer_token", token)?;
            }
            for key in &self.auth.api_keys {
                Self::validate_env_reference("auth.api_keys[].key", &key.key)?;
            }
        }

        if self.agent_auth.enabled {
            for agent in &self.agent_auth.agents {
                if let Some(secret) = agent.hs256_secret.as_deref() {
                    Self::validate_env_reference("agent_auth.agents[].hs256_secret", secret)?;
                }
            }
        }

        if self.key_server.enabled
            && let Some(token) = self.key_server.admin_token.as_deref()
        {
            Self::validate_env_reference("key_server.admin_token", token)?;
        }

        Ok(())
    }

    fn validate_env_reference(field: &str, value: &str) -> Result<()> {
        let Some(var_name) = value.strip_prefix("env:") else {
            return Ok(());
        };

        if var_name.is_empty() {
            return Err(Error::ConfigValidation(format!(
                "{field} uses an empty env: reference"
            )));
        }

        let Some(value) = env::var_os(var_name) else {
            return Err(Error::ConfigValidation(format!(
                "{field} references missing environment variable '{var_name}'"
            )));
        };

        if value.to_str().is_none() {
            return Err(Error::ConfigValidation(format!(
                "{field} references environment variable '{var_name}' with non-UTF-8 contents"
            )));
        }

        Ok(())
    }

    fn validate_backend_runtime_profiles(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            let Some(profile_name) = backend.runtime_profile.as_deref() else {
                continue;
            };
            if profile_name.is_empty() {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile must not be empty"
                )));
            }
            if !matches!(backend.transport, TransportConfig::Stdio { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile is currently supported only for stdio backends"
                )));
            }
            if !self.runtime.profiles.contains_key(profile_name) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile references unknown runtime profile '{profile_name}'"
                )));
            }
        }

        Ok(())
    }
}

fn remote_transport_identity(transport: &TransportConfig) -> Option<(&'static str, &str)> {
    match transport {
        TransportConfig::Http { http_url, .. } => Some((transport.transport_type(), http_url)),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => Some((transport.transport_type(), a2a_url)),
        TransportConfig::Stdio { .. } => None,
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
    /// Externally reachable base URL of this gateway (scheme + host + optional
    /// port), e.g. `https://mcp.your-domain.tld`. Set this when the gateway
    /// runs behind a TLS-terminating reverse proxy so RFC 9728
    /// protected-resource metadata advertises the real public HTTPS origin
    /// instead of the raw bind address. When unset, metadata reflects the bind
    /// `host:port`, which is correct only for local / development use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
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
            public_url: None,
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

/// A single backend tool that is statically surfaced in `tools/list`.
///
/// Surfaced tools appear as first-class entries alongside meta-tools, giving
/// LLMs direct one-hop access to high-value tools without the full discovery
/// overhead.  The gateway proxies calls transparently to the configured backend.
///
/// # Example
///
/// ```yaml
/// meta_mcp:
///   surfaced_tools:
///     - server: my_backend
///       tool: my_important_tool
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfacedToolConfig {
    /// Name of the backend server that owns the tool.
    pub server: String,
    /// Exact tool name as reported by the backend's `tools/list`.
    pub tool: String,
}

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
    /// Tools to surface directly in `tools/list` alongside meta-tools.
    ///
    /// Each entry pins one backend tool so that LLMs can call it directly
    /// (one hop) instead of going through `gateway_invoke` (two hops).
    /// The gateway validates at startup that surfaced tool names do not
    /// collide with any meta-tool name.
    #[serde(default)]
    pub surfaced_tools: Vec<SurfacedToolConfig>,
    /// Canonical response-projection rollout mode (MIK-5877).
    ///
    /// `off` (default) — projection never runs, even for a capability that
    /// declares a spec (no contract change for live users). `on` — project
    /// whenever a spec is present. `experimental` — sticky per-session A/B
    /// split between projected (treatment) and raw (control).
    #[serde(default)]
    pub projection_mode: crate::projection::ProjectionMode,
}

impl Default for MetaMcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_tools: true,
            cache_ttl: Duration::from_secs(300),
            warm_start: Vec::new(),
            surfaced_tools: Vec::new(),
            projection_mode: crate::projection::ProjectionMode::default(),
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
    /// Runtime profile name resolved from top-level `runtime.profiles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_profile: Option<String>,
    /// End-user identity propagation (MIK-6704 / ADR-007). When set, the gateway
    /// mints a per-user credential for outbound calls to this backend instead of
    /// presenting only the shared static credential. Absent → unchanged
    /// static-credential behavior (IDP.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_propagation: Option<crate::identity_propagation::IdentityPropagationConfig>,
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
            runtime_profile: None,
            identity_propagation: None,
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
    /// Client secret for providers that issue fixed credentials (e.g. Slack, Figma).
    /// When set, sent as `client_secret` in the token-exchange request.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Hostname for the local OAuth callback server (default: `"localhost"`).
    ///
    /// When set to `"localhost"` (the default) the server dual-binds both
    /// `127.0.0.1` and `[::1]` so the redirect works regardless of how the
    /// browser resolves `localhost`.  Set to `"127.0.0.1"` to force IPv4-only.
    #[serde(default)]
    pub callback_host: Option<String>,
    /// Fixed port for the OAuth callback server (default: OS-assigned ephemeral port).
    ///
    /// Use a fixed port (e.g. `8085`) when the OAuth app in the provider dashboard
    /// requires an exact redirect URI (Slack, Figma, etc.).
    #[serde(default)]
    pub callback_port: Option<u16>,
    /// URL path for the OAuth callback endpoint (default: `"/oauth/callback"`).
    ///
    /// Override when a provider requires a specific redirect URI path.
    #[serde(default)]
    pub callback_path: Option<String>,
    /// Seconds before expiry to proactively refresh the token (default: 300).
    #[serde(default = "default_token_refresh_buffer")]
    pub token_refresh_buffer_secs: u64,
    /// Explicitly bless this gateway-held OAuth token for shared use across
    /// every caller on a multi-user gateway (ADR-008 INV-2).
    ///
    /// Default `false` = fail-closed: a multi-user gateway refuses to serve one
    /// stored token to different users, because the token is held per-backend
    /// (not per-user) and would otherwise let user A act as user B. Set `true`
    /// only for a genuinely shared service account (a team bot, a read-only
    /// public API login); every such dispatch is logged. A single-user gateway
    /// ignores this flag — the sole caller always owns the token.
    #[serde(default)]
    pub shared_account: bool,
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
    /// A2A (`Agent2Agent`) transport.
    ///
    /// The gateway fetches the Agent Card from `<a2a_url>/.well-known/agent.json`
    /// (or a custom path), converts A2A skills to MCP tools, and proxies
    /// `tools/call` invocations as A2A `message/send` requests.
    ///
    /// Requires the `a2a` Cargo feature (enabled by default).
    ///
    /// # Example (gateway.yaml)
    ///
    /// ```yaml
    /// backends:
    ///   travel-agent:
    ///     transport: a2a
    ///     a2a_url: "https://travel.example.com"
    /// ```
    #[cfg(feature = "a2a")]
    A2a {
        /// Base URL of the remote A2A agent.
        a2a_url: String,
        /// Custom path for the Agent Card.
        ///
        /// Defaults to `/.well-known/agent.json` when absent.
        #[serde(default)]
        a2a_agent_card_path: Option<String>,
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
            #[cfg(feature = "a2a")]
            Self::A2a { .. } => "a2a",
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
