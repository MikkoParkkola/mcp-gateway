// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend, OAuth and transport configuration (split from `mod.rs`).

use super::{
    ChainMode, Deserialize, Duration, HashMap, InputSchemaEnforcement, Serialize, humantime_serde,
};

// ── Backend ───────────────────────────────────────────────────────────────────

/// Backend configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    /// Human-readable description.
    pub description: String,
    /// Whether backend is enabled.
    pub enabled: bool,
    /// Transport type.
    #[serde(flatten)]
    pub transport: TransportConfig,
    /// Stop this backend's process after it has been unused for this long,
    /// restarting it on the next request.
    ///
    /// Valid ONLY for a backend whose process the gateway owns — one declared
    /// with a `command`. For an externally managed HTTP endpoint the gateway can
    /// close its client connection but cannot stop the server on the other end,
    /// so the setting is rejected at config load rather than silently accepted.
    /// Locality does not grant ownership: a local HTTP MCP server is still not
    /// ours to stop.
    ///
    /// `None` means never stop the backend once started, which is the historical
    /// behaviour.
    #[serde(default, with = "humantime_serde::option")]
    pub stop_when_idle_for: Option<Duration>,
    /// Longest single JSON-RPC message, in bytes, this stdio backend may send
    /// (one newline-terminated line). `None` means 16 MiB. Valid only for a
    /// backend the gateway starts with a `command`; between 64 KiB and 1 GiB.
    #[serde(default)]
    pub max_frame_bytes: Option<usize>,
    /// Request timeout for this backend.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Environment variables (for stdio).
    pub env: HashMap<String, String>,
    /// HTTP headers (for http/sse). On a `ws_url` backend they go only on the
    /// upgrade request, once per connect, never per message.
    pub headers: HashMap<String, String>,
    /// OAuth configuration (optional).
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
    /// Secret injection rules.
    #[serde(default)]
    pub secrets: Vec<crate::secret_injection::CredentialRule>,
    /// Pass-through mode: skip input sanitization on this backend's
    /// `tools/call` requests.
    ///
    /// **Security warning**: enabling this forwards caller-supplied arguments
    /// to the backend without `sanitize_json_value()`. It is narrower than the
    /// name suggests — `apply_backend_tool_call_security` gates only
    /// sanitization on this flag, so tool-name validation, the tool-policy
    /// authorization check and the firewall still run. Only set this for
    /// fully-trusted internal backends. Default: `false`.
    #[serde(default)]
    pub passthrough: bool,
    /// Tools served although their description fails the tool-poisoning
    /// check (AX-010), each pinned to the descriptor digest the gateway logs
    /// when it withholds the tool. A changed description is withheld again.
    #[serde(default)]
    pub allow_flagged_tools: std::collections::BTreeMap<String, String>,
    /// Undeclared tool-call argument keys: `closed` (default), `standard`, `off`.
    pub input_schema_enforcement: InputSchemaEnforcement,
    /// Permit this backend to carry credentials over cleartext `http://` or
    /// `ws://` to a non-loopback host.
    ///
    /// **Security warning**: a credential sent to a non-loopback `http://`
    /// endpoint is readable by every host on the path and is replayable
    /// forever. Config load REFUSES that combination unless this is set, which
    /// makes the exception a recorded operator decision rather than a typo.
    /// Loopback is exempt without the flag: the packet does not leave the
    /// machine. Default: `false`.
    #[serde(default)]
    pub allow_cleartext_credentials: bool,
    /// Runtime profile name resolved from top-level `runtime.profiles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_profile: Option<String>,
    /// End-user identity propagation (MIK-6704 / ADR-007). When set, the gateway
    /// mints a per-user credential for outbound calls to this backend instead of
    /// presenting only the shared static credential. Absent → unchanged
    /// static-credential behavior (IDP.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_propagation: Option<crate::identity_propagation::IdentityPropagationConfig>,
    /// Explicit reference to an `accounts.descriptors` MAP KEY: the descriptor's
    /// logical id, never a registry name, provider id or email. An undeclared
    /// key refuses startup (`account_bindings`). Mutually exclusive with
    /// [`Self::identity_propagation`]: two answers to how this backend is
    /// authenticated are a conflict, not a precedence rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// ASI07: whether this backend's signature chain is ignored, verified or
    /// required (design 2026-09-30-asi07-chain-inc3, D1). Default `off`.
    pub signature_chain: ChainMode,
    /// Key ids that may sign the origin link of this backend's chains.
    pub chain_origins: Vec<String>,
    /// Key id that must sign the last link this backend delivers.
    pub chain_signer: Option<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            description: String::new(),
            enabled: true,
            transport: TransportConfig::default(),
            stop_when_idle_for: None,
            max_frame_bytes: None,
            timeout: Duration::from_secs(30),
            env: HashMap::new(),
            headers: HashMap::new(),
            oauth: None,
            secrets: Vec::new(),
            passthrough: false,
            input_schema_enforcement: InputSchemaEnforcement::Closed,
            allow_flagged_tools: std::collections::BTreeMap::new(),
            allow_cleartext_credentials: false,
            runtime_profile: None,
            identity_propagation: None,
            account: None,
            signature_chain: ChainMode::Off,
            chain_origins: Vec::new(),
            chain_signer: None,
        }
    }
}

/// OAuth configuration for a backend.
#[derive(Clone, Serialize, Deserialize)]
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

// Manual `Debug` that redacts the fixed OAuth client secret (CWE-532, mirrors
// PR #323). A derived `Debug` would print `client_secret` verbatim into any
// trace or error context; only its presence is surfaced.
impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("OAuthConfig")
            .field("enabled", &self.enabled)
            .field("scopes", &self.scopes)
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret))
            .field("callback_host", &self.callback_host)
            .field("callback_port", &self.callback_port)
            .field("callback_path", &self.callback_path)
            .field("token_refresh_buffer_secs", &self.token_refresh_buffer_secs)
            .field("shared_account", &self.shared_account)
            .finish()
    }
}

pub(super) fn default_token_refresh_buffer() -> u64 {
    300
}
pub(super) fn default_true() -> bool {
    true
}

// ── Transport ─────────────────────────────────────────────────────────────────

/// Transport configuration. Its `Debug` (in `backend_debug.rs`) redacts
/// URLs and commands, which can carry credentials.
#[derive(Clone, Serialize, Deserialize)]
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
        /// `true`: Streamable HTTP (direct POST). `false`: the legacy SSE
        /// handshake. Absent: detected at connect, POST `initialize` first and
        /// the SSE `GET` only if that POST is refused with a 4xx (MCP
        /// backwards-compatibility rule).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        streamable_http: Option<bool>,
        /// Override protocol version.
        #[serde(default)]
        protocol_version: Option<String>,
    },
    /// WebSocket transport: one persistent socket per backend, legacy
    /// `initialize` handshake only. `headers` go on the upgrade request once.
    WebSocket {
        /// WebSocket URL (`ws://` or `wss://`).
        ws_url: String,
        /// Override protocol version (a pre-2026-07-28 revision).
        #[serde(default)]
        protocol_version: Option<String>,
    },
    /// A2A (`Agent2Agent`) transport.
    ///
    /// Outbound delegation to an A2A 1.0 agent (JSON-RPC binding). The gateway
    /// fetches the Agent Card from `<a2a_url>/.well-known/agent-card.json` (or
    /// `a2a_agent_card_path`), exposes the agent as one tool, `send_message`,
    /// and sends each call as an A2A `SendMessage` to the card's JSON-RPC
    /// endpoint, which must share the origin of `a2a_url`.
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
        /// Defaults to `/.well-known/agent-card.json` when absent.
        #[serde(default)]
        a2a_agent_card_path: Option<String>,
    },
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Http {
            http_url: String::new(),
            streamable_http: None,
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
                streamable_http: Some(false) | None,
                ..
            } if http_url.ends_with("/sse") => "sse",
            Self::Http {
                streamable_http: Some(true),
                ..
            } => "streamable-http",
            Self::Http { .. } => "http",
            Self::WebSocket { .. } => "websocket",
            #[cfg(feature = "a2a")]
            Self::A2a { .. } => "a2a",
        }
    }

    /// Whether the transport this config selects can carry per-request
    /// outbound headers, e.g. a propagated end-user identity credential
    /// (MIK-6710).
    ///
    /// This mirrors [`crate::transport::Transport::carries_identity_headers`]
    /// but is evaluated statically from config alone, so the
    /// identity-propagation dispatch gate can refuse a `required` backend
    /// BEFORE its transport is started (and before any credential is
    /// minted) rather than after. Keep the two in sync: `HttpTransport` and
    /// the A2A transport (MIK-8063) apply `extra_headers` to the wire; stdio
    /// and WebSocket carry no per-request header channel.
    #[must_use]
    pub fn carries_identity_headers(&self) -> bool {
        !matches!(self, Self::Stdio { .. } | Self::WebSocket { .. })
    }
}
