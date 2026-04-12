//! Error types for MCP Gateway

use std::io;

use thiserror::Error;

/// Result type alias for MCP Gateway
pub type Result<T> = std::result::Result<T, Error>;

/// MCP Gateway errors
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Configuration validation failure — semantically invalid config.
    ///
    /// Use this instead of `Internal` when a config value fails a semantic
    /// constraint (e.g. conflicting fields, invalid URL, missing required key).
    #[error("Configuration validation error: {0}")]
    ConfigValidation(String),

    /// Config watcher error — file watcher setup or event delivery failed.
    ///
    /// Use this instead of `Internal` for `notify`-crate failures in the
    /// hot-reload subsystem.
    #[error("Config watcher error: {0}")]
    ConfigWatcher(String),

    /// Capability file SHA-256 pin mismatch — potential rug-pull attack.
    ///
    /// Raised by the capability loader when a YAML's embedded `sha256:` pin
    /// does not match the on-disk file content. The capability is refused
    /// load. See `crate::capability::hash` for the hashing strategy.
    #[error(
        "Capability hash mismatch (rug-pull protection) in {file}: expected {expected}, actual {actual}"
    )]
    CapabilityHashMismatch {
        /// The hash embedded in the YAML `sha256:` field (trusted baseline).
        expected: String,
        /// The hash computed from the current file content.
        actual: String,
        /// The file path that failed verification.
        file: String,
    },

    /// Backend not found
    #[error("Backend not found: {0}")]
    BackendNotFound(String),

    /// Backend unavailable (circuit open)
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Circuit breaker is open — request rejected without being dispatched.
    ///
    /// Carries the backend name.  Use [`rpc_codes::SERVER_ERROR_START`] (-32000)
    /// as the JSON-RPC code for this variant.
    #[error("Circuit breaker open for backend '{0}'")]
    CircuitOpen(String),

    /// Tool not found in any connected backend.
    ///
    /// Carries the tool name that was requested.
    #[error("Tool not found: '{0}'")]
    ToolNotFound(String),

    /// Backend timeout
    #[error("Backend timeout: {0}")]
    BackendTimeout(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// OAuth client error — token acquisition, refresh, or callback failure.
    ///
    /// Use this instead of `Internal` for all errors originating in the
    /// `oauth/client`, `oauth/metadata`, `oauth/callback`, and `oauth/storage`
    /// modules.
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// TLS error — certificate loading, binding, or handshake failure.
    ///
    /// Use this instead of `Internal` for `rustls`/`axum-server` errors in
    /// the TLS server path.
    #[error("TLS error: {0}")]
    Tls(String),

    /// JSON-RPC error
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc {
        /// Error code
        code: i32,
        /// Error message
        message: String,
        /// Optional data
        data: Option<serde_json::Value>,
    },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Server shutdown
    #[error("Server shutdown")]
    Shutdown,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Create a JSON-RPC error
    pub fn json_rpc(code: i32, message: impl Into<String>) -> Self {
        Self::JsonRpc {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Convert to JSON-RPC error code
    #[must_use]
    pub fn to_rpc_code(&self) -> i32 {
        match self {
            Self::JsonRpc { code, .. } => *code,
            Self::Json(_) => -32700,     // Parse error
            Self::Protocol(_) => -32600, // Invalid request
            Self::BackendNotFound(_) | Self::ToolNotFound(_) => -32001,
            Self::BackendUnavailable(_)
            | Self::CircuitOpen(_)
            | Self::BackendTimeout(_)
            | Self::Transport(_) => -32000,
            _ => -32603, // Internal error
        }
    }
}

/// Standard JSON-RPC error codes
pub mod rpc_codes {
    /// Parse error - Invalid JSON
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid Request - Not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Server error range start
    pub const SERVER_ERROR_START: i32 = -32000;
    /// Server error range end
    pub const SERVER_ERROR_END: i32 = -32099;
}
