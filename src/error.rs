// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

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

    /// Authorization refused this call.
    ///
    /// A distinct variant, not an opaque `JsonRpc`, so a consumer can ask "is
    /// this a denial?" without matching on message text. The playbook engine
    /// needs exactly that: a denial must not be retried, while a timeout must
    /// be, and the two are indistinguishable once flattened to a string.
    ///
    /// `code` is the code the router's own refusal envelope would carry, so a
    /// caller sees one classification whichever gate rejected.
    #[error("{message}")]
    Forbidden {
        /// JSON-RPC error code the refusal envelope carries.
        code: i32,
        /// HTTP status the refusal deserves.
        ///
        /// Carried rather than derived: the router gate already answers a
        /// refusal with 403, and a denial that only the chokepoint can see —
        /// a playbook step — must not come back 200 with an error buried in
        /// the body. One refusal, one status, whichever gate produced it.
        status: u16,
        /// Human-readable refusal reason, safe to return to the caller.
        message: String,
    },

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

    /// A transport failure that waiting cannot fix.
    ///
    /// `Transport` means "failed, cause unknown, possibly transient", which is
    /// the honest answer at most of its ~59 construction sites. This variant is
    /// for the few that genuinely know better: a command path that does not
    /// exist, a file that is not executable, a request the server calls
    /// malformed.
    ///
    /// The distinction has a caller. Warm-start retries indefinitely while a
    /// backend's tool cache is empty, so before this a mistyped command path
    /// produced a respawn attempt once a minute for the whole process lifetime,
    /// with nothing in the logs saying the configuration was simply wrong.
    ///
    /// When in doubt, use `Transport`. An unknown failure retrying is a cost;
    /// a recoverable failure classified permanent needs a restart to notice.
    ///
    /// HTTP status codes are deliberately NOT classified here, and the attempt
    /// is worth recording. A first pass marked 4xx permanent; two existing
    /// tests refused it, because this protocol overloads BOTH 404 and 400 to
    /// mean "your MCP session expired, reinitialise and retry" (#247). A
    /// status-only classifier is therefore unsafe in this codebase, whatever it
    /// would mean in a plain REST API. Classifying an HTTP failure needs the
    /// body, not just the code.
    #[error("Transport error (permanent): {0}")]
    TransportPermanent(String),

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
            Self::JsonRpc { code, .. } | Self::Forbidden { code, .. } => *code,
            Self::Json(_) => -32700,     // Parse error
            Self::Protocol(_) => -32600, // Invalid request
            Self::BackendNotFound(_) | Self::ToolNotFound(_) => -32001,
            Self::BackendUnavailable(_)
            | Self::CircuitOpen(_)
            | Self::BackendTimeout(_)
            | Self::Transport(_)
            // Same class as `Transport` to a JSON-RPC caller: a backend-side
            // failure, not a gateway fault. Omitting it reported a missing
            // backend command as an internal error.
            | Self::TransportPermanent(_) => -32000,
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

#[cfg(test)]
mod rpc_code_tests {
    use super::Error;

    #[test]
    fn a_permanent_transport_failure_reports_as_a_backend_error() {
        // Omitting the variant here reported a missing backend command as an
        // INTERNAL error, blaming the gateway for the operator's typo.
        assert_eq!(
            Error::TransportPermanent("Failed to spawn: no such file".to_string()).to_rpc_code(),
            -32000,
        );
        assert_eq!(
            Error::Transport("connection refused".to_string()).to_rpc_code(),
            -32000,
            "the two transport variants must look the same to a JSON-RPC caller"
        );
    }
}
